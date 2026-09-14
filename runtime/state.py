"""Canonical audit-state machine (Spec §5).

`audit-state.json` is the single source of truth for an audit run. Agent
memory is a cache, never the resume authority.

Phase states (Spec §5.3):

    pending
      ↓
    in_progress
      ├── complete
      ├── failed
      └── skipped

Forbidden:

    pending → complete          (must go through in_progress)
    failed  → complete          (must re-enter in_progress)

Allowed recovery:

    failed → in_progress → complete

Atomic writes (Spec §5.4) are performed via :mod:`atomic_io`.

Schema versioning: state files carry ``schema_version``. The runtime refuses
to load state with an unknown schema version unless explicitly accepted.
"""

from __future__ import annotations

import datetime as _dt
import json
import os
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Mapping, Optional

from .atomic_io import (
    AtomicIOError,
    read_json_or_corrupt,
    sha256_file,
    write_json_atomic,
)

STATE_SCHEMA_VERSION = 1

# Phase state machine
PHASE_PENDING = "pending"
PHASE_IN_PROGRESS = "in_progress"
PHASE_COMPLETE = "complete"
PHASE_FAILED = "failed"
PHASE_SKIPPED = "skipped"

PHASE_STATES: frozenset[str] = frozenset({
    PHASE_PENDING, PHASE_IN_PROGRESS, PHASE_COMPLETE, PHASE_FAILED, PHASE_SKIPPED,
})

ALLOWED_TRANSITIONS: dict[str, frozenset[str]] = {
    PHASE_PENDING: frozenset({PHASE_IN_PROGRESS, PHASE_SKIPPED}),
    PHASE_IN_PROGRESS: frozenset({PHASE_COMPLETE, PHASE_FAILED}),
    PHASE_FAILED: frozenset({PHASE_IN_PROGRESS}),  # recovery only
    PHASE_SKIPPED: frozenset(),
    PHASE_COMPLETE: frozenset({PHASE_IN_PROGRESS}),  # re-open on rerun
}


class StateTransitionError(RuntimeError):
    """Raised when an illegal phase transition is requested."""


@dataclass
class ArtifactRecord:
    path: str
    sha256: str

    @classmethod
    def from_path(cls, path: str) -> "ArtifactRecord":
        return cls(path=path, sha256=sha256_file(path))

    def to_dict(self) -> dict[str, Any]:
        return {"path": self.path, "sha256": self.sha256}


@dataclass
class PhaseState:
    name: str
    status: str = PHASE_PENDING
    attempt: int = 0
    max_attempts: int = 2
    started_at: Optional[str] = None
    heartbeat_at: Optional[str] = None
    completed_at: Optional[str] = None
    artifacts: list[ArtifactRecord] = field(default_factory=list)
    last_error: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "status": self.status,
            "attempt": self.attempt,
            "max_attempts": self.max_attempts,
            "started_at": self.started_at,
            "heartbeat_at": self.heartbeat_at,
            "completed_at": self.completed_at,
            "artifacts": [a.to_dict() for a in self.artifacts],
            "last_error": self.last_error,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "PhaseState":
        return cls(
            name=data.get("name", ""),
            status=data.get("status", PHASE_PENDING),
            attempt=int(data.get("attempt", 0)),
            max_attempts=int(data.get("max_attempts", 2)),
            started_at=data.get("started_at"),
            heartbeat_at=data.get("heartbeat_at"),
            completed_at=data.get("completed_at"),
            artifacts=[ArtifactRecord(**a) for a in data.get("artifacts", [])],
            last_error=data.get("last_error"),
        )


def _now_iso() -> str:
    return _dt.datetime.now(_dt.timezone.utc).isoformat()


@dataclass
class AuditState:
    """Top-level audit state, persisted to ``audit-state.json``."""

    schema_version: int = STATE_SCHEMA_VERSION
    audit_id: str = ""
    mode: str = "balanced"
    status: str = "in_progress"

    source: dict[str, Any] = field(default_factory=dict)
    runtime: dict[str, Any] = field(default_factory=dict)
    phases: dict[str, PhaseState] = field(default_factory=dict)

    started_at: str = field(default_factory=_now_iso)
    updated_at: str = field(default_factory=_now_iso)
    completed_at: Optional[str] = None

    lock: threading.RLock = field(default_factory=threading.RLock, repr=False)

    # ---- construction / persistence ----

    @classmethod
    def new(cls, *, audit_id: str, mode: str, source: Mapping[str, Any], runtime: Mapping[str, Any]) -> "AuditState":
        state = cls(
            audit_id=audit_id,
            mode=mode,
            source=dict(source),
            runtime=dict(runtime),
        )
        return state

    @classmethod
    def load(cls, path: os.PathLike[str] | str) -> "AuditState":
        raw = read_json_or_corrupt(path)
        return cls.from_dict(raw)

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "AuditState":
        schema_version = int(data.get("schema_version", STATE_SCHEMA_VERSION))
        if schema_version != STATE_SCHEMA_VERSION:
            raise StateTransitionError(
                f"unsupported audit-state schema_version={schema_version}; "
                f"runtime supports {STATE_SCHEMA_VERSION}"
            )
        phases = {
            name: PhaseState.from_dict(p) for name, p in data.get("phases", {}).items()
        }
        state = cls(
            schema_version=schema_version,
            audit_id=data.get("audit_id", ""),
            mode=data.get("mode", "balanced"),
            status=data.get("status", "in_progress"),
            source=dict(data.get("source", {})),
            runtime=dict(data.get("runtime", {})),
            phases=phases,
            started_at=data.get("started_at", _now_iso()),
            updated_at=data.get("updated_at", _now_iso()),
            completed_at=data.get("completed_at"),
        )
        return state

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "audit_id": self.audit_id,
            "mode": self.mode,
            "status": self.status,
            "source": self.source,
            "runtime": self.runtime,
            "phases": {name: p.to_dict() for name, p in self.phases.items()},
            "started_at": self.started_at,
            "updated_at": self.updated_at,
            "completed_at": self.completed_at,
        }

    def save(self, path: os.PathLike[str] | str) -> None:
        with self.lock:
            self.updated_at = _now_iso()
            write_json_atomic(path, self.to_dict())

    # ---- phase machine ----

    def ensure_phase(self, name: str, *, max_attempts: int = 2) -> PhaseState:
        with self.lock:
            if name not in self.phases:
                self.phases[name] = PhaseState(name=name, max_attempts=max_attempts)
            return self.phases[name]

    def transition(self, phase_name: str, *, to: str, error: Optional[str] = None) -> PhaseState:
        """Apply a state-machine transition for *phase_name*.

        Raises StateTransitionError on illegal transitions.
        """
        with self.lock:
            phase = self.ensure_phase(phase_name)
            current = phase.status
            if to not in PHASE_STATES:
                raise StateTransitionError(f"unknown phase state {to!r}")
            # No-op transitions are not allowed (except in_progress heartbeats).
            if current == to and to != PHASE_IN_PROGRESS:
                raise StateTransitionError(
                    f"no-op transition for {phase_name}: already in {to}"
                )
            allowed = ALLOWED_TRANSITIONS.get(current, frozenset())
            if to not in allowed and to != PHASE_IN_PROGRESS:
                raise StateTransitionError(
                    f"illegal phase transition for {phase_name}: {current} → {to}"
                )
            phase.status = to
            now = _now_iso()
            # Increment attempt whenever we transition from a non-in-progress
            # state into in_progress (i.e. a fresh start after pending/failed/
            # complete re-open). Heartbeats (in_progress -> in_progress) do
            # not bump the counter.
            if to == PHASE_IN_PROGRESS and current != PHASE_IN_PROGRESS:
                phase.attempt += 1
                if phase.started_at is None:
                    phase.started_at = now
            phase.heartbeat_at = now
            if to == PHASE_COMPLETE:
                phase.completed_at = now
                phase.last_error = None
            if to == PHASE_FAILED:
                phase.last_error = error
            return phase

    def heartbeat(self, phase_name: str) -> None:
        with self.lock:
            phase = self.ensure_phase(phase_name)
            phase.heartbeat_at = _now_iso()

    def record_artifact(self, phase_name: str, path: os.PathLike[str] | str) -> ArtifactRecord:
        record = ArtifactRecord.from_path(str(path))
        with self.lock:
            phase = self.ensure_phase(phase_name)
            # Replace by path, keep order
            phase.artifacts = [a for a in phase.artifacts if a.path != record.path]
            phase.artifacts.append(record)
        return record

    # ---- queries ----

    def is_phase_complete(self, phase_name: str) -> bool:
        return self.phases.get(phase_name, PhaseState(name=phase_name)).status == PHASE_COMPLETE

    def incomplete_phases(self, all_phases: Iterable[str]) -> list[str]:
        return [p for p in all_phases if not self.is_phase_complete(p)]

    def all_terminal(self, all_phases: Iterable[str]) -> bool:
        for name in all_phases:
            status = self.phases.get(name, PhaseState(name=name)).status
            if status not in (PHASE_COMPLETE, PHASE_SKIPPED):
                return False
        return True

    def attempts_exhausted(self, phase_name: str) -> bool:
        phase = self.phases.get(phase_name)
        if not phase:
            return False
        return phase.attempt >= phase.max_attempts and phase.status == PHASE_FAILED

    def mark_complete(self) -> None:
        with self.lock:
            self.status = "complete"
            self.completed_at = _now_iso()