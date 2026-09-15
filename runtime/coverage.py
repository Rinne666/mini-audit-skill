"""Coverage ledger (Spec §20).

A coverage unit is the triple ``subsystem × boundary × attack_class``.
Each unit moves through its own state machine:

    planned
      ↓
    in_progress
      ├── covered
      ├── candidate
      ├── blocked
      ├── deferred
      └── out_of_scope

We never claim "full coverage". We report the histogram of unit states
(planned: 110, covered: 92, candidate: 8, blocked: 4, deferred: 6).

An audit run cannot reach ``complete`` while any planned unit remains
unresolved (Spec §21). The runtime enforces this at the audit-complete
gate.

Hardening v1.1 §9 closes a hole in that rule: an *empty* ledger
(``{"units": []}``) trivially satisfied "no unresolved planned units", so a
run that never did coverage planning could pass the final gate. Completion
now additionally requires that planning actually ran
(``planning_status == "complete"``) and that it produced at least one unit
(``unit_count > 0``).
"""

from __future__ import annotations

import datetime as _dt
import os
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Mapping, Optional

from .atomic_io import read_json_or_corrupt, write_json_atomic
from .schema import load_schema_or_none, validate_instance

COVERAGE_SCHEMA_VERSION = 1

# Planning lifecycle (Hardening v1.1 §9)
PLANNING_NOT_STARTED = "not_started"
PLANNING_IN_PROGRESS = "in_progress"
PLANNING_COMPLETE = "complete"
PLANNING_STATES: frozenset[str] = frozenset({
    PLANNING_NOT_STARTED, PLANNING_IN_PROGRESS, PLANNING_COMPLETE,
})

UNIT_PLANNED = "planned"
UNIT_IN_PROGRESS = "in_progress"
UNIT_COVERED = "covered"
UNIT_CANDIDATE = "candidate"
UNIT_BLOCKED = "blocked"
UNIT_DEFERRED = "deferred"
UNIT_OUT_OF_SCOPE = "out_of_scope"

UNIT_STATES: frozenset[str] = frozenset({
    UNIT_PLANNED, UNIT_IN_PROGRESS, UNIT_COVERED, UNIT_CANDIDATE,
    UNIT_BLOCKED, UNIT_DEFERRED, UNIT_OUT_OF_SCOPE,
})

UNIT_TRANSITIONS: dict[str, frozenset[str]] = {
    UNIT_PLANNED: frozenset({UNIT_IN_PROGRESS, UNIT_OUT_OF_SCOPE, UNIT_DEFERRED}),
    UNIT_IN_PROGRESS: frozenset({UNIT_COVERED, UNIT_CANDIDATE, UNIT_BLOCKED, UNIT_DEFERRED}),
    UNIT_COVERED: frozenset({UNIT_CANDIDATE}),  # can later produce a finding
    UNIT_CANDIDATE: frozenset({UNIT_COVERED, UNIT_BLOCKED, UNIT_DEFERRED}),
    UNIT_BLOCKED: frozenset({UNIT_IN_PROGRESS}),
    UNIT_DEFERRED: frozenset({UNIT_PLANNED, UNIT_IN_PROGRESS, UNIT_OUT_OF_SCOPE}),
    UNIT_OUT_OF_SCOPE: frozenset(),
}


def _now_iso() -> str:
    return _dt.datetime.now(_dt.timezone.utc).isoformat()


@dataclass
class CoverageCheck:
    id: str
    status: str = UNIT_PLANNED
    agent_id: str = ""
    method: str = "source"  # source | runtime | scanner | external
    note: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {"id": self.id, "status": self.status, "agent_id": self.agent_id, "method": self.method, "note": self.note}

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "CoverageCheck":
        return cls(
            id=data.get("id", ""),
            status=data.get("status", UNIT_PLANNED),
            agent_id=data.get("agent_id", ""),
            method=data.get("method", "source"),
            note=data.get("note", ""),
        )


@dataclass
class CoverageUnit:
    id: str
    subsystem: str
    boundary: str
    attack_class: str
    status: str = UNIT_PLANNED
    reviewed_paths: list[str] = None  # type: ignore[assignment]
    checks: list[CoverageCheck] = None  # type: ignore[assignment]
    candidate_ids: list[str] = None  # type: ignore[assignment]
    gaps: list[str] = None  # type: ignore[assignment]
    updated_at: str = ""

    def __post_init__(self) -> None:
        if self.reviewed_paths is None:
            self.reviewed_paths = []
        if self.checks is None:
            self.checks = []
        if self.candidate_ids is None:
            self.candidate_ids = []
        if self.gaps is None:
            self.gaps = []
        if not self.updated_at:
            self.updated_at = _now_iso()

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "subsystem": self.subsystem,
            "boundary": self.boundary,
            "attack_class": self.attack_class,
            "status": self.status,
            "reviewed_paths": list(self.reviewed_paths),
            "checks": [c.to_dict() for c in self.checks],
            "candidate_ids": list(self.candidate_ids),
            "gaps": list(self.gaps),
            "updated_at": self.updated_at,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "CoverageUnit":
        return cls(
            id=data.get("id", ""),
            subsystem=data.get("subsystem", ""),
            boundary=data.get("boundary", ""),
            attack_class=data.get("attack_class", ""),
            status=data.get("status", UNIT_PLANNED),
            reviewed_paths=list(data.get("reviewed_paths", [])),
            checks=[CoverageCheck.from_dict(c) for c in data.get("checks", [])],
            candidate_ids=list(data.get("candidate_ids", [])),
            gaps=list(data.get("gaps", [])),
            updated_at=data.get("updated_at", _now_iso()),
        )


class CoverageLedgerError(RuntimeError):
    """Raised when an illegal unit transition or coverage gate is violated."""


class CoverageLedger:
    """Coverage ledger state machine backed by ``coverage-ledger.json``."""

    def __init__(self, audit_id: str, units: list[CoverageUnit], lock: Optional[threading.RLock] = None,
                 *, planning_status: str = PLANNING_NOT_STARTED) -> None:
        self.audit_id = audit_id
        self.units: list[CoverageUnit] = list(units)
        self.lock = lock or threading.RLock()
        if planning_status not in PLANNING_STATES:
            raise CoverageLedgerError(f"unknown planning_status {planning_status!r}")
        self.planning_status = planning_status

    @classmethod
    def empty(cls, *, audit_id: str) -> "CoverageLedger":
        return cls(audit_id=audit_id, units=[])

    @classmethod
    def load(cls, path: os.PathLike[str] | str) -> "CoverageLedger":
        try:
            data = read_json_or_corrupt(path)
        except FileNotFoundError:
            return cls.empty(audit_id="")
        return cls.from_dict(data)

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "CoverageLedger":
        # Hardening v1.1 §5: the shipped coverage schema is authoritative.
        schema = load_schema_or_none("coverage-ledger")
        if schema is not None:
            errors = validate_instance(dict(data), schema)
            if errors:
                raise CoverageLedgerError(
                    "coverage-ledger.schema.json validation failed: "
                    + "; ".join(str(e) for e in errors[:5])
                )
        units = [CoverageUnit.from_dict(u) for u in data.get("units", [])]
        planning_status = data.get("planning_status", PLANNING_NOT_STARTED)
        if planning_status not in PLANNING_STATES:
            raise CoverageLedgerError(f"unknown planning_status {planning_status!r}")
        return cls(audit_id=data.get("audit_id", ""), units=units, planning_status=planning_status)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": COVERAGE_SCHEMA_VERSION,
            "audit_id": self.audit_id,
            "planning_status": self.planning_status,
            "units": [u.to_dict() for u in self.units],
        }

    def save(self, path: os.PathLike[str] | str) -> None:
        with self.lock:
            write_json_atomic(path, self.to_dict())

    # ---- planning lifecycle ----

    def begin_planning(self) -> None:
        """Mark coverage planning as started (idempotent)."""
        with self.lock:
            if self.planning_status == PLANNING_NOT_STARTED:
                self.planning_status = PLANNING_IN_PROGRESS

    def finalize_planning(self) -> None:
        """Mark coverage planning as finished.

        Only after this may the final gate consider the ledger complete —
        together with ``unit_count > 0``.
        """
        with self.lock:
            self.planning_status = PLANNING_COMPLETE

    # ---- CRUD ----

    def add_unit(self, *, subsystem: str, boundary: str, attack_class: str, unit_id: Optional[str] = None) -> CoverageUnit:
        if unit_id is None:
            unit_id = f"{subsystem}|{boundary}|{attack_class}"
        with self.lock:
            if any(u.id == unit_id for u in self.units):
                raise CoverageLedgerError(f"duplicate coverage unit id: {unit_id}")
            if self.planning_status == PLANNING_NOT_STARTED:
                self.planning_status = PLANNING_IN_PROGRESS
            unit = CoverageUnit(id=unit_id, subsystem=subsystem, boundary=boundary, attack_class=attack_class)
            self.units.append(unit)
            return unit

    def get(self, unit_id: str) -> Optional[CoverageUnit]:
        with self.lock:
            for u in self.units:
                if u.id == unit_id:
                    return u
        return None

    def transition(self, unit_id: str, *, to: str, gap: Optional[str] = None) -> CoverageUnit:
        if to not in UNIT_STATES:
            raise CoverageLedgerError(f"unknown unit state {to!r}")
        with self.lock:
            unit = self.get(unit_id)
            if unit is None:
                raise CoverageLedgerError(f"unknown coverage unit: {unit_id}")
            allowed = UNIT_TRANSITIONS.get(unit.status, frozenset())
            if to not in allowed and unit.status != to:
                raise CoverageLedgerError(f"illegal unit transition: {unit.status} → {to}")
            unit.status = to
            unit.updated_at = _now_iso()
            if to == UNIT_BLOCKED and gap and gap not in unit.gaps:
                unit.gaps.append(gap)
            return unit

    def record_check(self, unit_id: str, *, check_id: str, agent_id: str, method: str = "source", note: str = "") -> CoverageCheck:
        with self.lock:
            unit = self.get(unit_id)
            if unit is None:
                raise CoverageLedgerError(f"unknown coverage unit: {unit_id}")
            for c in unit.checks:
                if c.id == check_id:
                    c.agent_id = agent_id or c.agent_id
                    c.method = method or c.method
                    c.note = note or c.note
                    return c
            check = CoverageCheck(id=check_id, status="covered", agent_id=agent_id, method=method, note=note)
            unit.checks.append(check)
            return check

    def attach_candidate(self, unit_id: str, candidate_id: str) -> None:
        with self.lock:
            unit = self.get(unit_id)
            if unit is None:
                raise CoverageLedgerError(f"unknown coverage unit: {unit_id}")
            if candidate_id not in unit.candidate_ids:
                unit.candidate_ids.append(candidate_id)

    # ---- queries ----

    def histogram(self) -> dict[str, int]:
        with self.lock:
            out = {s: 0 for s in UNIT_STATES}
            for u in self.units:
                out[u.status] = out.get(u.status, 0) + 1
            return out

    def has_unresolved_planned(self) -> bool:
        with self.lock:
            for u in self.units:
                if u.status in (UNIT_PLANNED, UNIT_IN_PROGRESS):
                    return True
        return False

    def unresolved_units(self) -> list[CoverageUnit]:
        with self.lock:
            return [u for u in self.units if u.status in (UNIT_PLANNED, UNIT_IN_PROGRESS)]

    def by_subsystem(self) -> dict[str, list[CoverageUnit]]:
        with self.lock:
            out: dict[str, list[CoverageUnit]] = {}
            for u in self.units:
                out.setdefault(u.subsystem, []).append(u)
            return out

    def audit_complete_ok(self) -> tuple[bool, list[str]]:
        """Return (ok, unresolved_unit_ids).

        ``ok`` requires all three of (Hardening v1.1 §9):

        * ``planning_status == "complete"`` — coverage planning ran;
        * ``unit_count > 0`` — planning actually produced units;
        * no unit is ``planned`` or ``in_progress``.

        The second element stays a list of *unit ids* for backward
        compatibility; use :meth:`completeness_report` for full reasons.
        """
        report = self.completeness_report()
        return (report["ok"], report["unresolved"])

    def completeness_report(self) -> dict[str, Any]:
        """Structured completeness verdict, including why it failed."""
        with self.lock:
            unresolved = [u.id for u in self.units if u.status in (UNIT_PLANNED, UNIT_IN_PROGRESS)]
            reasons: list[str] = []
            if self.planning_status != PLANNING_COMPLETE:
                reasons.append(
                    f"coverage planning is {self.planning_status!r}, not 'complete'"
                )
            if len(self.units) == 0:
                reasons.append("coverage plan is empty (unit_count == 0)")
            if unresolved:
                reasons.append(f"{len(unresolved)} coverage unit(s) still planned/in_progress")
            return {
                "ok": not reasons,
                "planning_status": self.planning_status,
                "unit_count": len(self.units),
                "unresolved": unresolved,
                "reasons": reasons,
                "histogram": self.histogram(),
            }

    def unit_count(self) -> int:
        with self.lock:
            return len(self.units)


def make_unit_id(subsystem: str, boundary: str, attack_class: str) -> str:
    """Canonical coverage unit id format: subsystem|boundary|attack_class."""
    return f"{subsystem}|{boundary}|{attack_class}"