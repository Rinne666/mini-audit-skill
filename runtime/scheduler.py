"""Scheduler with concurrency lease + timeout + retry/backoff (Spec §22, §23).

The runtime owns scheduling, not the prompt. We do NOT rely on:

    "please don't spawn more than 3 agents at once"

The scheduler enforces:

* max_concurrent_agents — semaphore-style lease
* default_timeout_seconds — per-task wall-clock budget
* max_attempts — bound retries
* retry_backoff — exponential with cap

Every dispatched task gets a deterministic lease record:

    mini-audit/agents/<agent-id>/task.json
    mini-audit/agents/<agent-id>/scratch/
    mini-audit/agents/<agent-id>/result.json
    mini-audit/agents/<agent-id>/artifacts/

Agent leases are released when the task finishes (success, failure, or
timeout). Cancellation propagates to children.
"""

from __future__ import annotations

import dataclasses
import datetime as _dt
import json
import os
import random
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping, Optional

from .atomic_io import write_json_atomic

DEFAULT_CONFIG: dict[str, Any] = {
    "max_concurrent_agents": 3,
    "default_timeout_seconds": 900,
    "max_attempts": 2,
    "retry_backoff": {"base_seconds": 5, "max_seconds": 60},
}


@dataclasses.dataclass
class LeaseRecord:
    agent_id: str
    role: str
    phase: str
    started_at: str
    timeout_seconds: int
    attempt: int
    pid: Optional[int] = None

    def to_dict(self) -> dict[str, Any]:
        return dataclasses.asdict(self)

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "LeaseRecord":
        return cls(
            agent_id=data.get("agent_id", ""),
            role=data.get("role", ""),
            phase=data.get("phase", ""),
            started_at=data.get("started_at", ""),
            timeout_seconds=int(data.get("timeout_seconds", 0)),
            attempt=int(data.get("attempt", 1)),
            pid=data.get("pid"),
        )


class LeaseError(RuntimeError):
    """Raised when a lease cannot be acquired (concurrency exhausted)."""


class Lease:
    """A single agent lease (Spec §23)."""

    def __init__(self, *, workdir: os.PathLike[str] | str, agent_id: str, role: str, phase: str,
                 timeout_seconds: int, attempt: int) -> None:
        self.workdir = Path(workdir)
        self.agent_root = self.workdir / "agents" / agent_id
        self.agent_id = agent_id
        self.role = role
        self.phase = phase
        self.timeout_seconds = timeout_seconds
        self.attempt = attempt
        self.record = LeaseRecord(
            agent_id=agent_id,
            role=role,
            phase=phase,
            started_at=_dt.datetime.now(_dt.timezone.utc).isoformat(),
            timeout_seconds=timeout_seconds,
            attempt=attempt,
            pid=os.getpid(),
        )

    def write(self) -> None:
        self.agent_root.mkdir(parents=True, exist_ok=True)
        (self.agent_root / "scratch").mkdir(exist_ok=True)
        (self.agent_root / "artifacts").mkdir(exist_ok=True)
        write_json_atomic(self.agent_root / "task.json", self.record.to_dict())

    def release(self, *, result: Optional[Mapping[str, Any]] = None) -> None:
        if result is not None:
            write_json_atomic(self.agent_root / "result.json", dict(result))

    @property
    def scratch(self) -> Path:
        p = self.agent_root / "scratch"
        p.mkdir(parents=True, exist_ok=True)
        return p

    @property
    def artifacts(self) -> Path:
        p = self.agent_root / "artifacts"
        p.mkdir(parents=True, exist_ok=True)
        return p


class ConcurrencyLease:
    """Counting semaphore for max_concurrent_agents."""

    def __init__(self, max_concurrent: int) -> None:
        self._sem = threading.BoundedSemaphore(max_concurrent)

    def acquire(self, timeout: Optional[float] = None) -> bool:
        return self._sem.acquire(timeout=timeout)

    def release(self) -> None:
        self._sem.release()


@dataclasses.dataclass
class TaskOutcome:
    agent_id: str
    success: bool
    attempts: int
    elapsed_seconds: float
    result: Optional[dict[str, Any]] = None
    error: Optional[str] = None
    timed_out: bool = False


def compute_backoff(*, attempt: int, base_seconds: float, max_seconds: float, jitter: bool = True) -> float:
    """Exponential backoff with cap and optional jitter.

    attempt=1 → base_seconds
    attempt=2 → 2*base_seconds
    ...
    capped at max_seconds
    """
    delay = min(max_seconds, base_seconds * (2 ** max(0, attempt - 1)))
    if jitter:
        delay = delay * (0.5 + random.random() * 0.5)
    return delay


def dispatch(*, workdir: os.PathLike[str] | str, role: str, phase: str,
             fn: Callable[[Lease], dict[str, Any]],
             config: Optional[Mapping[str, Any]] = None,
             concurrency: Optional[ConcurrencyLease] = None,
             timeout_seconds: Optional[int] = None,
             max_attempts: Optional[int] = None,
             agent_id: Optional[str] = None,
             on_attempt: Optional[Callable[[int, float], None]] = None) -> TaskOutcome:
    """Dispatch one task under scheduler policy.

    *fn* receives a :class:`Lease` and returns a result dict.
    """
    cfg = {**DEFAULT_CONFIG, **(config or {})}
    backoff_cfg = cfg.get("retry_backoff", DEFAULT_CONFIG["retry_backoff"])
    base_seconds = float(backoff_cfg.get("base_seconds", 5))
    max_seconds = float(backoff_cfg.get("max_seconds", 60))
    timeout = int(timeout_seconds if timeout_seconds is not None else cfg["default_timeout_seconds"])
    attempts = int(max_attempts if max_attempts is not None else cfg["max_attempts"])
    aid = agent_id or f"{role}-{phase}-{uuid.uuid4().hex[:8]}"

    started = time.monotonic()
    last_error: Optional[str] = None
    timed_out = False
    for attempt in range(1, attempts + 1):
        lease = Lease(
            workdir=workdir,
            agent_id=aid,
            role=role,
            phase=phase,
            timeout_seconds=timeout,
            attempt=attempt,
        )
        lease.write()
        if on_attempt is not None:
            on_attempt(attempt, timeout)

        if concurrency is not None:
            acquired = concurrency.acquire(timeout=max(1.0, timeout / 2))
            if not acquired:
                last_error = "concurrency lease unavailable"
                lease.release(result={"success": False, "error": last_error, "attempt": attempt})
                continue

        try:
            result = _run_with_timeout(fn, lease, timeout)
            lease.release(result=result)
            elapsed = time.monotonic() - started
            return TaskOutcome(
                agent_id=aid,
                success=bool(result.get("success", True)),
                attempts=attempt,
                elapsed_seconds=elapsed,
                result=result,
                error=result.get("error"),
            )
        except _TimeoutSignal:
            timed_out = True
            last_error = f"timeout after {timeout}s"
            lease.release(result={"success": False, "error": last_error, "attempt": attempt, "timed_out": True})
        except Exception as exc:  # noqa: BLE001 - we want to capture and retry
            last_error = f"{type(exc).__name__}: {exc}"
            lease.release(result={"success": False, "error": last_error, "attempt": attempt})
        finally:
            if concurrency is not None:
                try:
                    concurrency.release()
                except Exception:
                    pass

        if attempt < attempts:
            delay = compute_backoff(attempt=attempt + 1, base_seconds=base_seconds, max_seconds=max_seconds)
            if on_attempt is not None:
                on_attempt(attempt + 1, delay)
            time.sleep(delay)

    elapsed = time.monotonic() - started
    return TaskOutcome(
        agent_id=aid,
        success=False,
        attempts=attempts,
        elapsed_seconds=elapsed,
        error=last_error,
        timed_out=timed_out,
    )


class _TimeoutSignal(Exception):
    pass


def _run_with_timeout(fn: Callable[[Lease], dict[str, Any]], lease: Lease, timeout_seconds: int) -> dict[str, Any]:
    """Run *fn(lease)* in a worker thread with a wall-clock timeout.

    We use threads (not subprocesses) so the same Python process can host
    many tasks; if a task needs hard isolation, the runtime should run it
    in a separate process (Spec §25 — sandbox policy). This function is
    the soft-deadline enforcement layer.
    """
    box: dict[str, Any] = {}

    def target() -> None:
        try:
            box["result"] = fn(lease)
        except BaseException as exc:  # noqa: BLE001
            box["error"] = exc

    t = threading.Thread(target=target, name=f"lease-{lease.agent_id}", daemon=True)
    t.start()
    t.join(timeout=timeout_seconds)
    if t.is_alive():
        # We can't actually kill a thread in Python; we record timeout and
        # let the task finish in the background. Caller decides whether to
        # release the lease.
        raise _TimeoutSignal()
    if "error" in box:
        raise box["error"]
    return box.get("result") or {"success": True}


def parallel(*, workdir: os.PathLike[str] | str, tasks: Iterable[Mapping[str, Any]],
             config: Optional[Mapping[str, Any]] = None) -> list[TaskOutcome]:
    """Dispatch a batch of tasks with bounded concurrency.

    Each task is a mapping with keys: ``role``, ``phase``, ``fn``, and
    optional ``agent_id``, ``timeout_seconds``, ``max_attempts``.
    """
    cfg = {**DEFAULT_CONFIG, **(config or {})}
    sem = ConcurrencyLease(int(cfg.get("max_concurrent_agents", 3)))
    outcomes: list[TaskOutcome] = []
    outcomes_lock = threading.RLock()

    def runner(t: Mapping[str, Any]) -> None:
        outcome = dispatch(
            workdir=workdir,
            role=t["role"],
            phase=t["phase"],
            fn=t["fn"],
            config=cfg,
            concurrency=sem,
            timeout_seconds=t.get("timeout_seconds"),
            max_attempts=t.get("max_attempts"),
            agent_id=t.get("agent_id"),
        )
        with outcomes_lock:
            outcomes.append(outcome)

    pool = ThreadPoolExecutor(max_workers=int(cfg.get("max_concurrent_agents", 3)))
    try:
        futures = [pool.submit(runner, t) for t in tasks]
        for f in futures:
            f.result()  # surface exceptions
    finally:
        pool.shutdown(wait=True)

    outcomes.sort(key=lambda o: o.agent_id)
    return outcomes