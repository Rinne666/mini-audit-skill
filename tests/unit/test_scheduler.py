"""Tests for runtime/scheduler.py — concurrency lease + timeout + retry/backoff."""
from __future__ import annotations

import threading
import time
from pathlib import Path

import pytest

from runtime.scheduler import (
    ConcurrencyLease,
    Lease,
    compute_backoff,
    dispatch,
)


def test_compute_backoff_capped() -> None:
    base = 5.0
    cap = 60.0
    # attempt=1 -> 5
    d1 = compute_backoff(attempt=1, base_seconds=base, max_seconds=cap, jitter=False)
    assert d1 == 5.0
    # attempt=4 -> 5*2^3=40, still under cap
    d4 = compute_backoff(attempt=4, base_seconds=base, max_seconds=cap, jitter=False)
    assert d4 == 40.0
    # attempt=10 -> would be 5*2^9=2560, capped to 60
    d10 = compute_backoff(attempt=10, base_seconds=base, max_seconds=cap, jitter=False)
    assert d10 == 60.0


def test_compute_backoff_jitter_range() -> None:
    for _ in range(20):
        d = compute_backoff(attempt=2, base_seconds=10, max_seconds=60, jitter=True)
        # 2*10=20 base, jitter in [0.5, 1.0)
        assert 10.0 <= d <= 20.0


def test_concurrency_lease_bounds() -> None:
    lease = ConcurrencyLease(max_concurrent=2)
    assert lease.acquire(timeout=0.1)
    assert lease.acquire(timeout=0.1)
    assert not lease.acquire(timeout=0.1)
    lease.release()
    assert lease.acquire(timeout=0.1)


def test_dispatch_succeeds_first_try(tmp_path: Path) -> None:
    def task(lease: Lease) -> dict:
        lease.scratch.joinpath("ok.txt").write_text("ok", encoding="utf-8")
        return {"success": True, "msg": "done"}

    outcome = dispatch(workdir=tmp_path, role="t", phase="L1", fn=task)
    assert outcome.success
    assert outcome.attempts == 1
    assert (tmp_path / "agents" / outcome.agent_id / "task.json").exists()
    assert (tmp_path / "agents" / outcome.agent_id / "result.json").exists()


def test_dispatch_retries_then_fails(tmp_path: Path) -> None:
    def task(lease: Lease) -> dict:
        raise RuntimeError("nope")

    outcome = dispatch(workdir=tmp_path, role="t", phase="L1", fn=task,
                       config={"max_attempts": 2, "retry_backoff": {"base_seconds": 0.01, "max_seconds": 0.05}})
    assert not outcome.success
    assert outcome.attempts == 2
    assert "RuntimeError" in (outcome.error or "")


def test_dispatch_recovers_on_second_attempt(tmp_path: Path) -> None:
    state = {"n": 0}

    def task(lease: Lease) -> dict:
        state["n"] += 1
        if state["n"] < 2:
            raise RuntimeError("transient")
        return {"success": True, "attempt": state["n"]}

    outcome = dispatch(workdir=tmp_path, role="t", phase="L1", fn=task,
                       config={"max_attempts": 3, "retry_backoff": {"base_seconds": 0.01, "max_seconds": 0.05}})
    assert outcome.success
    assert outcome.attempts == 2


def test_dispatch_respects_timeout(tmp_path: Path) -> None:
    def task(lease: Lease) -> dict:
        time.sleep(5)
        return {"success": True}

    outcome = dispatch(workdir=tmp_path, role="t", phase="L1", fn=task, timeout_seconds=1)
    assert not outcome.success
    assert outcome.timed_out is True


def test_dispatch_records_artifacts_per_attempt(tmp_path: Path) -> None:
    def task(lease: Lease) -> dict:
        # Write an artifact into the lease scratch
        lease.scratch.joinpath("trace.json").write_text('{"x": 1}', encoding="utf-8")
        return {"success": True}

    outcome = dispatch(workdir=tmp_path, role="t", phase="L1", fn=task)
    assert outcome.success
    assert (tmp_path / "agents" / outcome.agent_id / "scratch" / "trace.json").exists()


def test_parallel_bounds_concurrency(tmp_path: Path) -> None:
    from runtime.scheduler import parallel

    active = 0
    peak = 0
    lock = threading.Lock()
    barrier = threading.Event()

    def make_task(i: int):
        def task(lease: Lease) -> dict:
            nonlocal active, peak
            with lock:
                active += 1
                peak = max(peak, active)
            time.sleep(0.3)
            with lock:
                active -= 1
            return {"success": True, "i": i}
        return {"role": "t", "phase": f"L{i}", "fn": task, "agent_id": f"agent-{i}"}

    tasks = [make_task(i) for i in range(6)]
    config = {"max_concurrent_agents": 2, "default_timeout_seconds": 30,
              "retry_backoff": {"base_seconds": 0.01, "max_seconds": 0.05}}
    outcomes = parallel(workdir=tmp_path, tasks=tasks, config=config)
    assert len(outcomes) == 6
    assert all(o.success for o in outcomes)
    assert peak <= 2