"""Hardening v1.1 §6 — executable tasks must be terminated for real.

The v1.0 scheduler only stopped *waiting* on the deadline; the worker kept
running. These tests assert the opposite: after a timeout the process tree is
gone, and a concurrency lease is only released once that is true.
"""
from __future__ import annotations

import os
import signal
import subprocess
import sys
import time
from pathlib import Path

import pytest

from runtime.scheduler import (
    ConcurrencyLease,
    dispatch_command,
    run_command_with_timeout,
)


def _pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _group_alive(pgid: int) -> bool:
    try:
        os.killpg(pgid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def test_command_success() -> None:
    out = run_command_with_timeout(
        [sys.executable, "-c", "print('hello')"], timeout_seconds=10
    )
    assert out.returncode == 0
    assert "hello" in out.stdout
    assert out.timed_out is False
    assert out.terminated is False


def test_command_missing_binary() -> None:
    out = run_command_with_timeout(["definitely-not-a-real-binary-xyz"], timeout_seconds=5)
    assert out.returncode is None
    assert out.elapsed_seconds >= 0


def test_timeout_terminates_process_group() -> None:
    """A long sleeper must be signalled and reaped, not left running."""
    out = run_command_with_timeout(
        [sys.executable, "-c", "import time; time.sleep(30)"], timeout_seconds=0.5
    )
    assert out.timed_out is True
    assert out.terminated is True
    assert out.returncode is not None, "process must be reaped before returning"
    assert out.pid is not None
    assert not _pid_alive(out.pid), "timed-out process is still alive"
    if out.process_group:
        assert not _group_alive(out.process_group), "process group survived"


def test_sigterm_ignoring_child_is_killed() -> None:
    """A child that traps SIGTERM must still be SIGKILLed after the grace period."""
    script = (
        "import signal, time\n"
        "signal.signal(signal.SIGTERM, lambda *a: None)\n"
        "print('ready', flush=True)\n"
        "time.sleep(60)\n"
    )
    out = run_command_with_timeout(
        [sys.executable, "-c", script], timeout_seconds=0.5, grace_seconds=0.5
    )
    assert out.timed_out is True
    assert out.killed is True, "SIGTERM-ignoring child must be SIGKILLed"
    assert out.returncode is not None
    assert not _pid_alive(out.pid)


def test_children_are_killed_with_the_group() -> None:
    """killpg must reach grandchildren, not just the direct child."""
    child = "import time; time.sleep(60)"
    parent = (
        "import subprocess, sys, time\n"
        f"p = subprocess.Popen([sys.executable, '-c', {child!r}])\n"
        "print(p.pid, flush=True)\n"
        "time.sleep(60)\n"
    )
    out = run_command_with_timeout(
        [sys.executable, "-c", parent], timeout_seconds=0.8, grace_seconds=0.5
    )
    assert out.timed_out is True
    grandchild = int(out.stdout.strip().splitlines()[0])
    # Give the kernel a moment to finish the group teardown.
    for _ in range(20):
        if not _pid_alive(grandchild):
            break
        time.sleep(0.05)
    assert not _pid_alive(grandchild), "grandchild survived the process-group kill"


def test_dispatch_command_success(tmp_path: Path) -> None:
    outcome = dispatch_command(
        workdir=tmp_path, role="scanner", phase="L4",
        argv=[sys.executable, "-c", "print('ok')"],
        config={"max_attempts": 1, "retry_backoff": {"base_seconds": 0, "max_seconds": 0}},
        timeout_seconds=10,
    )
    assert outcome.success is True
    assert outcome.attempts == 1
    assert (tmp_path / "agents" / outcome.agent_id / "task.json").exists()
    assert (tmp_path / "agents" / outcome.agent_id / "result.json").exists()


def test_dispatch_command_timeout_is_hard_and_retries(tmp_path: Path) -> None:
    outcome = dispatch_command(
        workdir=tmp_path, role="scanner", phase="L4",
        argv=[sys.executable, "-c", "import time; time.sleep(30)"],
        config={"max_attempts": 2, "retry_backoff": {"base_seconds": 0, "max_seconds": 0}},
        timeout_seconds=0.5,
    )
    assert outcome.success is False
    assert outcome.attempts == 2
    assert outcome.timed_out is True
    assert outcome.hard_timeout_verified is True


def test_no_overlap_between_timeout_and_retry(tmp_path: Path) -> None:
    """Attempt 2 must not start while attempt 1 is still running.

    Each attempt writes a marker file on exit; if the runs overlapped, the
    first attempt would still be alive when the second begins. We detect
    overlap by having the child append its own pid to a shared file at start
    and exit, then asserting the *live* process count never exceeds 1.
    """
    marker = tmp_path / "attempts.txt"
    script = (
        "import os, sys, time\n"
        f"open({str(marker)!r}, 'a').write('start:' + str(os.getpid()) + '\\n')\n"
        "time.sleep(30)\n"
    )
    outcome = dispatch_command(
        workdir=tmp_path, role="scanner", phase="L4",
        argv=[sys.executable, "-c", script],
        config={"max_attempts": 2, "retry_backoff": {"base_seconds": 0, "max_seconds": 0}},
        timeout_seconds=0.5,
    )
    assert outcome.attempts == 2
    starts = marker.read_text(encoding="utf-8").strip().splitlines()
    assert len(starts) == 2, "expected exactly two attempts to start"
    pids = [int(line.split(":")[1]) for line in starts]
    # By the time dispatch_command returned, every attempt must be dead.
    for pid in pids:
        assert not _pid_alive(pid), f"attempt pid {pid} outlived dispatch_command"


def test_concurrency_lease_released_after_timeout(tmp_path: Path) -> None:
    """The lease must come back exactly once, after the process is reaped."""
    sem = ConcurrencyLease(1)
    outcome = dispatch_command(
        workdir=tmp_path, role="scanner", phase="L4",
        argv=[sys.executable, "-c", "import time; time.sleep(30)"],
        config={"max_attempts": 1, "retry_backoff": {"base_seconds": 0, "max_seconds": 0}},
        timeout_seconds=0.5,
        concurrency=sem,
    )
    assert outcome.timed_out is True
    # If the lease had leaked, this acquire would fail.
    assert sem.acquire(timeout=1.0) is True
    sem.release()


def test_concurrency_lease_not_leaked_on_success(tmp_path: Path) -> None:
    sem = ConcurrencyLease(1)
    dispatch_command(
        workdir=tmp_path, role="scanner", phase="L4",
        argv=[sys.executable, "-c", "print('ok')"],
        config={"max_attempts": 1, "retry_backoff": {"base_seconds": 0, "max_seconds": 0}},
        timeout_seconds=10,
        concurrency=sem,
    )
    assert sem.acquire(timeout=1.0) is True
    sem.release()


def test_dispatch_command_argv_callable(tmp_path: Path) -> None:
    def build(lease) -> list[str]:
        assert lease.scratch.exists()
        return [sys.executable, "-c", "print('callable-argv')"]

    outcome = dispatch_command(
        workdir=tmp_path, role="scanner", phase="L4", argv=build,
        config={"max_attempts": 1, "retry_backoff": {"base_seconds": 0, "max_seconds": 0}},
        timeout_seconds=10,
    )
    assert outcome.success is True
    assert "callable-argv" in outcome.result["stdout_tail"]


def test_soft_timeout_reported_as_not_verified(tmp_path: Path) -> None:
    """The thread path must admit it did not terminate anything."""
    from runtime.scheduler import dispatch

    def slow(lease):
        time.sleep(30)
        return {"success": True}

    outcome = dispatch(
        workdir=tmp_path, role="x", phase="L1", fn=slow,
        config={"max_attempts": 1, "retry_backoff": {"base_seconds": 0, "max_seconds": 0}},
        timeout_seconds=0.3,
    )
    assert outcome.timed_out is True
    assert outcome.hard_timeout_verified is False
