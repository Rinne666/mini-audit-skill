"""Hard-timeout process primitive (Spec §6 hardening v1.1).

The only deterministic safety primitive the runtime owns about processes.
The Harness owns agent scheduling; this module owns nothing but ``kill on
deadline``:

* spawn *argv* in its own process group
* SIGTERM on deadline, wait ``grace_seconds``, SIGKILL the group
* reap before returning, so callers never see an overlap between a
  timed-out attempt and the next one
* no retry, no backoff, no lease, no agent id — those belong to the
  Harness, not here

The sandbox policy (`runtime/sandbox.py`, `runtime/sandbox_backend.py`)
uses this primitive to enforce ``hard_timeout_verified=True`` on every
PoC and scanner execution.
"""

from __future__ import annotations

import dataclasses
import os
import signal
import subprocess
import time
from pathlib import Path
from typing import Mapping, Optional, Sequence


@dataclasses.dataclass
class CommandOutcome:
    """Result of a single ``run_command_with_timeout`` call.

    No attempt counter, no backoff state, no lease. Those would be the
    Harness's problem.
    """

    argv: list[str]
    returncode: Optional[int]
    stdout: str
    stderr: str
    elapsed_seconds: float
    timed_out: bool = False
    terminated: bool = False
    killed: bool = False
    pid: Optional[int] = None
    process_group: Optional[int] = None

    @property
    def terminated_for_real(self) -> bool:
        """True iff we sent a signal to the process group (SIGTERM or
        SIGKILL), not merely stopped waiting for it.

        SIGTERM-only termination is still "terminated for real" — the
        group received a kill signal and the children had to die from
        it. SIGKILL is the fallback if a child refuses SIGTERM.
        """
        return self.terminated or self.killed

    def to_dict(self) -> dict[str, object]:
        return dataclasses.asdict(self)


def _signal_process_group(proc: "subprocess.Popen", sig: int) -> None:
    """Send ``sig`` to *proc*'s whole process group, if we still own it."""
    pid = proc.pid
    if pid is None:
        return
    try:
        pgid = os.getpgid(pid)
    except (ProcessLookupError, OSError):
        return
    try:
        os.killpg(pgid, sig)
    except (ProcessLookupError, OSError):
        # The leader already exited; nothing more to do.
        pass


def run_command_with_timeout(
    argv: Sequence[str],
    *,
    timeout_seconds: float,
    cwd: os.PathLike[str] | str | None = None,
    env: Optional[Mapping[str, str]] = None,
    grace_seconds: float = 5.0,
    stdin_data: Optional[str] = None,
) -> CommandOutcome:
    """Run *argv* in its own process group with a hard wall-clock deadline.

    On deadline: SIGTERM the group, wait ``grace_seconds``, SIGKILL the
    group, reap. This function does not return until the child is reaped,
    so a timed-out command here is genuinely stopped — unlike a thread
    deadline that can only stop waiting.
    """
    argv_list = [str(a) for a in argv]
    started = time.monotonic()
    try:
        proc = subprocess.Popen(
            argv_list,
            cwd=str(cwd) if cwd is not None else None,
            env=dict(env) if env is not None else None,
            stdin=subprocess.PIPE if stdin_data is not None else subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            start_new_session=True,  # new process group → killpg reaches children
        )
    except FileNotFoundError as exc:
        return CommandOutcome(
            argv=argv_list,
            returncode=None,
            stdout="",
            stderr=str(exc),
            elapsed_seconds=time.monotonic() - started,
        )

    try:
        pgid = os.getpgid(proc.pid)
    except (ProcessLookupError, OSError):
        pgid = None

    timed_out = False
    terminated = False
    killed = False
    out = ""
    err = ""

    try:
        out, err = proc.communicate(input=stdin_data, timeout=timeout_seconds)
    except subprocess.TimeoutExpired:
        timed_out = True
        _signal_process_group(proc, signal.SIGTERM)
        terminated = True
        try:
            out, err = proc.communicate(timeout=grace_seconds)
        except subprocess.TimeoutExpired:
            _signal_process_group(proc, signal.SIGKILL)
            killed = True
            out, err = proc.communicate()

    returncode = proc.poll()
    elapsed = time.monotonic() - started

    return CommandOutcome(
        argv=argv_list,
        returncode=returncode,
        stdout=out or "",
        stderr=err or "",
        elapsed_seconds=elapsed,
        timed_out=timed_out,
        terminated=terminated,
        killed=killed,
        pid=proc.pid,
        process_group=pgid,
    )