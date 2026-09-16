"""Search Governance write lock (Search Governance v1, R2-5).

Two different things in this runtime are easy to confuse, and this module
exists partly to keep them apart:

    scheduler.Lease / ConcurrencyLease
        A concurrency *quota*. How many agents may run at once. Implemented
        with an in-process ``threading.Semaphore``; it says nothing about who
        may write canonical state, and it does not span processes.

    SearchGovernanceLock
        Cross-process mutual exclusion over the research artifacts. A research
        delta mutates ``search-ledger.json`` and ``attack-graph.json`` (and may
        patch candidate records), and those writes are one logical transaction,
        so they are covered by one lock rather than one lock per file —
        per-file locks reintroduce lock ordering, deadlock and half-applied
        transactions.

Rules this module implements:

* One global lock file, ``mini-audit/.search-governance.lock``.
* ``LOCK_EX`` for writers, ``LOCK_SH`` for readers that must read more than
  one research artifact consistently (a reader that saw a new ledger beside
  an old graph would be reading a transaction's middle).
* A short timeout (5s) after which the caller fails fast with exit code 3 and
  a machine-readable busy error, rather than hanging a CI job.
* The lock file is never unlinked. Removing it while another process holds a
  lock on the same inode is the classic ``flock`` race: the next process
  creates a new inode, locks *that*, and both think they hold the lock.

The holder metadata in the file is **best-effort diagnostics only**. Multiple
shared readers may hold the lock at once and a blocked exclusive writer cannot
tell which of them it is waiting on, so no correctness decision may depend on
it.
"""

from __future__ import annotations

import datetime as _dt
import errno
import json
import os
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator, Optional

try:  # POSIX only — the runtime already depends on sh/ulimit/POSIX rename.
    import fcntl
except ImportError:  # pragma: no cover - platform guard
    fcntl = None  # type: ignore[assignment]


LOCK_FILENAME = ".search-governance.lock"
LOCK_TIMEOUT_SECONDS = 5.0
BUSY_EXIT_CODE = 3
TIMEOUT_ENV = "MINI_AUDIT_SEARCH_LOCK_TIMEOUT"
_POLL_INTERVAL_SECONDS = 0.05


def default_timeout() -> float:
    """Lock timeout, overridable for tests and unusual deployments.

    Follows the runtime's existing ``MINI_AUDIT_*`` env-override convention
    (``MINI_AUDIT_SCHEMA_DIR``, ``MINI_AUDIT_DOCKER_IMAGE``) so the busy path
    can be exercised without a five-second sleep.
    """
    raw = os.environ.get(TIMEOUT_ENV)
    if raw:
        try:
            value = float(raw)
        except ValueError:
            return LOCK_TIMEOUT_SECONDS
        if value > 0:
            return value
    return LOCK_TIMEOUT_SECONDS


class SearchLockBusy(RuntimeError):
    """Raised when the lock cannot be taken inside the timeout."""

    def __init__(self, message: str, *, holder: Optional[dict[str, Any]] = None) -> None:
        super().__init__(message)
        self.holder: dict[str, Any] = dict(holder or {})

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": False,
            "error": "search-governance lock busy",
            "holder": self.holder,
        }


def lock_path(audit_root: os.PathLike[str] | str) -> Path:
    return Path(audit_root) / LOCK_FILENAME


def _now() -> str:
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class SearchGovernanceLock:
    """A held (or acquirable) Search Governance lock.

    Not reentrant and not nestable: ``flock`` is per open file description, so
    a second acquisition in the same process would block against itself. Each
    CLI command acquires once, around its whole transaction.
    """

    def __init__(
        self,
        audit_root: os.PathLike[str] | str,
        *,
        exclusive: bool = True,
        timeout: Optional[float] = None,
        operation: Optional[str] = None,
        agent: Optional[str] = None,
    ) -> None:
        self.audit_root = Path(audit_root)
        self.path = lock_path(audit_root)
        self.exclusive = exclusive
        self.timeout = float(default_timeout() if timeout is None else timeout)
        self.operation = operation
        self.agent = agent
        self._fd: Optional[int] = None

    # -- metadata ---------------------------------------------------------

    def holder_metadata(self) -> dict[str, Any]:
        return {
            "pid": os.getpid(),
            "agent": self.agent or "",
            "operation": self.operation or "",
            "acquired_at": _now(),
            "mode": "exclusive" if self.exclusive else "shared",
        }

    def read_holder(self) -> dict[str, Any]:
        """Best-effort read of whoever last wrote the lock file.

        Diagnostic only — see the module docstring. Returns ``{}`` when the
        file is absent, empty, mid-write, or not JSON.
        """
        try:
            raw = self.path.read_text(encoding="utf-8")
        except OSError:
            return {}
        if not raw.strip():
            return {}
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            return {}
        return data if isinstance(data, dict) else {}

    def _write_holder(self) -> None:
        """Record diagnostics on the lock file we hold exclusively.

        Deliberately written only by exclusive holders: a shared reader must
        not rewrite the record another reader is relying on.
        """
        if not self.exclusive or self._fd is None:
            return
        payload = json.dumps(self.holder_metadata(), indent=2, sort_keys=True) + "\n"
        try:
            os.ftruncate(self._fd, 0)
            os.lseek(self._fd, 0, os.SEEK_SET)
            os.write(self._fd, payload.encode("utf-8"))
            os.fsync(self._fd)
        except OSError:
            # Diagnostics must never be able to fail a transaction.
            pass

    # -- acquire / release ------------------------------------------------

    def acquire(self) -> "SearchGovernanceLock":
        if fcntl is None:  # pragma: no cover - platform guard
            raise RuntimeError(
                "Search Governance locking requires fcntl (POSIX); "
                "this platform cannot provide the cross-process guarantee"
            )
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._fd = os.open(str(self.path), os.O_RDWR | os.O_CREAT, 0o600)
        flag = fcntl.LOCK_EX if self.exclusive else fcntl.LOCK_SH
        deadline = time.monotonic() + max(0.0, self.timeout)
        while True:
            try:
                fcntl.flock(self._fd, flag | fcntl.LOCK_NB)
                break
            except OSError as exc:
                if exc.errno not in (errno.EAGAIN, errno.EACCES, errno.EWOULDBLOCK):
                    self._close()
                    raise
                if time.monotonic() >= deadline:
                    holder = self.read_holder()
                    self._close()
                    raise SearchLockBusy(
                        f"could not acquire the Search Governance lock at {self.path} "
                        f"within {self.timeout:g}s"
                        + (f" (holder: {holder})" if holder else ""),
                        holder=holder,
                    ) from exc
                time.sleep(_POLL_INTERVAL_SECONDS)
        self._write_holder()
        return self

    def release(self) -> None:
        if self._fd is None:
            return
        try:
            fcntl.flock(self._fd, fcntl.LOCK_UN)
        except OSError:  # pragma: no cover - closing releases anyway
            pass
        self._close()

    def _close(self) -> None:
        if self._fd is not None:
            try:
                os.close(self._fd)
            except OSError:  # pragma: no cover
                pass
            self._fd = None

    @property
    def held(self) -> bool:
        return self._fd is not None

    # -- context manager --------------------------------------------------

    def __enter__(self) -> "SearchGovernanceLock":
        return self.acquire()

    def __exit__(self, exc_type, exc, tb) -> bool:
        self.release()
        return False


@contextmanager
def search_governance_lock(
    audit_root: os.PathLike[str] | str,
    *,
    exclusive: bool = True,
    timeout: Optional[float] = None,
    operation: Optional[str] = None,
    agent: Optional[str] = None,
) -> Iterator[SearchGovernanceLock]:
    """Acquire the Search Governance lock for the duration of the block."""
    lock = SearchGovernanceLock(
        audit_root, exclusive=exclusive, timeout=timeout,
        operation=operation, agent=agent,
    )
    lock.acquire()
    try:
        yield lock
    finally:
        lock.release()
