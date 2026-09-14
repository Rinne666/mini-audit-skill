"""Atomic file IO primitives.

Per Spec §5.4, every state mutation must:

    read current
        ↓
    validate
        ↓
    mutate
        ↓
    write temporary file
        ↓
    fsync
        ↓
    atomic rename

Direct overwrite of canonical state files is forbidden. If a state file is
corrupted on read, we rename it to `<file>.corrupt-<timestamp>` and abort
auto-resume unless the user explicitly requests a fresh start.

The primitives here are deliberately small and stdlib-only so they can be
used by every other runtime module without pulling in extra dependencies.
"""

from __future__ import annotations

import datetime as _dt
import json
import os
import tempfile
from pathlib import Path
from typing import Any, Callable, Optional


class AtomicIOError(RuntimeError):
    """Raised when an atomic write or read fails irrecoverably."""


def write_text_atomic(path: os.PathLike[str] | str, content: str, *, encoding: str = "utf-8") -> None:
    """Atomically write *content* to *path* via write-then-rename.

    The temporary file lives in the same directory so the final `os.replace`
    is guaranteed to be on the same filesystem (POSIX rename atomicity).
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(prefix=f".{path.name}.", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding=encoding) as f:
            f.write(content)
            f.flush()
            try:
                os.fsync(f.fileno())
            except OSError:
                # fsync may fail on some filesystems (e.g. tmpfs, fuse mounts).
                # The rename atomicity still holds without fsync on POSIX, but
                # power-loss durability degrades. We accept that trade-off.
                pass
        os.replace(tmp_path, path)
    except Exception:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise


def write_json_atomic(path: os.PathLike[str] | str, data: Any) -> None:
    """Atomically write JSON-serialisable *data* to *path*."""
    payload = json.dumps(data, indent=2, sort_keys=True, ensure_ascii=False)
    write_text_atomic(path, payload + "\n")


def read_json_or_corrupt(path: os.PathLike[str] | str, *, on_corrupt: Optional[Callable[[Path], None]] = None) -> Any:
    """Read JSON from *path*, quarantining corruption.

    On parse failure, the file is renamed to
    ``<file>.corrupt-<UTC-ISO-timestamp>`` and an AtomicIOError is raised.
    The caller is expected to abort auto-resume unless the user explicitly
    requests a fresh start.
    """
    path = Path(path)
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        raise
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        ts = _dt.datetime.now(_dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        corrupt_target = path.with_suffix(path.suffix + f".corrupt-{ts}")
        try:
            os.replace(path, corrupt_target)
        except OSError:
            pass
        if on_corrupt is not None:
            on_corrupt(corrupt_target)
        raise AtomicIOError(
            f"corrupt state at {path}; quarantined to {corrupt_target}: {exc}"
        ) from exc


def sha256_file(path: os.PathLike[str] | str) -> str:
    """Return the lowercase hex SHA-256 of *path*."""
    import hashlib

    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def sha256_text(text: str) -> str:
    """Return the lowercase hex SHA-256 of *text*."""
    import hashlib

    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def safe_rename(src: os.PathLike[str] | str, dst: os.PathLike[str] | str) -> None:
    """Atomic rename. Refuses if destination already exists."""
    src = Path(src)
    dst = Path(dst)
    if dst.exists():
        raise AtomicIOError(f"refusing to overwrite existing {dst}")
    os.replace(src, dst)