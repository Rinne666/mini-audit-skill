"""Source identity (Spec §6).

Every audit run captures a stable identity for the code under audit:

    repo root
    remote repository
    git commit
    branch
    dirty flag
    tree hash

On `--action=resume`, the runtime compares the captured identity to the
current state of the working tree. If commit or tree hash changed, resume
is marked `SOURCE_CHANGED` and refuses to silently reuse phase results.
The user must pass `--accept-source-change` to acknowledge; even then,
source-derived phases are forced to re-run.
"""

from __future__ import annotations

import dataclasses
import datetime as _dt
import hashlib
import json
import os
import subprocess
from pathlib import Path
from typing import Any, Mapping, Optional


class SourceIdentityError(RuntimeError):
    """Raised when source identity capture or comparison fails."""


def _run_git(repo_root: Path, *args: str, check: bool = True) -> str:
    try:
        proc = subprocess.run(
            ["git", "-C", str(repo_root), *args],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
    except FileNotFoundError as exc:
        raise SourceIdentityError("git binary not found") from exc
    except subprocess.TimeoutExpired as exc:
        raise SourceIdentityError(f"git {args} timed out") from exc
    if check and proc.returncode != 0:
        raise SourceIdentityError(
            f"git {args} failed: {proc.stderr.strip() or proc.stdout.strip()}"
        )
    return (proc.stdout or "").strip()


@dataclasses.dataclass
class SourceIdentity:
    """Captured identity of the code under audit."""

    repository: Optional[str]
    root: str
    commit: str
    branch: str
    dirty: bool
    tree_hash: str
    captured_at: str

    def to_dict(self) -> dict[str, Any]:
        return dataclasses.asdict(self)

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "SourceIdentity":
        return cls(
            repository=data.get("repository"),
            root=data.get("root", ""),
            commit=data.get("commit", ""),
            branch=data.get("branch", ""),
            dirty=bool(data.get("dirty", False)),
            tree_hash=data.get("tree_hash", ""),
            captured_at=data.get("captured_at", ""),
        )

    @classmethod
    def capture(cls, repo_root: os.PathLike[str] | str) -> "SourceIdentity":
        """Capture identity for the repo at *repo_root*.

        Works for git repos; falls back to a content-hash identity for
        non-git directories so the runtime still functions (with reduced
        resume confidence).
        """
        root = Path(repo_root).resolve()
        if not root.exists():
            raise SourceIdentityError(f"repo root {root} does not exist")
        if not root.is_dir():
            raise SourceIdentityError(f"repo root {root} is not a directory")

        is_git = (root / ".git").exists() and _run_git(root, "rev-parse", "--is-inside-work-tree", check=False) == "true"
        if not is_git:
            return cls._capture_non_git(root)

        commit = _run_git(root, "rev-parse", "HEAD")
        branch = _run_git(root, "rev-parse", "--abbrev-ref", "HEAD")
        try:
            remote_url = _run_git(root, "config", "--get", "remote.origin.url", check=False)
        except SourceIdentityError:
            remote_url = ""
        dirty_proc = subprocess.run(
            ["git", "-C", str(root), "status", "--porcelain"],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        dirty = bool(dirty_proc.stdout.strip())
        tree_hash = _run_git(root, "rev-parse", "HEAD^{tree}")

        return cls(
            repository=remote_url or None,
            root=str(root),
            commit=commit,
            branch=branch,
            dirty=dirty,
            tree_hash=tree_hash,
            captured_at=_dt.datetime.now(_dt.timezone.utc).isoformat(),
        )

    @classmethod
    def _capture_non_git(cls, root: Path) -> "SourceIdentity":
        """Best-effort identity for a directory without git."""
        h = hashlib.sha256()
        for path in sorted(root.rglob("*")):
            if any(part.startswith(".git") for part in path.parts):
                continue
            if path.is_file():
                rel = path.relative_to(root).as_posix()
                h.update(rel.encode("utf-8"))
                with open(path, "rb") as f:
                    for chunk in iter(lambda: f.read(65536), b""):
                        h.update(chunk)
        return cls(
            repository=None,
            root=str(root),
            commit="",
            branch="",
            dirty=False,
            tree_hash=f"sha256:{h.hexdigest()}",
            captured_at=_dt.datetime.now(_dt.timezone.utc).isoformat(),
        )

    def matches(self, other: "SourceIdentity") -> bool:
        """True if the two identities describe the same code snapshot.

        For non-git sources we compare tree_hash only.
        """
        if not self.commit and not other.commit:
            return self.tree_hash == other.tree_hash and self.tree_hash != ""
        return (
            self.commit == other.commit
            and self.tree_hash == other.tree_hash
            and self.root == other.root
        )

    def diff_summary(self, other: "SourceIdentity") -> dict[str, Any]:
        """Return a structured diff between two identities."""
        return {
            "commit_changed": self.commit != other.commit,
            "tree_hash_changed": self.tree_hash != other.tree_hash,
            "branch_changed": self.branch != other.branch,
            "dirty_changed": self.dirty != other.dirty,
            "root_changed": self.root != other.root,
        }

    def to_canonical_json(self) -> str:
        """Deterministic JSON for hashing / comparison."""
        return json.dumps(self.to_dict(), indent=2, sort_keys=True)