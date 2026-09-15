"""Source identity (Spec §6, Hardening v1.1 §1).

Every audit run captures a stable identity for the code under audit:

    repo root
    remote repository
    git commit
    branch
    dirty flag
    tree hash          (committed snapshot: ``git rev-parse HEAD^{tree}``)
    worktree hash      (working-tree snapshot: tracked diff + untracked files)

``tree_hash`` alone cannot see uncommitted work: a clean checkout and a
heavily edited working tree share the same ``HEAD^{tree}``. Hardening v1.1
adds ``worktree_hash`` so that resume compares the *actual source the audit
read*, not just the last commit.

``worktree_hash`` covers:

* ``git diff HEAD`` — every tracked change (staged + unstaged) as a binary
  patch, so any content change to a tracked file moves the hash;
* every untracked, non-ignored file — relative path + content, so adding a
  new file moves the hash.

On `--action=resume`, the runtime compares the captured identity to the
current state of the working tree. If commit, tree hash, *or* worktree hash
changed, resume is marked `SOURCE_CHANGED` and refuses to silently reuse
phase results. The user must pass `--accept-source-change` to acknowledge;
even then, source-derived phases are forced to re-run.
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

WORKTREE_HASH_ALGO = "worktree-v1"


class SourceIdentityError(RuntimeError):
    """Raised when source identity capture or comparison fails."""


def _run_git_raw(repo_root: Path, *args: str, check: bool = True) -> bytes:
    """Run git and return raw bytes (binary-safe, needed for diff hashing)."""
    try:
        proc = subprocess.run(
            ["git", "-C", str(repo_root), *args],
            capture_output=True,
            timeout=60,
            check=False,
        )
    except FileNotFoundError as exc:
        raise SourceIdentityError("git binary not found") from exc
    except subprocess.TimeoutExpired as exc:
        raise SourceIdentityError(f"git {args} timed out") from exc
    if check and proc.returncode != 0:
        # git's stderr is bytes when capture_output=True without text=True
        stderr = (proc.stderr or b"").decode("utf-8", "replace").strip()
        stdout = (proc.stdout or b"").decode("utf-8", "replace").strip()
        raise SourceIdentityError(f"git {args} failed: {stderr or stdout}")
    return proc.stdout or b""


def _run_git(repo_root: Path, *args: str, check: bool = True) -> str:
    return _run_git_raw(repo_root, *args, check=check).decode("utf-8", "replace").strip()


def compute_worktree_hash(repo_root: os.PathLike[str] | str) -> str:
    """Compute a SHA-256 over the working tree (tracked diff + untracked files).

    Returns ``"sha256:<hex>"``. Deterministic for a given working-tree state:
    identical trees hash identically regardless of capture time, so two
    captures of an unchanged tree compare equal.
    """
    root = Path(repo_root).resolve()
    h = hashlib.sha256()
    h.update(WORKTREE_HASH_ALGO.encode("utf-8"))
    h.update(b"\0")

    # 1. Tracked changes relative to HEAD (staged + unstaged combined).
    #    ``--binary`` keeps the patch byte-exact; no color, no pager.
    tracked = _run_git_raw(
        root, "diff", "HEAD", "--binary", "--no-color", "--no-ext-diff", check=False
    )
    h.update(b"tracked\0")
    h.update(tracked)
    h.update(b"\0")

    # 2. Untracked, non-ignored files: relative path + content.
    untracked = _run_git(root, "ls-files", "--others", "--exclude-standard", check=False)
    rel_paths = [p for p in untracked.splitlines() if p.strip()]
    h.update(b"untracked\0")
    for rel in sorted(rel_paths):
        full = root / rel
        h.update(rel.encode("utf-8"))
        h.update(b"\0")
        try:
            if full.is_symlink():
                h.update(b"symlink\0")
                h.update(os.readlink(full).encode("utf-8"))
            elif full.is_file():
                with open(full, "rb") as f:
                    for chunk in iter(lambda: f.read(65536), b""):
                        h.update(chunk)
            else:
                # Directory entry (should not normally happen) — record the name only.
                h.update(b"nonfile\0")
        except OSError:
            # Unreadable file: record its name so the hash still moves when it
            # appears/disappears, but do not silently substitute content.
            h.update(b"unreadable\0")
        h.update(b"\0")

    return f"sha256:{h.hexdigest()}"


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
    # Defaulted so pre-v1.1 identities (and hand-built test fixtures) remain
    # constructible; an empty value selects the legacy comparison path.
    worktree_hash: str = ""

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
            worktree_hash=data.get("worktree_hash", ""),
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

        is_git = (root / ".git").exists() and _run_git(
            root, "rev-parse", "--is-inside-work-tree", check=False
        ) == "true"
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
        worktree_hash = compute_worktree_hash(root)

        return cls(
            repository=remote_url or None,
            root=str(root),
            commit=commit,
            branch=branch,
            dirty=dirty,
            tree_hash=tree_hash,
            worktree_hash=worktree_hash,
            captured_at=_dt.datetime.now(_dt.timezone.utc).isoformat(),
        )

    @classmethod
    def _capture_non_git(cls, root: Path) -> "SourceIdentity":
        """Best-effort identity for a directory without git.

        The content hash already covers every file in the tree, so the
        working-tree hash and the tree hash are the same value.
        """
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
        content_hash = f"sha256:{h.hexdigest()}"
        return cls(
            repository=None,
            root=str(root),
            commit="",
            branch="",
            dirty=False,
            tree_hash=content_hash,
            worktree_hash=content_hash,
            captured_at=_dt.datetime.now(_dt.timezone.utc).isoformat(),
        )

    def matches(self, other: "SourceIdentity") -> bool:
        """True if the two identities describe the same code snapshot.

        For non-git sources we compare tree_hash only. For git sources we
        compare commit + worktree_hash (+ root). A dirty working tree whose
        content differs from the captured one therefore never matches, even
        when the commit is unchanged.

        Backward compatibility: v1 state files have no ``worktree_hash``.
        When either side lacks it we fall back to tree_hash + dirty-flag
        comparison, which is strictly weaker but still catches a clean↔dirty
        flip.
        """
        if not self.commit and not other.commit:
            return self.tree_hash == other.tree_hash and self.tree_hash != ""

        if self.root != other.root or self.commit != other.commit:
            return False

        if not self.worktree_hash or not other.worktree_hash:
            # Legacy comparison: committed snapshot + dirty flag.
            return self.tree_hash == other.tree_hash and self.dirty == other.dirty

        return self.worktree_hash == other.worktree_hash

    def diff_summary(self, other: "SourceIdentity") -> dict[str, Any]:
        """Return a structured diff between two identities."""
        return {
            "commit_changed": self.commit != other.commit,
            "tree_hash_changed": self.tree_hash != other.tree_hash,
            "worktree_hash_changed": self.worktree_hash != other.worktree_hash,
            "branch_changed": self.branch != other.branch,
            "dirty_changed": self.dirty != other.dirty,
            "root_changed": self.root != other.root,
        }

    def to_canonical_json(self) -> str:
        """Deterministic JSON for hashing / comparison."""
        return json.dumps(self.to_dict(), indent=2, sort_keys=True)
