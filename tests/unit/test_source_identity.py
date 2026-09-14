"""Tests for runtime/source_identity.py — git-based identity + resume check."""
from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

from runtime.source_identity import SourceIdentity, SourceIdentityError


def _init_git_repo(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)
    subprocess.run(["git", "-C", str(path), "init", "-b", "main"], check=True, capture_output=True)
    subprocess.run(["git", "-C", str(path), "config", "user.email", "test@test"], check=True, capture_output=True)
    subprocess.run(["git", "-C", str(path), "config", "user.name", "Test"], check=True, capture_output=True)
    (path / "README.md").write_text("hello", encoding="utf-8")
    subprocess.run(["git", "-C", str(path), "add", "README.md"], check=True, capture_output=True)
    subprocess.run(["git", "-C", str(path), "commit", "-m", "initial"], check=True, capture_output=True)


def test_capture_for_git_repo(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    _init_git_repo(repo)
    identity = SourceIdentity.capture(repo)
    assert identity.root == str(repo.resolve())
    assert identity.commit
    assert identity.tree_hash.startswith("") or len(identity.tree_hash) >= 7
    assert identity.branch == "main"
    assert identity.dirty is False
    assert identity.captured_at


def test_capture_for_non_git_dir(tmp_path: Path) -> None:
    identity = SourceIdentity.capture(tmp_path)
    assert identity.commit == ""
    assert identity.tree_hash.startswith("sha256:")
    assert identity.branch == ""


def test_capture_dirty_repo(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    _init_git_repo(repo)
    (repo / "README.md").write_text("modified", encoding="utf-8")
    identity = SourceIdentity.capture(repo)
    assert identity.dirty is True


def test_capture_missing_path_raises(tmp_path: Path) -> None:
    with pytest.raises(SourceIdentityError):
        SourceIdentity.capture(tmp_path / "nope")


def test_matches_identical() -> None:
    a = SourceIdentity(
        repository="git@example.com:owner/repo.git",
        root="/repo",
        commit="abc",
        branch="main",
        dirty=False,
        tree_hash="t1",
        captured_at="2026-01-01T00:00:00Z",
    )
    b = SourceIdentity(
        repository="git@example.com:owner/repo.git",
        root="/repo",
        commit="abc",
        branch="main",
        dirty=False,
        tree_hash="t1",
        captured_at="2026-01-02T00:00:00Z",
    )
    assert a.matches(b)


def test_matches_differs_on_commit() -> None:
    a = SourceIdentity(repository="", root="/r", commit="abc", branch="main",
                       dirty=False, tree_hash="t1", captured_at="")
    b = SourceIdentity(repository="", root="/r", commit="def", branch="main",
                       dirty=False, tree_hash="t1", captured_at="")
    assert not a.matches(b)


def test_matches_differs_on_tree_hash() -> None:
    a = SourceIdentity(repository="", root="/r", commit="abc", branch="main",
                       dirty=False, tree_hash="t1", captured_at="")
    b = SourceIdentity(repository="", root="/r", commit="abc", branch="main",
                       dirty=False, tree_hash="t2", captured_at="")
    assert not a.matches(b)


def test_non_git_match_uses_tree_hash_only() -> None:
    a = SourceIdentity(repository=None, root="/r", commit="", branch="",
                       dirty=False, tree_hash="sha256:abc", captured_at="")
    b = SourceIdentity(repository=None, root="/r", commit="", branch="",
                       dirty=False, tree_hash="sha256:abc", captured_at="")
    assert a.matches(b)


def test_diff_summary() -> None:
    a = SourceIdentity(repository="", root="/r", commit="abc", branch="main",
                       dirty=False, tree_hash="t1", captured_at="")
    b = SourceIdentity(repository="", root="/r", commit="def", branch="feat",
                       dirty=True, tree_hash="t2", captured_at="")
    d = a.diff_summary(b)
    assert d["commit_changed"] is True
    assert d["tree_hash_changed"] is True
    assert d["branch_changed"] is True
    assert d["dirty_changed"] is True


def test_roundtrip_via_dict() -> None:
    a = SourceIdentity(repository="r", root="/r", commit="abc", branch="main",
                       dirty=False, tree_hash="t1", captured_at="2026-01-01T00:00:00Z")
    b = SourceIdentity.from_dict(a.to_dict())
    assert a == b