"""Tests for runtime/source_identity.py — git-based identity + resume check."""
from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

from runtime.source_identity import (
    SourceIdentity,
    SourceIdentityError,
    compute_worktree_hash,
)


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


# ---------------------------------------------------------------------------
# Hardening v1.1 §1 — worktree_hash (dirty-tree detection)
# ---------------------------------------------------------------------------


def test_capture_records_worktree_hash(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    _init_git_repo(repo)
    identity = SourceIdentity.capture(repo)
    assert identity.worktree_hash.startswith("sha256:")
    assert identity.dirty is False


def test_worktree_hash_stable_for_clean_tree(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    _init_git_repo(repo)
    a = SourceIdentity.capture(repo)
    b = SourceIdentity.capture(repo)
    assert a.worktree_hash == b.worktree_hash
    assert a.matches(b)


def test_clean_then_dirty_does_not_match(tmp_path: Path) -> None:
    """clean → dirty must break matches(), even though HEAD^{tree} is unchanged."""
    repo = tmp_path / "repo"
    _init_git_repo(repo)
    clean = SourceIdentity.capture(repo)
    (repo / "README.md").write_text("modified content", encoding="utf-8")
    dirty = SourceIdentity.capture(repo)

    assert clean.commit == dirty.commit
    assert clean.tree_hash == dirty.tree_hash  # HEAD^{tree} is blind to this
    assert clean.worktree_hash != dirty.worktree_hash
    assert clean.matches(dirty) is False
    assert dirty.matches(clean) is False


def test_dirty_file_changed_does_not_match(tmp_path: Path) -> None:
    """Two different dirty states must not match."""
    repo = tmp_path / "repo"
    _init_git_repo(repo)
    (repo / "README.md").write_text("edit one", encoding="utf-8")
    first = SourceIdentity.capture(repo)
    (repo / "README.md").write_text("edit two", encoding="utf-8")
    second = SourceIdentity.capture(repo)
    assert first.dirty is True and second.dirty is True
    assert first.worktree_hash != second.worktree_hash
    assert first.matches(second) is False


def test_untracked_file_added_does_not_match(tmp_path: Path) -> None:
    """Adding a new untracked file must break matches()."""
    repo = tmp_path / "repo"
    _init_git_repo(repo)
    before = SourceIdentity.capture(repo)
    (repo / "new_module.py").write_text("print('hi')\n", encoding="utf-8")
    after = SourceIdentity.capture(repo)

    assert before.commit == after.commit
    assert before.tree_hash == after.tree_hash
    assert before.worktree_hash != after.worktree_hash
    assert before.matches(after) is False


def test_untracked_file_content_change_does_not_match(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    _init_git_repo(repo)
    (repo / "new_module.py").write_text("v1\n", encoding="utf-8")
    before = SourceIdentity.capture(repo)
    (repo / "new_module.py").write_text("v2\n", encoding="utf-8")
    after = SourceIdentity.capture(repo)
    assert before.worktree_hash != after.worktree_hash
    assert before.matches(after) is False


def test_staged_change_detected(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    _init_git_repo(repo)
    clean = SourceIdentity.capture(repo)
    (repo / "README.md").write_text("staged edit", encoding="utf-8")
    subprocess.run(["git", "-C", str(repo), "add", "README.md"], check=True, capture_output=True)
    staged = SourceIdentity.capture(repo)
    assert clean.matches(staged) is False


def test_ignored_files_do_not_count(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    _init_git_repo(repo)
    (repo / ".gitignore").write_text("*.log\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(repo), "add", ".gitignore"], check=True, capture_output=True)
    subprocess.run(["git", "-C", str(repo), "commit", "-m", "ignore"], check=True, capture_output=True)
    before = SourceIdentity.capture(repo)
    (repo / "noise.log").write_text("ignored\n", encoding="utf-8")
    after = SourceIdentity.capture(repo)
    assert before.matches(after) is True


def test_worktree_hash_diff_summary_reports_change(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    _init_git_repo(repo)
    a = SourceIdentity.capture(repo)
    (repo / "README.md").write_text("changed", encoding="utf-8")
    b = SourceIdentity.capture(repo)
    d = a.diff_summary(b)
    assert d["worktree_hash_changed"] is True
    assert d["commit_changed"] is False
    assert d["tree_hash_changed"] is False


def test_legacy_identity_without_worktree_hash_falls_back(tmp_path: Path) -> None:
    """A v1 state file has no worktree_hash; comparison degrades to legacy."""
    legacy = SourceIdentity.from_dict({
        "repository": "r", "root": "/r", "commit": "abc", "branch": "main",
        "dirty": False, "tree_hash": "t1", "captured_at": "",
    })
    assert legacy.worktree_hash == ""
    current_clean = SourceIdentity(repository="r", root="/r", commit="abc", branch="main",
                                   dirty=False, tree_hash="t1", captured_at="")
    assert legacy.matches(current_clean) is True
    current_dirty = SourceIdentity(repository="r", root="/r", commit="abc", branch="main",
                                   dirty=True, tree_hash="t1", captured_at="")
    assert legacy.matches(current_dirty) is False


def test_non_git_worktree_hash_equals_tree_hash(tmp_path: Path) -> None:
    (tmp_path / "a.txt").write_text("x", encoding="utf-8")
    identity = SourceIdentity.capture(tmp_path)
    assert identity.worktree_hash == identity.tree_hash
    assert identity.worktree_hash.startswith("sha256:")


def test_compute_worktree_hash_is_deterministic(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    _init_git_repo(repo)
    assert compute_worktree_hash(repo) == compute_worktree_hash(repo)
