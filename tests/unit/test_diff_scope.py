"""Tests for runtime/diff_scope.py — D0/D1/D2/D4 of diff-mode pipeline."""
from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from runtime.diff_scope import (
    score_path,
    prioritize_paths,
    find_text_callers,
)


def test_score_path_baseline() -> None:
    assert score_path("src/utils.ts", status="modified") >= 1


def test_score_path_admin_route_high() -> None:
    s = score_path("src/api/admin/users.py", status="modified")
    assert s >= 5  # route hit + filename hit


def test_score_path_added_bonus() -> None:
    s_added = score_path("src/auth/login.ts", status="added")
    s_modified = score_path("src/auth/login.ts", status="modified")
    assert s_added > s_modified


def test_score_path_deleted_penalty() -> None:
    s_deleted = score_path("src/auth/login.ts", status="deleted")
    s_modified = score_path("src/auth/login.ts", status="modified")
    assert s_deleted <= s_modified


def test_score_path_capped_at_10() -> None:
    s = score_path("src/api/admin/billing/payment/auth/session/upload/import.ts", status="added")
    assert s <= 10


def test_prioritize_paths_sorts_desc() -> None:
    paths = [
        {"path": "src/utils.ts", "status": "modified"},
        {"path": "src/api/admin/users.py", "status": "modified"},
        {"path": "src/auth/login.ts", "status": "added"},
    ]
    ranked = prioritize_paths(paths)
    scores = [p["risk_score"] for p in ranked]
    assert scores == sorted(scores, reverse=True)
    # All have risk_score attached
    assert all("risk_score" in p for p in ranked)


@pytest.mark.skipif(
    subprocess.run(["which", "grep"], capture_output=True).returncode != 0,
    reason="grep not available",
)
def test_find_text_callers(tmp_path: Path) -> None:
    (tmp_path / "a.py").write_text("def foo():\n    return 1\n\ndef bar():\n    return foo()\n", encoding="utf-8")
    (tmp_path / "b.py").write_text("from a import foo\nfoo()\n", encoding="utf-8")
    callers = find_text_callers(tmp_path, symbol="foo")
    assert len(callers) >= 2
    files = {c["file"] for c in callers}
    assert "a.py" in files
    assert "b.py" in files


@pytest.mark.skipif(
    subprocess.run(["which", "grep"], capture_output=True).returncode != 0,
    reason="grep not available",
)
def test_find_text_callers_no_match(tmp_path: Path) -> None:
    (tmp_path / "a.py").write_text("x = 1\n", encoding="utf-8")
    assert find_text_callers(tmp_path, symbol="nosuchsymbol_xyz") == []


def test_diff_scope_build_requires_git(tmp_path: Path) -> None:
    """build_diff_scope shells out to git, so we just verify it fails clearly on non-git dir."""
    from runtime.diff_scope import build_diff_scope
    non_git = tmp_path / "not-a-repo"
    non_git.mkdir()
    with pytest.raises(Exception):
        # baseline/target may be invalid; we only care that errors are surfaced, not swallowed
        build_diff_scope(non_git, baseline="HEAD", target="HEAD")