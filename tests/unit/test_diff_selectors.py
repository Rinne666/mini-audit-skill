"""Incremental Audit v1 — D0 selector resolution and the change-set it feeds.

The three selectors exist so a caller can say what they mean instead of
hand-computing two SHAs. The one that matters most is ``--base``/``--head``:
``base..head`` is the *obvious* answer and it is wrong, because it describes the
difference between two tips. Everything the base branch did since the fork shows
up as if the head branch had undone it. Several tests below assert the merge
base specifically, by checking that the resolved change-set does NOT contain the
entry that the naive range produces.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from runtime.diff_scope import (
    DiffRangeError,
    build_diff_scope,
    resolve_diff_range,
    structured_blast_radius,
)

SKILL_ROOT = Path(__file__).resolve().parent.parent.parent
LAUNCHER = SKILL_ROOT / "scripts" / "mini-audit-runtime"

EMPTY_TREE = "4b825dc642cb6eb9a060e54bf8d69288fbee4904"


# ---------------------------------------------------------------------------
# git fixtures
# ---------------------------------------------------------------------------


def _git(repo: Path, *args: str) -> str:
    proc = subprocess.run(["git", "-C", str(repo), *args],
                          capture_output=True, text=True, check=True)
    return proc.stdout


def _init(repo: Path) -> None:
    repo.mkdir(parents=True, exist_ok=True)
    _git(repo, "init", "-b", "main")
    _git(repo, "config", "user.email", "t@t")
    _git(repo, "config", "user.name", "Tester")


def _commit(repo: Path, message: str) -> str:
    _git(repo, "add", "-A")
    _git(repo, "commit", "-m", message)
    return _git(repo, "rev-parse", "HEAD").strip()


def _sha(repo: Path, rev: str) -> str:
    return _git(repo, "rev-parse", rev).strip()


def _merge_base(repo: Path, left: str, right: str) -> str:
    return _git(repo, "merge-base", left, right).strip()


@pytest.fixture()
def repo(tmp_path: Path) -> dict:
    """A branch that renames, deletes and adds — while `main` moves on.

    The shape matters: `main` advances with a file the feature branch never
    touched, which is what makes the naive `base..head` range observably wrong.
    """
    root = tmp_path / "repo"
    _init(root)
    (root / "src").mkdir()
    (root / "docs").mkdir()
    (root / "src" / "app.py").write_text(
        "def handler(payload):\n"
        "    return payload\n"
        "\n", encoding="utf-8")
    (root / "src" / "util.py").write_text("def helper():\n    return 1\n", encoding="utf-8")
    (root / "src" / "legacy.py").write_text("def old_query():\n    return 0\n", encoding="utf-8")
    (root / "docs" / "old.md").write_text("# notes\n", encoding="utf-8")
    base = _commit(root, "initial import")
    _git(root, "tag", "v1")

    _git(root, "checkout", "-q", "-b", "feature")

    # B1 — modify an existing file, rename another, delete a third.
    app = root / "src" / "app.py"
    app.write_text(app.read_text(encoding="utf-8") + (
        "def handler_v2(payload):\n"
        "    return dangerous_query(payload)\n"
        "\n"), encoding="utf-8")
    _git(root, "mv", "docs/old.md", "docs/new.md")
    (root / "src" / "legacy.py").unlink()
    b1 = _commit(root, "rework the query path")

    # B2 — add a new security-relevant entrypoint.
    (root / "src" / "auth").mkdir()
    (root / "src" / "auth" / "login.py").write_text(
        "def login_route(request):\n"
        "    return dangerous_query(request.params['q'])\n"
        "\n", encoding="utf-8")
    b2 = _commit(root, "add login route")

    # main advances independently — with a file feature never sees.
    _git(root, "checkout", "-q", "main")
    (root / "src" / "main_only.py").write_text("def untouched():\n    return True\n",
                                               encoding="utf-8")
    main_tip = _commit(root, "main advances")

    # Leave HEAD on the feature branch, so `--since` has a meaningful target.
    _git(root, "checkout", "-q", "feature")

    return {
        "root": root,
        "base": base,
        "b1": b1,
        "b2": b2,
        "main_tip": main_tip,
        "feature_tip": _sha(root, "feature"),
        "merge_base": _merge_base(root, "main", "feature"),
    }


def _run_cli(*args: str, cwd: Path) -> subprocess.CompletedProcess:
    import os
    env = dict(os.environ)
    env.pop("PYTHONPATH", None)
    return subprocess.run([sys.executable, str(LAUNCHER), *args],
                          capture_output=True, text=True, cwd=str(cwd), env=env)


# ---------------------------------------------------------------------------
# 1. commit selector
# ---------------------------------------------------------------------------


def test_commit_selector_is_the_parent_to_the_commit(repo: dict) -> None:
    resolved = resolve_diff_range(repo["root"], commit=repo["b2"])
    assert resolved.baseline == repo["b1"], "baseline must be <sha>^"
    assert resolved.target == repo["b2"]
    assert resolved.scope_type == "commit"
    assert resolved.merge_base == ""


def test_commit_selector_reports_only_what_that_commit_introduced(repo: dict) -> None:
    scope = build_diff_scope(repo["root"], baseline=repo["b1"], target=repo["b2"],
                             resolved_range=resolve_diff_range(repo["root"], commit=repo["b2"]))
    assert [(c["path"], c["status"]) for c in scope.changed] == [("src/auth/login.py", "added")]
    assert scope.scope_type == "commit"
    assert scope.selector == {"commit": repo["b2"]}


def test_a_root_commit_diffs_against_the_empty_tree(tmp_path: Path) -> None:
    """`<sha>^` does not resolve for a repository's first commit.

    Falling back to the empty tree is what `git diff --root` does, and it keeps
    "audit this commit" answerable on day one rather than erroring out.
    """
    root = tmp_path / "fresh"
    _init(root)
    (root / "a.py").write_text("x = 1\n", encoding="utf-8")
    only = _commit(root, "first commit")

    resolved = resolve_diff_range(root, commit=only)
    assert resolved.baseline == EMPTY_TREE
    assert resolved.target == only

    scope = build_diff_scope(root, baseline=resolved.baseline, target=resolved.target)
    assert [(c["path"], c["status"]) for c in scope.changed] == [("a.py", "added")]


# ---------------------------------------------------------------------------
# 2. since selector
# ---------------------------------------------------------------------------


def test_since_selector_runs_from_the_ref_to_head(repo: dict) -> None:
    resolved = resolve_diff_range(repo["root"], since="v1")
    assert resolved.baseline == repo["base"]
    assert resolved.target == repo["feature_tip"], "target is HEAD, resolved to a sha"
    assert resolved.scope_type == "since"
    assert resolved.selector == {"since": "v1"}


def test_since_accepts_a_sha_as_well_as_a_tag(repo: dict) -> None:
    by_tag = resolve_diff_range(repo["root"], since="v1")
    by_sha = resolve_diff_range(repo["root"], since=repo["base"])
    assert by_tag.baseline == by_sha.baseline == repo["base"]


# ---------------------------------------------------------------------------
# 3. branch / PR selector — the merge base is the point
# ---------------------------------------------------------------------------


def test_base_head_starts_at_the_merge_base_not_the_base_tip(repo: dict) -> None:
    resolved = resolve_diff_range(repo["root"], base="main", head="feature")
    assert resolved.merge_base == repo["merge_base"]
    assert resolved.baseline == repo["merge_base"]
    assert resolved.baseline != repo["main_tip"], \
        "baseline must be the fork point, not the base branch's tip"
    assert resolved.target == repo["feature_tip"]
    assert resolved.scope_type == "base-head"


def test_base_head_does_not_report_the_base_branch_own_work(repo: dict) -> None:
    """The failing case the merge base exists to avoid.

    `git diff main..feature` lists `src/main_only.py` as deleted — a file main
    added and the feature branch simply never saw. An incremental audit built on
    that range would spend a round asking why the PR removed a file it never
    touched, and would report the base branch's own commits as this branch's
    change. Asserting the absence is what proves the merge base was used.
    """
    naive = _git(repo["root"], "diff", "--name-status",
                 f"{repo['main_tip']}..{repo['feature_tip']}")
    assert "D\tsrc/main_only.py" in naive, "fixture no longer produces the naive failure"

    resolved = resolve_diff_range(repo["root"], base="main", head="feature")
    scope = build_diff_scope(repo["root"], baseline=resolved.baseline,
                             target=resolved.target, resolved_range=resolved)
    paths = {c["path"] for c in scope.changed}
    assert "src/main_only.py" not in paths
    assert paths == {"src/app.py", "docs/new.md", "src/legacy.py", "src/auth/login.py"}


def test_base_head_requires_both_sides(repo: dict) -> None:
    with pytest.raises(DiffRangeError, match="together"):
        resolve_diff_range(repo["root"], base="main")
    with pytest.raises(DiffRangeError, match="together"):
        resolve_diff_range(repo["root"], head="feature")


def test_base_head_names_unrelated_histories(repo: dict) -> None:
    """Two root commits in one repository have no common ancestor.

    Silently diffing them would produce a change-set that reads like the whole
    tree was rewritten; the audit needs to be told its premise is missing.
    """
    root: Path = repo["root"]
    _git(root, "checkout", "-q", "--orphan", "unrelated")
    _git(root, "rm", "-rq", "--cached", ".")
    (root / "z.py").write_text("z = 1\n", encoding="utf-8")
    orphan = _commit(root, "unrelated root")
    _git(root, "checkout", "-q", "feature")

    with pytest.raises(DiffRangeError, match="merge base"):
        resolve_diff_range(root, base=repo["main_tip"], head=orphan)


# ---------------------------------------------------------------------------
# 4. renamed / deleted / added paths
# ---------------------------------------------------------------------------


def test_every_change_kind_reaches_the_scope(repo: dict) -> None:
    resolved = resolve_diff_range(repo["root"], commit=repo["b1"])
    scope = build_diff_scope(repo["root"], baseline=resolved.baseline,
                             target=resolved.target, resolved_range=resolved)
    by_path = {c["path"]: c for c in scope.changed}

    assert by_path["src/app.py"]["status"] == "modified"
    assert by_path["src/legacy.py"]["status"] == "deleted"
    assert by_path["docs/new.md"]["status"] == "renamed"
    assert by_path["docs/new.md"]["old_path"] == "docs/old.md"


# ---------------------------------------------------------------------------
# 5. changed line ranges
# ---------------------------------------------------------------------------


def test_changed_line_ranges_point_at_the_added_lines(repo: dict) -> None:
    # `src/app.py` was three lines before B1 and gained three more at the end.
    resolved = resolve_diff_range(repo["root"], commit=repo["b1"])
    scope = build_diff_scope(repo["root"], baseline=resolved.baseline,
                             target=resolved.target, resolved_range=resolved)
    assert scope.line_ranges["src/app.py"] == [(4, 6)], scope.line_ranges


def test_a_deleted_file_does_not_lend_its_hunk_header_to_another_file(repo: dict) -> None:
    """Regression: `+++ /dev/null` left the parser pointing at the previous file.

    A deletion's hunk header is `@@ -1,2 +0,0 @@`: zero lines on the new side.
    The old parser forced the count to 1, so the file parsed just before the
    deletion acquired a phantom `(0, 0)` range — and `(0, 0)` is where D5/D6
    would then send a reviewer looking.
    """
    resolved = resolve_diff_range(repo["root"], commit=repo["b1"])
    scope = build_diff_scope(repo["root"], baseline=resolved.baseline,
                             target=resolved.target, resolved_range=resolved)

    # The deleted file is still in the change-set; it simply contributes no
    # added lines, which is the truth about a deletion.
    assert any(c["path"] == "src/legacy.py" and c["status"] == "deleted"
               for c in scope.changed)
    assert scope.line_ranges.get("src/legacy.py", []) == []

    for path, ranges in scope.line_ranges.items():
        for start, end in ranges:
            assert start >= 1 and end >= start, f"{path}: bogus range {(start, end)}"


def test_a_rename_without_edits_reports_no_changed_lines(repo: dict) -> None:
    """A pure rename is a rename; a whole-file range would be a false claim.

    This one bit twice. The parser needed `+++ b/` handling for real (see the
    deletion test above), and the range query needed the rename's *old* path in
    its pathspec — restricted to the new path alone, git cannot pair the two
    sides, so it reports the file as newly added and hands back lines 1..N for a
    file that only moved.
    """
    resolved = resolve_diff_range(repo["root"], commit=repo["b1"])
    scope = build_diff_scope(repo["root"], baseline=resolved.baseline,
                             target=resolved.target, resolved_range=resolved)
    assert scope.line_ranges.get("docs/new.md", []) == []
    # The rename is still recorded as a rename, with its origin.
    renamed = next(c for c in scope.changed if c["path"] == "docs/new.md")
    assert renamed["status"] == "renamed" and renamed["old_path"] == "docs/old.md"


def test_line_ranges_cover_an_added_file_from_line_one(repo: dict) -> None:
    resolved = resolve_diff_range(repo["root"], commit=repo["b2"])
    scope = build_diff_scope(repo["root"], baseline=resolved.baseline,
                             target=resolved.target, resolved_range=resolved)
    assert scope.line_ranges["src/auth/login.py"] == [(1, 3)]


# ---------------------------------------------------------------------------
# 6. risk ranking
# ---------------------------------------------------------------------------


def test_a_security_relevant_added_file_ranks_first(repo: dict) -> None:
    resolved = resolve_diff_range(repo["root"], base="main", head="feature")
    scope = build_diff_scope(repo["root"], baseline=resolved.baseline,
                             target=resolved.target, resolved_range=resolved)
    ranked = [c["path"] for c in scope.risk_ranked]
    assert ranked[0] == "src/auth/login.py", ranked
    assert scope.risk_ranked[0]["risk_score"] >= 6
    # A deleted file has no callers left, so it scores below an ordinary edit.
    assert scope.risk_ranked[-1]["path"] == "src/legacy.py"


# ---------------------------------------------------------------------------
# 7. D4 carries the symbols the agent asks about
# ---------------------------------------------------------------------------


def test_blast_radius_uses_the_agent_supplied_symbol(repo: dict) -> None:
    """D4 is a *query* over an agent-named symbol, not a runtime guess.

    The symbol comes from the diff review (the Tier 1 questions in
    `methodology/diff-audit.md`), so the runtime must accept it as input and
    report where the symbol is reached from, not decide for itself what to
    trace.

    Note the boundary of the default backend: it attributes the *match line*, so
    `looks_like_entrypoint` only fires when the calling line itself names an
    entrypoint. Here the call sits inside `login_route` but the matched line is
    the `return`, so it reads False. That is a limitation of text search, not of
    D4 — `find_symbol_references` is the seam an AST backend plugs into, and the
    record already carries the field such a backend would fill.
    """
    blast = structured_blast_radius(repo["root"],
                                    changed_paths=["src/auth/login.py", "src/app.py"],
                                    symbols=["dangerous_query"])
    entry = blast["per_symbol"]["dangerous_query"]
    assert blast["symbols"] == ["dangerous_query"]
    assert entry["count"] >= 2, entry
    files = {r["file"] for r in entry["references"]}
    assert "src/auth/login.py" in files and "src/app.py" in files

    login = next(r for r in entry["references"] if r["file"] == "src/auth/login.py")
    assert login["security_sensitive"] is True
    assert login["locality"] == "same_file"
    assert login["backend"] == "text-grep"
    # One security-sensitive caller, no cross-module one, so: moderate. "wide"
    # needs a caller outside the module or a second sensitive one — the runtime
    # reports what is there rather than rounding up.
    assert entry["security_sensitive"] == 1
    assert entry["cross_module"] == 0
    assert entry["blast_radius"] == "moderate", entry


# ---------------------------------------------------------------------------
# guards
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("kwargs,expected", [
    ({}, "no change-set given"),
    ({"commit": "HEAD", "since": "HEAD"}, "ambiguous selector"),
    ({"base": "HEAD"}, "together"),
    ({"baseline": "HEAD"}, "together"),
])
def test_ambiguous_or_incomplete_requests_are_refused(repo: dict, kwargs: dict,
                                                      expected: str) -> None:
    with pytest.raises(DiffRangeError, match=expected):
        resolve_diff_range(repo["root"], **kwargs)


def test_explicit_range_may_not_be_mixed_with_a_selector(repo: dict) -> None:
    with pytest.raises(DiffRangeError, match="not both"):
        resolve_diff_range(repo["root"], commit=repo["b2"],
                           baseline=repo["base"], target=repo["b2"])


def test_an_unresolvable_ref_is_named(repo: dict) -> None:
    with pytest.raises(DiffRangeError, match="does not resolve"):
        resolve_diff_range(repo["root"], commit="deadbeef" * 5)
    with pytest.raises(DiffRangeError, match="does not resolve"):
        resolve_diff_range(repo["root"], since="no-such-tag")


# ---------------------------------------------------------------------------
# explicit range keeps working — it is the escape hatch
# ---------------------------------------------------------------------------


def test_explicit_range_is_passed_through_verbatim(repo: dict) -> None:
    resolved = resolve_diff_range(repo["root"], baseline=repo["main_tip"],
                                  target=repo["feature_tip"])
    assert resolved.baseline == repo["main_tip"], "explicit input is not normalised"
    assert resolved.target == repo["feature_tip"]
    assert resolved.scope_type == "explicit"
    assert resolved.merge_base == ""


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def test_cli_records_the_selector_in_the_artifact(repo: dict, tmp_path: Path) -> None:
    proc = _run_cli("diff", "scope", "--repo-root", str(repo["root"]),
                    "--base", "main", "--head", "feature",
                    "--audit-root", "mini-audit", cwd=tmp_path)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    emitted = json.loads(proc.stdout)
    assert emitted["scope_type"] == "base-head"
    assert emitted["merge_base"] == repo["merge_base"]
    assert emitted["selector"] == {"base": "main", "head": "feature"}
    assert emitted["changed"] == 4

    artifact = json.loads((tmp_path / "mini-audit" / "diff-scope.json").read_text(encoding="utf-8"))
    assert artifact["scope_type"] == "base-head"
    assert artifact["merge_base"] == repo["merge_base"]
    assert "src/main_only.py" not in {c["path"] for c in artifact["changed"]}


def test_cli_refuses_a_request_with_no_change_set(repo: dict, tmp_path: Path) -> None:
    proc = _run_cli("diff", "scope", "--repo-root", str(repo["root"]),
                    "--audit-root", "mini-audit", cwd=tmp_path)
    assert proc.returncode != 0
    payload = json.loads(proc.stdout)
    assert payload["code"] == "DIFF_RANGE"


def test_cli_diff_stage_still_accepts_an_explicit_range(repo: dict, tmp_path: Path) -> None:
    """The pre-existing invocation must not regress: same flags, same output."""
    proc = _run_cli("diff", "stage", "--repo-root", str(repo["root"]),
                    "--baseline", repo["merge_base"], "--target", repo["feature_tip"],
                    "--stage", "D4", "--symbol", "dangerous_query",
                    "--audit-root", "mini-audit", cwd=tmp_path)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    emitted = json.loads(proc.stdout)
    assert emitted["scope_type"] == "explicit"
    assert emitted["stages"] == ["D4"]
    assert emitted["summary"]["D4_symbols"] == 1
    assert (tmp_path / "mini-audit" / "diff-d4.json").exists()


def test_cli_diff_stage_resolves_a_commit_selector(repo: dict, tmp_path: Path) -> None:
    proc = _run_cli("diff", "stage", "--repo-root", str(repo["root"]),
                    "--commit", repo["b2"], "--stage", "D3", "--stage", "D5",
                    "--audit-root", "mini-audit", cwd=tmp_path)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    emitted = json.loads(proc.stdout)
    assert emitted["baseline"] == repo["b1"] and emitted["target"] == repo["b2"]
    assert emitted["summary"]["D3_paths_with_history"] == 1
    assert (tmp_path / "mini-audit" / "diff-d3.json").exists()
    assert (tmp_path / "mini-audit" / "diff-d5.json").exists()
