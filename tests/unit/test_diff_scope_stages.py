"""Hardening v1.1 §11 — diff mode stages D3–D6."""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from runtime.diff_scope import (
    analyze_path_history,
    analyze_test_gaps,
    build_adversarial_plan,
    build_diff_scope,
    build_diff_scope_extended,
    candidate_test_paths,
    hypothesize_classes,
    is_test_path,
    structured_blast_radius,
)

SKILL_ROOT = Path(__file__).resolve().parent.parent.parent
LAUNCHER = SKILL_ROOT / "scripts" / "mini-audit-runtime"


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


@pytest.fixture()
def repo(tmp_path: Path) -> dict:
    """A repo where a security-sensitive file is edited several times,
    one commit reverts, and the change has no accompanying test."""
    r = tmp_path / "repo"
    _init(r)
    (r / "src" / "auth").mkdir(parents=True)
    (r / "src" / "auth" / "session.py").write_text("def check(u):\n    return True\n", encoding="utf-8")
    (r / "src" / "util.py").write_text("def helper():\n    return 1\n", encoding="utf-8")
    base = _commit(r, "initial import")
    return {"root": r, "baseline": base}


def test_d3_history_counts_commits_and_detects_regression(repo: dict) -> None:
    r: Path = repo["root"]
    (r / "src" / "auth" / "session.py").write_text("def check(u):\n    return False\n", encoding="utf-8")
    _commit(r, "fix security bug: tighten session check")
    (r / "src" / "auth" / "session.py").write_text("def check(u):\n    return True\n", encoding="utf-8")
    _commit(r, "Revert \"fix security bug: tighten session check\"")
    (r / "src" / "auth" / "session.py").write_text("def check(u):\n    return u is not None\n", encoding="utf-8")
    target = _commit(r, "hotfix: re-apply check")

    history = analyze_path_history(r, baseline=repo["baseline"], target=target,
                                   paths=["src/auth/session.py", "src/util.py"])
    session = history["src/auth/session.py"]
    assert session.commits == 3
    assert session.regression_signals, "revert/hotfix subjects must be flagged"
    assert session.security_fix_signals, "security-fix subjects must be flagged"
    assert session.regression_risk >= 4
    assert session.churn > 0

    util = history["src/util.py"]
    assert util.commits == 0
    assert util.regression_risk == 0


def test_d4_blast_radius_is_structured(repo: dict) -> None:
    r: Path = repo["root"]
    (r / "src" / "api").mkdir(parents=True)
    (r / "src" / "api" / "handler.py").write_text(
        "from src.auth.session import check\n\n"
        "def handle_request(req):\n"
        "    return check(req.user)\n",
        encoding="utf-8",
    )
    (r / "src" / "auth" / "session.py").write_text("def check(u):\n    return True\n", encoding="utf-8")
    target = _commit(r, "wire session check into request handler")

    blast = structured_blast_radius(r, changed_paths=["src/auth/session.py"], symbols=["check"])
    assert "check" in blast["per_symbol"]
    entry = blast["per_symbol"]["check"]
    assert entry["count"] >= 1
    refs = entry["references"]
    assert all("locality" in x and "security_sensitive" in x and "looks_like_entrypoint" in x for x in refs)
    assert any(x["looks_like_entrypoint"] for x in refs), "handler callers must be recognised"
    assert entry["blast_radius"] in ("moderate", "wide")


def test_d5_detects_untested_and_stale(repo: dict) -> None:
    r: Path = repo["root"]
    # util.py has a test that is NOT touched; session.py has no test at all.
    (r / "tests").mkdir(exist_ok=True)
    (r / "tests" / "test_util.py").write_text("def test_helper():\n    assert True\n", encoding="utf-8")
    _commit(r, "add util test")

    (r / "src" / "auth" / "session.py").write_text("def check(u):\n    return u is not None\n", encoding="utf-8")
    (r / "src" / "util.py").write_text("def helper():\n    return 2\n", encoding="utf-8")
    target = _commit(r, "change session and util")

    gaps = analyze_test_gaps(r, changed_paths=["src/auth/session.py", "src/util.py"])
    untested_paths = [x["path"] for x in gaps["untested_paths"]]
    stale_paths = [x["path"] for x in gaps["test_stale_paths"]]
    assert "src/auth/session.py" in untested_paths, "no test exists for session.py"
    assert "src/util.py" in stale_paths, "util.py changed but test_util.py did not"
    assert gaps["total_changed_sources"] == 2
    assert gaps["test_coverage_ratio"] == 0.0
    assert gaps["gap_risk"] in ("high", "medium")


def test_d5_test_path_detection() -> None:
    assert is_test_path("tests/test_a.py")
    assert is_test_path("src/a_test.go")
    assert is_test_path("web/a.spec.ts")
    assert is_test_path("pkg/__tests__/x.js")
    assert not is_test_path("src/session.py")
    cands = candidate_test_paths("src/auth/session.py")
    assert "tests/test_session.py" in cands
    assert any(c.startswith("src/auth/") for c in cands)


def test_d6_plan_targets_high_risk_paths(repo: dict) -> None:
    r: Path = repo["root"]
    (r / "src" / "exec.py").write_text(
        "import subprocess\n\n"
        "def run(cmd):\n"
        "    return subprocess.Popen(cmd, shell=True)\n",
        encoding="utf-8",
    )
    target = _commit(r, "add exec helper")

    scope = build_diff_scope(r, baseline=repo["baseline"], target=target)
    plan = build_adversarial_plan(r, risk_ranked=scope.risk_ranked,
                                  line_ranges=scope.line_ranges, min_risk=0)
    assert plan["task_count"] >= 1
    task = next(t for t in plan["tasks"] if t["path"] == "src/exec.py")
    assert "rce" in task["hypothesis_classes"]
    assert len(task["adversarial_questions"]) >= 3
    assert any("entrypoint" in e for e in task["required_evidence"])
    assert "attacker_could_already_do_this_via_normal_features" in task["anti_patterns_to_rule_out"]


def test_d6_min_risk_filters(repo: dict) -> None:
    r: Path = repo["root"]
    (r / "notes.txt").write_text("hello\n", encoding="utf-8")
    target = _commit(r, "add notes")
    scope = build_diff_scope(r, baseline=repo["baseline"], target=target)
    plan = build_adversarial_plan(r, risk_ranked=scope.risk_ranked,
                                  line_ranges=scope.line_ranges, min_risk=4)
    assert all(t["risk_score"] >= 4 for t in plan["tasks"])


def test_hypothesize_classes_fallbacks() -> None:
    assert hypothesize_classes("a/b.py", "subprocess.Popen(cmd, shell=True)") == ["rce"] or \
        "rce" in hypothesize_classes("a/b.py", "subprocess.Popen(cmd, shell=True)")
    assert hypothesize_classes("a/plain.txt", "just words") == ["unclassified"]
    assert "sql_injection" in hypothesize_classes("db.py", 'cursor.execute("select * from t")')


def test_build_diff_scope_extended_runs_all_stages(repo: dict) -> None:
    r: Path = repo["root"]
    (r / "src" / "auth" / "session.py").write_text(
        "import subprocess\n\n"
        "def check(u):\n"
        "    return subprocess.run(u, shell=True)\n",
        encoding="utf-8",
    )
    target = _commit(r, "session check runs a command")

    extended = build_diff_scope_extended(r, baseline=repo["baseline"], target=target,
                                         risky_symbols=["check"], min_risk=0)
    for key in ("baseline", "target", "changed", "risk_ranked", "line_ranges",
                "callers", "D3_history", "D4_blast_radius", "D5_test_gaps",
                "D6_adversarial_plan"):
        assert key in extended
    assert "src/auth/session.py" in extended["D3_history"]
    assert extended["D4_blast_radius"]["symbols"] == ["check"]
    assert extended["D6_adversarial_plan"]["task_count"] >= 1
    # combined_risk folds D3 regression risk into the D2 score
    assert all("combined_risk" in e for e in extended["risk_ranked"])


def test_extended_output_is_json_serializable(repo: dict) -> None:
    r: Path = repo["root"]
    (r / "src" / "auth" / "session.py").write_text("def check(u):\n    return 1\n", encoding="utf-8")
    target = _commit(r, "tweak")
    extended = build_diff_scope_extended(r, baseline=repo["baseline"], target=target)
    json.dumps(extended, sort_keys=True)  # must not raise


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _run_cli(*args: str, cwd: Path) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, str(LAUNCHER), *args],
                          capture_output=True, text=True, cwd=str(cwd), check=False)


def test_cli_diff_stage_all(repo: dict, tmp_path: Path) -> None:
    r: Path = repo["root"]
    (r / "src" / "auth" / "session.py").write_text(
        "import subprocess\n\ndef check(u):\n    return subprocess.run(u, shell=True)\n",
        encoding="utf-8",
    )
    target = _commit(r, "session check runs a command")

    result = _run_cli("diff", "stage", "--repo-root", str(r),
                      "--baseline", repo["baseline"], "--target", target,
                      "--symbol", "check", "--min-risk", "0",
                      "--audit-root", "mini-audit", cwd=tmp_path)
    assert result.returncode == 0, result.stdout + result.stderr
    payload = json.loads(result.stdout)
    assert payload["stages"] == ["D3", "D4", "D5", "D6"]
    for name in ("diff-d3.json", "diff-d4.json", "diff-d5.json", "diff-d6.json"):
        assert (tmp_path / "mini-audit" / name).exists()
    assert payload["summary"]["D6_tasks"] >= 1


def test_cli_diff_stage_single(repo: dict, tmp_path: Path) -> None:
    r: Path = repo["root"]
    target = repo["baseline"]
    result = _run_cli("diff", "stage", "--repo-root", str(r),
                      "--baseline", repo["baseline"], "--target", target,
                      "--stage", "D5", "--audit-root", "mini-audit", cwd=tmp_path)
    assert result.returncode == 0, result.stdout + result.stderr
    payload = json.loads(result.stdout)
    assert payload["stages"] == ["D5"]
    assert (tmp_path / "mini-audit" / "diff-d5.json").exists()
    assert not (tmp_path / "mini-audit" / "diff-d3.json").exists()


def test_cli_diff_stage_rejects_bad_stage(repo: dict, tmp_path: Path) -> None:
    result = _run_cli("diff", "stage", "--repo-root", str(repo["root"]),
                      "--baseline", repo["baseline"], "--target", repo["baseline"],
                      "--stage", "D9", cwd=tmp_path)
    assert result.returncode == 2
