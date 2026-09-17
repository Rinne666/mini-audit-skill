"""Tests for runtime/cli.py — CLI dispatcher end-to-end (smoke tests)."""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

SKILL_ROOT = Path(__file__).resolve().parent.parent.parent
LAUNCHER = SKILL_ROOT / "scripts" / "mini-audit-runtime"


def _run_cli(*args: str, cwd: Path = Path(".")) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(LAUNCHER), *args],
        capture_output=True,
        text=True,
        cwd=str(cwd),
        check=False,
    )


def _confirmed(**overrides):
    base = {
        "id": "F-001",
        "verdict": "confirmed",
        "class": "idor",
        "title": "IDOR on invoice lookup",
        "summary": "An authenticated ordinary user can read other tenants' invoices.",
        "source_ref": {"commit": "abc123", "tree_hash": "t"},
        "attacker": {"identity": "authenticated ordinary user", "existing_authority": "read own tenant invoices"},
        "boundary": {
            "type": "tenant_isolation",
            "security_invariant": "Tenant A cannot access Tenant B objects",
            "before_capability": "read Tenant A invoices",
            "after_capability": "read Tenant B invoices",
            "crossed": True,
        },
        "root_cause": "Missing ownership check before findById",
        "trace": [
            {"kind": "entrypoint", "file": "src/api.ts", "line": 40, "symbol": "getInvoice"},
            {"kind": "sink", "file": "src/db.ts", "line": 60, "symbol": "findById"},
        ],
        "severity": {"overall": "high"},
        "verification": {"technical_verifier": "verify-c001"},
    }
    base.update(overrides)
    from runtime.fingerprint import compute_fingerprint
    base["fingerprint"] = compute_fingerprint(base)
    return base


def test_cli_state_init(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    result = _run_cli("state", "init", "--repo-root", str(repo), "--audit-root", "mini-audit",
                      cwd=tmp_path)
    assert result.returncode == 0, result.stderr
    out = json.loads(result.stdout)
    assert out["ok"] is True
    assert out["command"] == "state.init"
    assert (tmp_path / "mini-audit" / "audit-state.json").exists()


def test_cli_state_show_after_init(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    _run_cli("state", "init", "--repo-root", str(repo), "--audit-root", "mini-audit",
             cwd=tmp_path)
    result = _run_cli("state", "show", "--audit-root", "mini-audit", cwd=tmp_path)
    assert result.returncode == 0
    out = json.loads(result.stdout)
    assert out["state"]["audit_id"]


def test_cli_phase_lifecycle(tmp_path: Path) -> None:
    """Hardening v1.1 §2 — `phase complete` cannot bypass the phase gate."""
    repo = tmp_path / "repo"
    repo.mkdir()
    _run_cli("state", "init", "--repo-root", str(repo), "--audit-root", "mini-audit",
             cwd=tmp_path)
    r1 = _run_cli("phase", "start", "L5", "--audit-root", "mini-audit", cwd=tmp_path)
    assert r1.returncode == 0, r1.stdout + r1.stderr

    # L5's gate requires at least one probe-workspace/*/probe-summary.md.
    # Without it, `complete` must fail and must NOT advance state.
    r2 = _run_cli("phase", "complete", "L5", "--audit-root", "mini-audit", cwd=tmp_path)
    assert r2.returncode == 1, r2.stdout + r2.stderr
    out2 = json.loads(r2.stdout)
    assert out2["ok"] is False
    assert "gate failed" in out2["error"]
    assert out2["gate"]["passed"] is False

    show = _run_cli("state", "show", "--audit-root", "mini-audit", cwd=tmp_path)
    assert json.loads(show.stdout)["state"]["phases"]["L5"]["status"] != "complete"

    # Satisfy the gate artifact, re-enter the phase, then complete for real.
    probe_dir = tmp_path / "mini-audit" / "probe-workspace" / "slice-1"
    probe_dir.mkdir(parents=True)
    (probe_dir / "probe-summary.md").write_text("## probe\nno issues found\n", encoding="utf-8")

    r3 = _run_cli("phase", "start", "L5", "--audit-root", "mini-audit", cwd=tmp_path)
    assert r3.returncode == 0, r3.stdout + r3.stderr
    r4 = _run_cli("phase", "complete", "L5", "--audit-root", "mini-audit", cwd=tmp_path)
    assert r4.returncode == 0, r4.stdout + r4.stderr
    assert json.loads(r4.stdout)["gate"]["passed"] is True

    # complete -> complete is still an illegal no-op transition.
    r5 = _run_cli("phase", "complete", "L5", "--audit-root", "mini-audit", cwd=tmp_path)
    assert r5.returncode == 2
    assert json.loads(r5.stdout)["ok"] is False


def test_cli_phase_complete_gated_phase_without_artifact_stays_noncomplete(tmp_path: Path) -> None:
    """A gated phase can never be marked complete on the agent's word alone."""
    repo = tmp_path / "repo"
    repo.mkdir()
    _run_cli("state", "init", "--repo-root", str(repo), "--audit-root", "mini-audit", cwd=tmp_path)
    _run_cli("phase", "start", "L1", "--audit-root", "mini-audit", cwd=tmp_path)
    r = _run_cli("phase", "complete", "L1", "--audit-root", "mini-audit", cwd=tmp_path)
    assert r.returncode == 1
    show = json.loads(_run_cli("state", "show", "--audit-root", "mini-audit", cwd=tmp_path).stdout)
    assert show["state"]["phases"]["L1"]["status"] == "failed"


def test_cli_phase_start_respects_max_attempts(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    _run_cli("state", "init", "--repo-root", str(repo), "--audit-root", "mini-audit", cwd=tmp_path)
    for _ in range(2):
        assert _run_cli("phase", "start", "L5", "--audit-root", "mini-audit",
                        cwd=tmp_path).returncode == 0
        _run_cli("phase", "fail", "L5", "--error", "boom", "--audit-root", "mini-audit", cwd=tmp_path)
    r = _run_cli("phase", "start", "L5", "--audit-root", "mini-audit", cwd=tmp_path)
    assert r.returncode == 2
    assert "max_attempts" in json.loads(r.stdout)["error"]

    # --reset opens a fresh attempt budget.
    r2 = _run_cli("phase", "start", "L5", "--reset", "--audit-root", "mini-audit", cwd=tmp_path)
    assert r2.returncode == 0, r2.stdout + r2.stderr
    assert json.loads(r2.stdout)["attempt"] == 1


def test_cli_finding_validate_roundtrip(tmp_path: Path) -> None:
    f = _confirmed()
    p = tmp_path / "finding.json"
    p.write_text(json.dumps(f), encoding="utf-8")
    result = _run_cli("finding", "validate", str(p), cwd=tmp_path)
    assert result.returncode == 0, result.stdout + result.stderr
    out = json.loads(result.stdout)
    assert out["ok"] is True
    assert out["fingerprint"].startswith("v1:")


def test_cli_finding_validate_rejects_mismatch(tmp_path: Path) -> None:
    f = _confirmed()
    f["fingerprint"] = "v1:" + "0" * 64  # wrong fingerprint
    p = tmp_path / "finding.json"
    p.write_text(json.dumps(f), encoding="utf-8")
    result = _run_cli("finding", "validate", str(p), cwd=tmp_path)
    assert result.returncode == 1
    out = json.loads(result.stdout)
    assert out["ok"] is False


def test_cli_export_json(tmp_path: Path) -> None:
    f = _confirmed()
    f["id"] = "F-001"
    repo = tmp_path / "repo"
    repo.mkdir()
    _run_cli("state", "init", "--repo-root", str(repo), "--audit-root", "mini-audit",
             cwd=tmp_path)
    findings_path = tmp_path / "mini-audit" / "findings.json"
    findings_path.parent.mkdir(parents=True, exist_ok=True)
    from runtime.findings import FindingStore
    s = FindingStore.empty(audit_id="x")
    s.upsert(f)
    s.save(findings_path)
    out = tmp_path / "out.json"
    result = _run_cli("export", "--format", "json", "--output", str(out),
                      "--audit-root", "mini-audit", cwd=tmp_path)
    assert result.returncode == 0, result.stdout + result.stderr
    assert out.exists()
    payload = json.loads(out.read_text(encoding="utf-8"))
    assert len(payload["findings"]) == 1


def test_cli_gate_fails_when_artifacts_missing(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    _run_cli("state", "init", "--repo-root", str(repo), "--audit-root", "mini-audit",
             cwd=tmp_path)
    result = _run_cli("gate", "L1", "--audit-root", "mini-audit", cwd=tmp_path)
    assert result.returncode == 1
    out = json.loads(result.stdout)
    assert out["ok"] is False
    assert any(f["check"] == "existence" for f in out["result"]["failures"])


def test_cli_coverage_init_and_validate(tmp_path: Path) -> None:
    plan = {
        "audit_id": "x",
        "units": [
            {"id": "billing|tenant|idor", "subsystem": "billing",
             "boundary": "tenant", "attack_class": "idor"},
        ],
    }
    plan_path = tmp_path / "plan.json"
    plan_path.write_text(json.dumps(plan), encoding="utf-8")
    repo = tmp_path / "repo"
    repo.mkdir()
    _run_cli("state", "init", "--repo-root", str(repo), "--audit-root", "mini-audit",
             cwd=tmp_path)
    r1 = _run_cli("coverage", "init", str(plan_path),
                  "--audit-root", "mini-audit", cwd=tmp_path)
    assert r1.returncode == 0
    r2 = _run_cli("coverage", "validate", "--audit-root", "mini-audit", cwd=tmp_path)
    assert r2.returncode == 1  # unresolved planned unit
    out = json.loads(r2.stdout)
    assert out["ok"] is False
    assert "billing|tenant|idor" in out["unresolved"]


def _write_l7_artifacts(tmp_path: Path, *, extra_phases: dict | None = None) -> None:
    """Materialise everything the L7 gate requires, plus a realistic state.

    ``extra_phases`` lets a test declare sibling phases (e.g. L1..L6c complete)
    so the terminality check has something to actually check.
    """
    audit = tmp_path / "mini-audit"
    audit.mkdir(parents=True, exist_ok=True)
    (audit / "findings.json").write_text(
        json.dumps({"schema_version": 1, "audit_id": "a", "findings": [_confirmed()]}),
        encoding="utf-8",
    )
    (audit / "final-audit-report.md").write_text(
        "# report\n" + "content " * 30, encoding="utf-8"
    )
    (audit / "coverage-ledger.json").write_text(
        json.dumps({
            "schema_version": 1,
            "audit_id": "a",
            "planning_status": "complete",
            "units": [{
                "id": "a|b|c", "subsystem": "a", "boundary": "b",
                "attack_class": "c", "status": "covered",
            }],
        }),
        encoding="utf-8",
    )
    phases = {"L7": {"name": "L7", "status": "in_progress"}}
    phases.update(extra_phases or {})
    (audit / "audit-state.json").write_text(
        json.dumps({
            "schema_version": 1,
            "audit_id": "a",
            "mode": "balanced",
            "status": "in_progress",
            "source": {"root": "/repo", "commit": "abc", "tree_hash": "t"},
            "runtime": {"version": "1.1.0"},
            "phases": phases,
            "started_at": "2026-01-01T00:00:00Z",
            "updated_at": "2026-01-01T00:00:00Z",
        }),
        encoding="utf-8",
    )


def test_cli_l7_can_complete_when_siblings_are_terminal(tmp_path: Path) -> None:
    """Regression: L7 must not deadlock against its own terminality check.

    `phase complete L7` runs L7's gate, and that gate asserts every *other*
    phase is terminal. Before the fix the CLI put L7 itself into
    `required_phases` while L7 was still `in_progress`, so the gate failed
    against L7 unconditionally and L7 could never become `complete`.
    """
    repo = tmp_path / "repo"
    repo.mkdir()
    _run_cli("state", "init", "--repo-root", str(repo), "--audit-root", "mini-audit",
             cwd=tmp_path)
    _write_l7_artifacts(tmp_path, extra_phases={
        name: {"name": name, "status": "complete"} for name in ("L1", "L2", "L6", "L6b", "L6c")
    })

    r = _run_cli("phase", "complete", "L7", "--audit-root", "mini-audit",
                 "--workdir", str(tmp_path), cwd=tmp_path)
    assert r.returncode == 0, r.stdout + r.stderr
    out = json.loads(r.stdout)
    assert out["gate"]["passed"] is True, out["gate"]["failures"]
    assert out["status"] == "complete"


def test_cli_l7_completes_when_it_is_the_only_phase(tmp_path: Path) -> None:
    """`state init` declares no phases, so completing L7 leaves no siblings.

    An empty `required_phases` must mean "nothing else to require", not
    "fall back to requiring every declared phase" (which would re-include L7).
    """
    repo = tmp_path / "repo"
    repo.mkdir()
    _run_cli("state", "init", "--repo-root", str(repo), "--audit-root", "mini-audit",
             cwd=tmp_path)
    _write_l7_artifacts(tmp_path)  # only L7 exists, and it is in_progress

    r = _run_cli("phase", "complete", "L7", "--audit-root", "mini-audit",
                 "--workdir", str(tmp_path), cwd=tmp_path)
    assert r.returncode == 0, r.stdout + r.stderr
    assert json.loads(r.stdout)["gate"]["passed"] is True


def test_cli_l7_still_blocked_by_a_genuinely_non_terminal_phase(tmp_path: Path) -> None:
    """The fix must not weaken the check: a real sibling in progress still blocks."""
    repo = tmp_path / "repo"
    repo.mkdir()
    _run_cli("state", "init", "--repo-root", str(repo), "--audit-root", "mini-audit",
             cwd=tmp_path)
    _write_l7_artifacts(tmp_path, extra_phases={
        "L1": {"name": "L1", "status": "complete"},
        "L6": {"name": "L6", "status": "in_progress"},
    })

    r = _run_cli("phase", "complete", "L7", "--audit-root", "mini-audit",
                 "--workdir", str(tmp_path), cwd=tmp_path)
    assert r.returncode == 1, r.stdout + r.stderr
    out = json.loads(r.stdout)
    assert out["gate"]["passed"] is False
    assert any("non-terminal" in f["message"] for f in out["gate"]["failures"])
    assert any("L6" in f["message"] for f in out["gate"]["failures"])
    # L7 itself must never be reported as the offender.
    assert not any("L7" in f["message"] for f in out["gate"]["failures"])


def test_cli_lite_phase_is_gated_v1_1_1(tmp_path: Path) -> None:
    """v1.1.1 §19: lite phases now run a gate instead of trusting the agent.

    Before v1.1.1 only balanced phases declared gates, so `phase complete Q0`
    advanced state with an empty workspace.
    """
    repo = tmp_path / "repo"
    repo.mkdir()
    _run_cli("state", "init", "--repo-root", str(repo), "--audit-root", "mini-audit",
             "--mode", "lite", cwd=tmp_path)
    _run_cli("phase", "start", "Q0", "--audit-root", "mini-audit", cwd=tmp_path)

    blocked = _run_cli("phase", "complete", "Q0", "--audit-root", "mini-audit",
                       "--workdir", str(tmp_path), cwd=tmp_path)
    assert blocked.returncode == 1, blocked.stdout + blocked.stderr
    out = json.loads(blocked.stdout)
    assert out["gate"]["passed"] is False

    surface = tmp_path / "mini-audit" / "attack-surface"
    surface.mkdir(parents=True, exist_ok=True)
    (surface / "recon-report.md").write_text("# recon\n" + "x " * 100, encoding="utf-8")
    (surface / "candidates-summary.md").write_text("summary", encoding="utf-8")
    (surface / "candidates.jsonl").write_text('{"id":"c1"}\n', encoding="utf-8")

    # The failed gate parked Q0 in `failed`; a fresh attempt needs --reset.
    _run_cli("phase", "start", "Q0", "--reset", "--audit-root", "mini-audit", cwd=tmp_path)
    ok = _run_cli("phase", "complete", "Q0", "--audit-root", "mini-audit",
                  "--workdir", str(tmp_path), cwd=tmp_path)
    assert ok.returncode == 0, ok.stdout + ok.stderr
    assert json.loads(ok.stdout)["gate"]["passed"] is True


def test_cli_ungated_phase_still_completes_without_a_gate(tmp_path: Path) -> None:
    """Phases with no documented artifact contract must keep working.

    Guards the boundary the other way: adding gates for the phases that
    *have* contracts must not accidentally gate the ones that do not
    (e.g. deep P4, which writes sections into a shared document).
    """
    repo = tmp_path / "repo"
    repo.mkdir()
    _run_cli("state", "init", "--repo-root", str(repo), "--audit-root", "mini-audit",
             "--mode", "deep", cwd=tmp_path)
    _run_cli("phase", "start", "P4", "--audit-root", "mini-audit", cwd=tmp_path)
    r = _run_cli("phase", "complete", "P4", "--audit-root", "mini-audit",
                 "--workdir", str(tmp_path), cwd=tmp_path)
    assert r.returncode == 0, r.stdout + r.stderr
    assert json.loads(r.stdout)["gate"]["passed"] is True


def test_cli_sarif_normalize(tmp_path: Path) -> None:
    sarif = {
        "$schema": "https://example.com/sarif.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "semgrep", "rules": []}},
            "results": [{
                "ruleId": "python.lang.security.audit.eval",
                "message": {"text": "x"},
                "locations": [{"physicalLocation": {
                    "artifactLocation": {"uri": "x.py"},
                    "region": {"startLine": 1}}}],
            }],
        }],
    }
    sarif_path = tmp_path / "in.sarif"
    sarif_path.write_text(json.dumps(sarif), encoding="utf-8")
    repo = tmp_path / "repo"
    repo.mkdir()
    _run_cli("state", "init", "--repo-root", str(repo), "--audit-root", "mini-audit",
             cwd=tmp_path)
    r = _run_cli("sarif", "normalize", str(sarif_path), "--source", "semgrep",
                 "--audit-root", "mini-audit", cwd=tmp_path)
    assert r.returncode == 0, r.stdout + r.stderr
    out = json.loads(r.stdout)
    assert out["count"] == 1
    assert (tmp_path / "mini-audit" / "candidates" / "semgrep-candidates.json").exists()


# ---------------------------------------------------------------------------
# Skill-First Refactor v2: cmd_run_with_lease is deprecated (spec §9)
# ---------------------------------------------------------------------------
#
# ``cmd_run_with_lease`` was a CLI dispatcher that ran registered tasks under
# the scheduler's lease / dispatch half. After the v2 refactor agent scheduling
# belongs to the Harness, not the runtime, so the command is no longer
# registered in ``build_parser`` and now raises a DeprecationWarning if a
# Harness stub imports and calls it directly.


def test_cmd_run_with_lease_emits_deprecation_warning(tmp_path: Path) -> None:
    import argparse
    import warnings
    from runtime import cli

    repo = tmp_path / "repo"
    repo.mkdir()
    namespace = argparse.Namespace(
        task="fingerprint",  # a registered task name (any one is fine)
        workdir=str(tmp_path),
        phase="adhoc",
        config=None,
        timeout=5,
        max_attempts=1,
        agent_id="test",
    )
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        try:
            cli.cmd_run_with_lease(namespace)
        except SystemExit:
            # The function may SystemExit if the registry refuses; the
            # DeprecationWarning fires regardless of how it terminates.
            pass
    deprecation = [
        w for w in caught
        if issubclass(w.category, DeprecationWarning)
        and "cmd_run_with_lease" in str(w.message)
    ]
    assert deprecation, (
        "expected cmd_run_with_lease to emit a DeprecationWarning "
        f"referencing itself; got {[str(w.message) for w in caught]!r}"
    )


def test_build_parser_no_longer_exposes_lease_command() -> None:
    """Spec §9: agent scheduling is Harness-owned. The runtime's CLI must
    not advertise a ``lease`` subcommand to consumers."""
    from runtime import cli

    # argparse surfaces subcommands via the parser's optionals/choices; a
    # # reliable way to check is to feed a syntactically valid but
    # # subcommand-less argv and assert the parser fails on the missing
    # # subcommand at the parse-error level rather than dispatching.
    parser = cli.build_parser()
    # We don't need to actually call parser.parse_args; we just verify the
    # lease-related subparser is absent from the parser's internal subparsers
    # tree.
    def _walk(sp):
        for action in sp._actions:  # noqa: SLF001 (introspection)
            if isinstance(action, argparse._SubParsersAction):
                yield action.choices
                for child in action.choices.values():
                    if isinstance(child, argparse.ArgumentParser):
                        yield from _walk(child)
    import argparse
    found = []
    for choices in _walk(parser):
        if isinstance(choices, dict):
            for name in choices:
                if "lease" in name.lower():
                    found.append(name)
    assert not found, (
        f"build_parser must not expose lease-related subcommands (spec §9); "
        f"found {found!r}"
    )