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