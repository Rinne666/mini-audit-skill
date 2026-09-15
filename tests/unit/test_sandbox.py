"""Hardening v1.1 §8 — sandbox policy: fail closed, never fall back to host."""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from runtime.sandbox import (
    CRITICAL_CHECKS,
    EXECUTION_KINDS,
    KIND_POC,
    KIND_SOURCE_SCAN,
    KIND_TARGET,
    KIND_TARGET_BUILD,
    SandboxBlocked,
    check_sandbox,
    evaluate_probe,
    probe_file,
    read_probe,
    run_sandboxed,
)


def _probe(**checks: bool) -> dict:
    base = {
        "sandbox_available": False,
        "external_network_disabled": False,
        "safe_writable_scratch": False,
        "timeout_available": False,
        "resource_limit_available": False,
        "environment_sanitized": False,
    }
    base.update(checks)
    return {"schema_version": 1, "checks": base}


def test_missing_probe_blocks_everything(tmp_path: Path) -> None:
    for kind in EXECUTION_KINDS:
        d = check_sandbox(kind, tmp_path)
        assert d.ok is False
        assert d.execution_status == "blocked"
        assert d.verdict == "needs_validation"
        assert d.probe_present is False
        assert "probe not found" in d.reason


def test_source_scan_needs_only_scratch(tmp_path: Path) -> None:
    d = evaluate_probe(_probe(safe_writable_scratch=True), KIND_SOURCE_SCAN, audit_root=tmp_path)
    assert d.ok is True
    assert d.execution_status == "allowed"


def test_target_build_needs_sandbox(tmp_path: Path) -> None:
    d = evaluate_probe(_probe(safe_writable_scratch=True), KIND_TARGET_BUILD, audit_root=tmp_path)
    assert d.ok is False
    assert "sandbox_available" in d.missing_critical

    d2 = evaluate_probe(
        _probe(safe_writable_scratch=True, sandbox_available=True),
        KIND_TARGET_BUILD, audit_root=tmp_path,
    )
    assert d2.ok is True


def test_poc_needs_network_isolation_and_limits(tmp_path: Path) -> None:
    d = evaluate_probe(
        _probe(sandbox_available=True, safe_writable_scratch=True),
        KIND_POC, audit_root=tmp_path,
    )
    assert d.ok is False
    assert set(d.missing_critical) == {"external_network_disabled", "resource_limit_available"}


def test_target_needs_everything(tmp_path: Path) -> None:
    d = evaluate_probe({
        "checks": {k: True for k in CRITICAL_CHECKS[KIND_TARGET]},
    }, KIND_TARGET, audit_root=tmp_path)
    assert d.ok is True

    partial = {k: True for k in CRITICAL_CHECKS[KIND_TARGET] if k != "environment_sanitized"}
    d2 = evaluate_probe({"checks": partial}, KIND_TARGET, audit_root=tmp_path)
    assert d2.ok is False
    assert d2.missing_critical == ["environment_sanitized"]


def test_unknown_kind_rejected(tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        evaluate_probe(_probe(), "not-a-kind", audit_root=tmp_path)


def test_probe_artifact_path(tmp_path: Path) -> None:
    assert probe_file(tmp_path) == tmp_path / "sandbox" / "probe.json"


def test_read_probe_returns_none_when_absent_or_corrupt(tmp_path: Path) -> None:
    assert read_probe(tmp_path) is None
    p = probe_file(tmp_path)
    p.parent.mkdir(parents=True)
    p.write_text("{not json", encoding="utf-8")
    assert read_probe(tmp_path) is None


def test_blocked_decision_never_says_host_fallback(tmp_path: Path) -> None:
    d = check_sandbox(KIND_POC, tmp_path)
    payload = d.to_dict()
    assert payload["host_fallback"] is False
    assert payload["hard_timeout_enforced_by_runtime"] is True
    assert payload["verdict"] == "needs_validation"


def test_verdict_never_rejected_when_blocked(tmp_path: Path) -> None:
    """Absence of a sandbox is not evidence the bug is absent."""
    d = check_sandbox(KIND_POC, tmp_path)
    assert d.verdict != "rejected"
    assert d.verdict == "needs_validation"


def test_run_sandboxed_does_not_execute_when_blocked(tmp_path: Path) -> None:
    sentinel = tmp_path / "ran.txt"
    result = run_sandboxed(
        [sys.executable, "-c", f"open({str(sentinel)!r}, 'w').write('x')"],
        kind=KIND_POC, audit_root=tmp_path, timeout_seconds=10,
    )
    assert result.executed is False
    assert result.outcome is None
    assert result.decision.verdict == "needs_validation"
    assert not sentinel.exists()
    assert result.to_dict()["ok"] is False


def test_run_sandboxed_executes_when_allowed(tmp_path: Path) -> None:
    sentinel = tmp_path / "ran.txt"
    probe = _probe(
        sandbox_available=True, external_network_disabled=True,
        safe_writable_scratch=True, resource_limit_available=True,
    )
    result = run_sandboxed(
        [sys.executable, "-c", f"open({str(sentinel)!r}, 'w').write('x')"],
        kind=KIND_POC, audit_root=tmp_path, timeout_seconds=30, probe=probe,
    )
    assert result.executed is True
    assert result.outcome.returncode == 0
    assert sentinel.exists()
    assert result.to_dict()["ok"] is True


def test_run_sandboxed_hard_kills_on_timeout(tmp_path: Path) -> None:
    probe = _probe(
        sandbox_available=True, external_network_disabled=True,
        safe_writable_scratch=True, resource_limit_available=True,
    )
    result = run_sandboxed(
        [sys.executable, "-c", "import time; time.sleep(30)"],
        kind=KIND_POC, audit_root=tmp_path, timeout_seconds=0.5, probe=probe,
        grace_seconds=0.5,
    )
    assert result.executed is True
    assert result.outcome.timed_out is True
    assert result.outcome.terminated_for_real is True
    assert result.outcome.returncode is not None


def test_sandbox_blocked_exception_carries_decision(tmp_path: Path) -> None:
    decision = check_sandbox(KIND_POC, tmp_path)
    exc = SandboxBlocked(decision)
    assert exc.decision is decision
    assert "probe not found" in str(exc)


# ---------------------------------------------------------------------------
# CLI surface
# ---------------------------------------------------------------------------


def _run_cli(*args: str, cwd: Path) -> "subprocess.CompletedProcess":
    import subprocess

    launcher = Path(__file__).resolve().parent.parent.parent / "scripts" / "mini-audit-runtime"
    return subprocess.run([sys.executable, str(launcher), *args],
                          capture_output=True, text=True, cwd=str(cwd), check=False)


def test_cli_sandbox_check_blocks(tmp_path: Path) -> None:
    result = _run_cli("sandbox", "check", "--kind", "poc", cwd=tmp_path)
    assert result.returncode == 1
    payload = json.loads(result.stdout)
    assert payload["ok"] is False
    assert payload["execution_status"] == "blocked"
    assert payload["verdict"] == "needs_validation"


def test_cli_sandbox_run_refuses_blocked_command(tmp_path: Path) -> None:
    sentinel = tmp_path / "ran.txt"
    result = _run_cli("sandbox", "run", "--kind", "poc", "--",
                      "bash", "-c", f"echo x > {sentinel}", cwd=tmp_path)
    assert result.returncode == 1
    payload = json.loads(result.stdout)
    assert payload["executed"] is False
    assert not sentinel.exists()


def test_cli_sandbox_run_executes_when_probe_allows(tmp_path: Path) -> None:
    audit_root = tmp_path / "mini-audit"
    (audit_root / "sandbox").mkdir(parents=True)
    (audit_root / "sandbox" / "probe.json").write_text(json.dumps(_probe(
        sandbox_available=True, external_network_disabled=True,
        safe_writable_scratch=True, resource_limit_available=True,
    )), encoding="utf-8")
    sentinel = tmp_path / "ran.txt"
    result = _run_cli("sandbox", "run", "--kind", "poc", "--audit-root", str(audit_root),
                      "--timeout", "30", "--", "bash", "-c", f"echo x > {sentinel}", cwd=tmp_path)
    assert result.returncode == 0, result.stdout + result.stderr
    assert sentinel.exists()
