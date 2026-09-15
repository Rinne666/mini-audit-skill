"""Hardening v1.1 §8 + v1.1.1 §2 — sandbox policy: verified backends, fail closed.

v1.1 decided *whether to run* from a document that only recorded what the host
claimed, then ran the command with plain ``subprocess``. These tests pin the
v1.1.1 contract:

* a capability-only probe grants nothing;
* a probe admits execution only via a backend that **demonstrated** the controls
  the kind requires;
* an admitted run actually goes through the wrapper;
* a blocked request never executes anything.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from runtime.sandbox import (
    EXECUTION_KINDS,
    KIND_POC,
    KIND_SOURCE_SCAN,
    KIND_TARGET,
    KIND_TARGET_BUILD,
    REQUIRED_CONTROLS,
    SandboxBlocked,
    check_sandbox,
    evaluate_probe,
    probe_document,
    probe_file,
    read_probe,
    run_sandboxed,
    write_probe,
)
from runtime.sandbox_backend import (
    ALL_CONTROLS,
    CONTROL_ENV_SANITIZED,
    CONTROL_NETWORK_DENIAL,
    CONTROL_READ_ONLY_SOURCE,
    CONTROL_RESOURCE_LIMITS,
    CONTROL_WRITE_CONFINEMENT,
    IsolationBackend,
)

ALL_TRUE = {c: True for c in ALL_CONTROLS}

# Deliberately not a real backend name: an injected `backend=` is used wherever a
# test needs the run to actually happen, so these tests never depend on what the
# host happens to have installed.
FAKE = "fake"


def _backend_report(name: str = FAKE, controls: dict | None = None, usable: bool = True) -> dict:
    controls = dict(ALL_TRUE if controls is None else controls)
    return {
        "backend": name,
        "usable": usable,
        "verified": usable and any(controls.values()),
        "controls": controls,
        "demonstrated": sorted(k for k, v in controls.items() if v),
        "evidence": {"isolated": {"wrote_forbidden": 0}, "baseline": {"wrote_forbidden": 1}},
        "detail": f"stub backend {name}",
        "image": "",
    }


def _probe(*reports: dict) -> dict:
    return {"schema_version": 2, "backends": list(reports) or [_backend_report()]}


class WrappingBackend(IsolationBackend):
    """A backend whose wrapper is observable in the child's stderr.

    Used to prove that an admitted run goes *through* the backend rather than
    straight to `subprocess`.
    """

    name = FAKE
    binary = "sh"

    def build_argv(self, argv, spec):
        return ["sh", "-c", 'echo MINI-AUDIT-WRAPPER-APPLIED >&2; exec "$@"', "wrapper", *argv]


# ---------------------------------------------------------------------------
# Probe → decision
# ---------------------------------------------------------------------------


def test_missing_probe_blocks_everything(tmp_path: Path) -> None:
    for kind in EXECUTION_KINDS:
        d = check_sandbox(kind, tmp_path)
        assert d.ok is False
        assert d.execution_status == "blocked"
        assert d.verdict == "needs_validation"
        assert d.probe_present is False
        assert d.isolation_backend is None
        assert "probe not found" in d.reason


def test_legacy_capability_only_probe_grants_nothing(tmp_path: Path) -> None:
    """The v1.1 probe shape recorded claims, not evidence."""
    legacy = {"schema_version": 1, "checks": {k: True for k in (
        "sandbox_available", "external_network_disabled", "safe_writable_scratch",
        "timeout_available", "resource_limit_available", "environment_sanitized",
    )}}
    for kind in EXECUTION_KINDS:
        d = evaluate_probe(legacy, kind, audit_root=tmp_path)
        assert d.ok is False
        assert d.legacy_probe is True
        assert "legacy" in d.reason
        assert set(d.missing_critical) == set(REQUIRED_CONTROLS[kind])


def test_verified_backend_admits_and_names_the_backend(tmp_path: Path) -> None:
    d = evaluate_probe(_probe(), KIND_POC, audit_root=tmp_path)
    assert d.ok is True
    assert d.isolation_backend == FAKE
    assert d.isolation_verified is True
    assert d.to_dict()["host_fallback"] is False


def test_unusable_backends_block_with_a_per_backend_reason(tmp_path: Path) -> None:
    probe = _probe(
        _backend_report("bwrap", usable=False),
        _backend_report("sandbox-exec", usable=False),
    )
    d = evaluate_probe(probe, KIND_POC, audit_root=tmp_path)
    assert d.ok is False
    assert "no usable isolation backend" in d.reason
    assert "bwrap" in d.reason and "sandbox-exec" in d.reason


def test_a_backend_that_did_not_demonstrate_a_required_control_blocks(tmp_path: Path) -> None:
    """A backend that isolates writes but not network cannot run a PoC."""
    weak = _backend_report(FAKE, controls={
        CONTROL_WRITE_CONFINEMENT: True,
        CONTROL_READ_ONLY_SOURCE: True,
        CONTROL_NETWORK_DENIAL: False,
        CONTROL_RESOURCE_LIMITS: True,
        CONTROL_ENV_SANITIZED: True,
        "hard_timeout": True,
    })
    d = evaluate_probe(_probe(weak), KIND_POC, audit_root=tmp_path)
    assert d.ok is False
    assert CONTROL_NETWORK_DENIAL in d.missing_critical
    assert d.isolation_backend == FAKE  # recorded, but not admitted


def test_the_best_available_backend_wins(tmp_path: Path) -> None:
    weak = _backend_report("weak", controls={CONTROL_WRITE_CONFINEMENT: True})
    strong = _backend_report("strong")
    d = evaluate_probe(_probe(weak, strong), KIND_POC, audit_root=tmp_path)
    assert d.ok is True
    assert d.isolation_backend == "strong"


def test_required_controls_are_ordered_by_kind(tmp_path: Path) -> None:
    """source-scan may reach the network; target-controlled kinds may not."""
    assert CONTROL_NETWORK_DENIAL not in REQUIRED_CONTROLS[KIND_SOURCE_SCAN]
    for kind in (KIND_TARGET_BUILD, KIND_POC, KIND_TARGET):
        assert CONTROL_NETWORK_DENIAL in REQUIRED_CONTROLS[kind]
    assert CONTROL_ENV_SANITIZED in REQUIRED_CONTROLS[KIND_TARGET]
    assert CONTROL_ENV_SANITIZED not in REQUIRED_CONTROLS[KIND_SOURCE_SCAN]
    assert set(REQUIRED_CONTROLS[KIND_TARGET]) >= set(REQUIRED_CONTROLS[KIND_POC])


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


def test_write_probe_roundtrip(tmp_path: Path) -> None:
    write_probe(tmp_path, _probe())
    assert read_probe(tmp_path)["schema_version"] == 2


def test_probe_document_records_every_backend_with_evidence(tmp_path: Path) -> None:
    """Verification output must be auditable, not a bare boolean."""
    repo = tmp_path / "repo"
    repo.mkdir()
    audit = tmp_path / "mini-audit"
    audit.mkdir()
    doc = probe_document(KIND_POC, repo_root=repo, audit_root=audit,
                         base_env={"PATH": "/usr/bin:/bin"}, timeout_seconds=5)
    assert doc["schema_version"] == 2
    names = {b["backend"] for b in doc["backends"]}
    assert {"bwrap", "sandbox-exec", "docker"} <= names
    for b in doc["backends"]:
        # Every backend states what it demonstrated and why it could not.
        assert "controls" in b and "usable" in b and b["detail"] or b["demonstrated"]


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


# ---------------------------------------------------------------------------
# Execution
# ---------------------------------------------------------------------------


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


def test_run_sandboxed_refuses_when_the_named_backend_is_gone(tmp_path: Path) -> None:
    """A probe can outlive the backend it names; we must not run uncontained."""
    sentinel = tmp_path / "ran.txt"
    probe = _probe(_backend_report("bwrap"))  # not available on this host
    result = run_sandboxed(
        [sys.executable, "-c", f"open({str(sentinel)!r}, 'w').write('x')"],
        kind=KIND_POC, audit_root=tmp_path, probe=probe, timeout_seconds=10,
    )
    assert result.executed is False
    assert not sentinel.exists()
    assert "not\navailable now" in result.decision.reason.replace(" ", "\n") or \
        "not available now" in result.decision.reason


def test_run_sandboxed_executes_through_the_wrapper(tmp_path: Path) -> None:
    """An admitted run must go through the backend, not straight to subprocess."""
    sentinel = tmp_path / "ran.txt"
    result = run_sandboxed(
        [sys.executable, "-c",
         f"import pathlib; pathlib.Path({str(sentinel)!r}).write_text('x')"],
        kind=KIND_POC,
        audit_root=tmp_path,
        probe=_probe(),
        timeout_seconds=30,
        backend=WrappingBackend(),
    )
    assert result.executed is True
    assert result.outcome.returncode == 0
    assert sentinel.exists()
    assert "MINI-AUDIT-WRAPPER-APPLIED" in (result.outcome.stderr or ""), (
        "the command must have been launched through the backend"
    )
    assert result.argv and result.argv[0] == "sh"
    assert result.to_dict()["isolation_argv"]


def test_run_sandboxed_hard_kills_on_timeout(tmp_path: Path) -> None:
    result = run_sandboxed(
        [sys.executable, "-c", "import time; time.sleep(30)"],
        kind=KIND_POC, audit_root=tmp_path, probe=_probe(), timeout_seconds=0.5,
        grace_seconds=0.5, backend=WrappingBackend(),
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
    assert payload["isolation_backend"] is None


def test_cli_sandbox_run_refuses_blocked_command(tmp_path: Path) -> None:
    sentinel = tmp_path / "ran.txt"
    result = _run_cli("sandbox", "run", "--kind", "poc", "--",
                      "bash", "-c", f"echo x > {sentinel}", cwd=tmp_path)
    assert result.returncode == 1
    payload = json.loads(result.stdout)
    assert payload["executed"] is False
    assert not sentinel.exists()


@pytest.mark.skipif(
    not any(b.name == "docker" and b.available() for b in __import__(
        "runtime.sandbox_backend", fromlist=["BACKENDS"]).BACKENDS),
    reason="no usable isolation backend on this host",
)
def test_cli_sandbox_probe_then_run_contains_a_real_command(tmp_path: Path) -> None:
    """Live: probe → run, and the container really stops an escape write."""
    repo = tmp_path / "repo"
    repo.mkdir()
    audit_root = tmp_path / "mini-audit"

    probe = _run_cli("sandbox", "probe", "--kind", "poc", "--repo-root", str(repo),
                     "--audit-root", str(audit_root), cwd=tmp_path)
    assert probe.returncode == 0, probe.stdout + probe.stderr
    written = json.loads(probe.stdout)
    assert written["decision"]["isolation_verified"] is True
    assert written["decision"]["isolation_backend"] == "docker"

    outside = tmp_path / "escaped.txt"
    inside = audit_root / "inside.txt"
    result = _run_cli(
        "sandbox", "run", "--kind", "poc", "--repo-root", str(repo),
        "--audit-root", str(audit_root), "--timeout", "60", "--",
        "sh", "-c",
        f"printf x > {outside} 2>/dev/null; printf y > {inside} 2>/dev/null; true",
        cwd=tmp_path,
    )
    payload = json.loads(result.stdout)
    assert payload["executed"] is True
    assert not outside.exists(), "the escape write must have been confined"
    assert inside.exists(), "the command must have really run (scratch is writable)"
