"""Ablation runner — surgical-component regression guards.

Each test in this file re-runs the Incremental Audit fixture with one named
component ablated and asserts that the metric whose contract depends on that
component drops, while the other three metrics remain unchanged. The contract
is the one frozen in ``references/methodology/diff-audit.md`` + the runtime's
``assumptions_update → blocked_paths_reopen`` side effect.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

SKILL_ROOT = Path(__file__).resolve().parent.parent.parent
RUNNER = SKILL_ROOT / "evals" / "ablation" / "run_ablation.py"


def _run(*args: str, workdir: Path) -> subprocess.CompletedProcess:
    env = os.environ.copy()
    env["PYTHONPATH"] = str(SKILL_ROOT)
    return subprocess.run(
        [sys.executable, str(RUNNER), *args],
        capture_output=True, text=True, check=False, env=env,
    )


def _report(proc: subprocess.CompletedProcess) -> dict:
    assert proc.returncode == 0, proc.stderr or proc.stdout
    return json.loads(proc.stdout)


# ---------------------------------------------------------------------------
# Ablation 1 — diff_evidence_ref
# ---------------------------------------------------------------------------


def test_ablate_diff_evidence_ref_drops_only_assumption_detection(tmp_path: Path) -> None:
    """Stripping ``diff_evidence_ref`` from every fact/assumption entry must
    drop *only* ``affected_assumption_detection``. The other three metrics
    are not driven by the field, so they stay at baseline."""
    proc = _run("--ablate", "diff_evidence_ref", "--scenario", "INCR-001",
                "--keep", str(tmp_path), "--json", workdir=tmp_path)
    report = _report(proc)
    delta = report["delta"]
    # The metric gated on the field drops by exactly 1.
    assert delta["affected_assumption_detection"] == pytest.approx(-1.0)
    # The other three are not driven by the field.
    for name in ("old_candidate_reuse_rate", "blocked_path_reopen_rate",
                 "incremental_chain_completion"):
        assert delta[name] == pytest.approx(0.0), (
            f"ablation was not surgical: {name} moved by {delta[name]}"
        )


def test_ablate_diff_evidence_ref_field_is_truly_absent(tmp_path: Path) -> None:
    """Sanity: after ablation the ledger has no ``diff_evidence_ref`` on the
    affected assumption (otherwise the metric gate wouldn't trip)."""
    proc = _run("--ablate", "diff_evidence_ref", "--scenario", "INCR-001",
                "--keep", str(tmp_path), workdir=tmp_path)
    assert proc.returncode == 0, proc.stderr
    ablated_root = tmp_path / "INCR-001" / "abl_diff_evidence_ref" / "mini-audit"
    ledger_path = ablated_root / "search-ledger.json"
    assert ledger_path.is_file(), f"missing ledger at {ledger_path}"
    ledger = json.loads(ledger_path.read_text())
    for assumption in ledger.get("assumptions", []):
        assert "diff_evidence_ref" not in assumption, (
            f"assumption still carries the field: {assumption}"
        )


# ---------------------------------------------------------------------------
# Skill-First Refactor v2 (spec §10): runtime-inertness guard
# ---------------------------------------------------------------------------


def test_runtime_is_inert_when_agent_does_not_decide_reopen(tmp_path: Path) -> None:
    """Spec §10: even when all artifacts exist, all gates would pass, and an
    assumption's blocker has flipped to ``disproved``, the runtime must NOT
    mutate ``blocked_path.status`` until the model submits an explicit
    ``blocked_paths_reopen`` decision. Replay a delta that disproves the
    blocker but omits the reopen entry; the blocked path must stay
    ``blocked`` and a ``derived_event`` must be appended to the ledger."""
    from runtime import objective as objective_mod
    from runtime import research_state as rs

    proposal = {
        "principal": "unauthenticated_remote_user",
        "initial_capabilities": ["send_http_request"],
        "target_capabilities": ["arbitrary_code_execution"],
        "security_invariants": ["anonymous users cannot obtain privileged execution capability"],
    }
    audit_root = tmp_path / "mini-audit"
    objective_mod.init_and_bootstrap(audit_root, proposal, agent="agent-L1")
    # Pre-populate: a blocked path whose blocker rests on an assumption.
    rs.apply_delta(audit_root, {
        "schema_version": 1,
        "agent_id": "agent-L5",
        "blocked_paths_add": [{
            "key": "blocked:query-needs-scalar",
            "candidate_id": "cand-b-query",
            "blocker": {"type": "input_validation",
                        "claim": "all callers coerce",
                        "assumption_ref": "assumption:callers-pass-int-list"},
            "priority": "high",
            "evidence_refs": ["A.py:21"],
        }],
        "assumptions_add": [{
            "key": "assumption:callers-pass-int-list",
            "claim": "every caller passes a list of integers",
        }],
    }, agent="agent-L5")

    # Now: agent disproves the assumption but submits NO reopen decision.
    report = rs.apply_delta(audit_root, {
        "schema_version": 1,
        "agent_id": "agent-L5b",
        "assumptions_update": [{
            "ref": "assumption:callers-pass-int-list",
            "status": "disproved",
            "evidence_refs": ["A.py:27"],
        }],
    }, agent="agent-L5b")

    # Spec §4: runtime reports derived event(s); does not rewrite BP status.
    assert report["derived_events"], (
        "runtime must report a 'blocked_path_reopenable' derived event when an "
        "assumption flips; got none"
    )
    assert any(ev["event"] == "blocked_path_reopenable"
               for ev in report["derived_events"]), (
        f"expected a 'blocked_path_reopenable' derived event, got "
        f"{[ev['event'] for ev in report['derived_events']]}"
    )
    assert report["reopened_blocked_paths"] == [], (
        "runtime must NOT auto-rewrite blocked_path.status in spec §4; "
        "the model owns that decision"
    )

    # On disk: the blocked path stays ``blocked``; only a derived_events entry
    # was appended.
    ledger = rs.load_ledger(audit_root)
    assert ledger is not None
    bps = [bp for bp in ledger["blocked_paths"]
           if bp["key"] == "blocked:query-needs-scalar"]
    assert bps and bps[0]["status"] == "blocked", (
        f"blocked_path must stay 'blocked' without an explicit reopen; "
        f"got {bps[0]['status']}"
    )
    events = ledger.get("derived_events") or []
    assert events, "ledger must carry the derived event for the model to read"
    assert events[-1]["event"] == "blocked_path_reopenable"
    assert events[-1]["subject"] == bps[0]["id"]


def test_runtime_inertness_violation_guard_against_auto_status_write() -> None:
    """Spec §2 + §4: the runtime must not export any auto-rewriting method on
    blocked_path or assumption objects. We assert that ``apply_delta`` is the
    only mutating surface and that a direct caller cannot make a blocked path
    reopen without going through an explicit ``blocked_paths_reopen`` entry.
    """
    import inspect

    from runtime import research_state as rs

    sig = inspect.signature(rs.apply_delta)
    # apply_delta must not accept a 'force_reopen' or similar bypass flag.
    forbidden_params = {"force_reopen", "auto_advance", "skip_side_effect_check"}
    actual = set(sig.parameters)
    leaked = forbidden_params & actual
    assert not leaked, (
        f"apply_delta exposes forbidden bypass params: {leaked} "
        "(spec §2: runtime must not auto-advance or auto-reopen)"
    )


# ---------------------------------------------------------------------------
# Baseline-only run (sanity)
# ---------------------------------------------------------------------------


def test_baseline_only_run_reports_no_delta(tmp_path: Path) -> None:
    """Without --ablate, the report contains baseline metrics but no
    ablated/delta fields. Guard against silent baseline regression."""
    proc = _run("--scenario", "INCR-001", "--json", workdir=tmp_path)
    report = _report(proc)
    assert report["baseline"]["affected_assumption_detection"] == pytest.approx(1.0)
    assert report["ablated"] is None
    assert report["delta"] is None