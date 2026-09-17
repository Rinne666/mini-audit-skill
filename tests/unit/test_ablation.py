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
# Ablation 2 — auto_reopen (assumption → blocked-path side effect)
# ---------------------------------------------------------------------------


def test_ablate_auto_reopen_drops_only_reopen_assumption(tmp_path: Path) -> None:
    """Removing the assumption→blocked-path side effect must drop
    ``blocked_path_reopen_rate`` to 0 (and, transitively,
    ``affected_assumption_detection`` — the metric requires the assumption
    to actually be marked disproved, which the side-effect bypass disables).
    The two reuse/completion metrics stay at baseline."""
    proc = _run("--ablate", "auto_reopen", "--scenario", "INCR-001",
                "--keep", str(tmp_path), "--json", workdir=tmp_path)
    report = _report(proc)
    delta = report["delta"]
    assert delta["blocked_path_reopen_rate"] == pytest.approx(-1.0)
    assert delta["affected_assumption_detection"] == pytest.approx(-1.0)
    for name in ("old_candidate_reuse_rate", "incremental_chain_completion"):
        assert delta[name] == pytest.approx(0.0), (
            f"ablation was not surgical: {name} moved by {delta[name]}"
        )


def test_ablate_auto_reopen_keeps_assumption_unverified(tmp_path: Path) -> None:
    """The auto_reopen ablation rewrites the delta so the assumption status
    update is dropped. The ledger must therefore carry the assumption in its
    pre-ablation ``unverified`` state and the blocked path in ``blocked``."""
    proc = _run("--ablate", "auto_reopen", "--scenario", "INCR-001",
                "--keep", str(tmp_path), workdir=tmp_path)
    assert proc.returncode == 0, proc.stderr
    ablated_root = tmp_path / "INCR-001" / "abl_auto_reopen" / "mini-audit"
    ledger = json.loads((ablated_root / "search-ledger.json").read_text())
    assumptions = ledger.get("assumptions") or []
    matching = [a for a in assumptions
                if a.get("key") == "assumption:callers-pass-int-list"]
    assert matching, "fixture's blocker assumption is missing — fixture drifted?"
    assert matching[0]["status"] == "unverified", (
        f"expected assumption to stay unverified after ablation, "
        f"got {matching[0]['status']}"
    )
    bps = ledger.get("blocked_paths") or []
    matching_bp = [bp for bp in bps
                   if bp.get("key") == "blocked:query-needs-scalar"]
    assert matching_bp, "fixture's blocked path is missing — fixture drifted?"
    assert matching_bp[0]["status"] == "blocked", (
        f"expected blocked path to stay blocked after ablation, "
        f"got {matching_bp[0]['status']}"
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