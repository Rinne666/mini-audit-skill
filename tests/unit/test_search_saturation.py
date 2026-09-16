"""Search saturation hard gate and signals (Phase D / §16, §17, §23).

The point of the hard gate is that it cannot be satisfied by relabelling. The
cases below are mostly adversarial: each one is a way an agent could try to
declare itself finished, and each one has to fail for a concrete reason.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from runtime import search_saturation as saturation
from runtime.gates import run_semantic


def _ledger(**overrides) -> dict:
    document = {"schema_version": 1, "generation": 1, "facts": [], "assumptions": [],
                "open_questions": [], "blocked_paths": [], "intents": []}
    document.update(overrides)
    return document


def _coverage(*, complete: bool = True, statuses: tuple[str, ...] = ("covered",)) -> dict:
    return {
        "schema_version": 1, "audit_id": "a",
        "planning_status": "complete" if complete else "in_progress",
        "units": [{"id": f"app|db|class{n}", "subsystem": "app", "boundary": "db",
                   "attack_class": f"class{n}", "status": status}
                  for n, status in enumerate(statuses)],
    }


def _question(**overrides) -> dict:
    question = {"id": "OQ-001", "key": "oq:x", "question": "is it reachable?",
                "priority": "P0", "status": "open"}
    question.update(overrides)
    return question


def _evaluate(ledger: dict | None = None, coverage: dict | None = None, *,
              base_dir: Path | None = None) -> dict:
    return saturation.evaluate(
        ledger=ledger if ledger is not None else _ledger(),
        graph=None,
        coverage=coverage if coverage is not None else _coverage(),
        candidates={},
        base_dir=base_dir,
    )


def _failures(document: dict) -> str:
    return " | ".join(document["hard_gate"]["failures"])


# ---------------------------------------------------------------------------
# Coverage
# ---------------------------------------------------------------------------


def test_a_complete_covered_ledger_passes() -> None:
    document = _evaluate()
    assert document["hard_gate"]["passed"] is True, _failures(document)
    assert document["hard_gate"]["coverage_unresolved"] == 0


def test_a_planned_unit_blocks() -> None:
    document = _evaluate(coverage=_coverage(statuses=("covered", "planned")))
    assert document["hard_gate"]["passed"] is False
    assert document["hard_gate"]["coverage_unresolved"] == 1


def test_a_missing_coverage_ledger_blocks() -> None:
    document = saturation.evaluate(ledger=_ledger(), graph=None, coverage=None, candidates={})
    assert document["hard_gate"]["passed"] is False
    assert "coverage-ledger.json is missing" in _failures(document)


def test_incomplete_planning_blocks() -> None:
    document = _evaluate(coverage=_coverage(complete=False))
    assert document["hard_gate"]["passed"] is False


# ---------------------------------------------------------------------------
# P0 questions — every terminal state must carry evidence
# ---------------------------------------------------------------------------


def test_an_open_p0_question_blocks() -> None:
    document = _evaluate(_ledger(open_questions=[_question()]))
    assert document["hard_gate"]["passed"] is False
    assert document["hard_gate"]["p0_open"] == 1


def test_a_non_p0_open_question_does_not_block() -> None:
    document = _evaluate(_ledger(open_questions=[_question(id="OQ-002", priority="P1")]))
    assert document["hard_gate"]["passed"] is True, _failures(document)
    assert document["signals"]["p1_open"] == 1


@pytest.mark.parametrize("status", ["resolved", "refuted"])
def test_a_resolution_without_evidence_blocks(status: str) -> None:
    document = _evaluate(_ledger(open_questions=[_question(status=status, reason="because")]))
    assert document["hard_gate"]["passed"] is False
    assert "no evidence_refs" in _failures(document)


@pytest.mark.parametrize("status", ["resolved", "refuted"])
def test_a_resolution_without_a_reason_blocks(status: str) -> None:
    document = _evaluate(_ledger(open_questions=[
        _question(status=status, evidence_refs=["evidence/a.md"])]))
    assert document["hard_gate"]["passed"] is False
    assert "no reason" in _failures(document)


def test_a_resolution_citing_a_missing_file_blocks(tmp_path: Path) -> None:
    document = _evaluate(
        _ledger(open_questions=[_question(status="resolved", reason="r",
                                          evidence_refs=["evidence/missing.md"])]),
        base_dir=tmp_path)
    assert document["hard_gate"]["passed"] is False
    assert "resolves to no file" in _failures(document)


def test_a_resolution_citing_a_real_file_passes(tmp_path: Path) -> None:
    (tmp_path / "evidence").mkdir()
    (tmp_path / "evidence" / "proof.md").write_text("traced at src/a.py:12\n", encoding="utf-8")
    document = _evaluate(
        _ledger(open_questions=[_question(status="resolved", reason="traced",
                                          evidence_refs=["evidence/proof.md:3"])]),
        base_dir=tmp_path)
    assert document["hard_gate"]["passed"] is True, _failures(document)
    assert document["signals"]["p0_resolved"] == 1


def test_a_deferral_without_a_reopen_condition_blocks() -> None:
    document = _evaluate(_ledger(open_questions=[
        _question(status="deferred", reason="waiting",
                  attempt_refs=["agents/a/scratch/probe.md"])]))
    assert document["hard_gate"]["passed"] is False
    assert "no reopen_if" in _failures(document)


def test_a_deferral_without_any_attempt_blocks() -> None:
    """Nothing records that the question was ever investigated."""
    document = _evaluate(_ledger(open_questions=[
        _question(status="deferred", reason="nothing found", reopen_if=["new information"])]))
    assert document["hard_gate"]["passed"] is False
    assert "neither attempt_refs nor a blocked_path_ref" in _failures(document)


def test_a_deferral_on_a_standing_blocker_passes(tmp_path: Path) -> None:
    from runtime import research_state as rs

    ledger = _ledger(
        open_questions=[_question(status="deferred", reason="blocked upstream",
                                  reopen_if=["A-001 is disproved"],
                                  blocked_path_ref="BP-001")],
        assumptions=[{"id": "A-001", "key": "assumption:x", "claim": "callers pass arrays",
                      "status": "supported"}],
        blocked_paths=[{"id": "BP-001", "key": "bp:1", "candidate_id": "cand-031",
                        "blocker": {"type": "input_validation", "claim": "arrays only",
                                    "assumption_ref": "A-001"},
                        "status": "blocked", "priority": "high"}],
    )
    assert rs.validate_ledger(ledger) == []
    document = _evaluate(ledger, base_dir=tmp_path)
    assert document["hard_gate"]["passed"] is True, _failures(document)
    assert document["signals"]["p0_deferred"] == 1


def test_a_deferral_on_a_disproved_assumption_blocks() -> None:
    """A blocker whose assumption has been disproved is not standing."""
    ledger = _ledger(
        open_questions=[_question(status="deferred", reason="blocked upstream",
                                  reopen_if=["x"], blocked_path_ref="BP-001")],
        assumptions=[{"id": "A-001", "key": "assumption:x", "claim": "callers pass arrays",
                      "status": "disproved"}],
        blocked_paths=[{"id": "BP-001", "key": "bp:1", "candidate_id": "cand-031",
                        "blocker": {"type": "input_validation", "claim": "arrays only",
                                    "assumption_ref": "A-001"},
                        "status": "blocked", "priority": "high"}],
    )
    document = _evaluate(ledger)
    assert document["hard_gate"]["passed"] is False
    assert "not 'supported'" in _failures(document)


@pytest.mark.parametrize("path_status", ["reopened", "closed"])
def test_a_deferral_on_an_actionable_path_blocks(path_status: str) -> None:
    """A reopened path is the opposite of a reason to wait."""
    ledger = _ledger(
        open_questions=[_question(status="deferred", reason="r", reopen_if=["x"],
                                  blocked_path_ref="BP-001")],
        blocked_paths=[{"id": "BP-001", "key": "bp:1", "candidate_id": "cand-031",
                        "blocker": {"type": "input_validation", "claim": "c"},
                        "status": path_status, "priority": "high"}],
    )
    document = _evaluate(ledger)
    assert document["hard_gate"]["passed"] is False
    assert "actionable" in _failures(document)


def test_a_deferral_citing_an_unknown_path_blocks() -> None:
    document = _evaluate(_ledger(open_questions=[
        _question(status="deferred", reason="r", reopen_if=["x"],
                  blocked_path_ref="BP-404")]))
    assert document["hard_gate"]["passed"] is False
    assert "no blocked path" in _failures(document)


# ---------------------------------------------------------------------------
# Soft signals, terminology and the report
# ---------------------------------------------------------------------------


def test_soft_signals_are_reported_without_blocking() -> None:
    ledger = _ledger(
        assumptions=[{"id": "A-001", "key": "assumption:x", "claim": "c",
                      "status": "unverified"}],
        blocked_paths=[{"id": "BP-001", "key": "bp:1", "candidate_id": "cand-031",
                        "blocker": {"type": "input_validation", "claim": "c"},
                        "status": "blocked", "priority": "high"}],
        open_questions=[_question(status="deferred", reason="r", reopen_if=["x"],
                                  blocked_path_ref="BP-001")],
    )
    candidates = {"cand-031": (Path("p"), {}, {"candidate_id": "cand-031",
                                              "research": {"chain_potential": "high"}})}
    document = saturation.evaluate(ledger=ledger, graph=None, coverage=_coverage(),
                                   candidates=candidates)
    # A blocker with no associated assumption cannot be invalidated, so
    # deferring on it is legitimate: the gate passes while the signals below
    # still describe the outstanding work.
    assert document["hard_gate"]["passed"] is True, _failures(document)
    signals = document["signals"]
    assert signals["unverified_assumptions"] == 1
    assert signals["high_priority_blocked_paths"] == 1
    assert signals["high_chain_candidates_open"] == 1
    assert signals["p0_deferred"] == 1


def test_a_passing_gate_does_not_claim_the_search_is_exhausted() -> None:
    document = _evaluate(_ledger(
        open_questions=[_question(status="resolved", reason="r", evidence_refs=["e"]),
                        _question(id="OQ-002", status="deferred", reason="r", reopen_if=["x"],
                                  attempt_refs=["t"])]),
        base_dir=None)
    # evidence refs are opaque without a base dir, so this one fails; the
    # terminology is asserted from a document that actually passes.
    passing = _evaluate(_ledger())
    assert passing["hard_gate"]["passed"] is True
    assert passing["verdict"] == saturation.VERDICT_MINIMUM_MET
    assert "exhaust" not in passing["verdict"]
    assert "floor, not a claim" in passing["verdict_means"]
    assert document["verdict"] == saturation.VERDICT_BLOCKED


def test_the_debt_summary_is_shown_even_when_the_gate_passes(tmp_path: Path) -> None:
    """18 deferred / 1 resolved must be visible, not smoothed into "done"."""
    (tmp_path / "attempts").mkdir()
    (tmp_path / "attempts" / "probe.md").write_text("caller search, no hit\n", encoding="utf-8")
    ledger = _ledger(open_questions=[
        _question(id=f"OQ-{n:03d}", status="deferred", reason="r", reopen_if=["x"],
                  attempt_refs=["attempts/probe.md"]) for n in range(1, 6)
    ])
    document = _evaluate(ledger, base_dir=tmp_path)
    assert document["hard_gate"]["passed"] is True, _failures(document)
    assert document["debt"]["p0_deferred"] == 5
    assert "5 deferred / 0 resolved" in document["debt"]["summary"]
    assert document["verdict"] == saturation.VERDICT_MINIMUM_MET


def test_the_report_is_written_and_matches_the_check(tmp_path: Path) -> None:
    from runtime import objective as objective_mod
    from runtime import research_state as rs

    root = tmp_path / "mini-audit"
    root.mkdir(parents=True)
    objective_mod.init_and_bootstrap(root, {
        "principal": "p", "initial_capabilities": ["x"], "target_capabilities": ["y"],
        "security_invariants": ["z"]})
    (root / "coverage-ledger.json").write_text(json.dumps(_coverage()), encoding="utf-8")

    document = saturation.report(root, workdir=tmp_path)
    written = json.loads((root / saturation.SATURATION_FILENAME).read_text(encoding="utf-8"))
    assert written["hard_gate"] == document["hard_gate"]
    assert written["hard_gate"]["passed"] is True, _failures(written)
    assert written["search_governance_enabled"] is True

    ok, message = run_semantic("search_saturation_hard_gate", {
        "enabled": True, "ledger": rs.load_ledger(root), "graph": None,
        "coverage": _coverage(), "candidates": {}, "base_dir": str(tmp_path), "failures": []})
    assert ok is True, message


def test_a_legacy_audit_passes_the_saturation_gate() -> None:
    ok, message = run_semantic("search_saturation_hard_gate", {"enabled": False})
    assert ok is True
    assert message == ""
