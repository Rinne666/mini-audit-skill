"""Tests for runtime/gates.py — phase gate runner."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from runtime.gates import (
    DEFAULT_PHASE_GATES,
    GateDefinition,
    GateError,
    GateRunner,
    SEMANTIC_CHECKS,
    check_exists,
    check_json_parseable,
    check_min_size,
    gate_for,
    run_semantic,
)


def test_check_exists(tmp_path: Path) -> None:
    target = tmp_path / "x.json"
    ok, msg = check_exists(str(target))
    assert not ok
    target.write_text("{}", encoding="utf-8")
    ok, msg = check_exists(str(target))
    assert ok and msg == ""


def test_check_min_size(tmp_path: Path) -> None:
    target = tmp_path / "x.json"
    target.write_text("ab", encoding="utf-8")
    ok, _ = check_min_size(str(target), min_bytes=5)
    assert not ok
    target.write_text("abcdef", encoding="utf-8")
    ok, _ = check_min_size(str(target), min_bytes=5)
    assert ok


def test_check_json_parseable(tmp_path: Path) -> None:
    target = tmp_path / "x.json"
    target.write_text("{not json", encoding="utf-8")
    ok, msg, data = check_json_parseable(str(target))
    assert not ok
    assert data is None

    target.write_text('{"a": 1}', encoding="utf-8")
    ok, _, data = check_json_parseable(str(target))
    assert ok
    assert data == {"a": 1}


def test_gate_definition_parse() -> None:
    raw = {
        "name": "L1",
        "required": [{"path": "x.json", "parse_json": True}],
        "semantic_checks": ["non_empty"],
    }
    g = GateDefinition.from_dict(raw)
    assert g.name == "L1"
    assert len(g.required) == 1


def test_gate_runner_happy(tmp_path: Path) -> None:
    (tmp_path / "data.json").write_text(json.dumps({"k": "v"}), encoding="utf-8")
    g = GateDefinition(name="t", required=[{"path": "data.json", "parse_json": True}])
    runner = GateRunner(workdir=tmp_path)
    result = runner.run(g)
    assert result.passed


def test_gate_runner_missing_file(tmp_path: Path) -> None:
    g = GateDefinition(name="t", required=[{"path": "missing.json", "parse_json": True}])
    runner = GateRunner(workdir=tmp_path)
    result = runner.run(g)
    assert not result.passed
    assert any(f.check == "existence" for f in result.failures)


def test_gate_runner_glob_match(tmp_path: Path) -> None:
    (tmp_path / "agents").mkdir()
    (tmp_path / "agents/a1.json").write_text("{}", encoding="utf-8")
    (tmp_path / "agents/a2.json").write_text("{}", encoding="utf-8")
    g = GateDefinition(name="t", required_glob=["agents/*.json"])
    runner = GateRunner(workdir=tmp_path)
    result = runner.run(g)
    assert result.passed


def test_gate_runner_glob_no_match(tmp_path: Path) -> None:
    g = GateDefinition(name="t", required_glob=["agents/*.json"])
    runner = GateRunner(workdir=tmp_path)
    result = runner.run(g)
    assert not result.passed
    assert any(f.check == "required_glob" for f in result.failures)


def test_semantic_check_every_chamber_closed() -> None:
    ok, msg = run_semantic("every_chamber_closed", {"chambers": [{"id": "c1", "debate_status": "closed"}]})
    assert ok, msg

    ok, msg = run_semantic("every_chamber_closed", {"chambers": [{"id": "c1", "debate_status": "open"}]})
    assert not ok


def test_semantic_check_every_valid_has_boundary_sentence() -> None:
    ok, _ = run_semantic("every_valid_candidate_has_boundary_sentence",
                          {"valid_candidates": [{"candidate_id": "c1", "boundary_sentence": "..."}]})
    assert ok
    ok, _ = run_semantic("every_valid_candidate_has_boundary_sentence",
                          {"valid_candidates": [{"candidate_id": "c1", "boundary_sentence": ""}]})
    assert not ok


def test_semantic_check_unknown_raises() -> None:
    ok, msg = run_semantic("totally_made_up", {})
    assert not ok
    assert "unknown" in msg


def test_default_gate_lookup() -> None:
    for phase in ["L1", "L2", "L3", "L4", "L5", "L6", "L6b", "L6c", "L7"]:
        g = gate_for(phase)
        assert g.name == phase


def test_gate_for_unknown_phase_raises() -> None:
    with pytest.raises(GateError):
        gate_for("Z9")


def test_semantic_coverage_no_planned() -> None:
    ok, _ = run_semantic("coverage_no_planned", {
        "planning_status": "complete",
        "units": [{"status": "covered"}, {"status": "blocked"}],
    })
    assert ok
    ok, _ = run_semantic("coverage_no_planned", {
        "planning_status": "complete",
        "units": [{"status": "planned"}],
    })
    assert not ok


def test_semantic_coverage_requires_planning_status() -> None:
    """v1.1.1: an absent planning_status is a failure, not a pass.

    The old check was `planning_status is not None and ... != complete`, so a
    ledger that simply omitted the field sailed through the final gate.
    """
    ok, reason = run_semantic("coverage_no_planned", {
        "units": [{"status": "covered"}],
    })
    assert not ok, "missing planning_status must fail"
    assert "planning_status" in reason or "planning is None" in reason

    ok, _ = run_semantic("coverage_no_planned", {
        "planning_status": "in_progress",
        "units": [{"status": "covered"}],
    })
    assert not ok


def test_semantic_every_confirmed_has_verifier() -> None:
    findings = {
        "findings": [
            {"verdict": "confirmed", "verification": {"technical_verifier": "v1"}},
            {"verdict": "rejected"},
        ]
    }
    ok, _ = run_semantic("every_confirmed_has_verifier", findings)
    assert ok

    findings_bad = {
        "findings": [
            {"verdict": "confirmed", "verification": {}},
        ]
    }
    ok, _ = run_semantic("every_confirmed_has_verifier", findings_bad)
    assert not ok