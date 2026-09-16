"""Hardening v1.1 §3 §4 §5 — artifact-bound semantic checks, glob JSON
aggregation, and real schema enforcement in gates."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from runtime.gates import (
    DEFAULT_PHASE_GATES,
    GateDefinition,
    GateRunner,
    gate_for,
)


def _write(path: Path, payload) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(payload, str):
        path.write_text(payload, encoding="utf-8")
    else:
        path.write_text(json.dumps(payload), encoding="utf-8")


def _finding(fp_id: str = "F-001", *, with_verifier: bool = True) -> dict:
    from runtime.fingerprint import compute_fingerprint

    f = {
        "id": fp_id,
        "verdict": "confirmed",
        "class": "idor",
        "title": "IDOR on invoice lookup",
        "summary": "An authenticated ordinary user can read other tenants' invoices.",
        "source_ref": {"commit": "abc123", "tree_hash": "t"},
        "boundary": {
            "type": "tenant_isolation",
            "security_invariant": "Tenant A cannot access Tenant B objects",
            "crossed": True,
        },
        "trace": [{"kind": "sink", "file": "x.py", "line": 1, "symbol": "findById"}],
        "severity": {"overall": "high"},
    }
    if with_verifier:
        f["verification"] = {"technical_verifier": "verify-1"}
    f["fingerprint"] = compute_fingerprint(f)
    return f


# ---------------------------------------------------------------------------
# §3 — semantic checks are bound to a declared artifact
# ---------------------------------------------------------------------------


def test_semantic_check_bound_to_declared_source(tmp_path: Path) -> None:
    """A failing declared source must fail the gate even if another artifact
    in the same gate would satisfy the check."""
    _write(tmp_path / "a" / "findings.json", {"findings": [_finding(with_verifier=False)]})  # bad
    _write(tmp_path / "b" / "findings.json", {"findings": [_finding()]})                     # good

    gate = GateDefinition(
        name="bound",
        required=[
            {"path": "a/findings.json", "parse_json": True},
            {"path": "b/findings.json", "parse_json": True},
        ],
        semantic_checks=[{"check": "every_confirmed_has_verifier", "source": "a/findings.json"}],
    )
    result = GateRunner(workdir=tmp_path).run(gate)
    assert not result.passed
    assert any(f.check == "semantic" and f.path == "a/findings.json" for f in result.failures)


def test_semantic_check_passes_on_declared_source(tmp_path: Path) -> None:
    _write(tmp_path / "a" / "findings.json", {"findings": [_finding()]})
    gate = GateDefinition(
        name="bound-ok",
        required=[{"path": "a/findings.json", "parse_json": True}],
        semantic_checks=[{"check": "every_confirmed_has_verifier", "source": "a/findings.json"}],
    )
    assert GateRunner(workdir=tmp_path).run(gate).passed


def test_declared_source_not_loaded_fails(tmp_path: Path) -> None:
    _write(tmp_path / "other.json", {"findings": [_finding()]})
    gate = GateDefinition(
        name="missing-src",
        required=[{"path": "other.json", "parse_json": True}],
        semantic_checks=[{"check": "every_confirmed_has_verifier", "source": "never-loaded.json"}],
    )
    result = GateRunner(workdir=tmp_path).run(gate)
    assert not result.passed
    assert any("no such artifact" in f.message for f in result.failures)


def test_unparseable_declared_source_fails(tmp_path: Path) -> None:
    _write(tmp_path / "broken.json", "{not json")
    gate = GateDefinition(
        name="broken",
        required=[{"path": "broken.json", "parse_json": True}],
        semantic_checks=[{"check": "non_empty", "source": "broken.json"}],
    )
    result = GateRunner(workdir=tmp_path).run(gate)
    assert not result.passed
    assert any(f.check == "parseability" for f in result.failures)


def test_unknown_semantic_check_fails(tmp_path: Path) -> None:
    _write(tmp_path / "x.json", {"a": 1})
    gate = GateDefinition(
        name="unknown",
        required=[{"path": "x.json", "parse_json": True}],
        semantic_checks=[{"check": "no_such_check", "source": "x.json"}],
    )
    result = GateRunner(workdir=tmp_path).run(gate)
    assert not result.passed
    assert any("unknown semantic check" in f.message for f in result.failures)


# ---------------------------------------------------------------------------
# §4 — glob artifacts: parse → aggregate → semantic validation
# ---------------------------------------------------------------------------


def _chamber(cid: str, *, closed: bool = True, with_boundary: bool = True,
             with_research: bool = True) -> dict:
    cand = {"candidate_id": f"cand-{cid}", "verdict": "VALID"}
    if with_boundary:
        cand["boundary_sentence"] = "an actor who could only read own rows can now read any row"
    if with_research:
        # Search Governance v1 (R2-2): the L6 gate, not the candidate schema,
        # requires an accepted candidate to declare its research value.
        cand["research"] = {"local_validity": "verified", "role": "chain_seed",
                            "chain_potential": "high"}
    return {
        "id": cid,
        "debate_status": "closed" if closed else "open",
        "valid_candidates": [cand],
    }


def test_l6_rejects_an_accepted_candidate_without_research(tmp_path: Path) -> None:
    """The schema keeps `research` optional; the chamber gate does not.

    A scanner-normalized 'untriaged' candidate is explicitly exempt, so the two
    halves of R2-2 are exercised together: permissive schema, strict gate.
    """
    _write(tmp_path / "mini-audit/chamber-workspace/c1/debate.json",
           _chamber("c1", with_research=False))
    result = GateRunner(workdir=tmp_path).run(gate_for("L6"))
    assert not result.passed
    assert any("research metadata" in f.message for f in result.failures), \
        [f.message for f in result.failures]


def test_glob_json_aggregated_and_semantically_validated(tmp_path: Path) -> None:
    _write(tmp_path / "mini-audit/chamber-workspace/c1/debate.json", _chamber("c1"))
    _write(tmp_path / "mini-audit/chamber-workspace/c2/debate.json", _chamber("c2"))
    gate = gate_for("L6")
    result = GateRunner(workdir=tmp_path).run(gate)
    assert result.passed, [f.message for f in result.failures]
    assert any("aggregated 2 file(s)" in n for n in result.notes)


def test_glob_aggregate_detects_open_chamber(tmp_path: Path) -> None:
    _write(tmp_path / "mini-audit/chamber-workspace/c1/debate.json", _chamber("c1"))
    _write(tmp_path / "mini-audit/chamber-workspace/c2/debate.json", _chamber("c2", closed=False))
    result = GateRunner(workdir=tmp_path).run(gate_for("L6"))
    assert not result.passed
    assert any("not closed" in f.message for f in result.failures)


def test_glob_aggregate_detects_missing_boundary_sentence(tmp_path: Path) -> None:
    _write(tmp_path / "mini-audit/chamber-workspace/c1/debate.json",
           _chamber("c1", with_boundary=False))
    result = GateRunner(workdir=tmp_path).run(gate_for("L6"))
    assert not result.passed
    assert any("boundary_sentence" in f.message for f in result.failures)


def test_glob_unparseable_member_fails(tmp_path: Path) -> None:
    _write(tmp_path / "mini-audit/chamber-workspace/c1/debate.json", _chamber("c1"))
    _write(tmp_path / "mini-audit/chamber-workspace/c2/debate.json", "{oops")
    result = GateRunner(workdir=tmp_path).run(gate_for("L6"))
    assert not result.passed
    assert any(f.check == "glob_parseability" for f in result.failures)


def test_glob_min_matches(tmp_path: Path) -> None:
    _write(tmp_path / "w/a.md", "x")
    gate = GateDefinition(name="g", required_glob=[
        {"pattern": "w/*.md", "min_matches": 2},
    ])
    result = GateRunner(workdir=tmp_path).run(gate)
    assert not result.passed
    assert any(f.check == "required_glob" for f in result.failures)

    _write(tmp_path / "w/b.md", "y")
    assert GateRunner(workdir=tmp_path).run(gate).passed


def test_glob_entry_missing_pattern_fails(tmp_path: Path) -> None:
    gate = GateDefinition(name="g", required_glob=[{"parse_json": True}])
    result = GateRunner(workdir=tmp_path).run(gate)
    assert not result.passed
    assert any("missing 'pattern'" in f.message for f in result.failures)


# ---------------------------------------------------------------------------
# §5 — schema enforcement inside gates
# ---------------------------------------------------------------------------


def test_required_entry_schema_enforced(tmp_path: Path) -> None:
    _write(tmp_path / "mini-audit/coverage-ledger.json", {
        "schema_version": 1,
        "audit_id": "a",
        "planning_status": "complete",
        "units": [{"id": "a|b|c", "subsystem": "a", "boundary": "b",
                   "attack_class": "c", "status": "nonsense"}],
    })
    gate = GateDefinition(name="cov", required=[
        {"path": "mini-audit/coverage-ledger.json", "parse_json": True, "schema": "coverage-ledger"},
    ])
    result = GateRunner(workdir=tmp_path).run(gate)
    assert not result.passed
    assert any(f.check == "schema" for f in result.failures)


def test_items_schema_enforced_on_each_finding(tmp_path: Path) -> None:
    bad = _finding()
    del bad["trace"]  # schema requires a non-empty trace
    _write(tmp_path / "mini-audit/findings.json", {"schema_version": 1, "audit_id": "a",
                                                  "findings": [bad]})
    gate = GateDefinition(name="f", required=[
        {"path": "mini-audit/findings.json", "parse_json": True,
         "items_key": "findings", "items_schema": "finding"},
    ])
    result = GateRunner(workdir=tmp_path).run(gate)
    assert not result.passed
    assert any(f.check == "schema" and "finding" in f.message for f in result.failures)


def test_items_schema_ok(tmp_path: Path) -> None:
    _write(tmp_path / "mini-audit/findings.json", {"schema_version": 1, "audit_id": "a",
                                                  "findings": [_finding()]})
    gate = GateDefinition(name="f", required=[
        {"path": "mini-audit/findings.json", "parse_json": True,
         "items_key": "findings", "items_schema": "finding"},
    ])
    assert GateRunner(workdir=tmp_path).run(gate).passed


def test_items_schema_declared_but_not_array_fails(tmp_path: Path) -> None:
    _write(tmp_path / "mini-audit/findings.json", {"findings": {"not": "a list"}})
    gate = GateDefinition(name="f", required=[
        {"path": "mini-audit/findings.json", "parse_json": True,
         "items_key": "findings", "items_schema": "finding"},
    ])
    result = GateRunner(workdir=tmp_path).run(gate)
    assert not result.passed
    assert any("not an array" in f.message for f in result.failures)


def test_no_placeholder_semantic(tmp_path: Path) -> None:
    _write(tmp_path / "report.json", {"summary": "TBD"})
    gate = GateDefinition(name="p", required=[{"path": "report.json", "parse_json": True}],
                          semantic_checks=[{"check": "no_placeholder_text", "source": "report.json"}])
    result = GateRunner(workdir=tmp_path).run(gate)
    assert not result.passed
    assert any("placeholder" in f.message for f in result.failures)


# ---------------------------------------------------------------------------
# The real L7 gate, end to end
# ---------------------------------------------------------------------------


def _valid_audit_state() -> dict:
    return {
        "schema_version": 1,
        "audit_id": "a",
        "mode": "balanced",
        "status": "in_progress",
        "source": {"root": "/repo", "commit": "abc", "tree_hash": "t"},
        "runtime": {"version": "1.1.0"},
        "phases": {
            "L1": {"name": "L1", "status": "complete"},
            "L7": {"name": "L7", "status": "in_progress"},
        },
        "started_at": "2026-01-01T00:00:00Z",
        "updated_at": "2026-01-01T00:00:00Z",
    }


def test_l7_gate_end_to_end(tmp_path: Path) -> None:
    _write(tmp_path / "mini-audit/findings.json",
           {"schema_version": 1, "audit_id": "a", "findings": [_finding()]})
    _write(tmp_path / "mini-audit/final-audit-report.md", "# report\n" + "content " * 30)
    _write(tmp_path / "mini-audit/coverage-ledger.json", {
        "schema_version": 1, "audit_id": "a", "planning_status": "complete",
        "units": [{"id": "a|b|c", "subsystem": "a", "boundary": "b",
                   "attack_class": "c", "status": "covered"}],
    })
    _write(tmp_path / "mini-audit/audit-state.json", _valid_audit_state())

    ctx = {"required_phases": ["L1"]}
    result = GateRunner(workdir=tmp_path).run(gate_for("L7"), ctx=ctx)
    assert result.passed, [f.message for f in result.failures]


def test_l7_gate_blocks_on_empty_coverage_plan(tmp_path: Path) -> None:
    """Hardening v1.1 §9 — an empty coverage plan must not pass the final gate."""
    _write(tmp_path / "mini-audit/findings.json",
           {"schema_version": 1, "audit_id": "a", "findings": []})
    _write(tmp_path / "mini-audit/final-audit-report.md", "# report\n" + "content " * 30)
    _write(tmp_path / "mini-audit/coverage-ledger.json", {
        "schema_version": 1, "audit_id": "a", "planning_status": "complete", "units": [],
    })
    _write(tmp_path / "mini-audit/audit-state.json", _valid_audit_state())

    result = GateRunner(workdir=tmp_path).run(gate_for("L7"), ctx={"required_phases": ["L1"]})
    assert not result.passed
    assert any("empty" in f.message for f in result.failures)


def test_l7_gate_blocks_on_planned_unit(tmp_path: Path) -> None:
    _write(tmp_path / "mini-audit/findings.json",
           {"schema_version": 1, "audit_id": "a", "findings": [_finding()]})
    _write(tmp_path / "mini-audit/final-audit-report.md", "# report\n" + "content " * 30)
    _write(tmp_path / "mini-audit/coverage-ledger.json", {
        "schema_version": 1, "audit_id": "a", "planning_status": "complete",
        "units": [{"id": "a|b|c", "subsystem": "a", "boundary": "b",
                   "attack_class": "c", "status": "planned"}],
    })
    _write(tmp_path / "mini-audit/audit-state.json", _valid_audit_state())
    result = GateRunner(workdir=tmp_path).run(gate_for("L7"), ctx={"required_phases": ["L1"]})
    assert not result.passed
    assert any("planned" in f.message for f in result.failures)


def test_l7_gate_blocks_on_non_terminal_phase(tmp_path: Path) -> None:
    _write(tmp_path / "mini-audit/findings.json",
           {"schema_version": 1, "audit_id": "a", "findings": [_finding()]})
    _write(tmp_path / "mini-audit/final-audit-report.md", "# report\n" + "content " * 30)
    _write(tmp_path / "mini-audit/coverage-ledger.json", {
        "schema_version": 1, "audit_id": "a", "planning_status": "complete",
        "units": [{"id": "a|b|c", "subsystem": "a", "boundary": "b",
                   "attack_class": "c", "status": "covered"}],
    })
    _write(tmp_path / "mini-audit/audit-state.json", _valid_audit_state())
    result = GateRunner(workdir=tmp_path).run(gate_for("L7"), ctx={"required_phases": ["L1", "L7"]})
    assert not result.passed
    assert any("non-terminal phases" in f.message for f in result.failures)


def test_l7_gate_blocks_on_missing_planning_status(tmp_path: Path) -> None:
    """v1.1.1: a coverage ledger that omits `planning_status` must not pass L7.

    `completeness_report()` was already strict, but the *gate* tolerated a
    missing field (`if planning_status is not None and ...`), so handing the
    runtime a ledger with no planning lifecycle recorded slipped past the
    final gate entirely.
    """
    _write(tmp_path / "mini-audit/findings.json",
           {"schema_version": 1, "audit_id": "a", "findings": [_finding()]})
    _write(tmp_path / "mini-audit/final-audit-report.md", "# report\n" + "content " * 30)
    _write(tmp_path / "mini-audit/coverage-ledger.json", {
        "schema_version": 1, "audit_id": "a",
        "units": [{"id": "a|b|c", "subsystem": "a", "boundary": "b",
                   "attack_class": "c", "status": "covered"}],
    })
    _write(tmp_path / "mini-audit/audit-state.json", _valid_audit_state())

    result = GateRunner(workdir=tmp_path).run(gate_for("L7"), ctx={"required_phases": ["L1"]})
    assert not result.passed
    checks = {f.check for f in result.failures}
    assert "schema" in checks, [f.message for f in result.failures]
    assert any("planning_status" in f.message for f in result.failures)


def test_gate_fails_closed_when_declared_schema_cannot_be_loaded(tmp_path: Path) -> None:
    """v1.1.1: a declared-but-unloadable schema must fail, not be skipped.

    Previously `load_schema_or_none` returned None and the runner merely added a
    note, which turned every declared schema into an advisory one.
    """
    _write(tmp_path / "artifact.json", {"anything": True})
    gate = GateDefinition.from_dict({
        "name": "X1",
        "required": [{"path": "artifact.json", "parse_json": True,
                      "schema": "definitely-not-a-real-schema"}],
    })
    result = GateRunner(workdir=tmp_path).run(gate)
    assert not result.passed
    assert any(f.check == "schema" and "could not be loaded" in f.message
               for f in result.failures), [f.message for f in result.failures]


def test_gate_fails_closed_when_items_schema_cannot_be_loaded(tmp_path: Path) -> None:
    _write(tmp_path / "findings.json", {"findings": [{"id": "x"}]})
    gate = GateDefinition.from_dict({
        "name": "X2",
        "required": [{"path": "findings.json", "parse_json": True,
                      "items_key": "findings", "items_schema": "nope-not-real"}],
    })
    result = GateRunner(workdir=tmp_path).run(gate)
    assert not result.passed
    assert any("could not be loaded" in f.message for f in result.failures)


def test_l7_gate_blocks_on_confirmed_without_verifier(tmp_path: Path) -> None:
    _write(tmp_path / "mini-audit/findings.json",
           {"schema_version": 1, "audit_id": "a", "findings": [_finding(with_verifier=False)]})
    _write(tmp_path / "mini-audit/final-audit-report.md", "# report\n" + "content " * 30)
    _write(tmp_path / "mini-audit/coverage-ledger.json", {
        "schema_version": 1, "audit_id": "a", "planning_status": "complete",
        "units": [{"id": "a|b|c", "subsystem": "a", "boundary": "b",
                   "attack_class": "c", "status": "covered"}],
    })
    _write(tmp_path / "mini-audit/audit-state.json", _valid_audit_state())
    result = GateRunner(workdir=tmp_path).run(gate_for("L7"), ctx={"required_phases": ["L1"]})
    assert not result.passed
    assert any("technical_verifier" in f.message for f in result.failures)


def test_all_default_gate_definitions_parse() -> None:
    for phase in DEFAULT_PHASE_GATES:
        gate = gate_for(phase)
        assert gate.name == phase
