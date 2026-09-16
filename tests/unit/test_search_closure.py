"""Capability closure and the L7 check (Phase D / §14, §15, §23).

The closure rule answers one question: *does the chain a confirmed finding
reports actually exist?* Two failure modes are being guarded against —
accepting a claim because it was written down, and rejecting a legacy audit for
a contract it never signed.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from runtime import attack_graph as ag
from runtime import search_closure as closure
from runtime.gates import SEARCH_GOVERNANCE_BUNDLE, run_semantic


def _node(node_id: str, node_type: str, name: str, *, status: str = "proposed",
          origin: str = "research") -> dict:
    return {"id": node_id, "key": f"k:{node_id}", "type": node_type, "name": name,
            "status": status, "origin": origin}


def _edge(edge_id: str, src: str, dst: str, relation: str, *, status: str = "verified",
          via: str | None = None, **extra) -> dict:
    edge = {"id": edge_id, "key": f"e:{edge_id}", "from": src, "to": dst,
            "relation": relation, "status": status}
    if via:
        edge["via_candidate"] = via
    edge.update(extra)
    return edge


def _graph(*, final_status: str = "verified") -> dict:
    return {
        "schema_version": 1, "generation": 1,
        "nodes": [
            _node("PRIN-001", "principal", "unauthenticated_remote_user",
                  status="verified", origin="objective"),
            _node("CAP-001", "capability", "send_http_request",
                  status="verified", origin="objective"),
            _node("CAP-002", "capability", "audit_log_write", status="verified"),
            _node("GOAL-001", "goal", "arbitrary_code_execution", status="verified"),
        ],
        "edges": [
            _edge("EDGE-001", "CAP-001", "CAP-002", "enables", status=final_status,
                  via="cand-031"),
            _edge("EDGE-002", "CAP-002", "GOAL-001", "enables", status="verified"),
        ],
    }


def _finding(refs: list[str] | None, *, verdict: str = "confirmed", finding_id: str = "F-001") -> dict:
    boundary = {"type": "privilege", "security_invariant": "i", "crossed": True}
    if refs is not None:
        boundary["capability_refs"] = refs
    return {
        "id": finding_id, "fingerprint": "v1:" + "a" * 64, "verdict": verdict,
        "class": "sqli", "title": "reported chain", "summary": "s" * 30,
        "source_ref": {"commit": "c", "tree_hash": "t"}, "trace": [{"kind": "sink"}],
        "boundary": boundary, "severity": {"overall": "high"},
        "verification": {"technical_verifier": "v"},
    }


def _bundle(*, findings: list[dict], graph: dict | None = None,
            candidates: dict | None = None, enabled: bool = True,
            failures: list[str] | None = None, base_dir: str | None = None) -> dict:
    return {
        "enabled": enabled,
        "objective": {"principal": "unauthenticated_remote_user"} if enabled else None,
        "graph": graph if graph is not None else (_graph() if enabled else None),
        "ledger": {"schema_version": 1, "generation": 1} if enabled else None,
        "coverage": None,
        "findings": findings,
        "candidates": candidates if candidates is not None else {"cand-031": ("p", {}, {})},
        "base_dir": base_dir,
        "failures": failures or [],
    }


def _check(bundle: dict) -> tuple[bool, str]:
    return run_semantic("reported_capability_paths_closed", bundle)


# ---------------------------------------------------------------------------
# The check, at the level of one confirmed finding
# ---------------------------------------------------------------------------


def test_a_valid_verified_path_passes() -> None:
    ok, message = _check(_bundle(findings=[_finding(["CAP-002"])]))
    assert ok is True, message


def test_a_confirmed_finding_without_refs_fails_when_enabled() -> None:
    ok, message = _check(_bundle(findings=[_finding(None)]))
    assert ok is False
    assert "no boundary.capability_refs" in message


def test_an_unknown_capability_ref_fails() -> None:
    ok, message = _check(_bundle(findings=[_finding(["CAP-999"])]))
    assert ok is False
    assert "exists in no attack graph node" in message


def test_an_unreachable_capability_fails() -> None:
    graph = _graph()
    graph["edges"] = [graph["edges"][1]]  # drop the enabling edge entirely
    ok, message = _check(_bundle(findings=[_finding(["CAP-002"])], graph=graph))
    assert ok is False
    assert "not reachable" in message


@pytest.mark.parametrize("status", ["proposed", "blocked", "refuted"])
def test_a_route_that_depends_on_an_unverified_edge_fails(status: str) -> None:
    """Only a verified edge may carry a reported chain, so the capability is
    simply unreachable — which is the right answer, not a technicality."""
    graph = _graph(final_status=status)
    ok, message = _check(_bundle(findings=[_finding(["CAP-002"])], graph=graph))
    assert ok is False
    assert "not reachable" in message


def test_a_reference_to_a_non_capability_node_fails() -> None:
    ok, message = _check(_bundle(findings=[_finding(["GOAL-001"])]))
    assert ok is False
    assert "not 'capability'" in message


def test_a_path_edge_citing_an_unknown_candidate_fails() -> None:
    ok, message = _check(_bundle(findings=[_finding(["CAP-002"])], candidates={}))
    assert ok is False
    assert "cand-031" in message and "no candidates" in message


def test_an_evidence_reference_that_resolves_to_no_file_fails(tmp_path: Path) -> None:
    graph = _graph()
    graph["edges"][0]["evidence_refs"] = ["evidence/missing.md"]
    ok, message = _check(_bundle(findings=[_finding(["CAP-002"])], graph=graph,
                                 base_dir=str(tmp_path)))
    assert ok is False
    assert "resolves to no file" in message


def test_an_evidence_reference_to_a_real_file_passes(tmp_path: Path) -> None:
    (tmp_path / "evidence").mkdir()
    (tmp_path / "evidence" / "exploit.log").write_text("proof\n", encoding="utf-8")
    graph = _graph()
    graph["edges"][0]["evidence_refs"] = ["evidence/exploit.log:12"]
    ok, message = _check(_bundle(findings=[_finding(["CAP-002"])], graph=graph,
                                 base_dir=str(tmp_path)))
    assert ok is True, message


def test_non_confirmed_findings_are_not_checked() -> None:
    ok, message = _check(_bundle(findings=[_finding(None, verdict="needs_validation"),
                                           _finding(None, verdict="rejected")]))
    assert ok is True, message


def test_a_legacy_audit_is_not_asked_for_refs() -> None:
    """§15: no objective and no graph means Search Governance was never
    enabled, so the closure contract does not apply."""
    ok, message = _check(_bundle(findings=[_finding(None)], enabled=False, graph=None))
    assert ok is True
    assert message == ""


def test_bundle_failures_are_folded_into_the_verdict() -> None:
    """A check that reasons from an invalid graph is reasoning from nothing."""
    ok, message = _check(_bundle(findings=[_finding(["CAP-002"])],
                                 failures=["search-ledger.json is at generation 4 but "
                                           "attack-graph.json is at 3"]))
    assert ok is False
    assert "generation" in message


def test_a_hardcoded_gate_injection_path_also_works(tmp_path: Path) -> None:
    """The runner builds the bundle from the workdir, so a caller that does not
    pre-seed still gets it — but pre-seeding must keep working."""
    from runtime.gates import build_search_governance_bundle

    audit = tmp_path / "mini-audit"
    audit.mkdir(parents=True)
    (audit / "audit-objective.json").write_text(json.dumps({
        "schema_version": 1, "revision": 1, "principal": "p",
        "initial_capabilities": ["x"], "target_capabilities": ["y"],
        "security_invariants": ["z"], "supersedes": []}), encoding="utf-8")
    (audit / "attack-graph.json").write_text(json.dumps({
        "schema_version": 1, "generation": 1,
        "nodes": [_node("PRIN-001", "principal", "p", status="verified", origin="objective")],
        "edges": []}), encoding="utf-8")
    (audit / "search-ledger.json").write_text(json.dumps({
        "schema_version": 1, "generation": 1, "facts": [], "assumptions": [],
        "open_questions": [], "blocked_paths": [], "intents": []}), encoding="utf-8")

    bundle = build_search_governance_bundle(tmp_path)
    assert bundle["enabled"] is True
    assert bundle["failures"] == []
    assert SEARCH_GOVERNANCE_BUNDLE == "search_governance"


def test_the_bundle_detects_a_corrupt_graph(tmp_path: Path) -> None:
    from runtime.gates import build_search_governance_bundle

    audit = tmp_path / "mini-audit"
    audit.mkdir(parents=True)
    (audit / "attack-graph.json").write_text("{not json", encoding="utf-8")
    bundle = build_search_governance_bundle(tmp_path)
    assert bundle["enabled"] is False  # the objective is absent too, so not enabled
    assert any("attack-graph.json" in f for f in bundle["failures"])


def test_the_bundle_detects_a_generation_mismatch(tmp_path: Path) -> None:
    from runtime.gates import build_search_governance_bundle

    audit = tmp_path / "mini-audit"
    audit.mkdir(parents=True)
    (audit / "audit-objective.json").write_text(json.dumps({
        "schema_version": 1, "revision": 1, "principal": "p",
        "initial_capabilities": ["x"], "target_capabilities": ["y"],
        "security_invariants": ["z"], "supersedes": []}), encoding="utf-8")
    (audit / "attack-graph.json").write_text(json.dumps({
        "schema_version": 1, "generation": 9,
        "nodes": [_node("PRIN-001", "principal", "p", status="verified", origin="objective")],
        "edges": []}), encoding="utf-8")
    (audit / "search-ledger.json").write_text(json.dumps({
        "schema_version": 1, "generation": 2, "facts": [], "assumptions": [],
        "open_questions": [], "blocked_paths": [], "intents": []}), encoding="utf-8")

    bundle = build_search_governance_bundle(tmp_path)
    assert bundle["enabled"] is True
    assert any("generation" in f for f in bundle["failures"]), bundle["failures"]


def test_module_level_evaluation_agrees_with_the_check() -> None:
    """One implementation, two callers — the governor's P0 rule 4 uses the same
    verdict the gate does."""
    result = closure.evaluate_closure(
        [_finding(["CAP-999"])], _graph(), {"cand-031": ("p", {}, {})}, enabled=True)
    assert result.closed is False
    assert result.checked_findings == 1
    assert result.checked_refs == 1
    assert _check(_bundle(findings=[_finding(["CAP-999"])]))[0] is False
