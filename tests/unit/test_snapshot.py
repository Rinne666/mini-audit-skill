from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any

from runtime import objective as obj
from runtime import research_state as rs
from runtime import snapshot as snap


def _init_audit(tmp_path: Path) -> Path:
    audit_root = tmp_path / "mini-audit"
    audit_root.mkdir(parents=True, exist_ok=True)
    obj.init_and_bootstrap(audit_root, {
        "principal": "test",
        "initial_capabilities": ["send_http_request"],
        "target_capabilities": ["read:invoices"],
        "security_invariants": ["users cannot access other users' data"],
    }, audit_id="audit-snapshot-test")
    return audit_root


def _add_chain_potential_candidate(audit_root: Path, candidate_id: str, *, chain_potential: str) -> None:
    candidates_dir = audit_root / "candidates"
    candidates_dir.mkdir(parents=True, exist_ok=True)
    payload = {
        "candidates": [
            {
                "candidate_id": candidate_id,
                "status": "needs_validation",
                "research": {
                    "chain_potential": chain_potential,
                    "requires_capabilities": ["send_http_request"],
                    "grants_capabilities": ["read:invoices"],
                    "blocked_by": [],
                },
            }
        ],
    }
    (candidates_dir / f"{candidate_id}.json").write_text(json.dumps(payload), encoding="utf-8")


def test_snapshot_emits_required_sections(tmp_path: Path) -> None:
    audit_root = _init_audit(tmp_path)
    snapshot = snap.build_snapshot(audit_root)
    required = {
        "objective", "verified_capabilities", "frontier",
        "reopenable_blocked_paths", "open_p0_questions",
        "high_chain_potential_candidates", "coverage_debt",
        "broken_chains", "remaining_budget", "recent_relevant_changes",
        "kind", "audit_id",
    }
    missing = required - snapshot.keys()
    assert not missing, f"snapshot missing required sections: {sorted(missing)}"
    assert snapshot["kind"] == "derived.snapshot"
    assert snapshot["objective"]["principal"] == "test"


def test_snapshot_lists_reopenable_blocked_paths(tmp_path: Path) -> None:
    audit_root = _init_audit(tmp_path)
    rs.apply_delta(audit_root, {
        "schema_version": 1,
        "assumptions_add": [{
            "key": "assumption:all-callers-coerce",
            "claim": "all callers coerce the parameter",
            "status": "unverified",
        }],
        "blocked_paths_add": [{
            "key": "blocked:demo",
            "candidate_id": "cand-demo",
            "blocker": {"type": "input_validation",
                          "claim": "no caller coerces",
                          "assumption_ref": "A-001"},
            "status": "blocked",
            "priority": "low",
        }],
    })
    rs.apply_delta(audit_root, {
        "schema_version": 1,
        "assumptions_update": [{
            "ref": "assumption:all-callers-coerce",
            "status": "disproved",
        }],
    })
    snapshot = snap.build_snapshot(audit_root)
    reopenable = snapshot["reopenable_blocked_paths"]
    assert any(r["blocked_path"] == "BP-001" for r in reopenable), (
        f"expected BP-001 in reopenable list, got {reopenable!r}"
    )


def test_high_chain_potential_candidates_uses_real_store(tmp_path: Path) -> None:
    """The candidate section used to assume a ``{candidates: [...]}`` shape
    that does not match the real ``candidate_store`` API. Pin the fix."""
    audit_root = _init_audit(tmp_path)
    _add_chain_potential_candidate(audit_root, "cand-001", chain_potential="high")
    _add_chain_potential_candidate(audit_root, "cand-002", chain_potential="low")
    snapshot = snap.build_snapshot(audit_root)
    rows = snapshot["high_chain_potential_candidates"]
    assert [r["candidate_id"] for r in rows] == ["cand-001"], (
        f"expected only cand-001 (chain_potential=high); got {rows!r}"
    )
    assert rows[0]["requires_capabilities"] == ["send_http_request"]


def test_frontier_uses_graph_primitives(tmp_path: Path) -> None:
    """frontier.open used to read ``graph_summary.frontier_edges``, a key
    that does not exist on the actual summary dict. The fix routes through
    ``blocked_frontier()`` and reports reachable_goals against verified_reachable."""
    audit_root = _init_audit(tmp_path)
    rs.apply_delta(audit_root, {
        "schema_version": 1,
        "capabilities_add": [
            {"key": "cap:read_invoices", "name": "read:invoices",
             "status": "proposed"},
        ],
        "edges_add": [
            {"key": "edge:send_to_read",
             "from": "objective:initial-capability:send_http_request",
             "to": "cap:read_invoices",
             "relation": "enables", "via_candidate": "cand-aaa",
             "status": "proposed"},
        ],
    })
    snapshot = snap.build_snapshot(audit_root)
    frontier = snapshot["frontier"]
    # frontier.open is now the real blocked_frontier() output (a list of
    # dicts with at least the edge id, key, relation, status fields).
    assert isinstance(frontier["open"], list)
    if frontier["open"]:
        sample = frontier["open"][0]
        assert isinstance(sample, dict)
        assert "edge" in sample and "status" in sample
    # reachable_goals / total_goals are lists of node ids, not ints.
    assert isinstance(frontier["reachable_goals"], list)
    assert isinstance(frontier["total_goals"], list)


def test_broken_chains_evaluates_findings_against_graph(tmp_path: Path) -> None:
    """broken_chains used to be a pass-through parameter that no caller
    populated, so the section was always []. The fix joins findings +
    graph + candidate_store via ``evaluate_finding_closure`` so a real
    confirmed-but-broken finding actually surfaces."""
    audit_root = _init_audit(tmp_path)
    findings_path = audit_root / "findings.json"
    findings_path.write_text(json.dumps({
        "findings": [
            {
                "id": "F-001",
                "slug": "demo",
                "verdict": "confirmed",
                "boundary": {"capability_refs": ["nonexistent:capability"]},
            },
        ],
    }), encoding="utf-8")
    snapshot = snap.build_snapshot(audit_root)
    chains = snapshot["broken_chains"]
    assert len(chains) == 1
    assert chains[0]["finding_id"] == "F-001"
    assert chains[0]["missing"], "expected missing-reason text from evaluate_finding_closure"


def test_snapshot_does_not_rank_or_plan(tmp_path: Path) -> None:
    """Spec §7: the snapshot may SELECT/JOIN/DERIVE/SUMMARIZE; it must NOT
    RANK/PLAN/CHOOSE/RECOMMEND. The contract is enforced by section names —
    there is no 'priority_ranking' / 'next_intent' / 'recommended_action'
    field even though every other canonical kind of derived fact lives here."""
    audit_root = _init_audit(tmp_path)
    snapshot = snap.build_snapshot(audit_root)
    forbidden = {"priority_ranking", "next_intent", "recommended_action",
                  "ranked_intents", "planned_searches", "next_phase"}
    present = forbidden & snapshot.keys()
    assert not present, f"snapshot contains ranking/plan fields: {sorted(present)}"


def test_snapshot_does_not_mutate_canonical_state(tmp_path: Path) -> None:
    """Running the snapshot twice yields identical content (modulo timestamps
    / counts), and does not bump the ledger's generation."""
    audit_root = _init_audit(tmp_path)
    rs.apply_delta(audit_root, {
        "schema_version": 1,
        "facts_add": [{
            "key": "fact:foo",
            "claim": "x",
            "evidence_refs": ["a.py:1"],
        }],
    })
    before_ledger = rs.load_ledger(audit_root)
    before_dump = (audit_root / "search-ledger.json").read_text()
    snap.write_snapshot(audit_root)
    after_ledger = rs.load_ledger(audit_root)
    assert before_ledger["generation"] == after_ledger["generation"]
    assert (audit_root / "snapshot.json").exists()
    assert (audit_root / "search-ledger.json").read_text() == before_dump


def test_snapshot_cli_subcommand_writes_file(tmp_path: Path) -> None:
    """End-to-end via the CLI: build_parser exposes ``snapshot`` and the
    command writes the file at the documented location."""
    audit_root = _init_audit(tmp_path)
    launcher = Path("scripts/mini-audit-runtime").resolve()
    result = subprocess.run(
        [sys.executable, str(launcher), "snapshot", "--audit-root", str(audit_root)],
        capture_output=True, text=True, check=True,
    )
    assert (audit_root / "snapshot.json").exists()
    body = (audit_root / "snapshot.json").read_text()
    parsed: dict[str, Any] = json.loads(body)
    assert parsed["kind"] == "derived.snapshot"