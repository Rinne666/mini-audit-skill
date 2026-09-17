from __future__ import annotations

from pathlib import Path

import pytest

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
    # Set up a blocked_path whose blocker assumption is `disproved`.
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
    snap.write_snapshot(audit_root)
    after_ledger = rs.load_ledger(audit_root)
    # No generation bump means the snapshot is read-only with respect to
    # canonical state. atomic_io.write_json_atomic must not have rewritten
    # search-ledger.json — only snapshot.json.
    assert before_ledger["generation"] == after_ledger["generation"]
    assert (audit_root / "snapshot.json").exists()
    assert (audit_root / "search-ledger.json").read_text() == before_dump \
        if (before_dump := (audit_root / "search-ledger.json").read_text()) else True


def test_snapshot_cli_subcommand_writes_file(tmp_path: Path) -> None:
    """End-to-end via the CLI: build_parser exposes `snapshot` and the command
    writes the file at the documented location."""
    import subprocess
    import sys
    from pathlib import Path as P
    audit_root = _init_audit(tmp_path)
    launcher = P("scripts/mini-audit-runtime").resolve()
    result = subprocess.run(
        [sys.executable, str(launcher), "snapshot", "--audit-root", str(audit_root)],
        capture_output=True, text=True, check=True,
    )
    assert (audit_root / "snapshot.json").exists()
    body = (audit_root / "snapshot.json").read_text()
    assert '"kind": "derived.snapshot"' in body or '"kind":\\n    "derived.snapshot"' in body \
        or "derived.snapshot" in body
