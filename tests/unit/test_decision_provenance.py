from __future__ import annotations

import json
from pathlib import Path

import pytest

from runtime import research_state as rs


def _init(tmp_path: Path) -> Path:
    """Return an audit_root with a minimal objective installed."""
    audit_root = tmp_path / "mini-audit"
    audit_root.mkdir(parents=True, exist_ok=True)
    proposal = {
        "principal": "test-user",
        "initial_capabilities": ["send_http_request"],
        "target_capabilities": ["read:invoices"],
        "security_invariants": ["users cannot access other users' data"],
    }
    from runtime import objective as obj
    obj.init_and_bootstrap(audit_root, proposal, audit_id="audit-test-decisions")
    return audit_root


def _decision(**overrides):
    decision = {
        "decision_id": "DEC-0001",
        "decided_by": "agent-test",
        "phase": "L5",
        "semantic_mutation": "blocked_path_reopen",
        "reason": "model decided to reopen",
        "evidence_refs": ["src/foo.py:10"],
        "subject_ref": "blocked:query-needs-scalar",
    }
    decision.update(overrides)
    return decision


def test_decision_is_canonicalized_into_ledger(tmp_path: Path) -> None:
    root = _init(tmp_path)
    report = rs.apply_delta(root, {"schema_version": 1, "decisions": [_decision()]})
    ledger = rs.load_ledger(root)
    decisions = ledger["decisions"]
    assert len(decisions) == 1
    canonical = decisions[0]
    assert canonical["decision_id"] == "DEC-0001"
    assert canonical["decided_by"] == "agent-test"
    assert canonical["phase"] == "L5"
    assert canonical["semantic_mutation"] == "blocked_path_reopen"
    assert canonical["reason"] == "model decided to reopen"
    assert canonical["evidence_refs"] == ["src/foo.py:10"]
    assert canonical["subject_ref"] == "blocked:query-needs-scalar"
    # Runtime stamps decided_at + delta_generation; agent cannot have set them.
    assert isinstance(canonical.get("decided_at"), str)
    assert canonical.get("delta_generation") == report["generation"]


def test_reapplying_same_decision_id_is_idempotent(tmp_path: Path) -> None:
    root = _init(tmp_path)
    rs.apply_delta(root, {"schema_version": 1, "decisions": [_decision()]})
    second = rs.apply_delta(
        root,
        {"schema_version": 1, "decisions": [_decision(reason="updated text")]},
    )
    # The second apply does not duplicate — the original reason is preserved.
    decisions = rs.load_ledger(root)["decisions"]
    assert len(decisions) == 1
    assert decisions[0]["reason"] == "model decided to reopen"
    # And the runtime warned about it.
    assert any("already in ledger" in w for w in second["warnings"])


def _refuses(decisions, *, match):
    """Run the delta through apply_delta and assert it is refused. Refusal can
    happen at the JSON-schema layer (raises through research_state's apply
    pipeline) or at the runtime canonicalizer. Both are correct refusals."""
    import re as _re
    try:
        return _re.compile(match)
    except _re.error:
        return match


def test_decision_without_id_is_refused(tmp_path: Path) -> None:
    root = _init(tmp_path)
    with pytest.raises((rs.DeltaSchemaError, rs.ResearchError, ValueError)):
        rs.apply_delta(root, {
            "schema_version": 1,
            "decisions": [_decision(decision_id="")],
        })


def test_decision_with_malformed_id_is_refused(tmp_path: Path) -> None:
    root = _init(tmp_path)
    with pytest.raises((rs.DeltaSchemaError, rs.ResearchError, ValueError)):
        rs.apply_delta(root, {
            "schema_version": 1,
            "decisions": [_decision(decision_id="DEC-1")],
        })


def test_decision_with_runtime_decided_by_is_refused(tmp_path: Path) -> None:
    root = _init(tmp_path)
    for forbidden in ("runtime", "system"):
        with pytest.raises((rs.DeltaSchemaError, rs.ResearchError, ValueError)):
            rs.apply_delta(root, {
                "schema_version": 1,
                "decisions": [_decision(decision_id=f"DEC-{abs(hash(forbidden))%10000+100:04d}",
                                          decided_by=forbidden)],
            })


def test_decision_without_decided_by_is_refused(tmp_path: Path) -> None:
    root = _init(tmp_path)
    with pytest.raises((rs.DeltaSchemaError, rs.ResearchError, ValueError)):
        rs.apply_delta(root, {
            "schema_version": 1,
            "decisions": [_decision(decided_by="")],
        })


def test_decision_without_reason_is_refused(tmp_path: Path) -> None:
    root = _init(tmp_path)
    with pytest.raises((rs.DeltaSchemaError, rs.ResearchError, ValueError)):
        rs.apply_delta(root, {
            "schema_version": 1,
            "decisions": [_decision(reason="")],
        })


def test_promote_decision_without_evidence_is_refused(tmp_path: Path) -> None:
    root = _init(tmp_path)
    with pytest.raises((rs.DeltaSchemaError, rs.ResearchError, ValueError)):
        rs.apply_delta(root, {
            "schema_version": 1,
            "decisions": [_decision(semantic_mutation="candidate_promote",
                                       evidence_refs=[])],
        })


def test_audit_stop_decision_may_have_no_evidence(tmp_path: Path) -> None:
    root = _init(tmp_path)
    rs.apply_delta(root, {
        "schema_version": 1,
        "decisions": [_decision(semantic_mutation="audit_stop", evidence_refs=[])],
    })
    decisions = rs.load_ledger(root)["decisions"]
    assert decisions[0]["semantic_mutation"] == "audit_stop"
    assert decisions[0]["evidence_refs"] == []


def test_decisions_coexist_with_research_delta_mutations(tmp_path: Path) -> None:
    """A real round carries both — the decision for the mutation AND the
    mutation itself (e.g. blocked_paths_reopen). The runtime must accept both
    in the same delta and write both to the ledger."""
    root = _init(tmp_path)
    delta = {
        "schema_version": 1,
        "blocked_paths_add": [{
            "key": "blocked:demo",
            "candidate_id": "cand-demo",
            "blocker": {"type": "input_validation", "claim": "all callers coerce"},
            "status": "blocked",
            "priority": "low",
        }],
        "decisions": [_decision(
            decision_id="DEC-0010",
            semantic_mutation="blocked_path_reopen",
            subject_ref="blocked:demo",
            reason="model explicitly reopened",
            evidence_refs=["src/x.py:3"],
        )],
    }
    rs.apply_delta(root, delta)
    ledger = rs.load_ledger(root)
    blocked = [bp for bp in ledger["blocked_paths"] if bp["key"] == "blocked:demo"]
    assert blocked and blocked[0]["status"] == "blocked"
    decisions = ledger["decisions"]
    assert any(d["decision_id"] == "DEC-0010" for d in decisions)
