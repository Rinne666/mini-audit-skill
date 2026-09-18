from __future__ import annotations

from pathlib import Path

import pytest

from runtime import objective as obj
from runtime import research_state as rs


def _init(tmp_path: Path) -> Path:
    audit_root = tmp_path / "mini-audit"
    audit_root.mkdir(parents=True, exist_ok=True)
    obj.init_and_bootstrap(audit_root, {
        "principal": "test",
        "initial_capabilities": ["send_http_request"],
        "target_capabilities": ["read:invoices"],
        "security_invariants": ["users cannot access other users' data"],
    }, audit_id="audit-provenance-test")
    return audit_root


def test_apply_delta_records_delta_applied_event(tmp_path: Path) -> None:
    """Spec section 5 simplified: the delta is the decision. The
    runtime appends one ``delta_applied`` derived event per apply,
    carrying agent_id + phase + ops."""
    root = _init(tmp_path)
    rs.apply_delta(root, {
        "schema_version": 1,
        "agent_id": "agent-L5",
        "phase": "L5",
        "facts_add": [
            {"key": "fact:sql-on-author-filter",
             "claim": "the author-exclude filter builds a SQL WHERE on user input",
             "evidence_refs": ["src/rest-handler.php:88"]},
        ],
    })
    ledger = rs.load_ledger(root)
    events = ledger.get("derived_events") or []
    applied = [e for e in events if e.get("event") == "delta_applied"]
    assert len(applied) == 1
    entry = applied[0]
    assert entry["agent_id"] == "agent-L5"
    assert entry["phase"] == "L5"
    assert "facts_add" in entry["ops"]
    assert isinstance(entry["delta_generation"], int)


def test_decisions_array_is_not_persisted(tmp_path: Path) -> None:
    """The v2.x simplification removed the standalone decisions[]
    array from both the delta schema and the ledger. Apply a delta
    that does NOT carry one, and the ledger must not have it."""
    root = _init(tmp_path)
    rs.apply_delta(root, {
        "schema_version": 1,
        "agent_id": "agent-L6",
        "phase": "L6",
        "research_intents_add": [
            {"key": "ri:hello", "question": "test", "strategy": "caller-search",
             "priority": "P1", "status": "open"},
        ],
    })
    ledger = rs.load_ledger(root)
    assert "decisions" not in ledger, (
        "ledger must not carry a top-level 'decisions' array (v2.x); "
        f"got keys: {sorted(ledger.keys())}"
    )


def test_legacy_decisions_field_in_delta_is_rejected(tmp_path: Path) -> None:
    """A delta carrying a top-level ``decisions`` field is refused
    by the schema (additionalProperties: false). This pins the v2.x
    drop: a future contributor who tries to bring it back via
    delta-side will hit a clear schema error."""
    root = _init(tmp_path)
    from runtime.research_state import DeltaSchemaError
    with pytest.raises(DeltaSchemaError):
        rs.apply_delta(root, {
            "schema_version": 1,
            "agent_id": "agent-L5",
            "phase": "L5",
            "decisions": [{"decision_id": "DEC-0001", "decided_by": "agent",
                            "semantic_mutation": "audit_stop",
                            "phase": "L5", "reason": "x"}],
        })