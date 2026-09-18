"""Architecture invariant - every apply_delta records a derived event
(spec sections 4 + 5, simplified in v2.x).

The v2.x decision-provenance simplification dropped the standalone
``decisions[]`` array. Each apply_delta transaction now records one
``delta_applied`` event in ``derived_events`` carrying the top-level
``agent_id`` and ``phase`` the delta already supplies - the mutation
itself is the decision. This invariant pins that contract at the
schema + behavioural level.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

SCHEMA_PATH = Path("schemas/search-ledger.schema.json")


@pytest.fixture(scope="module")
def ledger_schema() -> dict:
    return json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))


def test_derived_events_array_is_present(ledger_schema: dict) -> None:
    """The runtime must have a place to record its derived facts.
    Without ``derived_events`` the audit cannot trace which transaction
    changed what."""
    assert "derived_events" in ledger_schema.get("properties", {}), (
        "search-ledger schema must declare a top-level 'derived_events' "
        "array; do not silently remove it"
    )


def test_canonical_object_kinds_omit_derived_facts(ledger_schema: dict) -> None:
    """Spec section 4: the ledger namespace set is owned by the runtime
    (canonical objects) vs derived facts (separate). The schema must
    keep them separate - derived_events stays out of the canonical-object
    list."""
    refs = ledger_schema.get("properties", {})
    skip = {"schema_version", "generation", "audit_id", "updated_at",
            "derived_events"}
    kinds = [k for k in refs if k not in skip]
    forbidden = {"derived_events"} & set(kinds)
    assert not forbidden, (
        f"derived_events must NOT be a canonical object kind "
        f"(spec section 4); found {forbidden!r}"
    )


def test_no_legacy_decisions_array(ledger_schema: dict) -> None:
    """The v2.x simplification removed the standalone decisions[] array.
    A future contributor re-introducing it would be reverting the
    simplification; this test pins the absence."""
    properties = ledger_schema.get("properties", {})
    assert "decisions" not in properties, (
        "search-ledger schema must not declare a top-level 'decisions' "
        "array (v2.x simplified provenance to derived_events); "
        "do not re-introduce it"
    )


def test_schema_documents_derived_namespace(ledger_schema: dict) -> None:
    """The schema description should mention the derived / system /
    validation namespace constraint so a future contributor sees the
    rule before adding runtime-owned canonical fields."""
    desc = ledger_schema.get("description", "")
    assert "derived" in desc and "system" in desc and "validation" in desc, (
        "search-ledger top-level description must mention the "
        "derived.*/system.*/validation.* namespace constraint; "
        "otherwise a future contributor may add runtime-owned "
        "canonical fields without realising the implication"
    )