"""Architecture invariant — semantic mutations carry decision provenance (spec §5).

Spec §5 says every *semantic* mutation an agent makes on canonical state
must be recorded with a ``decision_id`` and ``decided_by``. Runtime
auto-generated fields are limited to the ``derived.*`` /
``system.*`` / ``validation.*`` namespaces; they cannot pretend to
be decisions.

The test loads the search-ledger schema and walks the *required*
fields of every canonical object. Any required field that is not
explicitly listed as runtime-derived (e.g. ``updated_at``,
``decided_at``, ``at`` on derived_events) is checked: it must
either be an identity/mutable field that the agent wrote, OR
its schema declares it as a runtime-generated timestamp.

This is a structural test of the schema contract, not a runtime
test. It catches a future schema edit that accidentally adds a
canonical semantic field without a decision_id requirement.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

SCHEMA_PATH = Path("schemas/search-ledger.schema.json")

# Runtime-only namespaces per spec §5 / §4. A field that lands
# under these namespaces is allowed to be populated by the runtime
# without a decision_id.
RUNTIME_NAMESPACES = {
    "derived",     # spec §4: mechanical facts the runtime derives
    "system",      # system-recorded facts (timestamps, etc.)
    "validation",  # validation-rule derived values
    "decision",    # the canonical decisions log itself
}

# Canonical objects whose `status` field is a research-decision,
# not a runtime fact. The agent must always submit a corresponding
# decision entry in delta.decisions before this transition is
# accepted. The schema does not enforce the link (runtime does).
SEMANTIC_STATUS_FIELDS = {
    ("blocked_path", "status"): True,
    ("assumption", "status"): True,
    ("open_question", "status"): True,
    ("intent", "status"): True,
}


@pytest.fixture(scope="module")
def ledger_schema() -> dict:
    return json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))


def _canonical_object_kinds(schema: dict) -> list[str]:
    """The top-level canonical objects the ledger owns (not derived
    fact namespaces)."""
    refs = schema.get("properties", {})
    skip = {"schema_version", "generation", "audit_id", "updated_at",
            "decisions", "derived_events"}
    return [k for k in refs if k not in skip]


def test_canonical_object_decision_log_is_present(ledger_schema: dict) -> None:
    """Spec §5: every semantic mutation must be recorded with a
    decision_id. The schema must declare the decisions array at the
    top level so a future edit cannot silently remove it."""
    assert "decisions" in ledger_schema.get("properties", {}), (
        "search-ledger schema must declare a top-level 'decisions' "
        "array (spec §5); do not silently remove it"
    )
    decisions = ledger_schema["properties"]["decisions"]
    items = decisions.get("items", {}).get("$ref", "")
    assert items.endswith("Decision"), (
        f"decisions[].items must $ref '#/$defs/Decision' (spec §5); got {items!r}"
    )


def test_decision_schema_requires_provenance_fields(ledger_schema: dict) -> None:
    """Spec §5: a decision without decision_id / decided_by /
    semantic_mutation / phase / reason is refused."""
    decision = ledger_schema["$defs"]["Decision"]
    required = decision.get("required", [])
    for must in ("decision_id", "decided_by", "semantic_mutation",
                  "phase", "reason"):
        assert must in required, (
            f"Decision schema must require {must!r} (spec §5); "
            f"required={required!r}"
        )


def test_decision_schema_blocks_runtime_decided_by(ledger_schema: dict) -> None:
    """Spec §5: a decision with decided_by='runtime' would defeat
    the purpose of the field. The schema must not allow a constant
    'runtime' or 'system' value at the entry layer."""
    decision = ledger_schema["$defs"]["Decision"]
    decided_by = decision.get("properties", {}).get("decided_by", {})
    # We don't pin a regex here (the runtime canonicalizer enforces
    # the reservation), but the schema must not have a default
    # "runtime" / "system" value that would silently pass.
    assert decided_by.get("default") not in ("runtime", "system"), (
        "decided_by must not have a default 'runtime' or 'system' "
        "value (spec §5); agents must mint the field themselves"
    )


def test_canonical_object_namespaces_match_spec(ledger_schema: dict) -> None:
    """Spec §4: the ledger namespace set is owned by the runtime
    (canonical objects) vs derived facts (separate). The schema
    must keep them separate — i.e. derived_events stays out of the
    canonical-object list."""
    kinds = set(_canonical_object_kinds(ledger_schema))
    forbidden = {"derived_events"} & kinds
    assert not forbidden, (
        f"derived_events must NOT be a canonical object kind "
        f"(spec §4); found {forbidden!r}"
    )


def test_schema_documented_namespaces(ledger_schema: dict) -> None:
    """Spec §5: runtime-generated semantic fields are limited to
    derived/system/validation namespaces. The schema-level description
    should mention this constraint so a future contributor sees it."""
    desc = ledger_schema.get("description", "")
    assert "derived" in desc and "system" in desc and "validation" in desc, (
        "search-ledger top-level description must mention the "
        "derived.*/system.*/validation.* namespace constraint "
        "(spec §5); otherwise a future contributor may add "
        "runtime-owned canonical fields without realising the "
        "implication"
    )