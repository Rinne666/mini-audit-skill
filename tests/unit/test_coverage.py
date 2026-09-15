"""Tests for runtime/coverage.py — coverage ledger state machine."""
from __future__ import annotations

from pathlib import Path

import pytest

from runtime.coverage import (
    UNIT_BLOCKED,
    UNIT_CANDIDATE,
    UNIT_COVERED,
    UNIT_DEFERRED,
    UNIT_IN_PROGRESS,
    UNIT_OUT_OF_SCOPE,
    UNIT_PLANNED,
    CoverageLedger,
    CoverageLedgerError,
    make_unit_id,
)


def _ledger() -> CoverageLedger:
    ledger = CoverageLedger.empty(audit_id="t")
    ledger.add_unit(subsystem="billing", boundary="tenant-isolation", attack_class="idor")
    ledger.add_unit(subsystem="auth", boundary="session", attack_class="session_fixation")
    ledger.add_unit(subsystem="upload", boundary="mime", attack_class="malicious_file")
    return ledger


def test_unit_id_format() -> None:
    assert make_unit_id("a", "b", "c") == "a|b|c"


def test_add_unit_rejects_duplicate_id() -> None:
    ledger = CoverageLedger.empty(audit_id="t")
    ledger.add_unit(subsystem="billing", boundary="tenant-isolation", attack_class="idor")
    with pytest.raises(CoverageLedgerError):
        ledger.add_unit(subsystem="billing", boundary="tenant-isolation", attack_class="idor")


def test_transition_pending_to_in_progress_to_covered() -> None:
    ledger = _ledger()
    unit = ledger.get("billing|tenant-isolation|idor")
    assert unit.status == UNIT_PLANNED
    ledger.transition(unit.id, to=UNIT_IN_PROGRESS)
    ledger.transition(unit.id, to=UNIT_COVERED)
    assert ledger.get(unit.id).status == UNIT_COVERED


def test_blocked_requires_in_progress() -> None:
    ledger = _ledger()
    with pytest.raises(CoverageLedgerError):
        ledger.transition("billing|tenant-isolation|idor", to=UNIT_BLOCKED)


def test_record_check_attaches() -> None:
    ledger = _ledger()
    ledger.record_check("billing|tenant-isolation|idor",
                        check_id="ownership-check", agent_id="hunter-01", method="source")
    unit = ledger.get("billing|tenant-isolation|idor")
    assert len(unit.checks) == 1
    assert unit.checks[0].method == "source"


def test_attach_candidate_id() -> None:
    ledger = _ledger()
    ledger.attach_candidate("billing|tenant-isolation|idor", "cand-abc")
    ledger.attach_candidate("billing|tenant-isolation|idor", "cand-abc")  # idempotent
    unit = ledger.get("billing|tenant-isolation|idor")
    assert unit.candidate_ids == ["cand-abc"]


def test_histogram_counts_states() -> None:
    ledger = _ledger()
    ledger.transition("billing|tenant-isolation|idor", to=UNIT_IN_PROGRESS)
    ledger.transition("billing|tenant-isolation|idor", to=UNIT_COVERED)
    ledger.transition("auth|session|session_fixation", to=UNIT_OUT_OF_SCOPE)
    h = ledger.histogram()
    assert h[UNIT_COVERED] == 1
    assert h[UNIT_OUT_OF_SCOPE] == 1
    assert h[UNIT_PLANNED] == 1


def test_unresolved_units_blocks_completion() -> None:
    ledger = _ledger()
    assert ledger.has_unresolved_planned() is True
    ok, unresolved = ledger.audit_complete_ok()
    assert ok is False
    assert "upload|mime|malicious_file" in unresolved

    ledger.transition("upload|mime|malicious_file", to=UNIT_IN_PROGRESS)
    ledger.transition("upload|mime|malicious_file", to=UNIT_BLOCKED, gap="requires sandbox")
    assert ledger.has_unresolved_planned() is True  # blocked still unresolved? No, blocked is terminal.
    # blocked is a terminal state — it should NOT block completion (audit_complete_ok only flags planned/in_progress)
    # Actually audit_complete_ok only flags planned/in_progress, so blocked is acceptable.
    ledger.transition("billing|tenant-isolation|idor", to=UNIT_IN_PROGRESS)
    ledger.transition("billing|tenant-isolation|idor", to=UNIT_COVERED)
    ledger.transition("auth|session|session_fixation", to=UNIT_OUT_OF_SCOPE)
    ledger.finalize_planning()  # Hardening v1.1 §9 — planning must complete
    ok, unresolved = ledger.audit_complete_ok()
    assert ok is True
    assert unresolved == []


def test_empty_plan_cannot_complete() -> None:
    """Hardening v1.1 §9 — {"units": []} must never satisfy the final gate."""
    ledger = CoverageLedger.empty(audit_id="t")
    ok, unresolved = ledger.audit_complete_ok()
    assert ok is False
    assert unresolved == []
    report = ledger.completeness_report()
    assert report["unit_count"] == 0
    assert any("empty" in r for r in report["reasons"])
    assert any("planning" in r for r in report["reasons"])

    # Even finalizing an empty plan does not help: unit_count > 0 is required.
    ledger.finalize_planning()
    ok, _ = ledger.audit_complete_ok()
    assert ok is False


def test_planning_status_must_be_complete() -> None:
    """All units resolved but planning never finalized → still blocked."""
    ledger = _ledger()
    for uid in ["billing|tenant-isolation|idor", "auth|session|session_fixation",
                "upload|mime|malicious_file"]:
        ledger.transition(uid, to=UNIT_OUT_OF_SCOPE)
    assert ledger.planning_status == "in_progress"
    ok, _ = ledger.audit_complete_ok()
    assert ok is False
    assert any("planning" in r for r in ledger.completeness_report()["reasons"])

    ledger.finalize_planning()
    ok, unresolved = ledger.audit_complete_ok()
    assert ok is True
    assert unresolved == []


def test_planning_status_roundtrips(tmp_path: Path) -> None:
    path = tmp_path / "coverage-ledger.json"
    ledger = _ledger()
    ledger.finalize_planning()
    ledger.save(path)
    loaded = CoverageLedger.load(path)
    assert loaded.planning_status == "complete"


def test_ledger_rejects_unknown_planning_status() -> None:
    with pytest.raises(CoverageLedgerError):
        CoverageLedger.from_dict({"schema_version": 1, "audit_id": "t", "units": [],
                                  "planning_status": "nonsense"})


def test_ledger_schema_rejects_malformed_unit() -> None:
    """Hardening v1.1 §5 — the coverage schema is enforced on load."""
    with pytest.raises(CoverageLedgerError):
        CoverageLedger.from_dict({
            "schema_version": 1,
            "audit_id": "t",
            "units": [{"id": "a|b|c", "subsystem": "a", "boundary": "b",
                       "attack_class": "c", "status": "not_a_state"}],
        })


def test_ledger_schema_requires_planning_status() -> None:
    """v1.1.1 — `planning_status` is a required field, so omitting it fails.

    A ledger with no recorded planning lifecycle must not be loadable at all:
    otherwise the only thing standing between it and the final gate is a
    semantic check that used to tolerate the missing field.
    """
    with pytest.raises(CoverageLedgerError) as exc:
        CoverageLedger.from_dict({
            "schema_version": 1,
            "audit_id": "t",
            "units": [{"id": "a|b|c", "subsystem": "a", "boundary": "b",
                       "attack_class": "c", "status": "covered"}],
        })
    assert "planning_status" in str(exc.value)


def test_save_load_roundtrip(tmp_path: Path) -> None:
    path = tmp_path / "coverage-ledger.json"
    ledger = _ledger()
    ledger.transition("billing|tenant-isolation|idor", to=UNIT_IN_PROGRESS)
    ledger.transition("billing|tenant-isolation|idor", to=UNIT_COVERED)
    ledger.save(path)
    loaded = CoverageLedger.load(path)
    assert loaded.audit_id == "t"
    assert loaded.unit_count() == 3
    assert loaded.get("billing|tenant-isolation|idor").status == UNIT_COVERED