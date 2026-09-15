"""Tests for runtime/state.py — phase state machine + atomic persistence."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from runtime.state import (
    PHASE_COMPLETE,
    PHASE_FAILED,
    PHASE_IN_PROGRESS,
    PHASE_PENDING,
    PHASE_SKIPPED,
    AuditState,
    PhaseState,
    StateTransitionError,
)


def _new_state() -> AuditState:
    return AuditState.new(
        audit_id="test-001",
        mode="balanced",
        source={"root": "/tmp/repo", "commit": "abc", "tree_hash": "t"},
        runtime={"version": "1.0.0", "agent_sdk": "test", "model": "test"},
    )


def test_phase_transition_pending_to_in_progress_to_complete() -> None:
    s = _new_state()
    s.ensure_phase("L1")
    s.transition("L1", to=PHASE_IN_PROGRESS)
    assert s.phases["L1"].status == PHASE_IN_PROGRESS
    assert s.phases["L1"].attempt == 1
    assert s.phases["L1"].started_at is not None
    s.transition("L1", to=PHASE_COMPLETE)
    assert s.phases["L1"].status == PHASE_COMPLETE
    assert s.phases["L1"].completed_at is not None


def test_pending_to_complete_is_illegal() -> None:
    s = _new_state()
    s.ensure_phase("L1")
    with pytest.raises(StateTransitionError):
        s.transition("L1", to=PHASE_COMPLETE)


def test_failed_to_complete_is_illegal() -> None:
    s = _new_state()
    s.ensure_phase("L1")
    s.transition("L1", to=PHASE_IN_PROGRESS)
    s.transition("L1", to=PHASE_FAILED, error="boom")
    with pytest.raises(StateTransitionError):
        s.transition("L1", to=PHASE_COMPLETE)


def test_failed_to_in_progress_is_allowed() -> None:
    s = _new_state()
    s.ensure_phase("L1")
    s.transition("L1", to=PHASE_IN_PROGRESS)
    s.transition("L1", to=PHASE_FAILED, error="boom")
    s.transition("L1", to=PHASE_IN_PROGRESS)  # recovery
    s.transition("L1", to=PHASE_COMPLETE)
    assert s.phases["L1"].status == PHASE_COMPLETE


def test_complete_can_be_reopened() -> None:
    s = _new_state()
    s.ensure_phase("L1")
    s.transition("L1", to=PHASE_IN_PROGRESS)
    s.transition("L1", to=PHASE_COMPLETE)
    s.transition("L1", to=PHASE_IN_PROGRESS)  # rerun
    assert s.phases["L1"].status == PHASE_IN_PROGRESS


def test_attempts_increment() -> None:
    s = _new_state()
    s.ensure_phase("L1", max_attempts=5)
    s.transition("L1", to=PHASE_IN_PROGRESS)
    assert s.phases["L1"].attempt == 1
    s.heartbeat("L1")  # liveness does not consume an attempt
    assert s.phases["L1"].attempt == 1
    s.transition("L1", to=PHASE_FAILED, error="x")
    s.transition("L1", to=PHASE_IN_PROGRESS)
    assert s.phases["L1"].attempt == 2


def test_in_progress_to_in_progress_is_illegal() -> None:
    """Hardening v1.1 §10: no special case for re-entering in_progress."""
    s = _new_state()
    s.ensure_phase("L1")
    s.transition("L1", to=PHASE_IN_PROGRESS)
    with pytest.raises(StateTransitionError):
        s.transition("L1", to=PHASE_IN_PROGRESS)


def test_heartbeat_requires_in_progress() -> None:
    s = _new_state()
    s.ensure_phase("L1")
    with pytest.raises(StateTransitionError):
        s.heartbeat("L1")


def test_skipped_cannot_reopen() -> None:
    """skipped is terminal; the old in_progress bypass used to allow this."""
    s = _new_state()
    s.ensure_phase("L1")
    s.transition("L1", to=PHASE_SKIPPED)
    with pytest.raises(StateTransitionError):
        s.transition("L1", to=PHASE_IN_PROGRESS)


def test_max_attempts_enforced() -> None:
    s = _new_state()
    s.ensure_phase("L1", max_attempts=2)
    s.transition("L1", to=PHASE_IN_PROGRESS)          # attempt 1
    s.transition("L1", to=PHASE_FAILED, error="boom")
    s.transition("L1", to=PHASE_IN_PROGRESS)          # attempt 2
    s.transition("L1", to=PHASE_FAILED, error="boom")
    with pytest.raises(StateTransitionError) as exc:
        s.transition("L1", to=PHASE_IN_PROGRESS)      # budget exhausted
    assert "max_attempts" in str(exc.value)


def test_reset_reopens_attempt_budget() -> None:
    s = _new_state()
    s.ensure_phase("L1", max_attempts=1)
    s.transition("L1", to=PHASE_IN_PROGRESS)
    s.transition("L1", to=PHASE_FAILED, error="boom")
    with pytest.raises(StateTransitionError):
        s.transition("L1", to=PHASE_IN_PROGRESS)
    s.transition("L1", to=PHASE_IN_PROGRESS, reset=True)
    assert s.phases["L1"].status == PHASE_IN_PROGRESS
    assert s.phases["L1"].attempt == 1


def test_attempts_exhausted_helper() -> None:
    s = _new_state()
    s.ensure_phase("L1", max_attempts=1)
    assert s.attempts_exhausted("L1") is False
    s.transition("L1", to=PHASE_IN_PROGRESS)
    s.transition("L1", to=PHASE_FAILED, error="boom")
    assert s.attempts_exhausted("L1") is True


def test_save_and_load_roundtrip(tmp_path: Path) -> None:
    s = _new_state()
    s.ensure_phase("L1")
    s.transition("L1", to=PHASE_IN_PROGRESS)
    path = tmp_path / "audit-state.json"
    s.save(path)
    loaded = AuditState.load(path)
    assert loaded.audit_id == "test-001"
    assert loaded.phases["L1"].status == PHASE_IN_PROGRESS


def test_corrupt_state_quarantines(tmp_path: Path) -> None:
    path = tmp_path / "audit-state.json"
    path.write_text("{not json", encoding="utf-8")
    from runtime.atomic_io import AtomicIOError
    with pytest.raises(AtomicIOError):
        AuditState.load(path)
    assert not path.exists()
    assert list(tmp_path.glob("audit-state.json.corrupt-*"))


def test_is_phase_complete_and_incomplete_phases() -> None:
    s = _new_state()
    s.ensure_phase("L1").status  # touch
    s.transition("L1", to=PHASE_IN_PROGRESS)
    s.transition("L1", to=PHASE_COMPLETE)
    s.ensure_phase("L2")
    assert s.is_phase_complete("L1")
    assert not s.is_phase_complete("L2")
    assert s.incomplete_phases(["L1", "L2", "L3"]) == ["L2", "L3"]


def test_all_terminal_requires_complete_or_skipped() -> None:
    s = _new_state()
    for p in ["L1", "L2"]:
        s.ensure_phase(p)
        s.transition(p, to=PHASE_IN_PROGRESS)
        s.transition(p, to=PHASE_COMPLETE)
    s.ensure_phase("L3")
    s.transition("L3", to=PHASE_SKIPPED)
    assert s.all_terminal(["L1", "L2", "L3"]) is True
    assert s.all_terminal(["L1", "L2"]) is True
    # Add L4 in_progress -> not terminal
    s.ensure_phase("L4")
    s.transition("L4", to=PHASE_IN_PROGRESS)
    assert s.all_terminal(["L1", "L2", "L4"]) is False


def test_unsupported_schema_version_rejected(tmp_path: Path) -> None:
    path = tmp_path / "audit-state.json"
    path.write_text(json.dumps({"schema_version": 999}), encoding="utf-8")
    with pytest.raises(StateTransitionError):
        AuditState.load(path)


def test_mark_complete_records_timestamp() -> None:
    s = _new_state()
    s.mark_complete()
    assert s.status == "complete"
    assert s.completed_at is not None


# ---------------------------------------------------------------------------
# Hardening v1.1 §5 — audit-state schema is authoritative
# ---------------------------------------------------------------------------


def test_load_rejects_schema_invalid_state(tmp_path: Path) -> None:
    path = tmp_path / "audit-state.json"
    bad = _new_state().to_dict()
    bad["mode"] = "nonsense-mode"  # not in the schema enum
    path.write_text(json.dumps(bad), encoding="utf-8")
    with pytest.raises(StateTransitionError):
        AuditState.load(path)


def test_load_rejects_missing_required_source(tmp_path: Path) -> None:
    path = tmp_path / "audit-state.json"
    bad = _new_state().to_dict()
    del bad["source"]["commit"]
    path.write_text(json.dumps(bad), encoding="utf-8")
    with pytest.raises(StateTransitionError):
        AuditState.load(path)


def test_save_refuses_invalid_state(tmp_path: Path) -> None:
    s = _new_state()
    s.mode = "definitely-not-a-mode"
    with pytest.raises(StateTransitionError):
        s.save(tmp_path / "audit-state.json")
    assert not (tmp_path / "audit-state.json").exists()


def test_save_load_accepts_all_documented_modes(tmp_path: Path) -> None:
    for mode in ["lite", "balanced", "deep", "diff", "confirm", "revisit",
                 "merge", "longshot", "reinvest", "knowledge-base", "judge"]:
        s = _new_state()
        s.mode = mode
        path = tmp_path / f"state-{mode}.json"
        s.save(path)
        assert AuditState.load(path).mode == mode
