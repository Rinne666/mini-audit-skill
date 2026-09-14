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
    s.ensure_phase("L1")
    s.transition("L1", to=PHASE_IN_PROGRESS)
    assert s.phases["L1"].attempt == 1
    s.transition("L1", to=PHASE_IN_PROGRESS)  # no-op increment
    assert s.phases["L1"].attempt == 1
    s.transition("L1", to=PHASE_FAILED, error="x")
    s.transition("L1", to=PHASE_IN_PROGRESS)
    assert s.phases["L1"].attempt == 2


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