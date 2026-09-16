"""Long-horizon replay evaluator (Phase E0 / §19-§22).

The important tests here are the negative controls. A metric that only ever
reports 1.0 proves nothing, so each of the three is exercised against a
deliberately broken replay: if the numbers do not move, they are decoration.
"""
from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from evals import long_horizon_run as lh
from runtime import research_state as rs

SCENARIO_PATH = Path(__file__).resolve().parent.parent.parent / "evals" / "long_horizon"


def _scenario() -> dict:
    """Load through the production loader.

    Reading the JSON directly would skip ``_fixture_dir``, and the replay would
    then look for the fixture's sources in the wrong place — so the tests would
    be exercising a path CI does not.
    """
    scenarios = lh.load_scenarios(only=["CHAIN-001"])
    assert scenarios, f"the CHAIN-001 fixture is missing under {SCENARIO_PATH}"
    return scenarios[0]


def _run(scenario: dict, tmp_path: Path) -> dict:
    workdir = tmp_path / str(scenario["id"])
    workdir.mkdir(parents=True, exist_ok=True)
    return lh.evaluate_scenario(scenario, workdir)


def test_the_shipped_scenario_meets_its_thresholds(tmp_path: Path) -> None:
    result = _run(_scenario(), tmp_path)
    assert result["metrics"]["premature_rejection_rate"] == 0.0
    assert result["metrics"]["blocked_path_reopen_rate"] == 1.0
    assert result["metrics"]["chain_completion_recall"] == 1.0
    assert lh.check_thresholds([result], result["metrics"]) == []
    assert result["counts"] == {"retain_total": 3, "prematurely_rejected": 0,
                                "should_reopen_total": 1, "reopened": 1,
                                "chains_total": 1, "chains_completed": 1}


def test_the_chain_is_not_complete_before_the_last_step(tmp_path: Path) -> None:
    """Negative control for chain_completion_recall: the chain only closes once
    the conversions are verified, so truncating the replay must show it."""
    scenario = _scenario()
    scenario["steps"] = scenario["steps"][:2]
    result = _run(scenario, tmp_path)
    assert result["metrics"]["chain_completion_recall"] == 0.0
    assert lh.check_thresholds([result], result["metrics"]), "thresholds should complain"


def test_the_metric_sees_a_blocker_that_never_reopens(tmp_path: Path) -> None:
    """Negative control for blocked_path_reopen_rate: without the fact that
    disproves the assumption, the path stays blocked."""
    scenario = _scenario()
    scenario["steps"] = [copy.deepcopy(scenario["steps"][0])]
    result = _run(scenario, tmp_path)
    assert result["metrics"]["blocked_path_reopen_rate"] == 0.0
    assert result["detail"]["should_reopen"] == ["BP-001"]
    assert result["detail"]["reopened"] == []


def test_the_metric_sees_a_prematurely_lost_primitive(tmp_path: Path) -> None:
    """Negative control for premature_rejection_rate.

    Truncate the replay at the first step *and* remove the blocked path: the
    primitive B is still locally valid, but the research state now records no
    reason to keep it and nothing it needs is held. The simulated chamber
    rejects it — the failure this metric exists to catch, a lead dropped
    because nothing preserved it.
    """
    scenario = _scenario()
    scenario["steps"] = [copy.deepcopy(scenario["steps"][0])]
    del scenario["steps"][0]["delta"]["blocked_paths_add"]
    result = _run(scenario, tmp_path)
    assert "cand-b-query" in result["detail"]["prematurely_rejected"]
    assert result["metrics"]["premature_rejection_rate"] > 0.0


def test_a_recorded_blocker_is_reason_enough_to_keep_a_lead(tmp_path: Path) -> None:
    """The first step alone keeps B, because the blocked path *is* the record
    that the lead matters. Requiring that blocker to be established first would
    reject precisely the candidates the mechanism exists to preserve."""
    scenario = _scenario()
    scenario["steps"] = [copy.deepcopy(scenario["steps"][0])]
    result = _run(scenario, tmp_path)

    assert "cand-b-query" not in result["detail"]["prematurely_rejected"]
    ledger = rs.load_ledger(tmp_path / scenario["id"] / "mini-audit")
    blocked = rs.iter_objects(ledger, "blocked_path")
    assert [path["id"] for path in blocked] == ["BP-001"]
    assert blocked[0]["status"] == "blocked"


def test_a_retained_lead_is_retained_by_research_state_not_by_the_script(tmp_path: Path) -> None:
    """The candidate survives because a blocker or a live prerequisite exists.

    cand-b-query is the interesting one: after its assumption is disproved the
    blocker is *gone*, so what keeps it is that the capability it requires has
    become reachable. That is the runtime's reachability computation doing the
    work, not the scenario file.
    """
    scenario = _scenario()
    result = _run(scenario, tmp_path)
    assert "cand-b-query" not in result["detail"]["rejected_by_verdict"]
    assert "cand-d-noise" in result["detail"]["rejected_by_verdict"]
    # Every retained candidate is either a reachable graph node's name, or one of
    # the candidates the fixture declared. The declared set is read from the
    # fixture rather than restated here: a hardcoded copy is how this assertion
    # went stale the moment a candidate id was renamed.
    declared = {str(candidate["candidate_id"]) for candidate in scenario["candidates"]}
    assert set(result["detail"]["retain"]) <= set(result["detail"]["reachable"]) | declared


def test_proposed_capabilities_do_not_count_as_held(tmp_path: Path) -> None:
    """A capability must be established in its own right: an inbound verified
    edge is not enough, or the node status enum would be decorative."""
    scenario = _scenario()
    scenario["steps"] = scenario["steps"][:1]
    result = _run(scenario, tmp_path)
    # control_sql_expression is created proposed in step 1, and its verified
    # `requires` edge points at a proposed prerequisite, so nothing beyond the
    # objective's own capabilities is reachable.
    assert result["detail"]["reachable"] == ["CAP-001", "PRIN-001"]


def test_scope_note_forbids_the_overclaim() -> None:
    """§22: these numbers say nothing about finding more bugs."""
    import io
    import contextlib

    buffer = io.StringIO()
    with contextlib.redirect_stdout(buffer):
        lh.main(["--json", "--scenario", "CHAIN-001"])
    payload = json.loads(buffer.getvalue())
    note = payload["scope_note"]
    assert "not vulnerability-discovery performance" in note
    assert "no model was run" in note


# ---------------------------------------------------------------------------
# The fixture has to stay honest about its sources
# ---------------------------------------------------------------------------


def test_a_fixture_whose_evidence_drifted_is_refused(tmp_path: Path) -> None:
    """A stale line number must fail loudly, not replay against nothing.

    The line is part of the claim: "B.py builds the SQL by concatenation" is
    true of one line and false of the file. Without this check, editing a source
    or a line number would leave every metric green while the fixture described
    code that no longer exists.
    """
    scenario = _scenario()
    scenario["steps"][0]["delta"]["facts_add"][0]["evidence_refs"] = ["B.py:9999"]
    with pytest.raises(lh.ScenarioError, match="has only"):
        _run(scenario, tmp_path)


def test_a_fixture_citing_a_missing_source_is_refused(tmp_path: Path) -> None:
    scenario = _scenario()
    scenario["sources"] = ["A.py", "D.py"]
    with pytest.raises(lh.ScenarioError, match="does not exist"):
        _run(scenario, tmp_path)


def test_a_fixture_with_sources_but_no_file_reference_is_refused(tmp_path: Path) -> None:
    """Otherwise the integrity check would pass vacuously — the shape of
    'declared but unchecked' this project keeps removing."""
    scenario = _scenario()
    for step in scenario["steps"]:
        for operation, entries in step["delta"].items():
            if not isinstance(entries, list):
                continue
            for entry in entries:
                if isinstance(entry, dict):
                    for field in ("evidence_refs", "verification_refs", "source_refs"):
                        entry.pop(field, None)
    with pytest.raises(lh.ScenarioError, match="cites no file:line"):
        _run(scenario, tmp_path)


def test_the_fixture_check_actually_ran(tmp_path: Path) -> None:
    """The count is surfaced, so a check that stopped matching is visible."""
    result = _run(_scenario(), tmp_path)
    assert result["fixture"]["sources"] == ["A.py", "B.py", "C.py"]
    assert result["fixture"]["evidence_refs_checked"] >= 6
