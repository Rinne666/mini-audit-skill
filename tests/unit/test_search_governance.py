"""Search Governance v1 Phase A — research state, objective, lock (R2-1..R2-7).

The properties under test are the ones the design freezes, not the
implementation's shape:

* an objective is canonical, immutable and auditable;
* a research delta is idempotent by key and all-or-nothing on conflict;
* the attack graph never holds a node type the runtime cannot check;
* `research` is optional in the candidate schema but required by the L6 gate;
* a busy Search Governance lock is a distinct, machine-readable exit.
"""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from runtime import attack_graph as ag
from runtime import objective as objective_mod
from runtime import research_state as rs
from runtime import schema as schema_mod
from runtime.objective import ObjectiveError
from runtime.research_state import (
    DeltaSchemaError,
    DuplicateKeyInDelta,
    IdentityAlreadyBound,
    ResearchKeyConflict,
    UnknownCandidate,
    UnknownReference,
)
from runtime.search_lock import (
    BUSY_EXIT_CODE,
    SearchGovernanceLock,
    SearchLockBusy,
    default_timeout,
    lock_path,
)

SKILL_ROOT = Path(__file__).resolve().parent.parent.parent
LAUNCHER = SKILL_ROOT / "scripts" / "mini-audit-runtime"

PROPOSAL = {
    "principal": "unauthenticated_remote_user",
    "initial_capabilities": ["send_http_request"],
    "target_capabilities": ["arbitrary_code_execution"],
    "security_invariants": ["anonymous users cannot obtain privileged execution capability"],
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _cli_env(**extra: str) -> dict[str, str]:
    env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
    env.update(extra)
    return env


def _run_cli(*args: str, cwd: Path, env: dict[str, str] | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(LAUNCHER), *args],
        capture_output=True,
        text=True,
        cwd=str(cwd),
        env=env or _cli_env(),
        check=False,
    )


def _audit_root(tmp_path: Path) -> Path:
    root = tmp_path / "mini-audit"
    root.mkdir(parents=True, exist_ok=True)
    return root


def _init(tmp_path: Path, proposal: dict | None = None) -> Path:
    root = _audit_root(tmp_path)
    objective_mod.init_and_bootstrap(root, proposal or PROPOSAL, agent="agent-L1")
    return root


def _write_candidate(tmp_path: Path, candidate_id: str = "cand-031") -> None:
    directory = tmp_path / "mini-audit" / "candidates"
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "review-chamber-candidates.json").write_text(
        json.dumps({"source": "review-chamber", "count": 1, "candidates": [
            {"candidate_id": candidate_id, "source": "review-chamber",
             "status": "needs_validation"}]}),
        encoding="utf-8",
    )


def _digest(*paths: Path) -> tuple[str, ...]:
    out = []
    for path in paths:
        out.append(hashlib.sha256(path.read_bytes()).hexdigest() if path.exists() else "-")
    return tuple(out)


def _delta(**overrides) -> dict:
    delta = {
        "schema_version": 1,
        "agent_id": "agent-L5",
        "phase": "L5",
        "facts_add": [{"key": "fact:rest-validates-int",
                       "claim": "REST handler coerces author_exclude to int[]",
                       "evidence_refs": ["src/rest-handler.php:88"]}],
        "assumptions_add": [{"key": "assumption:author_exclude-int-array",
                             "claim": "all callers pass an integer array into author_exclude"}],
        "capabilities_add": [
            {"key": "cap:control_scalar_parameter", "name": "control_scalar_parameter"},
            {"key": "cap:control_sql_expression", "name": "control_sql_expression"},
        ],
        "edges_add": [
            {"key": "edge:p->scalar",
             "from": "objective:initial-capability:send_http_request",
             "to": "cap:control_scalar_parameter", "relation": "enables",
             "status": "verified"},
            {"key": "edge:scalar->sql", "from": "cap:control_scalar_parameter",
             "to": "cap:control_sql_expression", "relation": "enables", "status": "verified"},
        ],
        "blocked_paths_add": [{
            "key": "bp:cand-031",
            "candidate_id": "cand-031",
            "blocker": {"type": "input_validation",
                        "claim": "normal REST path only accepts integer arrays",
                        "assumption_ref": "assumption:author_exclude-int-array"},
            "priority": "high",
            "reopen_if": ["A-001 is disproved"],
        }],
    }
    delta.update(overrides)
    return delta


# ---------------------------------------------------------------------------
# Objective: canonical, immutable, auditable
# ---------------------------------------------------------------------------


def test_objective_init_is_canonical_and_immutable(tmp_path: Path) -> None:
    root = _init(tmp_path)
    doc = objective_mod.load_objective(root)
    assert doc is not None
    assert doc["revision"] == 1
    assert doc["supersedes"] == []
    assert objective_mod.content_hash(doc).startswith("sha256:")

    with pytest.raises(ObjectiveError, match="already exists"):
        objective_mod.init_and_bootstrap(root, PROPOSAL)


def test_objective_init_bootstraps_the_attack_graph(tmp_path: Path) -> None:
    root = _init(tmp_path)
    graph = ag.load_graph(root)
    assert graph is not None
    nodes = {(n["type"], n["name"]): n for n in graph["nodes"]}
    assert ("principal", "unauthenticated_remote_user") in nodes
    assert nodes[("principal", "unauthenticated_remote_user")]["id"] == "PRIN-001"
    assert nodes[("capability", "send_http_request")]["status"] == "verified"
    assert nodes[("capability", "send_http_request")]["origin"] == "objective"
    assert ("goal", "arbitrary_code_execution") in nodes
    # Numbering is per prefix: the goal node must not consume a capability id.
    assert nodes[("capability", "send_http_request")]["id"] == "CAP-001"
    assert nodes[("goal", "arbitrary_code_execution")]["id"] == "GOAL-001"


def test_objective_replace_requires_force_and_reason(tmp_path: Path) -> None:
    root = _init(tmp_path)
    changed = {**PROPOSAL, "target_capabilities": ["arbitrary_code_execution", "read_other_tenant_data"]}

    with pytest.raises(ObjectiveError, match="--force"):
        objective_mod.replace_and_record(root, changed, force=False, reason="because")
    with pytest.raises(ObjectiveError, match="--reason"):
        objective_mod.replace_and_record(root, changed, force=True, reason="   ")
    assert objective_mod.load_objective(root)["revision"] == 1


def test_objective_revision_audit_trail_and_ledger_fact(tmp_path: Path) -> None:
    root = _init(tmp_path)
    before = objective_mod.content_hash(objective_mod.load_objective(root))
    changed = {**PROPOSAL, "target_capabilities": ["arbitrary_code_execution", "read_other_tenant_data"]}

    doc = objective_mod.replace_and_record(
        root, changed, force=True, reason="scope expanded to tenant boundary")

    assert doc["revision"] == 2
    assert len(doc["supersedes"]) == 1
    entry = doc["supersedes"][0]
    assert entry["revision"] == 1
    assert entry["previous_hash"] == before
    assert entry["reason"] == "scope expanded to tenant boundary"
    assert entry["at"]

    ledger = rs.load_ledger(root)
    system_facts = [f for f in ledger["facts"] if f["key"].startswith("system:objective-revision")]
    assert len(system_facts) == 1
    claim = system_facts[0]["claim"]
    # The fact must carry old/new revision, both hashes and the reason.
    assert "revision 1 -> 2" in claim
    assert before in claim
    assert objective_mod.content_hash(doc) in claim
    assert "scope expanded to tenant boundary" in claim


def test_objective_replace_refuses_identical_content(tmp_path: Path) -> None:
    root = _init(tmp_path)
    with pytest.raises(ObjectiveError, match="identical content"):
        objective_mod.replace_and_record(root, PROPOSAL, force=True, reason="again")
    assert objective_mod.load_objective(root)["revision"] == 1


def test_objective_replace_requires_an_existing_objective(tmp_path: Path) -> None:
    root = _audit_root(tmp_path)
    with pytest.raises(ObjectiveError, match="no canonical objective"):
        objective_mod.replace_and_record(root, PROPOSAL, force=True, reason="r")


def test_research_apply_requires_an_objective(tmp_path: Path) -> None:
    root = _audit_root(tmp_path)
    with pytest.raises(ObjectiveError):
        rs.apply_delta(root, {"schema_version": 1})


def test_objective_rejects_a_proposal_that_carries_a_revision(tmp_path: Path) -> None:
    with pytest.raises(ObjectiveError, match="revision"):
        objective_mod.canonicalize({**PROPOSAL, "revision": 3})
    with pytest.raises(ObjectiveError, match="supersedes"):
        objective_mod.canonicalize({**PROPOSAL, "supersedes": [{"revision": 1}]})


# ---------------------------------------------------------------------------
# Deltas: idempotency, merging, conflicts, forward references
# ---------------------------------------------------------------------------


def test_same_delta_twice_is_idempotent(tmp_path: Path) -> None:
    root = _init(tmp_path)
    _write_candidate(tmp_path)

    first = rs.apply_delta(root, _delta(), agent="agent-L5")
    assert first["created"]["fact"] == ["FCT-001"]
    assert first["created"]["capability"] == ["CAP-002", "CAP-003"]
    ledger_after_first = rs.load_ledger(root)
    graph_after_first = ag.load_graph(root)

    second = rs.apply_delta(root, _delta(), agent="agent-L5")
    assert second["created"] == {}
    assert len(second["merged"]["fact"]) == 1

    ledger_after_second = rs.load_ledger(root)
    for collection in ("facts", "assumptions", "open_questions", "blocked_paths", "intents"):
        assert len(ledger_after_second[collection]) == len(ledger_after_first[collection])
    graph_after_second = ag.load_graph(root)
    # 5 seeded/discovered nodes: principal, initial capability, goal, plus the
    # two capabilities this delta added. Re-applying must not grow that.
    assert len(graph_after_second["nodes"]) == len(graph_after_first["nodes"])
    assert len(graph_after_second["edges"]) == len(graph_after_first["edges"]) == 2


def test_same_key_same_identity_merges_mutable_fields(tmp_path: Path) -> None:
    root = _init(tmp_path)
    rs.apply_delta(root, _delta())
    report = rs.apply_delta(root, {"schema_version": 1,
                                   "assumptions_update": [
                                       {"ref": "assumption:author_exclude-int-array",
                                        "status": "supported",
                                        "evidence_refs": ["src/rest-handler.php:88"]}]})
    ledger = rs.load_ledger(root)
    assert len(ledger["assumptions"]) == 1
    assumption = ledger["assumptions"][0]
    assert assumption["status"] == "supported"
    assert assumption["evidence_refs"] == ["src/rest-handler.php:88"]
    assert "A-001" in report["merged"]["assumption"]


def test_same_key_different_identity_rejects_the_whole_delta(tmp_path: Path) -> None:
    root = _init(tmp_path)
    rs.apply_delta(root, _delta())
    ledger_file = rs.ledger_path(root)
    graph_file = ag.graph_path(root)
    before = _digest(ledger_file, graph_file)

    conflicting = {
        "schema_version": 1,
        # A perfectly valid sibling that must NOT land either.
        "facts_add": [{"key": "fact:sibling", "claim": "a valid sibling fact"}],
        "assumptions_add": [{"key": "assumption:author_exclude-int-array",
                             "claim": "a completely different claim"}],
    }
    with pytest.raises(ResearchKeyConflict) as excinfo:
        rs.apply_delta(root, conflicting)
    assert excinfo.value.code == "RESEARCH_KEY_CONFLICT"

    assert _digest(ledger_file, graph_file) == before, "a rejected delta changed state"
    assert rs.find_by_key(rs.load_ledger(root), "fact", "fact:sibling") is None


def test_duplicate_key_inside_one_delta_is_refused(tmp_path: Path) -> None:
    root = _init(tmp_path)
    with pytest.raises(DuplicateKeyInDelta):
        rs.apply_delta(root, {"schema_version": 1, "facts_add": [
            {"key": "fact:dup", "claim": "a"}, {"key": "fact:dup", "claim": "b"}]})


def test_keys_are_global_not_per_kind(tmp_path: Path) -> None:
    root = _init(tmp_path)
    with pytest.raises(DuplicateKeyInDelta):
        rs.apply_delta(root, {"schema_version": 1,
                              "facts_add": [{"key": "same", "claim": "a"}],
                              "research_intents_add": [{"key": "same",
                                                          "question": "q?",
                                                          "strategy": "capability-consumer-search",
                                                          "priority": "P2",
                                                          "status": "open"}]})


def test_forward_references_by_key_resolve_to_canonical_ids(tmp_path: Path) -> None:
    root = _init(tmp_path)
    report = rs.apply_delta(root, _delta())

    assert report["key_to_id"]["cap:control_scalar_parameter"] == "CAP-002"
    graph = ag.load_graph(root)
    edge = ag.find_edge_by_key(graph, "edge:p->scalar")
    assert edge is not None
    # Declared as a key, stored as the canonical id of a node created in the
    # same delta.
    assert edge["from"] == "CAP-001"
    assert edge["to"] == "CAP-002"

    ledger = rs.load_ledger(root)
    blocker = ledger["blocked_paths"][0]["blocker"]
    assert blocker["assumption_ref"] == "A-001"


def test_update_of_a_missing_object_is_refused(tmp_path: Path) -> None:
    root = _init(tmp_path)
    with pytest.raises(UnknownReference, match="does not resolve"):
        rs.apply_delta(root, {"schema_version": 1, "assumptions_update": [
            {"ref": "assumption:never-declared", "status": "supported"}]})


def test_unknown_reference_in_a_new_edge_is_refused(tmp_path: Path) -> None:
    root = _init(tmp_path)
    with pytest.raises(UnknownReference):
        rs.apply_delta(root, {"schema_version": 1, "edges_add": [
            {"key": "edge:dangling", "from": "cap:nope", "to": "cap:control_sql_expression",
             "relation": "enables"}]})


def test_identity_already_bound_to_another_key_is_refused(tmp_path: Path) -> None:
    """A capability's identity is (name, principal); a second key cannot claim it."""
    root = _init(tmp_path)
    rs.apply_delta(root, {"schema_version": 1, "capabilities_add": [
        {"key": "cap:sql", "name": "control_sql_expression"}]})
    with pytest.raises(IdentityAlreadyBound, match="reuse that key"):
        rs.apply_delta(root, {"schema_version": 1, "capabilities_add": [
            {"key": "cap:sql-again", "name": "control_sql_expression"}]})


def test_capability_identity_includes_the_principal(tmp_path: Path) -> None:
    """Same name, different principal → two capabilities, not a conflict."""
    root = _init(tmp_path)
    rs.apply_delta(root, {"schema_version": 1, "capabilities_add": [
        {"key": "cap:anon-sql", "name": "control_sql_expression",
         "principal": "unauthenticated_remote_user"}]})
    report = rs.apply_delta(root, {"schema_version": 1, "capabilities_add": [
        {"key": "cap:auth-sql", "name": "control_sql_expression",
         "principal": "authenticated_ordinary_user"}]})
    assert len(report["created"]["capability"]) == 1
    principals = {n.get("principal") for n in ag.load_graph(root)["nodes"]
                  if n["name"] == "control_sql_expression"}
    assert principals == {"unauthenticated_remote_user", "authenticated_ordinary_user"}


def test_capability_principal_defaults_to_the_objective(tmp_path: Path) -> None:
    root = _init(tmp_path)
    rs.apply_delta(root, {"schema_version": 1, "capabilities_add": [
        {"key": "cap:sql", "name": "control_sql_expression"}]})
    node = ag.find_node_by_key(ag.load_graph(root), "cap:sql")
    assert node["principal"] == "unauthenticated_remote_user"


def test_unknown_candidate_reference_is_a_warning_not_a_refusal(tmp_path: Path) -> None:
    root = _init(tmp_path)  # no candidate store at all
    report = rs.apply_delta(root, _delta())
    assert report["ok"] is True
    assert any("unknown candidate" in w for w in report["warnings"])


def test_orphan_candidate_patch_is_refused(tmp_path: Path) -> None:
    root = _init(tmp_path)
    _write_candidate(tmp_path)
    with pytest.raises(UnknownCandidate):
        rs.apply_delta(root, {"schema_version": 1, "candidate_updates": [
            {"candidate_id": "cand-999", "research": {"role": "chain_seed"}}]})


def test_candidate_research_patch_persists_without_touching_the_verdict(tmp_path: Path) -> None:
    root = _init(tmp_path)
    _write_candidate(tmp_path)
    report = rs.apply_delta(root, {"schema_version": 1, "candidate_updates": [
        {"candidate_id": "cand-031",
         "research": {"local_validity": "verified", "role": "chain_seed",
                      "blocked_by": ["BP-001"]}}]})
    assert report["candidate_files_touched"] == ["review-chamber-candidates.json"]

    saved = json.loads((tmp_path / "mini-audit" / "candidates"
                        / "review-chamber-candidates.json").read_text(encoding="utf-8"))
    candidate = saved["candidates"][0]
    assert candidate["research"]["role"] == "chain_seed"
    assert candidate["research"]["blocked_by"] == ["BP-001"]
    # The patch reaches the research plane only; the verdict is untouched.
    assert candidate["status"] == "needs_validation"
    assert "verdict" not in candidate


# ---------------------------------------------------------------------------
# Assumption lifecycle — Skill-First Refactor v2 (spec §4)
# ---------------------------------------------------------------------------
#
# v2 contract: an ``assumptions_update`` does NOT auto-rewrite
# ``blocked_path.status``. The runtime emits a derived event so the model
# can read the fact, and the model owns the reopen / close decision via an
# explicit ``blocked_paths_reopen`` (or a follow-up update) entry. These
# tests pin that boundary — the previous v1 behaviour (auto-reopen /
# auto-close on assumption flip) is no longer the contract.


def test_assumption_disproved_emits_derived_event_not_status_change(tmp_path: Path) -> None:
    """Spec §4: disproving an assumption is a *fact* the runtime reports,
    not a *decision* it executes. The blocked path stays ``blocked`` until
    the model submits an explicit ``blocked_paths_reopen`` entry."""
    root = _init(tmp_path)
    _write_candidate(tmp_path)
    rs.apply_delta(root, _delta())

    report = rs.apply_delta(root, {"schema_version": 1, "agent_id": "agent-L5b",
                                    "assumptions_update": [
        {"ref": "assumption:author_exclude-int-array", "status": "disproved",
         "evidence_refs": ["src/other-caller.php:40"]}]})

    # v2: assumption_transitions still recorded (factual state change).
    assert report["assumption_transitions"] == [
        {"id": "A-001", "from": "unverified", "to": "disproved"}]
    # v2: a derived event is reported for the model to read.
    events = report["derived_events"]
    assert any(ev["event"] == "blocked_path_reopenable" and ev["subject"] == "BP-001"
               for ev in events), (
        f"expected a 'blocked_path_reopenable' derived event for BP-001, "
        f"got {[ev['event'] for ev in events]}"
    )
    # v2: the runtime does NOT auto-rewrite blocked_path.status. Model decides.
    assert report["reopened_blocked_paths"] == []
    ledger = rs.load_ledger(root)
    assert ledger["blocked_paths"][0]["status"] == "blocked", (
        "blocked_path.status must stay 'blocked' without an explicit "
        "blocked_paths_reopen entry from the model"
    )
    # On disk: derived_events persisted.
    persisted = ledger.get("derived_events") or []
    assert any(ev["event"] == "blocked_path_reopenable" and ev["subject"] == "BP-001"
               for ev in persisted), (
        f"expected a 'blocked_path_reopenable' derived event for BP-001 on disk, "
        f"got {[ev.get('event') for ev in persisted]}"
    )
    # Reopening a path is not rejecting the candidate: the two lifecycles stay separate.
    saved = json.loads((tmp_path / "mini-audit" / "candidates"
                        / "review-chamber-candidates.json").read_text(encoding="utf-8"))
    assert saved["candidates"][0]["status"] == "needs_validation"


def test_assumption_supported_emits_derived_event_not_close(tmp_path: Path) -> None:
    """Spec §4: an assumption flip to ``supported`` is also a fact the runtime
    reports — closing a blocked path is still a research decision. The
    runtime does not write ``closed_blocked_paths`` on its own."""
    root = _init(tmp_path)
    _write_candidate(tmp_path)
    rs.apply_delta(root, _delta())

    report = rs.apply_delta(root, {"schema_version": 1, "agent_id": "agent-L5b",
                                    "assumptions_update": [
        {"ref": "assumption:author_exclude-int-array", "status": "supported",
         "evidence_refs": ["src/rest-handler.php:88"]}]})

    events = report["derived_events"]
    assert any(ev["event"] == "blocked_path_close_supported"
               and ev["subject"] == "BP-001" for ev in events), (
        f"expected a 'blocked_path_close_supported' derived event for BP-001, "
        f"got {[ev['event'] for ev in events]}"
    )
    assert report["closed_blocked_paths"] == [], (
        "runtime must NOT auto-close blocked paths in spec §4; the model owns close"
    )
    path = rs.load_ledger(root)["blocked_paths"][0]
    assert path["status"] == "blocked", (
        f"blocked_path.status must stay 'blocked' without explicit model action; "
        f"got {path['status']}"
    )
    assert "close_reason" not in path, (
        "runtime must not auto-write close_reason; that is a research decision"
    )


def test_blocked_path_reopen_operation_is_explicit(tmp_path: Path) -> None:
    """The model's explicit reopen entry still works — and is now the *only*
    path to a reopen. (Spec §4 moved it from runtime side-effect to model
    decision.)"""
    root = _init(tmp_path)
    _write_candidate(tmp_path)
    rs.apply_delta(root, _delta())
    report = rs.apply_delta(root, {"schema_version": 1, "blocked_paths_reopen": [
        {"ref": "bp:cand-031", "attempt_refs": ["agents/a/scratch/caller-search.md"]}]})
    assert report["reopened_blocked_paths"] == ["BP-001"]
    assert rs.load_ledger(root)["blocked_paths"][0]["status"] == "reopened"


def test_depended_on_by_is_derived_from_blocked_paths(tmp_path: Path) -> None:
    root = _init(tmp_path)
    _write_candidate(tmp_path)
    rs.apply_delta(root, _delta())
    assumption = rs.load_ledger(root)["assumptions"][0]
    assert assumption["depended_on_by"] == ["BP-001"]


# ---------------------------------------------------------------------------
# Lock
# ---------------------------------------------------------------------------


def test_lock_is_exclusive_and_reports_a_best_effort_holder(tmp_path: Path) -> None:
    root = _audit_root(tmp_path)
    holder = SearchGovernanceLock(root, exclusive=True, timeout=1.0,
                                  operation="research apply", agent="agent-17")
    holder.acquire()
    try:
        assert lock_path(root).exists()
        recorded = holder.read_holder()
        assert recorded["agent"] == "agent-17"
        assert recorded["operation"] == "research apply"

        with pytest.raises(SearchLockBusy) as excinfo:
            SearchGovernanceLock(root, exclusive=True, timeout=0.3,
                                 operation="objective replace").acquire()
        assert excinfo.value.to_dict()["error"] == "search-governance lock busy"
        assert excinfo.value.holder["pid"] == os.getpid()
    finally:
        holder.release()


def test_shared_readers_coexist_and_block_a_writer(tmp_path: Path) -> None:
    root = _audit_root(tmp_path)
    first = SearchGovernanceLock(root, exclusive=False, timeout=1.0).acquire()
    second = SearchGovernanceLock(root, exclusive=False, timeout=1.0).acquire()
    try:
        assert first.held and second.held
        with pytest.raises(SearchLockBusy):
            SearchGovernanceLock(root, exclusive=True, timeout=0.3).acquire()
    finally:
        first.release()
        second.release()


def test_lock_file_is_never_unlinked(tmp_path: Path) -> None:
    """Unlinking would let two processes each lock a different inode."""
    root = _audit_root(tmp_path)
    with SearchGovernanceLock(root, exclusive=True, timeout=1.0):
        assert lock_path(root).exists()
    assert lock_path(root).exists()


def test_lock_timeout_is_overridable_for_tests(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MINI_AUDIT_SEARCH_LOCK_TIMEOUT", "0.25")
    assert default_timeout() == 0.25
    monkeypatch.setenv("MINI_AUDIT_SEARCH_LOCK_TIMEOUT", "not-a-number")
    assert default_timeout() > 1.0


def test_busy_lock_exits_with_three(tmp_path: Path) -> None:
    root = _init(tmp_path)
    holder = SearchGovernanceLock(root, exclusive=True, timeout=1.0,
                                  operation="held by test", agent="agent-holder")
    holder.acquire()
    try:
        proc = _run_cli("research", "status", "--audit-root", str(root),
                        cwd=tmp_path, env=_cli_env(MINI_AUDIT_SEARCH_LOCK_TIMEOUT="0.3"))
    finally:
        holder.release()

    assert proc.returncode == BUSY_EXIT_CODE == 3, proc.stdout + proc.stderr
    payload = json.loads(proc.stdout)
    assert payload["ok"] is False
    assert payload["error"] == "search-governance lock busy"
    assert payload["holder"]["operation"] == "held by test"


def test_parallel_applies_do_not_lose_updates(tmp_path: Path) -> None:
    """Four concurrent transactions, each adding distinct facts, all must land.

    The lock covers the whole read-modify-write, so the last writer cannot
    silently discard another writer's facts.
    """
    root = _init(tmp_path)
    deltas = []
    for writer in range(4):
        path = tmp_path / f"delta-{writer}.json"
        path.write_text(json.dumps({
            "schema_version": 1, "agent_id": f"agent-{writer}",
            "facts_add": [{"key": f"fact:w{writer}-{n}",
                           "claim": f"writer {writer} fact {n}"} for n in range(25)],
        }), encoding="utf-8")
        deltas.append(path)

    procs = [
        subprocess.Popen(
            [sys.executable, str(LAUNCHER), "research", "apply", str(path),
             "--audit-root", str(root), "--agent", f"agent-{i}"],
            cwd=str(tmp_path), env=_cli_env(),
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
        for i, path in enumerate(deltas)
    ]
    outputs = [p.communicate() for p in procs]
    for (out, err), proc in zip(outputs, procs):
        assert proc.returncode == 0, out + err

    facts = rs.load_ledger(root)["facts"]
    keys = [f["key"] for f in facts]
    expected = {f"fact:w{w}-{n}" for w in range(4) for n in range(25)}
    assert expected <= set(keys), f"lost {sorted(expected - set(keys))}"
    assert len(keys) == len(set(keys)), "duplicate facts after concurrent applies"


# ---------------------------------------------------------------------------
# Schema contracts
# ---------------------------------------------------------------------------


def _validate(instance: dict, schema_name: str) -> list:
    return schema_mod.validate_instance(instance, schema_mod.load_schema(schema_name),
                                        use_jsonschema=False)


def _ledger_doc(**overrides) -> dict:
    doc = {"schema_version": 1, "generation": 1, "facts": [], "assumptions": [],
           "open_questions": [], "blocked_paths": [], "intents": []}
    doc.update(overrides)
    return doc


def _graph_doc(*, nodes: list | None = None, edges: list | None = None) -> dict:
    return {"schema_version": 1, "generation": 1,
            "nodes": nodes or [], "edges": edges or []}


def _question(**overrides) -> dict:
    base = {"id": "OQ-001", "key": "q:1", "question": "does an alternate caller bypass it?",
            "priority": "P0", "status": "open"}
    base.update(overrides)
    return base


@pytest.mark.parametrize("question, ok", [
    (_question(status="open"), True),
    (_question(status="resolved", reason="r", evidence_refs=["src/a.py:1"]), True),
    (_question(status="resolved", reason="r"), False),
    (_question(status="refuted", reason="r"), False),
    (_question(status="deferred", reason="r", reopen_if=["x"], attempt_refs=["t"]), True),
    (_question(status="deferred", reason="r", reopen_if=["x"], blocked_path_ref="BP-001"), True),
    (_question(status="deferred", reason="r", reopen_if=["x"]), False),
    (_question(status="deferred", reason="r", attempt_refs=["t"]), False),
    (_question(status="deferred", attempt_refs=["t"], reopen_if=["x"]), False),
])
def test_terminal_question_states_must_carry_evidence(question: dict, ok: bool) -> None:
    """A deferral with nothing behind it must not pass as a terminal state.

    This is the schema half of "the gate must not be handed back to the agent":
    `reason + reopen_if + (attempt_refs or blocked_path_ref)` is enforced here,
    and the cross-artifact validity of the referenced blocker is the L7 check.
    """
    assert (len(_validate(_ledger_doc(open_questions=[question]), "search-ledger")) == 0) is ok


def test_attack_graph_refuses_a_state_node_type() -> None:
    """`state` was dropped from v1: a node type the runtime cannot check would
    reintroduce the 'declared but unchecked' failure v1.1.1 removed."""
    node = {"id": "CAP-001", "key": "k", "type": "state", "name": "x", "status": "verified"}
    assert _validate(_graph_doc(nodes=[node]), "attack-graph")


@pytest.mark.parametrize("node_type", ["principal", "capability", "goal"])
def test_attack_graph_allows_only_the_three_v1_node_types(node_type: str) -> None:
    prefix = {"principal": "PRIN", "capability": "CAP", "goal": "GOAL"}[node_type]
    node = {"id": f"{prefix}-001", "key": "k", "type": node_type, "name": "n",
            "status": "proposed"}
    assert _validate(_graph_doc(nodes=[node]), "attack-graph") == []


def test_research_delta_rejects_unknown_fields_and_missing_identity() -> None:
    with_id = {"key": "cap:x", "name": "n", "id": "CAP-009"}
    assert _validate({"schema_version": 1, "capabilities_add": [with_id]}, "research-delta")
    assert _validate({"schema_version": 1,
                      "capabilities_add": [{"key": "cap:x"}]}, "research-delta")
    assert _validate({"schema_version": 1, "edges_add": [
        {"key": "e", "from": "CAP-001", "to": "CAP-002", "relation": "enables",
         "via_candidate": "C-17"}]}, "research-delta")


def test_scanner_candidate_can_omit_research_but_a_bad_value_is_still_caught() -> None:
    """R2-2: the schema stays permissive where the gate is strict."""
    assert _validate({"candidate_id": "cand-abc", "source": "semgrep",
                      "status": "untriaged"}, "candidate") == []
    assert _validate({"candidate_id": "cand-abc", "source": "review-chamber",
                      "status": "needs_validation",
                      "research": {"local_validity": "verified", "role": "chain_seed"}},
                     "candidate") == []
    assert _validate({"candidate_id": "cand-abc", "source": "x", "status": "untriaged",
                      "research": {"role": "seed"}}, "candidate")


def test_finding_capability_refs_are_optional_but_typed() -> None:
    def finding(boundary: dict) -> dict:
        return {"id": "F-001", "fingerprint": "v1:" + "a" * 64, "verdict": "confirmed",
                "class": "sqli", "title": "sql injection", "summary": "x" * 12,
                "source_ref": {"commit": "c", "tree_hash": "t"},
                "trace": [{"kind": "sink"}], "boundary": boundary,
                "severity": {"overall": "high"},
                "verification": {"technical_verifier": "v"}}

    base = {"type": "privilege", "security_invariant": "i", "crossed": True}
    assert _validate(finding(base), "finding") == []
    assert _validate(finding({**base, "capability_refs": ["CAP-002"]}), "finding") == []
    assert _validate(finding({**base, "capability_refs": ["cap-002"]}), "finding")
    assert _validate(finding({**base, "capability_refs": ["CAP-002", "CAP-002"]}), "finding")


def test_finding_capability_refs_resolve_against_the_attack_graph(tmp_path: Path) -> None:
    """The bridge is a resolvable id, not a string comparison against a name."""
    root = _init(tmp_path)
    report = rs.apply_delta(root, {"schema_version": 1, "capabilities_add": [
        {"key": "cap:sql", "name": "control_sql_expression", "status": "verified"}]})
    cap_id = report["key_to_id"]["cap:sql"]

    graph = ag.load_graph(root)
    node = ag.resolve_node_ref(graph, cap_id)
    assert node is not None and node["type"] == "capability"
    assert node["name"] == "control_sql_expression"
    # A reference that names no node resolves to nothing, which is exactly what
    # the L7 closure check turns into a hard failure.
    assert ag.resolve_node_ref(graph, "CAP-999") is None


# ---------------------------------------------------------------------------
# L1 gate integration
# ---------------------------------------------------------------------------


def test_l1_gate_blocks_without_the_canonical_objective(tmp_path: Path) -> None:
    (tmp_path / "mini-audit" / "attack-surface").mkdir(parents=True)
    (tmp_path / "mini-audit" / "attack-surface" / "intent-corpus.json").write_text(
        json.dumps({"intents": [{"id": "I-001"}]}), encoding="utf-8")
    _run_cli("state", "init", "--repo-root", str(tmp_path), "--audit-root", "mini-audit",
             "--mode", "balanced", cwd=tmp_path)
    _run_cli("phase", "start", "L1", "--audit-root", "mini-audit", cwd=tmp_path)

    blocked = _run_cli("phase", "complete", "L1", "--audit-root", "mini-audit",
                       "--workdir", str(tmp_path), cwd=tmp_path)
    assert blocked.returncode == 1, blocked.stdout + blocked.stderr
    messages = [f["message"] for f in json.loads(blocked.stdout)["gate"]["failures"]]
    assert any("audit-objective.json" in m for m in messages), messages
    assert any("search-ledger.json" in m for m in messages), messages


def test_l1_gate_passes_with_objective_and_ledger(tmp_path: Path) -> None:
    _init(tmp_path)
    (tmp_path / "mini-audit" / "attack-surface").mkdir(parents=True, exist_ok=True)
    (tmp_path / "mini-audit" / "attack-surface" / "intent-corpus.json").write_text(
        json.dumps({"intents": [{"id": "I-001"}]}), encoding="utf-8")
    _run_cli("state", "init", "--repo-root", str(tmp_path), "--audit-root", "mini-audit",
             "--mode", "balanced", cwd=tmp_path)
    _run_cli("phase", "start", "L1", "--audit-root", "mini-audit", cwd=tmp_path)

    ok = _run_cli("phase", "complete", "L1", "--audit-root", "mini-audit",
                  "--workdir", str(tmp_path), cwd=tmp_path)
    assert ok.returncode == 0, ok.stdout + ok.stderr
    assert json.loads(ok.stdout)["gate"]["passed"] is True


def test_l1_gate_rejects_a_objective_that_lost_a_required_field(tmp_path: Path) -> None:
    root = _init(tmp_path)
    (tmp_path / "mini-audit" / "attack-surface").mkdir(parents=True, exist_ok=True)
    (tmp_path / "mini-audit" / "attack-surface" / "intent-corpus.json").write_text(
        json.dumps({"intents": [{"id": "I-001"}]}), encoding="utf-8")
    doc = objective_mod.load_objective(root)
    del doc["security_invariants"]
    (root / "audit-objective.json").write_text(json.dumps(doc), encoding="utf-8")

    _run_cli("state", "init", "--repo-root", str(tmp_path), "--audit-root", "mini-audit",
             "--mode", "balanced", cwd=tmp_path)
    _run_cli("phase", "start", "L1", "--audit-root", "mini-audit", cwd=tmp_path)
    blocked = _run_cli("phase", "complete", "L1", "--audit-root", "mini-audit",
                       "--workdir", str(tmp_path), cwd=tmp_path)
    assert blocked.returncode == 1
    messages = [f["message"] for f in json.loads(blocked.stdout)["gate"]["failures"]]
    assert any("security_invariants" in m for m in messages), messages


# ---------------------------------------------------------------------------
# CLI surface
# ---------------------------------------------------------------------------


def test_cli_objective_round_trip(tmp_path: Path) -> None:
    proposal = tmp_path / "proposal.json"
    proposal.write_text(json.dumps(PROPOSAL), encoding="utf-8")

    created = _run_cli("objective", "init", "--from-proposal", str(proposal),
                       "--audit-root", "mini-audit", "--agent", "agent-L1", cwd=tmp_path)
    assert created.returncode == 0, created.stdout + created.stderr
    assert json.loads(created.stdout)["objective"]["revision"] == 1

    again = _run_cli("objective", "init", "--from-proposal", str(proposal),
                     "--audit-root", "mini-audit", cwd=tmp_path)
    assert again.returncode == 2
    assert "already exists" in json.loads(again.stdout)["error"]

    shown = _run_cli("objective", "show", "--audit-root", "mini-audit", cwd=tmp_path)
    assert shown.returncode == 0
    assert json.loads(shown.stdout)["objective"]["revision"] == 1


def test_cli_objective_replace_requires_both_flags(tmp_path: Path) -> None:
    _init(tmp_path)
    replacement = tmp_path / "objective-v2.json"
    replacement.write_text(json.dumps({**PROPOSAL, "principal": "authenticated_user"}),
                           encoding="utf-8")

    no_force = _run_cli("objective", "replace", "--from", str(replacement),
                        "--reason", "r", "--audit-root", "mini-audit", cwd=tmp_path)
    assert no_force.returncode == 2
    no_reason = _run_cli("objective", "replace", "--from", str(replacement), "--force",
                         "--audit-root", "mini-audit", cwd=tmp_path)
    assert no_reason.returncode == 2

    ok = _run_cli("objective", "replace", "--from", str(replacement), "--force",
                  "--reason", "principal corrected", "--audit-root", "mini-audit",
                  cwd=tmp_path)
    assert ok.returncode == 0, ok.stdout + ok.stderr
    payload = json.loads(ok.stdout)
    assert payload["objective"]["revision"] == 2
    assert payload["superseded"]["reason"] == "principal corrected"


def test_cli_research_apply_and_status(tmp_path: Path) -> None:
    root = _init(tmp_path)
    _write_candidate(tmp_path)
    delta = tmp_path / "delta.json"
    delta.write_text(json.dumps(_delta()), encoding="utf-8")

    applied = _run_cli("research", "apply", str(delta), "--audit-root", str(root),
                       "--agent", "agent-L5", cwd=tmp_path)
    assert applied.returncode == 0, applied.stdout + applied.stderr
    assert json.loads(applied.stdout)["key_to_id"]["cap:control_sql_expression"] == "CAP-003"

    status = _run_cli("research", "status", "--audit-root", str(root), cwd=tmp_path)
    assert status.returncode == 0
    payload = json.loads(status.stdout)
    assert payload["counts"]["facts"] == 1
    assert payload["counts"]["graph_edges"] == 2
    assert payload["blocked_paths_by_status"] == {"blocked": 1}


def test_cli_research_apply_reports_a_conflict_with_its_code(tmp_path: Path) -> None:
    root = _init(tmp_path)
    delta = tmp_path / "delta.json"
    delta.write_text(json.dumps(_delta()), encoding="utf-8")
    _run_cli("research", "apply", str(delta), "--audit-root", str(root), cwd=tmp_path)

    conflicting = tmp_path / "delta2.json"
    conflicting.write_text(json.dumps({
        "schema_version": 1,
        "assumptions_add": [{"key": "assumption:author_exclude-int-array",
                             "claim": "different"}]}), encoding="utf-8")
    proc = _run_cli("research", "apply", str(conflicting), "--audit-root", str(root),
                    cwd=tmp_path)
    assert proc.returncode == 2
    payload = json.loads(proc.stdout)
    assert payload["code"] == "RESEARCH_KEY_CONFLICT"


# ---------------------------------------------------------------------------
# P0-1 / P0-2 — the delta contract must be closed, and keys globally unique
# ---------------------------------------------------------------------------


def test_delta_rejects_an_unknown_top_level_field(tmp_path: Path) -> None:
    """A misspelled operation must not look like success.

    With ``additionalProperties: true`` at the top level, ``capabilites_add``
    validated cleanly and the runtime ignored it — the agent sees exit 0 and an
    empty `created` map, which is indistinguishable from "already applied".
    """
    root = _init(tmp_path)
    typo = {"schema_version": 1, "capabilites_add": [{"key": "cap:typo", "name": "typo"}]}

    assert _validate(typo, "research-delta"), "schema accepted a misspelled operation"

    before = _digest(rs.ledger_path(root), ag.graph_path(root))
    with pytest.raises(DeltaSchemaError):
        rs.apply_delta(root, typo)
    assert _digest(rs.ledger_path(root), ag.graph_path(root)) == before
    assert not any(n.get("key") == "cap:typo" for n in ag.load_graph(root)["nodes"])


def test_delta_rejects_an_unknown_top_level_field_through_the_cli(tmp_path: Path) -> None:
    root = _init(tmp_path)
    delta = tmp_path / "typo.json"
    delta.write_text(json.dumps({"schema_version": 1,
                                 "capabilites_add": [{"key": "cap:typo", "name": "typo"}]}),
                     encoding="utf-8")
    proc = _run_cli("research", "apply", str(delta), "--audit-root", str(root), cwd=tmp_path)
    assert proc.returncode != 0, proc.stdout + proc.stderr
    assert json.loads(proc.stdout)["code"] == "DELTA_SCHEMA"


def test_persisted_cross_kind_key_reuse_is_refused(tmp_path: Path) -> None:
    """A key is unique across the whole namespace, not per kind.

    References resolve by key first, so a `fact:shared` joined later by an
    `assumption:shared` would silently make every reference to `shared`
    ambiguous.
    """
    root = _init(tmp_path)
    rs.apply_delta(root, {"schema_version": 1,
                          "facts_add": [{"key": "shared:key", "claim": "a fact"}]})
    before = _digest(rs.ledger_path(root), ag.graph_path(root))

    with pytest.raises(ResearchKeyConflict) as excinfo:
        rs.apply_delta(root, {"schema_version": 1,
                              "assumptions_add": [{"key": "shared:key", "claim": "an assumption"}]})
    assert excinfo.value.code == "RESEARCH_KEY_CONFLICT"

    assert rs.find_by_key(rs.load_ledger(root), "assumption", "shared:key") is None
    assert _digest(rs.ledger_path(root), ag.graph_path(root)) == before


@pytest.mark.parametrize("conflicting", [
    {"research_intents_add": [{"key": "cap:sql", "question": "reuse a graph key?",
                                  "strategy": "capability-consumer-search",
                                  "priority": "P2", "status": "open"}]},
    {"facts_add": [{"key": "cap:sql", "claim": "reuse a graph key"}]},
])
def test_a_key_bound_to_a_graph_node_cannot_be_reused(tmp_path: Path,
                                                      conflicting: dict) -> None:
    root = _init(tmp_path)
    rs.apply_delta(root, {"schema_version": 1, "capabilities_add": [
        {"key": "cap:sql", "name": "control_sql_expression"}]})
    before = _digest(rs.ledger_path(root), ag.graph_path(root))
    with pytest.raises(ResearchKeyConflict):
        rs.apply_delta(root, {"schema_version": 1, **conflicting})
    assert _digest(rs.ledger_path(root), ag.graph_path(root)) == before


def test_a_key_cannot_shadow_the_objective_principal_node(tmp_path: Path) -> None:
    """The seeded principal node holds a key too; nothing may take it over."""
    root = _init(tmp_path)
    before = _digest(rs.ledger_path(root), ag.graph_path(root))
    with pytest.raises(ResearchKeyConflict, match="principal"):
        rs.apply_delta(root, {"schema_version": 1, "capabilities_add": [
            {"key": "objective:principal", "name": "shadow_the_principal"}]})
    assert _digest(rs.ledger_path(root), ag.graph_path(root)) == before


def test_wrong_kind_reference_names_the_kind_it_found(tmp_path: Path) -> None:
    """'unknown reference' would send the author looking in the wrong place."""
    root = _init(tmp_path)
    rs.apply_delta(root, {"schema_version": 1,
                          "facts_add": [{"key": "shared:key", "claim": "a fact"}]})
    with pytest.raises(UnknownReference, match="resolves to a fact"):
        rs.apply_delta(root, {"schema_version": 1, "edges_add": [
            {"key": "edge:wrongkind", "from": "shared:key", "to": "cap:sql",
             "relation": "enables"}]})


def test_same_kind_key_reuse_still_merges(tmp_path: Path) -> None:
    """Guard the other way: global uniqueness must not break ordinary merging."""
    root = _init(tmp_path)
    rs.apply_delta(root, {"schema_version": 1,
                          "facts_add": [{"key": "shared:key", "claim": "a fact"}]})
    report = rs.apply_delta(root, {"schema_version": 1,
                                   "facts_add": [{"key": "shared:key", "claim": "a fact",
                                                  "confidence": "high"}]})
    assert report["created"] == {}
    assert report["merged"]["fact"] == ["FCT-001"]
    assert rs.load_ledger(root)["facts"][0]["confidence"] == "high"


# ---------------------------------------------------------------------------
# P0-3 — one generation across the two research artifacts
# ---------------------------------------------------------------------------


def _generations(root: Path) -> tuple[int, int]:
    return (rs.load_ledger(root)["generation"], ag.load_graph(root)["generation"])


def test_ledger_and_graph_share_a_generation(tmp_path: Path) -> None:
    root = _init(tmp_path)
    assert _generations(root) == (1, 1)

    report = rs.apply_delta(root, {"schema_version": 1,
                                   "facts_add": [{"key": "fact:one", "claim": "a fact"}]})
    assert report["generation"] == 2
    assert _generations(root) == (2, 2)

    rs.apply_delta(root, {"schema_version": 1,
                          "facts_add": [{"key": "fact:two", "claim": "another fact"}]})
    assert _generations(root) == (3, 3)


def test_an_objective_revision_preserves_the_generation(tmp_path: Path) -> None:
    """A revision writes a ledger fact but deliberately leaves the graph alone,
    so it must not advance the counter — advancing it would manufacture a
    mismatch out of a legitimate single-artifact write."""
    root = _init(tmp_path)
    rs.apply_delta(root, {"schema_version": 1,
                          "facts_add": [{"key": "fact:one", "claim": "a fact"}]})
    before = _generations(root)
    objective_mod.replace_and_record(root, {**PROPOSAL, "principal": "someone_else"},
                                     force=True, reason="principal corrected")
    assert _generations(root) == before


def test_generation_mismatch_fails_closed(tmp_path: Path) -> None:
    """A crash between the two writes is the one thing staged validation
    cannot prevent, so it must be detectable on read."""
    root = _init(tmp_path)
    graph = ag.load_graph(root)
    graph["generation"] = 7
    ag.save_graph(root, graph)

    with pytest.raises(rs.ResearchGenerationMismatch) as excinfo:
        rs.load_research_state(root)
    assert excinfo.value.code == "RESEARCH_GENERATION_MISMATCH"
    assert "attack-graph.json is at generation 7" in str(excinfo.value)

    # And no further mutation is allowed on top of an incoherent pair.
    before = _digest(rs.ledger_path(root), ag.graph_path(root))
    with pytest.raises(rs.ResearchGenerationMismatch):
        rs.apply_delta(root, {"schema_version": 1,
                              "facts_add": [{"key": "fact:new", "claim": "should not land"}]})
    assert _digest(rs.ledger_path(root), ag.graph_path(root)) == before


def test_a_missing_graph_is_bootstrapped_at_the_ledger_generation(tmp_path: Path) -> None:
    """A half-created audit self-heals rather than becoming permanently
    incoherent: the new graph adopts the ledger's counter and re-seeds the
    principal node that edges are asserted against."""
    root = _init(tmp_path)
    rs.apply_delta(root, {"schema_version": 1,
                          "facts_add": [{"key": "fact:one", "claim": "a fact"}]})
    ag.graph_path(root).unlink()

    report = rs.apply_delta(root, {"schema_version": 1, "edges_add": [
        {"key": "edge:p->sql", "from": "objective:initial-capability:send_http_request",
         "to": "cap:sql", "relation": "enables"}],
        "capabilities_add": [{"key": "cap:sql", "name": "control_sql_expression"}]})
    assert report["ok"] is True

    graph = ag.load_graph(root)
    assert ag.find_node_by_key(graph, "objective:principal") is not None
    assert _generations(root) == (3, 3)
