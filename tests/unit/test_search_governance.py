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
                              "questions_add": [{"key": "same", "question": "q?"}]})


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
# Assumption lifecycle side effects (bidirectional)
# ---------------------------------------------------------------------------


def test_assumption_disproved_reopens_the_dependent_blocked_path(tmp_path: Path) -> None:
    root = _init(tmp_path)
    _write_candidate(tmp_path)
    rs.apply_delta(root, _delta())

    report = rs.apply_delta(root, {"schema_version": 1, "assumptions_update": [
        {"ref": "assumption:author_exclude-int-array", "status": "disproved",
         "evidence_refs": ["src/other-caller.php:40"]}]})

    assert report["reopened_blocked_paths"] == ["BP-001"]
    assert report["assumption_transitions"] == [
        {"id": "A-001", "from": "unverified", "to": "disproved"}]
    ledger = rs.load_ledger(root)
    assert ledger["blocked_paths"][0]["status"] == "reopened"
    # Reopening a path is not rejecting the candidate: the two lifecycles stay separate.
    saved = json.loads((tmp_path / "mini-audit" / "candidates"
                        / "review-chamber-candidates.json").read_text(encoding="utf-8"))
    assert saved["candidates"][0]["status"] == "needs_validation"


def test_assumption_supported_closes_the_blocked_path(tmp_path: Path) -> None:
    root = _init(tmp_path)
    _write_candidate(tmp_path)
    rs.apply_delta(root, _delta())

    report = rs.apply_delta(root, {"schema_version": 1, "assumptions_update": [
        {"ref": "assumption:author_exclude-int-array", "status": "supported",
         "evidence_refs": ["src/rest-handler.php:88"]}]})

    assert report["closed_blocked_paths"] == [{"id": "BP-001", "reason": "blocker_supported"}]
    path = rs.load_ledger(root)["blocked_paths"][0]
    assert path["status"] == "closed"
    assert path["close_reason"] == "blocker_supported"


def test_blocked_path_reopen_operation_is_explicit(tmp_path: Path) -> None:
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
    doc = {"schema_version": 1, "facts": [], "assumptions": [], "open_questions": [],
           "blocked_paths": [], "intents": []}
    doc.update(overrides)
    return doc


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
    assert _validate({"schema_version": 1, "nodes": [node], "edges": []}, "attack-graph")


@pytest.mark.parametrize("node_type", ["principal", "capability", "goal"])
def test_attack_graph_allows_only_the_three_v1_node_types(node_type: str) -> None:
    prefix = {"principal": "PRIN", "capability": "CAP", "goal": "GOAL"}[node_type]
    node = {"id": f"{prefix}-001", "key": "k", "type": node_type, "name": "n",
            "status": "proposed"}
    assert _validate({"schema_version": 1, "nodes": [node], "edges": []}, "attack-graph") == []


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
