"""Attack graph traversal semantics (Phase B / §3, §23).

The properties that matter here are about *direction* and *status*, because
those are the two places a graph query can quietly be wrong in a way that reads
as a plausible answer:

* only ``verified`` edges carry a claim — a ``proposed`` edge is a hypothesis
  and a ``refuted`` one is a known dead end;
* ``requires`` points from a capability to its prerequisite, so it is walked
  backwards. Read forwards it would mean "holding C-17 grants you its
  prerequisite", which is the opposite of what the relation says and would make
  the ``prerequisite`` role mean nothing.
"""
from __future__ import annotations

import pytest

from runtime import attack_graph as ag


def _node(node_id: str, node_type: str, name: str, *, status: str = "proposed",
          origin: str = "research", principal: str | None = None) -> dict:
    node = {"id": node_id, "key": f"k:{node_id}", "type": node_type, "name": name,
            "status": status, "origin": origin}
    if principal:
        node["principal"] = principal
    return node


def _edge(edge_id: str, src: str, dst: str, relation: str, *,
          status: str = "proposed", via: str | None = None) -> dict:
    edge = {"id": edge_id, "key": f"e:{edge_id}", "from": src, "to": dst,
            "relation": relation, "status": status}
    if via:
        edge["via_candidate"] = via
    return edge


def _graph() -> dict:
    """A deliberately awkward graph.

    CAP-005 is one blocked `requires` edge from a held capability; CAP-006 is
    unlocked by a *verified* `requires` edge (holding its prerequisite is what
    makes it reachable); CAP-007 needs something we do not have, so a verified
    `requires` edge pointing at it must not make it reachable.
    """
    return {
        "schema_version": 1, "generation": 1,
        "nodes": [
            _node("PRIN-001", "principal", "unauthenticated_remote_user",
                  status="verified", origin="objective"),
            _node("CAP-001", "capability", "send_http_request",
                  status="verified", origin="objective", principal="unauthenticated_remote_user"),
            _node("CAP-002", "capability", "control_scalar_parameter", status="verified"),
            _node("CAP-003", "capability", "control_sql_expression", status="verified"),
            _node("CAP-004", "capability", "privileged_state_mutation"),
            _node("CAP-005", "capability", "db_write"),
            _node("CAP-006", "capability", "dependent_on_scalar", status="verified"),
            _node("CAP-007", "capability", "needs_the_dependent"),
            _node("CAP-008", "capability", "proposed_but_pointed_at", status="proposed"),
            _node("GOAL-001", "goal", "arbitrary_code_execution", status="verified"),
            _node("GOAL-002", "goal", "read_other_tenant_data", status="verified"),
        ],
        "edges": [
            _edge("EDGE-001", "CAP-001", "CAP-002", "enables", status="verified"),
            _edge("EDGE-002", "CAP-002", "CAP-003", "enables", status="verified"),
            _edge("EDGE-003", "CAP-003", "CAP-004", "enables", status="proposed",
                  via="cand-017"),
            _edge("EDGE-004", "CAP-005", "CAP-002", "requires", status="blocked"),
            _edge("EDGE-005", "CAP-006", "CAP-002", "requires", status="verified"),
            _edge("EDGE-006", "CAP-002", "CAP-007", "requires", status="verified"),
            _edge("EDGE-007", "CAP-004", "GOAL-001", "enables", status="proposed"),
            _edge("EDGE-008", "CAP-003", "GOAL-002", "enables", status="verified"),
            _edge("EDGE-009", "CAP-003", "CAP-008", "enables", status="verified"),
        ],
    }


def test_a_capability_must_be_established_in_its_own_right() -> None:
    """A verified inbound edge is not enough.

    CAP-008 sits behind a verified edge from a held capability, but the
    capability itself is still only ``proposed`` — believed to exist, not
    established. Counting it as held would let an edge promote a hypothesis,
    and would make the node status enum decorative. The same rule keeps a
    ``refuted`` capability out even when something points at it.
    """
    graph = _graph()
    assert ag.verified_path(graph, "CAP-001", "CAP-008")["reachable"] is False
    assert "CAP-008" not in ag.reachable_capabilities(graph)["reachable"]

    _node_by_id(graph, "CAP-008")["status"] = "verified"
    assert ag.verified_path(graph, "CAP-001", "CAP-008")["reachable"] is True

    _node_by_id(graph, "CAP-008")["status"] = "refuted"
    assert ag.verified_path(graph, "CAP-001", "CAP-008")["reachable"] is False


def test_reachability_starts_from_the_objective_not_from_every_verified_node() -> None:
    """The principal and the objective's capabilities are definitional.

    They are declared to be held before any bug is found, so they are never
    required to carry exploit evidence — but a *researched* capability that
    nothing connects to the entry point is not reachable merely because someone
    marked it verified.
    """
    graph = _graph()
    assert ag.start_nodes(graph) == ["CAP-001", "PRIN-001"]
    report = ag.reachable_capabilities(graph)
    assert report["reachable_capabilities"] == ["CAP-001", "CAP-002", "CAP-003", "CAP-006"]
    assert "CAP-004" not in report["reachable"]
    assert "CAP-005" not in report["reachable"]


def _node_by_id(graph: dict, node_id: str) -> dict:
    return next(node for node in graph["nodes"] if node["id"] == node_id)


def test_verified_path_ignores_proposed_blocked_and_refuted_edges() -> None:
    """An unverified edge cannot carry a claim — and neither can an
    unestablished node, so both have to be promoted before the route is real."""
    graph = _graph()
    _node_by_id(graph, "CAP-004")["status"] = "verified"
    for status in ("proposed", "blocked", "refuted"):
        graph["edges"][2]["status"] = status
        assert ag.verified_path(graph, "CAP-001", "CAP-004")["reachable"] is False, status
    graph["edges"][2]["status"] = "verified"
    assert ag.verified_path(graph, "CAP-001", "CAP-004")["reachable"] is True


def test_verified_path_returns_the_route_it_used() -> None:
    path = ag.verified_path(_graph(), "CAP-001", "CAP-003")
    assert path["reachable"] is True
    assert path["hops"] == 2
    assert path["nodes"] == ["CAP-001", "CAP-002", "CAP-003"]
    assert path["edges"] == ["EDGE-001", "EDGE-002"]


def test_requires_is_walked_backwards_only() -> None:
    """Holding a prerequisite unlocks the dependent; holding the dependent does
    not conjure up its prerequisite."""
    graph = _graph()
    assert ag.verified_path(graph, "CAP-001", "CAP-006")["reachable"] is True
    assert ag.verified_path(graph, "CAP-002", "CAP-007")["reachable"] is False


def test_references_resolve_by_canonical_id_or_semantic_key() -> None:
    graph = _graph()
    by_id = ag.verified_path(graph, "CAP-001", "CAP-003")
    by_key = ag.verified_path(graph, "k:CAP-001", "k:CAP-003")
    assert by_id["nodes"] == by_key["nodes"]


def test_an_unknown_reference_raises_rather_than_reading_as_unreachable() -> None:
    """A typo must not look like a negative finding."""
    with pytest.raises(ag.GraphError, match="no node matches"):
        ag.verified_path(_graph(), "CAP-001", "cap:typo")


def test_goal_reachability_reports_both_sides() -> None:
    result = ag.paths_to_goals(_graph())
    assert [entry["goal"] for entry in result["reachable_goals"]] == ["GOAL-002"]
    assert [entry["goal"] for entry in result["unreachable_goals"]] == ["GOAL-001"]
    assert result["reachable_goals"][0]["path"]["edges"] == ["EDGE-001", "EDGE-002", "EDGE-008"]


def test_frontier_is_the_boundary_of_the_verified_region() -> None:
    frontier = ag.blocked_frontier(_graph())
    assert {entry["edge"] for entry in frontier} == {"EDGE-003", "EDGE-004"}
    # A blocked edge is a known obstacle; a proposed one is an untested idea.
    assert frontier[0]["status"] == "blocked"
    assert frontier[0]["unlocks_name"] == "db_write"
    # The edge's own direction and the traversal sense differ for `requires`,
    # and both are reported so the output cannot contradict the graph file.
    assert frontier[0]["edge_from"] == "CAP-005" and frontier[0]["edge_to"] == "CAP-002"
    assert frontier[0]["held"] == "CAP-002" and frontier[0]["unlocks"] == "CAP-005"
    proposed = next(entry for entry in frontier if entry["edge"] == "EDGE-003")
    assert proposed["via_candidate"] == "cand-017"


def test_goal_distance_has_two_readings() -> None:
    """Proven distance guards a claim; potential distance ranks the next move."""
    graph = _graph()
    proven = ag.goal_distance(graph)["hops_to_goal"]
    potential = ag.goal_distance(graph, statuses=ag.POTENTIAL_STATUSES)["hops_to_goal"]
    assert "GOAL-002" in proven and proven["CAP-003"] == 1
    # CAP-004 reaches GOAL-001 only through a proposed edge, so it is invisible
    # to the proven reading and one hop away in the potential one.
    assert "CAP-004" not in proven
    assert potential["CAP-004"] == 1


def test_summary_counts_by_type_and_status() -> None:
    summary = ag.graph_summary(_graph())
    assert summary["nodes"] == 11
    assert summary["edges"] == 9
    assert summary["nodes_by_type"] == {"capability": 8, "goal": 2, "principal": 1}
    assert summary["edges_by_status"] == {"blocked": 1, "proposed": 2, "verified": 6}
