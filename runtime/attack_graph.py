"""Attack graph data layer (Search Governance v1, R2-6).

The graph answers one question: *what does the attacker hold now, and how do
those capabilities convert into one another?* It is deliberately a data layer
— ids, consistency and the objective bootstrap live here, while identity
conflict policy lives in :mod:`runtime.research_state`, so that "what counts as
the same object" is decided in exactly one place.

Node types are restricted to ``principal``, ``capability`` and ``goal``. The
proposal also carried a ``state`` node type, which was dropped for v1: there is
no state vocabulary, no producer and no consumer for it, so shipping it would
mean a node type the schema accepts and the runtime does not understand — the
"declared but unchecked" shape that v1.1.1 removed from schema validation.

The principal node and the goal nodes are seeded from the canonical objective
rather than discovered. Without that, "a capability is reachable from the
objective's principal" has no starting point to be measured from.
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any, Iterable, Mapping, Optional, Sequence

from .atomic_io import read_json_or_corrupt, write_json_atomic
from .schema import SchemaError, load_schema, validate_instance


GRAPH_FILENAME = "attack-graph.json"
GRAPH_SCHEMA_NAME = "attack-graph"

NODE_TYPES = ("principal", "capability", "goal")
NODE_STATUSES = ("proposed", "verified", "refuted")
NODE_ORIGINS = ("objective", "research")
EDGE_RELATIONS = ("enables", "requires", "bypasses", "breaks_assumption", "escalates_to")
EDGE_STATUSES = ("proposed", "verified", "blocked", "refuted")
CONFIDENCE_LEVELS = ("unknown", "low", "medium", "high")

NODE_ID_PATTERN = re.compile(r"^(PRIN|CAP|GOAL)-([0-9]{3,})$")
EDGE_ID_PATTERN = re.compile(r"^EDGE-([0-9]{3,})$")


class GraphError(RuntimeError):
    """Raised when the attack graph is malformed or an operation cannot apply."""


# ---------------------------------------------------------------------------
# Paths and load/save
# ---------------------------------------------------------------------------


def graph_path(audit_root: os.PathLike[str] | str) -> Path:
    return Path(audit_root) / GRAPH_FILENAME


def empty_graph(*, audit_id: Optional[str] = None) -> dict[str, Any]:
    graph: dict[str, Any] = {
        "schema_version": 1, "generation": 1, "nodes": [], "edges": [],
    }
    if audit_id:
        graph["audit_id"] = audit_id
    return graph


def load_graph(audit_root: os.PathLike[str] | str) -> Optional[dict[str, Any]]:
    """Return the graph, or ``None`` when the file does not exist."""
    path = graph_path(audit_root)
    if not path.exists():
        return None
    data = read_json_or_corrupt(path)
    if not isinstance(data, dict):
        raise GraphError(f"{path} does not contain a JSON object")
    return data


def save_graph(audit_root: os.PathLike[str] | str, graph: Mapping[str, Any]) -> None:
    write_json_atomic(graph_path(audit_root), dict(graph))


def validate_graph(graph: Mapping[str, Any]) -> list[SchemaError]:
    return validate_instance(graph, load_schema(GRAPH_SCHEMA_NAME), use_jsonschema=False)


def validate_graph_raise(graph: Mapping[str, Any], *, artifact: str = GRAPH_FILENAME) -> None:
    errors = validate_graph(graph)
    if errors:
        detail = "; ".join(str(e) for e in errors[:5])
        more = f" (+{len(errors) - 5} more)" if len(errors) > 5 else ""
        raise GraphError(f"attack graph failed schema validation in {artifact}: {detail}{more}")


# ---------------------------------------------------------------------------
# Lookup
# ---------------------------------------------------------------------------


def node_index(graph: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
    """Map node id → node."""
    return {str(node.get("id")): node for node in graph.get("nodes", []) if isinstance(node, dict)}


def edge_index(graph: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
    return {str(edge.get("id")): edge for edge in graph.get("edges", []) if isinstance(edge, dict)}


def find_node_by_key(graph: Mapping[str, Any], key: str) -> Optional[dict[str, Any]]:
    for node in graph.get("nodes", []):
        if isinstance(node, dict) and node.get("key") == key:
            return node
    return None


def find_node_by_id(graph: Mapping[str, Any], node_id: str) -> Optional[dict[str, Any]]:
    return node_index(graph).get(node_id)


def find_edge_by_key(graph: Mapping[str, Any], key: str) -> Optional[dict[str, Any]]:
    for edge in graph.get("edges", []):
        if isinstance(edge, dict) and edge.get("key") == key:
            return edge
    return None


def find_edge_by_id(graph: Mapping[str, Any], edge_id: str) -> Optional[dict[str, Any]]:
    return edge_index(graph).get(edge_id)


def node_identity(node: Mapping[str, Any]) -> tuple:
    """The fields that decide whether two capability nodes are the same object.

    ``name`` alone is not enough: the same name held by two principals is two
    capabilities, which is exactly the case the proposal calls out
    (``anonymous → control_sql_expression`` vs
    ``authenticated_user → control_sql_expression``).
    """
    return (node.get("type"), node.get("name"), node.get("principal") or "")


def edge_identity(edge: Mapping[str, Any]) -> tuple:
    return (edge.get("from"), edge.get("to"), edge.get("relation"), edge.get("via_candidate") or "")


def resolve_node_ref(graph: Mapping[str, Any], ref: str) -> Optional[dict[str, Any]]:
    """Resolve a reference that may be a canonical id or a semantic key."""
    node = find_node_by_id(graph, ref)
    if node is not None:
        return node
    return find_node_by_key(graph, ref)


# ---------------------------------------------------------------------------
# Mutation primitives
# ---------------------------------------------------------------------------


def _next_id(existing: Iterable[Mapping[str, Any]], pattern: re.Pattern[str], prefix: str) -> str:
    highest = 0
    for item in existing:
        match = pattern.match(str(item.get("id", "")))
        if match:
            # Both patterns end in the numeric group, so the last group is the
            # counter whether or not the pattern also captures the prefix.
            highest = max(highest, int(match.groups()[-1]))
    return f"{prefix}-{highest + 1:03d}"


def next_node_id(graph: Mapping[str, Any], node_type: str) -> str:
    prefix = {"principal": "PRIN", "capability": "CAP", "goal": "GOAL"}[node_type]
    # Numbering is per prefix: a goal must not consume a capability's number.
    same_prefix = [n for n in graph.get("nodes", [])
                   if str(n.get("id", "")).startswith(f"{prefix}-")]
    return _next_id(same_prefix, NODE_ID_PATTERN, prefix)


def next_edge_id(graph: Mapping[str, Any]) -> str:
    return _next_id(graph.get("edges", []), EDGE_ID_PATTERN, "EDGE")


def add_node(graph: dict[str, Any], *, key: str, type: str, name: str,
             principal: Optional[str] = None, status: str = "proposed",
             origin: str = "research", **fields: Any) -> dict[str, Any]:
    """Append a node with an allocated id. Callers must have checked for an
    existing object with the same key first."""
    if type not in NODE_TYPES:
        raise GraphError(f"unknown node type {type!r}; v1 allows {list(NODE_TYPES)}")
    node: dict[str, Any] = {
        "id": next_node_id(graph, type),
        "key": key,
        "type": type,
        "name": name,
        "status": status,
        "origin": origin,
    }
    if principal:
        node["principal"] = principal
    node.update({k: v for k, v in fields.items() if v is not None})
    graph.setdefault("nodes", []).append(node)
    return node


def add_edge(graph: dict[str, Any], *, key: str, src: str, dst: str, relation: str,
             status: str = "proposed", **fields: Any) -> dict[str, Any]:
    """Append an edge. ``src``/``dst`` must already be canonical node ids —
    callers resolve semantic-key forward references before calling this."""
    if relation not in EDGE_RELATIONS:
        raise GraphError(f"unknown edge relation {relation!r}; v1 allows {list(EDGE_RELATIONS)}")
    edge: dict[str, Any] = {
        "id": next_edge_id(graph),
        "key": key,
        "from": src,
        "to": dst,
        "relation": relation,
        "status": status,
    }
    edge.update({k: v for k, v in fields.items() if v is not None})
    graph.setdefault("edges", []).append(edge)
    return edge


# ---------------------------------------------------------------------------
# Consistency
# ---------------------------------------------------------------------------


def inconsistencies(graph: Mapping[str, Any]) -> list[str]:
    """Structural problems that must never reach disk.

    A dangling edge reference is the interesting one: it makes a "this
    capability is reachable from the principal" claim unverifiable while the
    artifact still looks like a well-formed graph.
    """
    problems: list[str] = []
    seen_ids: set[str] = set()
    for node in graph.get("nodes", []):
        node_id = str(node.get("id", ""))
        if node_id in seen_ids:
            problems.append(f"duplicate node id {node_id!r}")
        seen_ids.add(node_id)

    seen_keys: set[str] = set()
    for node in graph.get("nodes", []):
        key = str(node.get("key", ""))
        if key in seen_keys:
            problems.append(f"duplicate node key {key!r}")
        seen_keys.add(key)

    for edge in graph.get("edges", []):
        for field_name in ("from", "to"):
            ref = str(edge.get(field_name, ""))
            if ref not in seen_ids:
                problems.append(
                    f"edge {edge.get('id')!r} references unknown node {ref!r} "
                    f"in {field_name!r}"
                )
    return problems


def require_consistent(graph: Mapping[str, Any]) -> None:
    problems = inconsistencies(graph)
    if problems:
        raise GraphError("attack graph is inconsistent: " + "; ".join(problems[:5]))


# ---------------------------------------------------------------------------
# Traversal
# ---------------------------------------------------------------------------

#: Relations walked *forwards* when asking "what else can the attacker get?".
#:
#: ``requires`` is deliberately not here. It points from a capability to its
#: prerequisite, so holding the prerequisite is what unlocks the dependent:
#: it is walked **backwards**. Reading it forwards would mean "holding C-17
#: grants you its prerequisite", which is the opposite of what the relation
#: says — and it would make the `prerequisite` role, and therefore blocked-path
#: reopening, mean nothing.
FORWARD_RELATIONS: tuple[str, ...] = (
    "enables", "escalates_to", "bypasses", "breaks_assumption",
)
REVERSE_RELATIONS: tuple[str, ...] = ("requires",)

TRAVERSABLE_STATUS = "verified"
FRONTIER_STATUSES = ("proposed", "blocked")

#: Everything except `refuted`. Used when the question is "how far *could* this
#: be", not "how far is this proven to be" — a proposed edge is a hypothesis
#: worth ranking, while a refuted one is a known dead end.
POTENTIAL_STATUSES: tuple[str, ...] = ("verified", "proposed", "blocked")


def _traversal_edges(graph: Mapping[str, Any],
                     statuses: Sequence[str] = (TRAVERSABLE_STATUS,),
                     ) -> list[tuple[str, str, dict[str, Any]]]:
    """``(from, to, edge)`` pairs after applying the per-relation direction rule.

    Sorted, so every BFS in this module is deterministic — a graph traversal
    whose answer depends on dict ordering is untestable.
    """
    pairs: list[tuple[str, str, dict[str, Any]]] = []
    for edge in graph.get("edges", []):
        if not isinstance(edge, dict) or edge.get("status") not in statuses:
            continue
        relation = edge.get("relation")
        src, dst = str(edge.get("from")), str(edge.get("to"))
        if relation in FORWARD_RELATIONS:
            pairs.append((src, dst, edge))
        elif relation in REVERSE_RELATIONS:
            pairs.append((dst, src, edge))
    return sorted(pairs, key=lambda item: (item[0], item[1], str(item[2].get("id"))))


def traversal_neighbours(graph: Mapping[str, Any], node_id: str,
                         statuses: Sequence[str] = (TRAVERSABLE_STATUS,),
                         ) -> list[dict[str, Any]]:
    """Edges leading *out of* ``node_id`` in the traversal sense.

    The public form of :func:`_traversal_edges` filtered to one node, so
    callers asking "does anything consume this capability?" do not have to
    reach into a private helper or re-derive the direction rule.
    """
    return [edge for parent, _child, edge in _traversal_edges(graph, tuple(statuses))
            if parent == node_id]


def _bfs(pairs: Sequence[tuple[str, str, dict[str, Any]]], starts: Iterable[str],
         ) -> tuple[dict[str, int], dict[str, tuple[str, dict[str, Any]]]]:
    """Breadth-first distances plus the first arriving (previous, edge)."""
    adjacency: dict[str, list[tuple[str, dict[str, Any]]]] = {}
    for src, dst, edge in pairs:
        adjacency.setdefault(src, []).append((dst, edge))

    distance: dict[str, int] = {}
    came_from: dict[str, tuple[str, dict[str, Any]]] = {}
    queue: list[str] = []
    for start in sorted(set(starts)):
        if start not in distance:
            distance[start] = 0
            queue.append(start)

    cursor = 0
    while cursor < len(queue):
        node = queue[cursor]
        cursor += 1
        for neighbour, edge in adjacency.get(node, []):
            if neighbour in distance:
                continue
            distance[neighbour] = distance[node] + 1
            came_from[neighbour] = (node, edge)
            queue.append(neighbour)
    return distance, came_from


def start_nodes(graph: Mapping[str, Any]) -> list[str]:
    """Where reachability begins: the principal and the objective's capabilities.

    These are definitional — the objective declares that this principal holds
    these capabilities before any bug is found — so they are never required to
    carry exploit evidence of their own.
    """
    starts: list[str] = []
    for node in graph.get("nodes", []):
        if not isinstance(node, Mapping):
            continue
        if node.get("type") == "principal":
            starts.append(str(node.get("id")))
        elif node.get("type") == "capability" and node.get("origin") == "objective":
            starts.append(str(node.get("id")))
    return sorted(starts)


def goal_nodes(graph: Mapping[str, Any]) -> list[str]:
    return sorted(str(n.get("id")) for n in graph.get("nodes", [])
                  if isinstance(n, Mapping) and n.get("type") == "goal")


def _established(graph: Mapping[str, Any], node_id: str) -> bool:
    """Is this node something the attacker is *demonstrated* to have?

    A node counts only when its own status is ``verified`` — the same word, and
    the same meaning, as for an edge. Without this, a capability marked
    ``refuted`` (investigated, found not to exist) would still be reported as
    held because some edge points at it, and a ``proposed`` one would be
    promoted by an edge alone. Both readings are fail-open, and the second also
    makes the node status enum decorative.
    """
    node = find_node_by_id(graph, node_id)
    return node is not None and node.get("status") == TRAVERSABLE_STATUS


def _established_pairs(graph: Mapping[str, Any],
                       statuses: Sequence[str] = (TRAVERSABLE_STATUS,),
                       ) -> list[tuple[str, str, dict[str, Any]]]:
    """:func:`_traversal_edges`, keeping only hops between established nodes.

    Used by the queries that answer "what does the attacker hold?" and "is this
    demonstrated?", where an unestablished waypoint means the route is not
    established either. Deliberately *not* used by :func:`blocked_frontier`,
    whose whole purpose is to look at edges whose far side is not yet held —
    applying the rule there would filter out every frontier edge.
    """
    return [pair for pair in _traversal_edges(graph, statuses)
            if _established(graph, pair[0]) and _established(graph, pair[1])]


def verified_reachable(graph: Mapping[str, Any],
                       starts: Optional[Iterable[str]] = None) -> set[str]:
    """Node ids reachable from *starts* using **verified** edges and nodes only.

    proposed / blocked / refuted edges are all excluded: a proposed edge is a
    hypothesis, and letting one make a capability "reachable" is exactly the
    "treat a claim as evidence" failure this runtime exists to prevent. The
    intermediate nodes must be established too — see :func:`_established`.
    """
    seed = [node for node in (list(starts) if starts is not None else start_nodes(graph))
            if _established(graph, node)]
    distance, _ = _bfs(_established_pairs(graph), seed)
    return set(distance)


def reachable_capabilities(graph: Mapping[str, Any]) -> dict[str, Any]:
    """Which capabilities the attacker is *demonstrated* to hold.

    Also reports verified capabilities that are **not** reachable. Those are the
    interesting ones: something established them as real, but nothing connects
    them to the entry point the objective declares.
    """
    nodes = node_index(graph)
    reachable = verified_reachable(graph)
    capabilities = sorted(nid for nid, node in nodes.items()
                          if node.get("type") == "capability")
    return {
        "start_nodes": start_nodes(graph),
        "reachable": sorted(reachable),
        "reachable_capabilities": [nid for nid in capabilities if nid in reachable],
        "unreachable_verified_capabilities": [
            nid for nid in capabilities
            if nid not in reachable and nodes[nid].get("status") == TRAVERSABLE_STATUS
        ],
    }


def verified_path(graph: Mapping[str, Any], src: str, dst: str) -> dict[str, Any]:
    """Shortest path from *src* to *dst* using verified edges and nodes only.

    Same rule as :func:`verified_reachable`, so the two cannot disagree about
    whether something is demonstrated. ``src``/``dst`` may be canonical ids or
    semantic keys. Raises :class:`GraphError` when a reference names no node —
    that is a caller error, not a negative answer, and conflating the two would
    let a typo read as "unreachable".
    """
    from_node = resolve_node_ref(graph, src)
    to_node = resolve_node_ref(graph, dst)
    if from_node is None:
        raise GraphError(f"no node matches reference {src!r}")
    if to_node is None:
        raise GraphError(f"no node matches reference {dst!r}")

    start_id, goal_id = str(from_node.get("id")), str(to_node.get("id"))
    if goal_id != start_id and not _established(graph, goal_id):
        return {"reachable": False, "from": start_id, "to": goal_id,
                "nodes": [], "edges": [], "hops": None}
    distance, came_from = _bfs(_established_pairs(graph), [start_id])
    if goal_id not in distance:
        return {"reachable": False, "from": start_id, "to": goal_id,
                "nodes": [], "edges": [], "hops": None}

    node_chain = [goal_id]
    edge_chain: list[str] = []
    cursor = goal_id
    while cursor != start_id:
        previous, edge = came_from[cursor]
        edge_chain.append(str(edge.get("id")))
        node_chain.append(previous)
        cursor = previous
    return {
        "reachable": True,
        "from": start_id,
        "to": goal_id,
        "hops": distance[goal_id],
        "nodes": list(reversed(node_chain)),
        "edges": list(reversed(edge_chain)),
    }


def paths_to_goals(graph: Mapping[str, Any]) -> dict[str, Any]:
    """Which declared goals are demonstrated reachable, and by what path."""
    nodes = node_index(graph)
    starts = start_nodes(graph)
    reachable: list[dict[str, Any]] = []
    unreachable: list[dict[str, Any]] = []
    for goal in goal_nodes(graph):
        best: Optional[dict[str, Any]] = None
        for start in starts:
            path = verified_path(graph, start, goal)
            if path["reachable"] and (best is None or path["hops"] < best["hops"]):
                best = {**path, "start": start}
        entry = {"goal": goal, "name": nodes.get(goal, {}).get("name")}
        if best is None:
            unreachable.append(entry)
        else:
            reachable.append({**entry, "path": best})
    return {
        "start_nodes": starts,
        "reachable_goals": reachable,
        "unreachable_goals": unreachable,
    }


def goal_distance(graph: Mapping[str, Any],
                  statuses: Sequence[str] = (TRAVERSABLE_STATUS,)) -> dict[str, Any]:
    """Hops from each node to the nearest goal (``None``/absent = no route).

    Computed by walking the graph backwards from the goals, so the number
    answers "how close is this node to something we are trying to reach".

    ``statuses`` decides what the number *means*, and the two readings are both
    needed:

    * ``("verified",)`` — **proven** distance. This is what a closure claim
      must use: a path is either demonstrated or it is not.
    * :data:`POTENTIAL_STATUSES` — **possible** distance, counting proposed and
      blocked edges. This is what prioritisation must use. With the strict
      reading, every node is "unreachable to goal" until the goal is finally
      taken, so "does this block a path near a goal" would be false for the
      entire search and the rule that depends on it would never fire.
    """
    pairs = _traversal_edges(graph, tuple(statuses))
    reversed_pairs = [(dst, src, edge) for src, dst, edge in pairs]
    distance, _ = _bfs(reversed_pairs, goal_nodes(graph))
    return {
        "hops_to_goal": dict(sorted(distance.items())),
        "unreachable_nodes": sorted(
            str(n.get("id")) for n in graph.get("nodes", [])
            if isinstance(n, Mapping) and str(n.get("id")) not in distance
        ),
    }


def blocked_frontier(graph: Mapping[str, Any]) -> list[dict[str, Any]]:
    """The next edges that would move the search forward, and what they unlock.

    An edge at the boundary of the verified region whose status is still
    `proposed` or `blocked` is the cheapest place to spend the next round: the
    capability on the far side is already one step from something we hold.
    `refuted` edges are excluded — they are known dead ends.

    Each entry names the edge's own endpoints (``edge_from``/``edge_to``) *and*
    the traversal sense (``held`` → ``unlocks``). The two differ for a
    `requires` edge, and reporting only one of them would make the output
    contradict the graph file.
    """
    reachable = verified_reachable(graph)
    nodes = node_index(graph)
    frontier: list[dict[str, Any]] = []
    for held, unlocked, edge in _traversal_edges(graph, FRONTIER_STATUSES):
        if held not in reachable or unlocked in reachable:
            continue
        node = nodes.get(unlocked, {})
        frontier.append({
            "edge": str(edge.get("id")),
            "key": edge.get("key"),
            "relation": edge.get("relation"),
            "status": edge.get("status"),
            "edge_from": edge.get("from"),
            "edge_to": edge.get("to"),
            "held": held,
            "unlocks": unlocked,
            "unlocks_type": node.get("type"),
            "unlocks_name": node.get("name"),
            "via_candidate": edge.get("via_candidate"),
        })
    return sorted(frontier, key=lambda item: (item["status"] != "blocked", item["edge"]))


def graph_summary(graph: Mapping[str, Any]) -> dict[str, Any]:
    """One-shot description used by ``graph show``."""
    nodes = graph.get("nodes", [])
    by_type: dict[str, int] = {}
    by_status: dict[str, int] = {}
    for node in nodes:
        if not isinstance(node, Mapping):
            continue
        by_type[str(node.get("type"))] = by_type.get(str(node.get("type")), 0) + 1
        by_status[str(node.get("status"))] = by_status.get(str(node.get("status")), 0) + 1
    edge_status: dict[str, int] = {}
    for edge in graph.get("edges", []):
        if isinstance(edge, Mapping):
            edge_status[str(edge.get("status"))] = edge_status.get(str(edge.get("status")), 0) + 1
    return {
        "generation": graph.get("generation"),
        "nodes": len(nodes),
        "edges": len(graph.get("edges", [])),
        "nodes_by_type": dict(sorted(by_type.items())),
        "nodes_by_status": dict(sorted(by_status.items())),
        "edges_by_status": dict(sorted(edge_status.items())),
        "start_nodes": start_nodes(graph),
        "goals": goal_nodes(graph),
    }


# ---------------------------------------------------------------------------
# Objective bootstrap
# ---------------------------------------------------------------------------

OBJECTIVE_PRINCIPAL_KEY = "objective:principal"
OBJECTIVE_INITIAL_KEY = "objective:initial-capability:{name}"
OBJECTIVE_GOAL_KEY = "objective:goal:{name}"


def seed_from_objective(graph: dict[str, Any],
                        objective: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Seed the principal, the initial capabilities and the goal nodes.

    Idempotent: a key that already exists is left alone, so re-running the
    bootstrap after a failed transaction cannot duplicate nodes.
    """
    principal = str(objective.get("principal") or "")
    if not principal:
        raise GraphError("cannot seed the attack graph: the objective has no principal")

    added: list[dict[str, Any]] = []
    if find_node_by_key(graph, OBJECTIVE_PRINCIPAL_KEY) is None:
        added.append(add_node(
            graph, key=OBJECTIVE_PRINCIPAL_KEY, type="principal", name=principal,
            status="verified", origin="objective",
        ))
    for name in objective.get("initial_capabilities") or []:
        key = OBJECTIVE_INITIAL_KEY.format(name=name)
        if find_node_by_key(graph, key) is None:
            added.append(add_node(
                graph, key=key, type="capability", name=str(name),
                principal=principal, status="verified", origin="objective",
            ))
    for name in objective.get("target_capabilities") or []:
        key = OBJECTIVE_GOAL_KEY.format(name=name)
        if find_node_by_key(graph, key) is None:
            added.append(add_node(
                graph, key=key, type="goal", name=str(name),
                status="verified", origin="objective",
            ))
    return added
