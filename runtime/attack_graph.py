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
    graph: dict[str, Any] = {"schema_version": 1, "nodes": [], "edges": []}
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
