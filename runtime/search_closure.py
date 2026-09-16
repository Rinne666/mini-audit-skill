"""Capability closure — does a reported attack chain actually reach? (R2-4 / §14).

One verdict is shared by two callers, which is why it lives in its own module
rather than inside either of them:

* the L7 gate's ``reported_capability_paths_closed`` semantic check, which
  turns a failure into a hard block;
* the Search Governor's P0 rule 4, which turns a failure into the next
  investigation.

Two copies of a rule that decide the same thing drift apart — the same reason
``schema.py`` exists instead of a hand-written validator beside a schema.

What this deliberately does **not** do: compare ``after_capability`` prose to a
capability name. Text matching breaks on the first rewording and would make the
check advisory in practice. The bridge is an id that resolves.

The closure rules, per confirmed finding:

1. ``boundary.capability_refs`` is non-empty;
2. every ref exists in the attack graph and is a ``capability`` node;
3. that capability is reachable from the objective's principal / initial
   capabilities over **verified** edges;
4. every edge on that path is verified;
5. every edge's ``via_candidate``, when present, resolves to a real candidate;
6. every declared ``evidence_refs`` / ``verification_refs`` resolves to a file
   that exists.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Iterable, Mapping, Optional, Sequence

from . import attack_graph as graph_mod


class ClosureResult:
    """Outcome of one closure evaluation."""

    def __init__(self) -> None:
        self.failures: list[str] = []
        self.checked_findings: int = 0
        self.checked_refs: int = 0
        self.notes: list[str] = []

    @property
    def closed(self) -> bool:
        return not self.failures

    def add(self, message: str) -> None:
        self.failures.append(message)

    def to_dict(self) -> dict[str, Any]:
        return {
            "closed": self.closed,
            "failures": list(self.failures),
            "checked_findings": self.checked_findings,
            "checked_refs": self.checked_refs,
            "notes": list(self.notes),
        }


def _iter_refs(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, Iterable) and not isinstance(value, Mapping):
        return [str(item) for item in value if isinstance(item, (str, int))]
    return []


def _resolve_reference(base_dir: Optional[Path], ref: str) -> Optional[Path]:
    """Resolve an evidence reference to a path, tolerating ``file:line`` forms.

    References inside the research plane are opaque strings: some are relative
    to the audit root, some to the repository root. Both spellings are tried
    against the base directory the caller supplied, and a bare ``path:LINE`` is
    accepted by stripping the line suffix. Anything that resolves nowhere is a
    dangling reference, which is what the closure check exists to catch.
    """
    if base_dir is None:
        return None
    candidate = ref.strip()
    if not candidate:
        return None
    attempts = [candidate]
    head, sep, tail = candidate.rpartition(":")
    if sep and tail.isdigit():
        attempts.append(head)
    for attempt in attempts:
        path = Path(attempt)
        resolved = path if path.is_absolute() else base_dir / path
        if resolved.exists():
            return resolved
    return None


def evaluate_finding_closure(
    finding: Mapping[str, Any],
    graph: Mapping[str, Any],
    candidates: Mapping[str, Any],
    *,
    base_dir: Optional[os.PathLike[str] | str] = None,
    result: Optional[ClosureResult] = None,
    require_refs: bool = True,
) -> ClosureResult:
    """Check one finding's capability refs against the graph."""
    result = result if result is not None else ClosureResult()
    base = Path(base_dir).resolve() if base_dir is not None else None
    label = str(finding.get("id") or "<finding>")

    boundary = finding.get("boundary")
    refs = _iter_refs((boundary or {}).get("capability_refs")) if isinstance(boundary, Mapping) else []

    if not refs:
        if require_refs:
            result.add(
                f"{label} is confirmed but declares no boundary.capability_refs; "
                "a Search Governance-enabled audit must say which capability it grants"
            )
        return result

    nodes = graph_mod.node_index(graph)
    for ref in dict.fromkeys(refs):
        result.checked_refs += 1
        node = nodes.get(ref)
        if node is None:
            result.add(f"{label} references {ref}, which exists in no attack graph node")
            continue
        if node.get("type") != "capability":
            result.add(
                f"{label} references {ref}, whose node type is "
                f"{node.get('type')!r}, not 'capability'"
            )
            continue

        path = _path_from_any_start(graph, ref)
        if path is None:
            result.add(
                f"{label} references {ref} ({node.get('name')!r}), which is not "
                "reachable from the objective's principal or initial capabilities "
                "over verified edges"
            )
            continue

        # Rule 4/5: the edges that carry the claim must themselves be checkable.
        for edge_id in path["edges"]:
            edge = graph_mod.find_edge_by_id(graph, edge_id)
            if edge is None:  # pragma: no cover - path construction guarantees it
                continue
            if edge.get("status") != graph_mod.TRAVERSABLE_STATUS:
                result.add(
                    f"{label} path edge {edge_id} has status {edge.get('status')!r}; "
                    "only a verified edge may carry a reported chain"
                )
            via = edge.get("via_candidate")
            if via and via not in candidates:
                result.add(
                    f"{label} path edge {edge_id} cites candidate {via!r}, "
                    "which appears in no candidates/*.json payload"
                )
            for field in ("evidence_refs", "verification_refs"):
                for ref_value in _iter_refs(edge.get(field)):
                    if _resolve_reference(base, ref_value) is None:
                        result.add(
                            f"{label} path edge {edge_id} declares {field} "
                            f"{ref_value!r}, which resolves to no file"
                        )

        node_evidence = _iter_refs(node.get("evidence_refs"))
        for ref_value in node_evidence:
            if _resolve_reference(base, ref_value) is None:
                result.add(
                    f"{label} capability {ref} declares evidence_refs {ref_value!r}, "
                    "which resolves to no file"
                )
    return result


def _path_from_any_start(graph: Mapping[str, Any], target_id: str) -> Optional[dict[str, Any]]:
    for start in graph_mod.start_nodes(graph):
        path = graph_mod.verified_path(graph, start, target_id)
        if path["reachable"]:
            return path
    return None


def evaluate_closure(
    findings: Sequence[Mapping[str, Any]],
    graph: Mapping[str, Any],
    candidates: Mapping[str, Any],
    *,
    base_dir: Optional[os.PathLike[str] | str] = None,
    enabled: bool = True,
) -> ClosureResult:
    """Check every confirmed finding.

    ``enabled`` reflects whether the audit is Search Governance-enabled at all
    (§15). A legacy audit has no objective and no graph, so demanding refs
    would fail it for a contract it never signed; the caller decides that from
    the artifacts' existence, not from a flag someone has to remember to set.
    """
    result = ClosureResult()
    if not enabled:
        result.notes.append(
            "Search Governance is not enabled for this audit "
            "(no audit-objective.json / attack-graph.json); closure not required"
        )
        return result
    for finding in findings:
        if not isinstance(finding, Mapping):
            continue
        if finding.get("verdict") != "confirmed":
            continue
        result.checked_findings += 1
        evaluate_finding_closure(finding, graph, candidates, base_dir=base_dir, result=result)
    return result
