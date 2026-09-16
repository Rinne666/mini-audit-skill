"""Audit objective — the control plane of Search Governance (v1, R2-3).

The objective answers *what is this audit trying to prove?* It is deliberately
separated from research state:

    audit-objective.json   control plane  — canonical, immutable once L1
                                           completes, replaced only by an
                                           explicit revision
    search-ledger.json     research plane — grows continuously, merged from
                                           agent-submitted deltas

An L1 agent may only write ``agents/<id>/scratch/objective-proposal.json``; the
runtime promotes it. If the thing being measured could move the goalposts
mid-run, "distance to the target" would become an agent-controlled number, so
*no* agent code path writes the canonical file.

Replacing an objective requires **both** ``--force`` and a non-empty
``--reason``, appends to an append-only ``supersedes`` trail, and records a
system fact in the search ledger. It deliberately does **not** reopen blocked
paths or re-seed the attack graph: a change of scope is recorded, not silently
acted upon. The one asymmetry worth knowing is that ``init`` bootstraps the
graph (principal, initial capabilities, goals) while ``replace`` leaves the
graph alone — re-seeding on replace could strand capabilities that research
already established, so it is left to an explicit step.
"""

from __future__ import annotations

import datetime as _dt
import json
import os
from pathlib import Path
from typing import Any, Mapping, Optional

from .atomic_io import sha256_text, write_json_atomic
from .schema import SchemaError, load_schema, validate_instance


OBJECTIVE_FILENAME = "audit-objective.json"
OBJECTIVE_SCHEMA_NAME = "audit-objective"

#: Fields that define the objective's content, and therefore its hash. The
#: revision counter and the supersedes trail are bookkeeping, not content.
CONTENT_FIELDS = (
    "principal",
    "initial_capabilities",
    "target_capabilities",
    "security_invariants",
)

_RUNTIME_OWNED_FIELDS = ("revision", "supersedes", "created_at", "updated_at")


class ObjectiveError(RuntimeError):
    """Raised when an objective cannot be initialised, read or replaced."""


def utc_now() -> str:
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------


def objective_path(audit_root: os.PathLike[str] | str) -> Path:
    return Path(audit_root) / OBJECTIVE_FILENAME


def proposal_path(audit_root: os.PathLike[str] | str, agent_id: str) -> Path:
    """Where an L1 agent is allowed to write its proposal."""
    return Path(audit_root) / "agents" / agent_id / "scratch" / "objective-proposal.json"


# ---------------------------------------------------------------------------
# Read / validate
# ---------------------------------------------------------------------------


def load_objective(audit_root: os.PathLike[str] | str) -> Optional[dict[str, Any]]:
    """Return the canonical objective, or ``None`` when it does not exist."""
    from .atomic_io import read_json_or_corrupt

    path = objective_path(audit_root)
    if not path.exists():
        return None
    data = read_json_or_corrupt(path)
    if not isinstance(data, dict):
        raise ObjectiveError(f"{path} does not contain a JSON object")
    return data


def validate_objective(doc: Mapping[str, Any]) -> list[SchemaError]:
    return validate_instance(doc, load_schema(OBJECTIVE_SCHEMA_NAME), use_jsonschema=False)


def validate_objective_raise(doc: Mapping[str, Any], *, artifact: str = OBJECTIVE_FILENAME) -> None:
    errors = validate_objective(doc)
    if errors:
        detail = "; ".join(str(e) for e in errors[:5])
        more = f" (+{len(errors) - 5} more)" if len(errors) > 5 else ""
        raise ObjectiveError(f"objective failed schema validation in {artifact}: {detail}{more}")


def require_objective(audit_root: os.PathLike[str] | str) -> dict[str, Any]:
    doc = load_objective(audit_root)
    if doc is None:
        raise ObjectiveError(
            f"no canonical objective at {objective_path(audit_root)}; "
            "an audit has no target until one is declared"
        )
    validate_objective_raise(doc)
    return doc


# ---------------------------------------------------------------------------
# Content hash
# ---------------------------------------------------------------------------


def content_only(doc: Mapping[str, Any]) -> dict[str, Any]:
    return {field: doc.get(field) for field in CONTENT_FIELDS}


def content_hash(doc: Mapping[str, Any]) -> str:
    """``sha256:<hex>`` over the objective's content fields.

    Recorded as ``previous_hash`` in the supersedes trail so a later reader can
    tell which text was replaced. It is an audit fingerprint rather than an
    independently re-verifiable digest: the superseded document itself is not
    archived, so re-computing it requires having kept the old file.
    """
    payload = json.dumps(content_only(doc), sort_keys=True, separators=(",", ":"),
                         ensure_ascii=False)
    return "sha256:" + sha256_text(payload)


# ---------------------------------------------------------------------------
# Build (no I/O)
# ---------------------------------------------------------------------------


def _strip_runtime_fields(doc: Mapping[str, Any], *, audit_id: Optional[str]) -> dict[str, Any]:
    built = {k: v for k, v in doc.items() if k not in _RUNTIME_OWNED_FIELDS}
    built.setdefault("schema_version", 1)
    if audit_id:
        built["audit_id"] = audit_id
    return built


def canonicalize(proposal: Mapping[str, Any], *, audit_id: Optional[str] = None) -> dict[str, Any]:
    """Turn an L1 proposal into a revision-1 canonical objective."""
    if not isinstance(proposal, Mapping):
        raise ObjectiveError("an objective proposal must be a JSON object")
    if proposal.get("revision") not in (None, 1):
        raise ObjectiveError(
            "a proposal must not carry revision > 1; use 'objective replace' to revise"
        )
    if proposal.get("supersedes"):
        raise ObjectiveError(
            "a proposal must not carry a supersedes trail; use 'objective replace' to revise"
        )
    doc = _strip_runtime_fields(proposal, audit_id=audit_id)
    now = utc_now()
    doc["revision"] = 1
    doc["supersedes"] = []
    doc["created_at"] = now
    doc["updated_at"] = now
    validate_objective_raise(doc, artifact="objective proposal")
    return doc


def build_replacement(current: Mapping[str, Any], new_doc: Mapping[str, Any], *,
                      reason: str, audit_id: Optional[str] = None) -> tuple[dict[str, Any], dict[str, Any]]:
    """Build the revision ``n+1`` document plus its supersedes entry."""
    reason = (reason or "").strip()
    if not reason:
        raise ObjectiveError(
            "--force requires --reason: a replaced objective must record why it was replaced"
        )
    if current.get("revision") != 1 and not current.get("supersedes"):
        raise ObjectiveError(
            "the current objective carries a revision > 1 but no supersedes trail; "
            "refusing to extend an unauditable history"
        )
    doc = _strip_runtime_fields(new_doc, audit_id=audit_id or current.get("audit_id"))
    previous_hash = content_hash(current)
    if content_hash(doc) == previous_hash:
        raise ObjectiveError(
            "the replacement has identical content; refusing to inflate the revision"
        )
    entry = {
        "revision": int(current.get("revision", 1)),
        "reason": reason,
        "at": utc_now(),
        "previous_hash": previous_hash,
    }
    doc["revision"] = int(current.get("revision", 1)) + 1
    doc["supersedes"] = list(current.get("supersedes") or []) + [entry]
    doc["created_at"] = current.get("created_at") or entry["at"]
    doc["updated_at"] = entry["at"]
    validate_objective_raise(doc)
    return doc, entry


def revision_fact(old: Mapping[str, Any], new: Mapping[str, Any],
                  entry: Mapping[str, Any]) -> dict[str, Any]:
    """The system fact written to the search ledger when the goalposts move.

    Refs inside the ledger are relative to the audit root, so this points at
    ``audit-objective.json`` rather than a repo path.
    """
    claim = (
        f"objective revision {entry['revision']} -> {new.get('revision')} at {entry['at']}: "
        f"previous_hash={entry['previous_hash']} new_hash={content_hash(new)} "
        f"reason={entry['reason']!r}"
    )
    return {
        "key": f"system:objective-revision-{new.get('revision')}",
        "claim": claim,
        "source_refs": [OBJECTIVE_FILENAME],
        "confidence": "high",
    }


# ---------------------------------------------------------------------------
# Locked transactions
# ---------------------------------------------------------------------------


def init_and_bootstrap(
    audit_root: os.PathLike[str] | str,
    proposal: Mapping[str, Any],
    *,
    audit_id: Optional[str] = None,
    agent: Optional[str] = None,
) -> dict[str, Any]:
    """Declare the objective and bootstrap the research artifacts.

    Order: take the lock, build and validate everything, then write. Every
    write is individually atomic, so the guarantee is "nothing is written until
    everything validates" rather than a single filesystem transaction.
    """
    from . import attack_graph as graph_mod
    from . import research_state as research
    from .search_lock import search_governance_lock

    audit_root = Path(audit_root)
    with search_governance_lock(audit_root, exclusive=True,
                                operation="objective init", agent=agent):
        if objective_path(audit_root).exists():
            raise ObjectiveError(
                f"{objective_path(audit_root)} already exists; "
                "use 'objective replace --force --reason ...' to revise it"
            )
        doc = canonicalize(proposal, audit_id=audit_id)

        ledger = research.load_ledger(audit_root)
        create_ledger = ledger is None
        if ledger is None:
            ledger = research.empty_ledger(audit_id=doc.get("audit_id"))
        research.validate_ledger_raise(ledger)

        graph = graph_mod.load_graph(audit_root)
        create_graph = graph is None
        if graph is None:
            graph = graph_mod.empty_graph(audit_id=doc.get("audit_id"))
        seeded = graph_mod.seed_from_objective(graph, doc)
        graph_mod.require_consistent(graph)
        graph_mod.validate_graph_raise(graph)

        write_json_atomic(objective_path(audit_root), doc)
        if create_ledger:
            research.save_ledger(audit_root, ledger)
        if create_graph or seeded:
            graph_mod.save_graph(audit_root, graph)
        return doc


def replace_and_record(
    audit_root: os.PathLike[str] | str,
    new_doc: Mapping[str, Any],
    *,
    force: bool = False,
    reason: str = "",
    audit_id: Optional[str] = None,
    agent: Optional[str] = None,
) -> dict[str, Any]:
    """Revise the objective and record the revision as a search-ledger fact."""
    from . import research_state as research
    from .search_lock import search_governance_lock

    if not force:
        raise ObjectiveError("replacing the audit objective requires --force")

    audit_root = Path(audit_root)
    with search_governance_lock(audit_root, exclusive=True,
                                operation="objective replace", agent=agent):
        current = require_objective(audit_root)
        doc, entry = build_replacement(current, new_doc, reason=reason, audit_id=audit_id)

        ledger = research.load_ledger(audit_root)
        if ledger is None:
            ledger = research.empty_ledger(audit_id=doc.get("audit_id"))
        research.upsert_fact(ledger, revision_fact(current, doc, entry))
        research.validate_ledger_raise(ledger)

        write_json_atomic(objective_path(audit_root), doc)
        research.save_ledger(audit_root, ledger)
        return doc
