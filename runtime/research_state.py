"""Search ledger / research state (Search Governance v1, R2-1).

The research plane records what the search knows, suspects, is blocked on and
intends to do next. Agents never write it: they submit a *research delta*, and
this module applies it inside one all-or-nothing transaction under the Search
Governance lock.

Two rules carry most of the weight:

**Semantic key as the idempotency address, canonical id as the identifier.**
An author picks a stable key (``assumption:author_exclude-int-array``); the
runtime allocates ``A-012``. Re-submitting the same delta is therefore a no-op
rather than a duplicate, which is what makes "apply it twice" safe.

**Identity fields decide conflicts; mutable fields merge.** Two objects sharing
a key must agree on their identity fields or the *whole* delta is rejected —
never partially applied, because a partially applied delta leaves the agent
unable to tell which of its claims took effect. ``status``, ``evidence_refs``
and friends are mutable and merge; ``claim``, ``question``,
``candidate_id + blocker.*``, ``name + principal`` and
``from/to/relation/via_candidate`` are not.

Refs inside the ledger are opaque strings relative to the audit root, except in
the positions listed in :data:`REF_FIELDS`, where a semantic key is rewritten to
its canonical id before anything is written. Keys are global across kinds, so a
reference is never ambiguous.
"""

from __future__ import annotations

import copy
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Optional, Sequence

from . import attack_graph as graph_mod
from .atomic_io import read_json_or_corrupt, write_json_atomic
from .objective import utc_now
from .schema import SchemaError, load_schema, validate_instance
from .search_lock import search_governance_lock


LEDGER_FILENAME = "search-ledger.json"
LEDGER_SCHEMA_NAME = "search-ledger"
DELTA_SCHEMA_NAME = "research-delta"

CANDIDATE_DIRNAME = "candidates"


class ResearchError(RuntimeError):
    """Base class for every refusal raised by the research transaction."""

    code = "RESEARCH_ERROR"


class ResearchKeyConflict(ResearchError):
    """Same key, different identity fields. Rejects the whole delta."""

    code = "RESEARCH_KEY_CONFLICT"


class DuplicateKeyInDelta(ResearchError):
    """The same semantic key is used twice inside one delta."""

    code = "DUPLICATE_KEY_IN_DELTA"


class IdentityAlreadyBound(ResearchError):
    """A new key claims a structured identity the graph already holds."""

    code = "IDENTITY_ALREADY_BOUND"


class UnknownReference(ResearchError):
    """A reference could not be resolved to any key or canonical id."""

    code = "UNKNOWN_REFERENCE"


class UnknownCandidate(ResearchError):
    """A ``candidate_updates`` patch targets a candidate that does not exist."""

    code = "UNKNOWN_CANDIDATE"


class DeltaSchemaError(ResearchError):
    """The delta, or the state it would produce, fails its schema."""

    code = "DELTA_SCHEMA"


class ResearchGenerationMismatch(ResearchError):
    """search-ledger.json and attack-graph.json disagree on generation.

    The two artifacts are written in sequence, so a crash between them can
    leave one ahead. That is precisely the case no amount of in-memory
    validation can rule out, which is why it is detected on read and treated
    as fail-closed rather than reconciled.
    """

    code = "RESEARCH_GENERATION_MISMATCH"


# ---------------------------------------------------------------------------
# Object model
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ObjectSpec:
    kind: str
    collection: str
    id_prefix: str
    identity_doc: tuple[str, ...]
    mutable_fields: tuple[str, ...]
    list_fields: tuple[str, ...]


LEDGER_SPECS: dict[str, ObjectSpec] = {
    "fact": ObjectSpec(
        "fact", "facts", "FCT",
        ("claim",),
        ("evidence_refs", "source_refs", "confidence", "diff_evidence_ref"),
        ("evidence_refs", "source_refs"),
    ),
    "assumption": ObjectSpec(
        "assumption", "assumptions", "A",
        ("claim",),
        ("status", "evidence_refs", "source_refs", "depended_on_by",
         "diff_evidence_ref"),
        ("evidence_refs", "source_refs", "depended_on_by"),
    ),
    "open_question": ObjectSpec(
        "open_question", "open_questions", "OQ",
        ("question",),
        ("priority", "status", "reason", "evidence_refs", "reopen_if",
         "attempt_refs", "blocked_path_ref", "related_candidates",
         "related_capabilities"),
        ("evidence_refs", "reopen_if", "attempt_refs", "related_candidates",
         "related_capabilities"),
    ),
    "blocked_path": ObjectSpec(
        "blocked_path", "blocked_paths", "BP",
        ("candidate_id", "blocker.type", "blocker.claim"),
        ("status", "evidence_refs", "priority", "reopen_if", "attempt_refs",
         "close_reason"),
        ("evidence_refs", "reopen_if", "attempt_refs"),
    ),
    "intent": ObjectSpec(
        "intent", "intents", "INT",
        ("question_ref", "strategy"),
        ("priority", "status", "reason", "assigned_agent", "attempt_refs"),
        ("attempt_refs",),
    ),
}

CAPABILITY_MUTABLE = ("status", "evidence_refs", "source_candidates",
                      "source_edges", "confidence")
CAPABILITY_LIST_FIELDS = ("evidence_refs", "source_candidates", "source_edges")
EDGE_MUTABLE = ("status", "evidence_refs", "verification_refs", "confidence")
EDGE_LIST_FIELDS = ("evidence_refs", "verification_refs")

#: ``delta field name → (kind, mode, is_graph_object)``. ``upsert`` creates or
#: merges by key; ``update`` refuses to create.
DELTA_OPS: tuple[tuple[str, str, str, bool], ...] = (
    ("facts_add", "fact", "upsert", False),
    ("assumptions_add", "assumption", "upsert", False),
    ("assumptions_update", "assumption", "update", False),
    ("questions_add", "open_question", "upsert", False),
    ("questions_resolve", "open_question", "update", False),
    ("blocked_paths_add", "blocked_path", "upsert", False),
    ("blocked_paths_reopen", "blocked_path", "update", False),
    ("intents_add", "intent", "upsert", False),
    ("capabilities_add", "capability", "upsert", True),
    ("capabilities_update", "capability", "update", True),
    ("edges_add", "edge", "upsert", True),
    ("edges_update", "edge", "update", True),
)

#: Creation defaults, so a delta may stay terse while the canonical object is
#: still schema-complete.
DEFAULTS: dict[str, dict[str, Any]] = {
    "assumption": {"status": "unverified"},
    "open_question": {"status": "open", "priority": "P1"},
    "blocked_path": {"status": "blocked", "priority": "medium"},
    "intent": {"status": "proposed", "priority": "P1"},
    "capability": {"status": "proposed"},
    "edge": {"status": "proposed"},
}

#: ``(kind, dotted path) → target kind`` (``None`` = any graph node). A semantic
#: key in these positions is rewritten to its canonical id, including forward
#: references to objects created by the same delta.
REF_FIELDS: tuple[tuple[str, str, Optional[str]], ...] = (
    ("blocked_path", "blocker.assumption_ref", "assumption"),
    ("open_question", "blocked_path_ref", "blocked_path"),
    ("open_question", "related_capabilities[]", "capability"),
    ("capability", "source_edges[]", "edge"),
    ("intent", "question_ref", "open_question"),
    ("edge", "from", None),
    ("edge", "to", None),
)

#: Refs checked against the candidate store but kept in their author form —
#: candidates retain their own id space (R2-2). A missing one is a warning at
#: apply time; Phase D's closure check is where it becomes fatal.
CANDIDATE_REF_FIELDS: tuple[tuple[str, str], ...] = (
    ("blocked_path", "candidate_id"),
    ("edge", "via_candidate"),
    ("capability", "source_candidates[]"),
    ("open_question", "related_candidates[]"),
)


def mutable_fields_of(kind: str) -> tuple[str, ...]:
    if kind == "capability":
        return CAPABILITY_MUTABLE
    if kind == "edge":
        return EDGE_MUTABLE
    return LEDGER_SPECS[kind].mutable_fields


def list_fields_of(kind: str) -> tuple[str, ...]:
    if kind == "capability":
        return CAPABILITY_LIST_FIELDS
    if kind == "edge":
        return EDGE_LIST_FIELDS
    return LEDGER_SPECS[kind].list_fields


def identity_of(kind: str, obj: Mapping[str, Any]) -> tuple:
    """The fields that must agree for two objects to be the same object.

    Free-text kinds (fact / assumption / open question) are keyed by a single
    prose field; blocked paths, capabilities and edges have structured
    identities, which is why a capability needs name *and* principal — the same
    name under two principals is two capabilities.
    """
    if kind == "blocked_path":
        blocker = obj.get("blocker") or {}
        return (
            obj.get("candidate_id"),
            blocker.get("type"),
            blocker.get("claim"),
            blocker.get("assumption_ref") or "",
        )
    if kind == "capability":
        return (obj.get("type"), obj.get("name"), obj.get("principal") or "")
    if kind == "edge":
        return (obj.get("from"), obj.get("to"), obj.get("relation"),
                obj.get("via_candidate") or "")
    return tuple(obj.get(field) for field in LEDGER_SPECS[kind].identity_doc)


def has_structured_identity(kind: str) -> bool:
    """Kinds whose identity tuple is closed-vocabulary and therefore authoritative.

    For these, a *new* key claiming an identity the graph already holds is a
    duplicate rather than a second object. Prose identities (fact / assumption /
    question) are not compared this way: prose equality is not a reliable dedupe
    signal, so their key stays the only address.
    """
    return kind in ("capability", "edge")


# ---------------------------------------------------------------------------
# Ledger I/O
# ---------------------------------------------------------------------------


def ledger_path(audit_root: os.PathLike[str] | str) -> Path:
    return Path(audit_root) / LEDGER_FILENAME


def empty_ledger(*, audit_id: Optional[str] = None) -> dict[str, Any]:
    ledger: dict[str, Any] = {
        "schema_version": 1,
        "generation": 1,
        "facts": [],
        "assumptions": [],
        "open_questions": [],
        "blocked_paths": [],
        "intents": [],
        # Spec §4: derived facts produced by the runtime. The runtime writes
        # here only; semantic mutations live on the canonical objects.
        "derived_events": [],
        # Spec §5: append-only decision provenance log. The runtime canonicalizes
        # entries from delta.decisions into this array; agents never write here.
        "decisions": [],
    }
    if audit_id:
        ledger["audit_id"] = audit_id
    return ledger


def load_ledger(audit_root: os.PathLike[str] | str) -> Optional[dict[str, Any]]:
    path = ledger_path(audit_root)
    if not path.exists():
        return None
    data = read_json_or_corrupt(path)
    if not isinstance(data, dict):
        raise ResearchError(f"{path} does not contain a JSON object")
    return data


def validate_ledger(ledger: Mapping[str, Any]) -> list[SchemaError]:
    return validate_instance(ledger, load_schema(LEDGER_SCHEMA_NAME), use_jsonschema=False)


def validate_ledger_raise(ledger: Mapping[str, Any], *, artifact: str = LEDGER_FILENAME) -> None:
    errors = validate_ledger(ledger)
    if errors:
        detail = "; ".join(str(e) for e in errors[:5])
        more = f" (+{len(errors) - 5} more)" if len(errors) > 5 else ""
        raise DeltaSchemaError(
            f"research state failed schema validation in {artifact}: {detail}{more}"
        )


def save_ledger(audit_root: os.PathLike[str] | str, ledger: Mapping[str, Any]) -> None:
    payload = dict(ledger)
    payload["updated_at"] = utc_now()
    write_json_atomic(ledger_path(audit_root), payload)


def require_ledger(audit_root: os.PathLike[str] | str) -> dict[str, Any]:
    ledger = load_ledger(audit_root)
    if ledger is None:
        raise ResearchError(
            f"no search ledger at {ledger_path(audit_root)}; "
            "declare an objective or apply a research delta first"
        )
    validate_ledger_raise(ledger)
    return ledger


# ---------------------------------------------------------------------------
# Generation — what "one transaction" can and cannot promise
#
# The research transaction is *not* a filesystem-atomic multi-file commit. It
# is a validated staged transaction under an exclusive lock with atomic
# per-file replacement. That guarantees (a) no lost update under concurrency
# and (b) nothing is written until everything validates. It does not guarantee
# that a crash between the ledger write and the graph write leaves no trace.
# The generation counter is how that residue is made detectable: both
# artifacts carry the same integer as of the last completed apply, so a reader
# that finds them disagreeing knows it is looking at an interrupted
# transaction and refuses to reason from it.
# ---------------------------------------------------------------------------


def generation_of(doc: Mapping[str, Any]) -> int:
    try:
        return int(doc.get("generation", 0))
    except (TypeError, ValueError):
        return 0


def verify_generation(ledger: Mapping[str, Any], graph: Mapping[str, Any]) -> None:
    """Refuse to use a ledger and a graph that came from different applies."""
    ledger_generation = generation_of(ledger)
    graph_generation = generation_of(graph)
    if ledger_generation != graph_generation:
        ahead, behind = (
            ("search-ledger.json", "attack-graph.json")
            if ledger_generation > graph_generation
            else ("attack-graph.json", "search-ledger.json")
        )
        raise ResearchGenerationMismatch(
            f"{ahead} is at generation {max(ledger_generation, graph_generation)} "
            f"but {behind} is at {min(ledger_generation, graph_generation)}; "
            "a previous research transaction was interrupted between the two "
            "writes, so the pair is not a coherent snapshot"
        )


def align_generation(ledger: dict[str, Any], graph: dict[str, Any], *,
                     ledger_created: bool, graph_created: bool) -> None:
    """Give a freshly created artifact the other one's counter.

    Two *existing* artifacts that disagree are a fail-closed condition (see
    :func:`verify_generation`). A newly created one adopts the existing
    counter instead of starting a divergent history — otherwise a half-created
    audit would be permanently incoherent by construction.
    """
    if ledger_created and not graph_created:
        ledger["generation"] = generation_of(graph)
    elif graph_created and not ledger_created:
        graph["generation"] = generation_of(ledger)


def load_research_state(audit_root: os.PathLike[str] | str) -> dict[str, Any]:
    """Load the ledger and the graph as one checked snapshot.

    Readers that need both (the governor, saturation, the L7 closure check,
    ``graph`` queries) go through here so the generation check can never be
    forgotten at a call site. Neither artifact is required to exist: callers
    distinguish "no research state yet" by ``exists``.
    """
    audit_root = Path(audit_root)
    ledger = load_ledger(audit_root)
    graph = graph_mod.load_graph(audit_root)
    if ledger is None and graph is None:
        return {"exists": False, "ledger": None, "graph": None, "audit_root": audit_root}
    if ledger is None:
        graph = graph or {}
        return {"exists": False, "ledger": None, "graph": graph, "audit_root": audit_root}
    if graph is None:
        return {"exists": True, "ledger": ledger, "graph": None, "audit_root": audit_root}
    verify_generation(ledger, graph)
    return {"exists": True, "ledger": ledger, "graph": graph, "audit_root": audit_root}


# ---------------------------------------------------------------------------
# Lookup and merge helpers
# ---------------------------------------------------------------------------


def collection_of(kind: str) -> str:
    return LEDGER_SPECS[kind].collection


def iter_objects(ledger: Mapping[str, Any], kind: str) -> list[dict[str, Any]]:
    return [o for o in ledger.get(collection_of(kind), []) if isinstance(o, dict)]


def find_by_key(ledger: Mapping[str, Any], kind: str, key: str) -> Optional[dict[str, Any]]:
    for obj in iter_objects(ledger, kind):
        if obj.get("key") == key:
            return obj
    return None


def find_by_id(ledger: Mapping[str, Any], kind: str, obj_id: str) -> Optional[dict[str, Any]]:
    for obj in iter_objects(ledger, kind):
        if obj.get("id") == obj_id:
            return obj
    return None


#: Every collection a semantic key can be bound to, in a stable order so error
#: messages are reproducible.
KEY_KINDS: tuple[str, ...] = (
    "fact", "assumption", "open_question", "blocked_path", "intent",
)


def find_key_anywhere(ledger: Mapping[str, Any], graph: Mapping[str, Any],
                      key: str) -> Optional[tuple[str, dict[str, Any]]]:
    """Resolve a semantic key anywhere in the Search Governance namespace.

    A key is unique across the *whole* namespace, not per kind. Without this,
    ``fact:shared`` could later be joined by ``assumption:shared`` and a
    reference to ``shared`` would become ambiguous — and every reference in a
    delta is resolved by key first. Graph nodes report their node type
    (``principal`` / ``capability`` / ``goal``) so that a capability cannot
    shadow the objective's principal node.
    """
    for kind in KEY_KINDS:
        obj = find_by_key(ledger, kind, key)
        if obj is not None:
            return (kind, obj)
    node = graph_mod.find_node_by_key(graph, key)
    if node is not None:
        return (str(node.get("type") or "capability"), node)
    edge = graph_mod.find_edge_by_key(graph, key)
    if edge is not None:
        return ("edge", edge)
    return None


_ID_SUFFIX = re.compile(r"-([0-9]{3,})$")


def _number_of(obj_id: str) -> Optional[int]:
    match = _ID_SUFFIX.search(obj_id)
    return int(match.group(1)) if match else None


def next_object_id(ledger: Mapping[str, Any], kind: str) -> str:
    prefix = LEDGER_SPECS[kind].id_prefix
    highest = 0
    for obj in iter_objects(ledger, kind):
        obj_id = str(obj.get("id", ""))
        if obj_id.startswith(prefix):
            number = _number_of(obj_id)
            if number is not None:
                highest = max(highest, number)
    return f"{prefix}-{highest + 1:03d}"


def _union_list(existing: Any, extra: Any) -> list[Any]:
    merged: list[Any] = list(existing or [])
    for item in extra or []:
        if item not in merged:
            merged.append(item)
    return merged


def merge_mutable(target: dict[str, Any], kind: str, entry: Mapping[str, Any]) -> dict[str, Any]:
    """Merge mutable fields. Lists union (existing first), scalars overwrite."""
    for field in mutable_fields_of(kind):
        if field not in entry:
            continue
        value = entry[field]
        if field in list_fields_of(kind):
            target[field] = _union_list(target.get(field), value)
        else:
            target[field] = value
    target["updated_at"] = utc_now()
    return target


# ---------------------------------------------------------------------------
# Candidate store
# ---------------------------------------------------------------------------


def candidate_store(audit_root: os.PathLike[str] | str) -> dict[str, tuple[Path, dict[str, Any], dict[str, Any]]]:
    """Map ``candidate_id → (file, payload, record)`` across ``candidates/*.json``.

    The payload is kept alongside the record so a patch can be written back
    without re-reading (and therefore without discarding the patch). The scan is
    deliberately tolerant: it walks for dicts carrying a ``candidate_id`` rather
    than assuming one producer's layout.
    """
    index: dict[str, tuple[Path, dict[str, Any], dict[str, Any]]] = {}
    directory = Path(audit_root) / CANDIDATE_DIRNAME
    if not directory.is_dir():
        return index
    for path in sorted(directory.glob("*.json")):
        try:
            payload = read_json_or_corrupt(path)
        except Exception:
            continue
        if not isinstance(payload, dict):
            continue

        def walk(node: Any) -> None:
            if isinstance(node, dict):
                cid = node.get("candidate_id")
                if isinstance(cid, str) and cid and cid not in index:
                    index[cid] = (path, payload, node)
                for value in node.values():
                    walk(value)
            elif isinstance(node, list):
                for value in node:
                    walk(value)

        walk(payload)
    return index


# ---------------------------------------------------------------------------
# Single-fact upsert (used by the objective revision trail)
# ---------------------------------------------------------------------------


def upsert_fact(ledger: dict[str, Any], entry: Mapping[str, Any]) -> dict[str, Any]:
    """In-memory fact upsert. Callers hold the Search Governance lock."""
    key = str(entry.get("key", ""))
    if not key:
        raise ResearchError("a fact requires a non-empty key")
    claim = entry.get("claim")
    existing = find_by_key(ledger, "fact", key)
    if existing is not None:
        if identity_of("fact", existing) != (claim,):
            raise ResearchKeyConflict(
                f"fact key {key!r} is already bound to claim "
                f"{existing.get('claim')!r}, not {claim!r}"
            )
        return merge_mutable(existing, "fact", entry)

    now = utc_now()
    fact: dict[str, Any] = {
        "id": next_object_id(ledger, "fact"),
        "key": key,
        "claim": claim,
        "created_at": now,
        "updated_at": now,
    }
    for field in LEDGER_SPECS["fact"].mutable_fields:
        if field in entry:
            fact[field] = entry[field]
    ledger.setdefault("facts", []).append(fact)
    return fact


# ---------------------------------------------------------------------------
# The transaction
# ---------------------------------------------------------------------------


class _Transaction:
    """Staged state. An exception anywhere aborts with zero writes."""

    def __init__(self, audit_root: Path, delta: Mapping[str, Any]) -> None:
        self.audit_root = audit_root
        self.delta = delta
        self.ledger: dict[str, Any] = {}
        self.graph: dict[str, Any] = {}
        self.objective_principal = ""
        self.candidates: dict[str, tuple[Path, dict[str, Any], dict[str, Any]]] = {}
        self.touched_candidate_payloads: dict[Path, dict[str, Any]] = {}
        self.key_to_id: dict[str, str] = {}
        self.planned_kinds: dict[str, str] = {}
        self.planned_ids: dict[str, str] = {}
        self.created: dict[str, list[str]] = {}
        self.merged: dict[str, list[str]] = {}
        self.warnings: list[str] = []
        self.reopened: list[str] = []
        self.closed: list[dict[str, str]] = []
        self.assumption_transitions: list[dict[str, str]] = []
        # Spec §4: mechanically-derived facts the runtime reports for the model
        # to read. Replaces the v1–v1.4 auto-rewriting side effect on
        # blocked_path.status / close_reason.
        self.derived_events: list[dict[str, Any]] = []


def apply_delta(
    audit_root: os.PathLike[str] | str,
    delta: Mapping[str, Any],
    *,
    agent: Optional[str] = None,
    timeout: Optional[float] = None,
) -> dict[str, Any]:
    """Apply a research delta. Either the whole delta lands, or nothing does."""
    audit_root = Path(audit_root)
    with search_governance_lock(audit_root, exclusive=True,
                                operation="research apply", agent=agent, timeout=timeout):
        return _apply_locked(audit_root, delta, agent=agent)


def _dotted_get(obj: Mapping[str, Any], path: str) -> Any:
    node: Any = obj
    for part in path.split("."):
        if not isinstance(node, Mapping):
            return None
        node = node.get(part)
    return node


def _dotted_set(obj: dict[str, Any], path: str, value: Any) -> None:
    parts = path.split(".")
    cursor: dict[str, Any] = obj
    for part in parts[:-1]:
        nxt = cursor.get(part)
        if not isinstance(nxt, dict):
            return
        cursor = nxt
    cursor[parts[-1]] = value


def _apply_locked(audit_root: Path, delta: Mapping[str, Any], *,
                  agent: Optional[str]) -> dict[str, Any]:
    from .objective import require_objective

    if not isinstance(delta, Mapping):
        raise ResearchError("a research delta must be a JSON object")

    # Step 3-4: parse the whole delta and validate it as a unit.
    errors = validate_instance(delta, load_schema(DELTA_SCHEMA_NAME), use_jsonschema=False)
    if errors:
        detail = "; ".join(str(e) for e in errors[:5])
        more = f" (+{len(errors) - 5} more)" if len(errors) > 5 else ""
        raise DeltaSchemaError(f"research delta failed schema validation: {detail}{more}")
    if delta.get("schema_version") != 1:
        raise DeltaSchemaError(
            f"unsupported research-delta schema_version {delta.get('schema_version')!r}"
        )

    # Work on a copy. Reference resolution rewrites keys into canonical ids in
    # place, and doing that to the caller's object means a delta can only be
    # applied once — the second attempt would try to resolve ids that the graph
    # is still in the middle of creating.
    delta = copy.deepcopy(dict(delta))

    # Step 2: read every artifact this transaction may touch.
    objective = require_objective(audit_root)
    txn = _Transaction(audit_root, delta)
    txn.objective_principal = str(objective.get("principal") or "")
    ledger = load_ledger(audit_root)
    graph = graph_mod.load_graph(audit_root)
    if ledger is not None and graph is not None:
        # Fail closed *before* mutating: a previous apply interrupted between
        # its two writes leaves a pair that must not be reasoned from.
        verify_generation(ledger, graph)
    txn.ledger = copy.deepcopy(ledger) if ledger is not None else empty_ledger(
        audit_id=objective.get("audit_id")
    )
    if graph is not None:
        txn.graph = copy.deepcopy(graph)
    else:
        # A missing graph is bootstrapped from the objective so the principal
        # and goal nodes exist before any edge is asserted against them.
        txn.graph = graph_mod.empty_graph(audit_id=objective.get("audit_id"))
        graph_mod.seed_from_objective(txn.graph, objective)
    align_generation(txn.ledger, txn.graph,
                     ledger_created=ledger is None, graph_created=graph is None)
    txn.candidates = candidate_store(audit_root)
    previous_status = {
        obj.get("id"): obj.get("status") for obj in iter_objects(txn.ledger, "assumption")
    }

    # Step 5-6: collect keys, reject duplicates (keys are global, not per-kind).
    planned: list[tuple[str, str, str, bool, dict[str, Any]]] = []
    seen_keys: dict[str, str] = {}
    for field_name, kind, mode, is_graph in DELTA_OPS:
        for index, entry in enumerate(delta.get(field_name) or []):
            if not isinstance(entry, dict):
                raise DeltaSchemaError(f"{field_name}[{index}] must be an object")
            if mode == "update":
                if not str(entry.get("ref", "")):
                    raise UnknownReference(f"{field_name}[{index}] requires a non-empty ref")
            else:
                key = str(entry.get("key", ""))
                if not key:
                    raise ResearchError(f"{field_name}[{index}] requires a non-empty key")
                if key in seen_keys:
                    raise DuplicateKeyInDelta(
                        f"semantic key {key!r} appears in both "
                        f"{seen_keys[key]!r} and {field_name!r}"
                    )
                seen_keys[key] = field_name
            planned.append((field_name, kind, mode, is_graph, entry))

    # Step 7-8: resolve existing keys and allocate ids for every new object.
    # A semantic key is unique across the whole namespace, so a key already
    # bound to another kind is a conflict rather than a second object — and
    # every reference in a delta is resolved by key first, so allowing the
    # duplicate would make existing references ambiguous.
    counters: dict[str, int] = {}
    for field_name, kind, mode, is_graph, entry in planned:
        if mode == "update":
            continue
        key = str(entry["key"])
        bound = find_key_anywhere(txn.ledger, txn.graph, key)
        if bound is not None and bound[0] != kind:
            raise ResearchKeyConflict(
                f"{field_name} declares key {key!r}, which is already bound to a "
                f"{bound[0]} ({bound[1].get('id')}); semantic keys are unique across "
                f"every research kind and the attack graph, not per kind"
            )
        existing_id = _existing_id_by_key(txn, kind, key)
        if existing_id is not None:
            txn.key_to_id[key] = existing_id
        else:
            txn.key_to_id[key] = _allocate(txn, kind, is_graph, counters)
        txn.planned_kinds[key] = kind
        txn.planned_ids[txn.key_to_id[key]] = kind

    # Step 9-11: resolve forward references, compare identity, merge or create.
    for field_name, kind, mode, is_graph, entry in planned:
        target = _resolve_target(txn, field_name, kind, mode, entry)
        _resolve_reference_fields(txn, kind, entry)
        _check_candidate_references(txn, kind, entry)

        if mode == "update":
            _apply_update(txn, field_name, kind, target, entry)
            continue
        if target is None:
            created = _create_object(txn, kind, is_graph, entry)
            txn.created.setdefault(kind, []).append(str(created["id"]))
            continue
        claimed = identity_of(kind, _entry_as_object(kind, entry, txn))
        if identity_of(kind, target) != claimed:
            raise ResearchKeyConflict(
                f"{kind} key {entry['key']!r} is already bound to identity "
                f"{identity_of(kind, target)!r}, but this delta claims {claimed!r}"
            )
        merge_mutable(target, kind, entry)
        txn.merged.setdefault(kind, []).append(str(target.get("id")))

    # Candidate research patches (the third member of the write set).
    for index, update in enumerate(delta.get("candidate_updates") or []):
        if not isinstance(update, dict):
            raise DeltaSchemaError(f"candidate_updates[{index}] must be an object")
        patch_candidate_research(txn, str(update.get("candidate_id")), update.get("research") or {})

    # Decision provenance (spec §5): validate + canonicalize delta.decisions.
    # The runtime is strict here because the decision log is the audit trail for
    # *why* the canonical state changed — a malformed entry silently dropped
    # would defeat the whole point of the field.
    _canonicalize_decisions(txn, delta.get("decisions") or [])

    # Step 13: side effects — assumption transitions move blocked paths.
    _apply_assumption_side_effects(txn, previous_status)
    _recompute_depended_on_by(txn)

    # Step 12: the resulting state must validate and stay internally consistent.
    graph_mod.require_consistent(txn.graph)
    graph_mod.validate_graph_raise(txn.graph)
    validate_ledger_raise(txn.ledger)

    # Step 15-16: nothing has been written yet; write only now. Both research
    # artifacts carry one generation, bumped together, so an interruption
    # between the two writes is detectable rather than silent.
    generation = max(generation_of(txn.ledger), generation_of(txn.graph)) + 1
    txn.ledger["generation"] = generation
    txn.graph["generation"] = generation
    # Stamp generation onto every decision so a later audit can correlate the
    # entry with the exact transaction that committed it (spec §5).
    for entry in txn.ledger.get("decisions", []):
        if entry.get("delta_generation") is None:
            entry["delta_generation"] = generation
    write_json_atomic(ledger_path(audit_root), {**txn.ledger, "updated_at": utc_now()})
    graph_mod.save_graph(audit_root, txn.graph)
    for path, payload in txn.touched_candidate_payloads.items():
        write_json_atomic(path, payload)

    return {
        "ok": True,
        "command": "research.apply",
        "agent": agent or "",
        "generation": generation,
        "created": {k: sorted(v) for k, v in txn.created.items()},
        "merged": {k: sorted(v) for k, v in txn.merged.items()},
        "key_to_id": dict(sorted(txn.key_to_id.items())),
        # Spec §4: derived events replace the v1–v1.4 auto-rewriting side
        # effect on blocked_path.status / close_reason. The model reads these
        # and decides what to do (reopen / defer / ignore / escalate).
        "derived_events": list(txn.derived_events),
        "reopened_blocked_paths": sorted(txn.reopened),
        "closed_blocked_paths": txn.closed,
        "assumption_transitions": txn.assumption_transitions,
        "candidate_files_touched": sorted(p.name for p in txn.touched_candidate_payloads),
        "warnings": txn.warnings,
    }


def _existing_id_by_key(txn: _Transaction, kind: str, key: str) -> Optional[str]:
    if kind == "capability":
        node = graph_mod.find_node_by_key(txn.graph, key)
        return str(node.get("id")) if node else None
    if kind == "edge":
        edge = graph_mod.find_edge_by_key(txn.graph, key)
        return str(edge.get("id")) if edge else None
    obj = find_by_key(txn.ledger, kind, key)
    return str(obj.get("id")) if obj else None


def _allocate(txn: _Transaction, kind: str, is_graph: bool, counters: dict[str, int]) -> str:
    """Allocate the next canonical id, counting allocations within this delta.

    The graph is not mutated while planning, so ``next_node_id`` would return
    the same value for every new capability in one delta; the per-prefix counter
    is what keeps a delta with several new objects from colliding with itself.
    """
    if is_graph:
        if kind == "edge":
            prefix = "EDGE"
            start = _number_of(graph_mod.next_edge_id(txn.graph)) or 1
        else:
            prefix = "CAP"
            start = _number_of(graph_mod.next_node_id(txn.graph, "capability")) or 1
    else:
        prefix = LEDGER_SPECS[kind].id_prefix
        start = _number_of(next_object_id(txn.ledger, kind)) or 1
    number = counters.get(prefix, start - 1) + 1
    counters[prefix] = number
    return f"{prefix}-{number:03d}"


def _lookup(txn: _Transaction, ref: str, kind: str) -> Optional[dict[str, Any]]:
    """Resolve ``ref`` (key or canonical id) to an existing object."""
    if kind == "capability":
        return (graph_mod.find_node_by_key(txn.graph, ref)
                or graph_mod.find_node_by_id(txn.graph, ref))
    if kind == "edge":
        return (graph_mod.find_edge_by_key(txn.graph, ref)
                or graph_mod.find_edge_by_id(txn.graph, ref))
    return find_by_key(txn.ledger, kind, ref) or find_by_id(txn.ledger, kind, ref)


def _lookup_any(txn: _Transaction, ref: str,
                target_kind: Optional[str]) -> Optional[tuple[str, str]]:
    """Return ``(kind, canonical_id)`` for a cross-artifact reference.

    Consults objects created by this same delta first, which is what makes
    forward references resolvable. Returns ``None`` when the reference is
    genuinely absent, so callers can raise their own contextual error — but
    when the key *does* exist under a different kind it raises here instead,
    because "unknown reference" would send the author looking in the wrong
    place.
    """
    planned = txn.planned_kinds.get(ref)
    if planned is not None:
        if target_kind is not None and planned != target_kind:
            raise UnknownReference(
                f"reference {ref!r} is a {planned}, not a {target_kind}"
            )
        if target_kind is None and planned != "capability":
            raise UnknownReference(f"reference {ref!r} is not a graph node")
        return (planned, txn.key_to_id[ref])

    # A canonical id belonging to an object this same delta is creating. Agents
    # should address those by key (the id does not exist yet from their side),
    # but resolution is idempotent: a delta that has already been through this
    # step must not fail on its second pass.
    planned_id_kind = txn.planned_ids.get(ref)
    if planned_id_kind is not None:
        if target_kind is not None and planned_id_kind != target_kind:
            raise UnknownReference(
                f"reference {ref!r} is a {planned_id_kind}, not a {target_kind}"
            )
        if target_kind is None and planned_id_kind != "capability":
            raise UnknownReference(f"reference {ref!r} is not a graph node")
        return (planned_id_kind, ref)

    if target_kind == "capability":
        node = (graph_mod.find_node_by_key(txn.graph, ref)
                or graph_mod.find_node_by_id(txn.graph, ref))
        if node is not None:
            return ("capability", str(node.get("id")))
    elif target_kind == "edge":
        edge = (graph_mod.find_edge_by_key(txn.graph, ref)
                or graph_mod.find_edge_by_id(txn.graph, ref))
        if edge is not None:
            return ("edge", str(edge.get("id")))
    elif target_kind is not None:
        obj = (find_by_key(txn.ledger, target_kind, ref)
               or find_by_id(txn.ledger, target_kind, ref))
        if obj is not None:
            return (target_kind, str(obj.get("id")))
    else:
        node = (graph_mod.find_node_by_key(txn.graph, ref)
                or graph_mod.find_node_by_id(txn.graph, ref))
        if node is not None:
            return ("node", str(node.get("id")))

    elsewhere = find_key_anywhere(txn.ledger, txn.graph, ref)
    if elsewhere is not None:
        raise UnknownReference(
            f"reference {ref!r} resolves to a {elsewhere[0]} "
            f"({elsewhere[1].get('id')}), not a {target_kind or 'graph node'}"
        )
    return None


def _resolve_target(txn: _Transaction, field_name: str, kind: str, mode: str,
                    entry: Mapping[str, Any]) -> Optional[dict[str, Any]]:
    if mode == "update":
        ref = str(entry.get("ref", ""))
        found = _lookup(txn, ref, kind)
        if found is None:
            raise UnknownReference(
                f"{field_name} ref {ref!r} does not resolve to an existing {kind}"
            )
        return found
    return _lookup(txn, str(entry["key"]), kind)


def _resolve_reference_fields(txn: _Transaction, kind: str, entry: dict[str, Any]) -> None:
    for ref_kind, path, target_kind in REF_FIELDS:
        if ref_kind != kind:
            continue
        if path.endswith("[]"):
            field = path[:-2]
            resolved: list[str] = []
            for value in entry.get(field) or []:
                hit = _lookup_any(txn, str(value), target_kind)
                if hit is None:
                    raise UnknownReference(
                        f"{kind}.{field} references {value!r}, which resolves to no "
                        f"{target_kind or 'graph node'}"
                    )
                resolved.append(hit[1])
            entry[field] = resolved
            continue
        value = _dotted_get(entry, path)
        if value is None:
            continue
        hit = _lookup_any(txn, str(value), target_kind)
        if hit is None:
            raise UnknownReference(
                f"{kind}.{path} references {value!r}, which resolves to no "
                f"{target_kind or 'graph node'}"
            )
        _dotted_set(entry, path, hit[1])


def _check_candidate_references(txn: _Transaction, kind: str, entry: Mapping[str, Any]) -> None:
    for ref_kind, path in CANDIDATE_REF_FIELDS:
        if ref_kind != kind:
            continue
        if path.endswith("[]"):
            values = entry.get(path[:-2]) or []
        else:
            value = _dotted_get(entry, path)
            values = [value] if value else []
        for value in values:
            if str(value) not in txn.candidates:
                txn.warnings.append(f"{kind}.{path} references unknown candidate {value!r}")


def _entry_as_object(kind: str, entry: Mapping[str, Any],
                     txn: Optional[_Transaction] = None) -> dict[str, Any]:
    """Shape a delta entry the way it will exist canonically, for identity checks."""
    if kind == "capability":
        principal = entry.get("principal") or (txn.objective_principal if txn else "")
        return {"type": "capability", "name": entry.get("name"), "principal": principal}
    if kind == "edge":
        return {"from": entry.get("from"), "to": entry.get("to"),
                "relation": entry.get("relation"),
                "via_candidate": entry.get("via_candidate") or ""}
    if kind == "blocked_path":
        blocker = entry.get("blocker") or {}
        return {
            "candidate_id": entry.get("candidate_id"),
            "blocker": {
                "type": blocker.get("type"),
                "claim": blocker.get("claim"),
                "assumption_ref": blocker.get("assumption_ref") or "",
            },
        }
    return {field: entry.get(field) for field in LEDGER_SPECS[kind].identity_doc}


def _apply_update(txn: _Transaction, field_name: str, kind: str,
                  target: Optional[dict[str, Any]], entry: dict[str, Any]) -> None:
    if target is None:  # pragma: no cover - _resolve_target already refused
        raise UnknownReference(f"{field_name} has no target")
    if field_name == "blocked_paths_reopen":
        target["status"] = "reopened"
        txn.reopened.append(str(target.get("id")))
    merge_mutable(target, kind, entry)
    txn.merged.setdefault(kind, []).append(str(target.get("id")))


def _create_object(txn: _Transaction, kind: str, is_graph: bool,
                   entry: Mapping[str, Any]) -> dict[str, Any]:
    key = str(entry["key"])
    obj_id = txn.key_to_id[key]
    now = utc_now()
    defaults = DEFAULTS.get(kind, {})

    if is_graph:
        if kind == "capability":
            principal = entry.get("principal") or txn.objective_principal
            for node in txn.graph.get("nodes", []):
                same = (node.get("type"), node.get("name"), node.get("principal") or "")
                if same == ("capability", entry.get("name"), principal):
                    raise IdentityAlreadyBound(
                        f"capability (name={entry.get('name')!r}, principal={principal!r}) "
                        f"already exists as {node.get('id')} under key "
                        f"{node.get('key')!r}; reuse that key instead of redeclaring it"
                    )
            node = graph_mod.add_node(
                txn.graph, key=key, type="capability", name=str(entry.get("name")),
                principal=principal, status=str(entry.get("status", defaults["status"])),
                origin="research",
            )
            node["created_at"] = now
            node["updated_at"] = now
            for field in CAPABILITY_MUTABLE:
                if field != "status" and field in entry:
                    node[field] = entry[field]
            return node

        for edge in txn.graph.get("edges", []):
            same = (edge.get("from"), edge.get("to"), edge.get("relation"),
                    edge.get("via_candidate") or "")
            if same == (entry.get("from"), entry.get("to"), entry.get("relation"),
                        entry.get("via_candidate") or ""):
                raise IdentityAlreadyBound(
                    f"edge ({entry.get('from')} -{entry.get('relation')}-> "
                    f"{entry.get('to')}) already exists as {edge.get('id')} under key "
                    f"{edge.get('key')!r}; reuse that key"
                )
        edge = graph_mod.add_edge(
            txn.graph, key=key, src=str(entry.get("from")), dst=str(entry.get("to")),
            relation=str(entry.get("relation")),
            status=str(entry.get("status", defaults["status"])),
        )
        # `via_candidate` is an identity field, not a mutable one, so it has to
        # be carried over explicitly rather than through the mutable merge.
        if entry.get("via_candidate"):
            edge["via_candidate"] = entry["via_candidate"]
        edge["created_at"] = now
        edge["updated_at"] = now
        for field in EDGE_MUTABLE:
            if field != "status" and field in entry:
                edge[field] = entry[field]
        return edge

    spec = LEDGER_SPECS[kind]
    obj: dict[str, Any] = {"id": obj_id, "key": key}
    if kind == "blocked_path":
        obj["candidate_id"] = entry["candidate_id"]
        # A resolved assumption_ref is a canonical id, so the identity stays
        # stable whether the author addressed the assumption by key or by id.
        obj["blocker"] = {k: v for k, v in (entry.get("blocker") or {}).items()
                          if v is not None}
    else:
        for field in spec.identity_doc:
            if field in entry:
                obj[field] = entry[field]
    for field, default in defaults.items():
        obj[field] = entry.get(field, default)
    for field in spec.mutable_fields:
        if field == "status":
            continue
        if field in entry:
            obj[field] = entry[field]
    obj["created_at"] = now
    obj["updated_at"] = now
    txn.ledger.setdefault(spec.collection, []).append(obj)
    return obj


def _apply_assumption_side_effects(txn: _Transaction,
                                  previous_status: Mapping[Any, Any]) -> None:
    """Record derived events when an assumption changes state.

    Spec §4 (Skill-First Refactor v2): the runtime may detect that a blocker
    has become reopenable (its assumption flipped to ``disproved``) and emit a
    derived event so the model knows. It must NOT mutate ``blocked_path.status``
    or ``close_reason`` itself — those are research decisions the model
    owns. Closing a path never rewrites the candidate's own status: "this
    route is obstructed" is not "this bug is disproved" — same principle
    holds; the runtime merely reports the fact that an obstruction is now
    gone, the model decides what to do.
    """
    now = utc_now()
    for assumption in iter_objects(txn.ledger, "assumption"):
        new_status = assumption.get("status")
        old_status = previous_status.get(assumption.get("id"))
        if new_status == old_status:
            continue
        txn.assumption_transitions.append({
            "id": str(assumption.get("id")),
            "from": str(old_status or ""),
            "to": str(new_status or ""),
        })
        if new_status not in ("disproved", "supported"):
            continue
        # Spec §4: detect mechanical fact, emit derived event, leave the
        # status mutation to the model. Reopen / close are decisions.
        event_name = ("blocked_path_reopenable"
                      if new_status == "disproved"
                      else "blocked_path_close_supported")
        for path in iter_objects(txn.ledger, "blocked_path"):
            if (path.get("blocker") or {}).get("assumption_ref") != assumption.get("id"):
                continue
            derived = {
                "event": event_name,
                "subject": str(path.get("id")),
                "reason": f"assumption {assumption.get('id')} transitioned "
                          f"{old_status or ''} -> {new_status}",
                "evidence_refs": list(path.get("evidence_refs") or []),
                "at": now,
                "delta_ref": str(txn.delta.get("agent_id") or ""),
            }
            txn.derived_events.append(derived)
        # Spec §4: derived events live on the ledger, not on the agent-visible
        # canonical objects. Sync the txn-level list back into the ledger dict
        # before persistence.
        txn.ledger["derived_events"] = list(txn.derived_events)


#: Decisions the runtime refuses to canonicalize. "runtime" is the obvious one:
#: the whole point of the field is to surface who *originated* the change.
DECISION_DECIDED_BY_RESERVED = frozenset({"runtime", "system"})

#: decision.kind values that require a non-empty evidence_refs list. Other
#: kinds allow an empty list (audit_stop is the main case — "no investigation
#: was performed" is itself a valid reason to stop).
_DECISION_REQUIRES_EVIDENCE = frozenset({
    "candidate_promote", "candidate_reject", "finding_confirm",
    "finding_defer", "blocked_path_reopen", "assumption_judge",
})


def _canonicalize_decisions(txn: _Transaction,
                            decisions: Sequence[Mapping[str, Any]]) -> None:
    """Validate and append decisions to ``txn.ledger["decisions"]``.

    Spec §5 contract:

    * Every entry must carry a non-empty ``decision_id`` and ``decided_by``.
      The runtime refuses to canonicalize entries without them.
    * ``decided_by`` must not be ``"runtime"`` or ``"system"`` — the field
      exists to record who *originated* a semantic change.
    * ``evidence_refs`` is required (non-empty) for mutations that rest on
      evidence, optional otherwise. ``audit_stop`` is the documented case
      where empty evidence is allowed.
    * ``decision_id`` is the idempotency address: re-applying the same id is
      a no-op so retries are safe.
    * The runtime stamps ``decided_at`` and ``delta_generation`` so a later
      audit can correlate the entry with the transaction that committed it.
    """
    if not decisions:
        return
    ledger = txn.ledger
    ledger.setdefault("decisions", [])
    seen_ids = {d.get("decision_id") for d in ledger.get("decisions", [])}
    for index, entry in enumerate(decisions):
        if not isinstance(entry, dict):
            raise DeltaSchemaError(f"decisions[{index}] must be an object")

        decision_id = str(entry.get("decision_id", "")).strip()
        if not decision_id:
            raise DeltaSchemaError(
                f"decisions[{index}] requires a non-empty decision_id "
                "(spec §5); minting the id is the agent's responsibility"
            )
        if not re.match(r"^DEC-[0-9]{4,}$", decision_id):
            raise DeltaSchemaError(
                f"decisions[{index}] decision_id {decision_id!r} does not match "
                "the DEC-NNNN pattern"
            )

        decided_by = str(entry.get("decided_by", "")).strip()
        if not decided_by:
            raise DeltaSchemaError(
                f"decisions[{index}] {decision_id!r} requires a non-empty "
                "decided_by; an entry without a decision-taker cannot be "
                "canonically attributed"
            )
        if decided_by in DECISION_DECIDED_BY_RESERVED:
            raise DeltaSchemaError(
                f"decisions[{index}] {decision_id!r} has decided_by="
                f"{decided_by!r}, which is reserved; the runtime does not "
                "originate decisions (spec §5)"
            )

        semantic_mutation = str(entry.get("semantic_mutation", "")).strip()
        if not semantic_mutation:
            raise DeltaSchemaError(
                f"decisions[{index}] {decision_id!r} requires a non-empty "
                "semantic_mutation"
            )

        if not str(entry.get("reason", "")).strip():
            raise DeltaSchemaError(
                f"decisions[{index}] {decision_id!r} requires a non-empty "
                "reason; a decision without a reason is refused"
            )

        if semantic_mutation in _DECISION_REQUIRES_EVIDENCE:
            refs = entry.get("evidence_refs") or []
            if not refs:
                raise DeltaSchemaError(
                    f"decisions[{index}] {decision_id!r} ({semantic_mutation}) "
                    "requires at least one evidence_ref"
                )

        # Idempotency: re-applying the same decision_id is a no-op.
        if decision_id in seen_ids:
            txn.warnings.append(
                f"decision {decision_id!r} already in ledger; "
                "skipping duplicate canonicalization"
            )
            continue

        now = utc_now()
        canonical = {
            "decision_id": decision_id,
            "decided_by": decided_by,
            "phase": str(entry.get("phase", "")).strip(),
            "semantic_mutation": semantic_mutation,
            "reason": str(entry.get("reason", "")).strip(),
            "evidence_refs": list(entry.get("evidence_refs") or []),
            "subject_ref": str(entry.get("subject_ref") or ""),
            "decided_at": now,
        }
        ledger["decisions"].append(canonical)
        seen_ids.add(decision_id)


def _recompute_depended_on_by(txn: _Transaction) -> None:
    """Maintain the informational reverse index on assumptions."""
    derived: dict[str, list[str]] = {}
    for path in iter_objects(txn.ledger, "blocked_path"):
        ref = (path.get("blocker") or {}).get("assumption_ref")
        if ref:
            derived.setdefault(str(ref), []).append(str(path.get("id")))
    for assumption in iter_objects(txn.ledger, "assumption"):
        extra = derived.get(str(assumption.get("id")), [])
        if extra:
            assumption["depended_on_by"] = _union_list(assumption.get("depended_on_by"), extra)


def patch_candidate_research(txn: _Transaction, candidate_id: str,
                             research: Mapping[str, Any]) -> None:
    """Merge a ``research`` patch onto a candidate record, in memory.

    No conflict rule applies here: the block has no identity fields, so scalars
    overwrite (reclassifying ``standalone`` → ``chain_seed`` is the point) and
    list fields union. A patch that names no existing candidate is refused —
    an orphan update would be silently invisible.
    """
    hit = txn.candidates.get(candidate_id)
    if hit is None:
        raise UnknownCandidate(
            f"candidate_updates targets {candidate_id!r}, which appears in no "
            f"{CANDIDATE_DIRNAME}/*.json payload"
        )
    path, payload, record = hit
    existing = record.get("research")
    current: dict[str, Any] = dict(existing) if isinstance(existing, Mapping) else {}
    for field, value in research.items():
        if field in ("requires_capabilities", "grants_capabilities",
                     "depends_on_assumptions", "breaks_assumptions",
                     "blocked_by", "reopen_conditions"):
            current[field] = _union_list(current.get(field), value)
        else:
            current[field] = value
    record["research"] = current
    txn.touched_candidate_payloads[path] = payload


# ---------------------------------------------------------------------------
# Read-only status
# ---------------------------------------------------------------------------


def research_status(audit_root: os.PathLike[str] | str) -> dict[str, Any]:
    """Summary used by ``research status`` (shared lock, no mutation)."""
    audit_root = Path(audit_root)
    with search_governance_lock(audit_root, exclusive=False, operation="research status"):
        ledger = load_ledger(audit_root)
        graph = graph_mod.load_graph(audit_root)
    if ledger is None:
        return {"ok": True, "exists": False, "ledger": str(ledger_path(audit_root))}

    def counts(kind: str, field: str) -> dict[str, int]:
        buckets: dict[str, int] = {}
        for obj in iter_objects(ledger, kind):
            value = str(obj.get(field, ""))
            buckets[value] = buckets.get(value, 0) + 1
        return dict(sorted(buckets.items()))

    open_p0 = sorted(
        str(obj.get("id")) for obj in iter_objects(ledger, "open_question")
        if obj.get("priority") == "P0" and obj.get("status") == "open"
    )
    return {
        "ok": True,
        "exists": True,
        "ledger": str(ledger_path(audit_root)),
        "counts": {
            "facts": len(iter_objects(ledger, "fact")),
            "assumptions": len(iter_objects(ledger, "assumption")),
            "open_questions": len(iter_objects(ledger, "open_question")),
            "blocked_paths": len(iter_objects(ledger, "blocked_path")),
            "intents": len(iter_objects(ledger, "intent")),
            "graph_nodes": len(graph.get("nodes", [])) if graph else 0,
            "graph_edges": len(graph.get("edges", [])) if graph else 0,
        },
        "questions_by_status": counts("open_question", "status"),
        "questions_by_priority": counts("open_question", "priority"),
        "assumptions_by_status": counts("assumption", "status"),
        "blocked_paths_by_status": counts("blocked_path", "status"),
        "open_p0_questions": open_p0,
    }
