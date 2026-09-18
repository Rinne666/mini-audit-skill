<!-- Loaded by mini-audit skill: research state contract -->
<!-- Used in phase(s): pre-flight for every audit; L1 objective bootstrap; L5/P8 probe rounds; L7 closure review; I1-I3 reinvest -->
<!-- Source: Search Governance v1 frozen decisions R2-1 … R2-5, as implemented in runtime/objective.py, runtime/research_state.py, runtime/attack_graph.py, runtime/search_lock.py -->

# Research state contract (研究状态契约)

> **Core principle (one line):**
> A long audit forgets. This contract is what stops it — the audit keeps a
> durable, machine-checkable record of what it knows, what it suspects, where it
> is blocked, and what it intends next; and the only way into that record is a
> validated delta, never an agent's direct write.

This document defines the durable state Search Governance maintains, who may
write it, and what the runtime guarantees. Every rule below is enforced in code;
this is the contract the code enforces.

---

## 1. The five canonical objects

| Object | File | Question it answers | Not to be confused with |
|---|---|---|---|
| **Objective** | `audit-objective.json` | What is this audit trying to prove? | the intent corpus (`L1`) — that is *what the project cares about*, not *what we are trying to reach* |
| **Research State** | `search-ledger.json` | What do we know, suspect, and where are we stuck? | Findings — research state carries half-finished leads, which findings must never contain |
| **Attack Graph** | `attack-graph.json` | How do the capabilities we hold convert into one another? | a vulnerability taxonomy — nodes are capabilities, not bug classes |
| **Coverage** | `coverage-ledger.json` | Where have we even looked? | research state — coverage says *examined*, not *understood* |
| **Findings** | `findings.json` | What can we report? | a capability. A capability records what the attacker can now do; only the permission-delta judgement makes a finding |

The names are fixed as they are today (`search-ledger.json` is not
`research-state.json`); what matters is that these five stay distinct. Collapsing
any pair of them loses exactly the information the audit needs after twenty
rounds: which leads are still open, which paths are blocked and why, and which
capability came from which primitive.

Research state is **not** the verdict plane. `candidate.status` and
`finding.verdict` answer "is this a real security defect"; research state answers
"is this worth remembering". They are orthogonal:

```text
candidate.status   = needs_validation      ← the security verdict
research.role      = chain_seed            ← the research value
research.local_validity = verified
```

That combination is entirely legitimate, and is the whole point of the split. A
capability whose local bug is real does not have to be exploitable today to be
worth keeping.

---

## 2. Who may write what

| Role | Reads | Writes |
|---|---|---|
| **Worker agent** | canonical state (read-only) | `agents/<id>/scratch/**` — nothing else, ever |
| **Orchestrator** | canonical state | `agents/<id>/scratch/**`, and canonical state **only through the runtime CLI** |
| **Runtime** | canonical state | the canonical artifacts themselves, under the Search Governance lock |

Two rules, in order of age:

1. **Agent output ≠ canonical state.** An agent's finding, objective or research
   delta is a proposal. This has been the rule since Runtime Hardening v1 and it
   is not negotiable: an agent that can edit the ledger can also declare its own
   question answered.
2. **The orchestrator is the single writer.** Workers run in parallel; if two of
   them applied deltas concurrently, the merge would be a read-modify-write race.
   Serialising it in one process makes the transaction well-defined without any
   coordination protocol.

The worker write path is therefore one file:

```text
mini-audit/agents/<agent-id>/scratch/research-delta.json
```

This is the deterministic boundary worth keeping, and the reason it is stated as
a *protocol* rather than left to convention: it is the only interface between
non-deterministic reasoning and deterministic state, so it is the only thing that
has to be exactly right.

**The lock.** `SearchGovernanceLock` (`mini-audit/.search-governance.lock`,
exclusive for writers, shared for multi-artifact readers, 5s timeout, exit code 3
with a machine-readable holder) exists because rule 2 is a *convention the
harness is expected to honour*, and a convention that is violated silently
corrupts state. It is cheap; keep it until the harness can make single-writer a
guarantee rather than an expectation. If it can, delete the lock — do not delete
it first and hope.

---

## 3. The research delta

An agent contributes through `mini-audit-runtime research apply <delta.json>`.
Twelve operations, no free-form edits:

```text
facts_add            assumptions_add      assumptions_update
research_intents_add research_intents_update blocked_paths_add
blocked_paths_reopen capabilities_add     capabilities_update
edges_add            edges_update
candidate_updates
```

`*_add` creates or merges (matched by semantic key). `*_update` changes an object
that must already exist and can never create one — which is why the update forms
carry no identity fields: re-declaring identity would let a typo silently become
a new object.

### The mutate forms

`templates/research-delta.json` is a round-1 template and therefore contains
creates only: in a first submission an object is simply declared with the status
it ends the round in. The mutate forms are for later rounds — promoting what an
earlier round proposed, and recording what a later round learned:

```json
{
  "assumptions_update": [
    {"ref": "assumption:author-exclude-int-array", "status": "disproved",
     "evidence_refs": ["src/cli/import-command.php:41"]}
  ],
  "research_intents_update": [
    {"ref": "ri:bp-031-prerequisite", "status": "open",
     "reason": "the CLI import path builds the same query without coercion",
     "evidence_refs": ["src/cli/import-command.php:41"]}
  ],
  "capabilities_update": [
    {"ref": "cap:control-sql-expression", "status": "verified",
     "evidence_refs": ["mini-audit/findings/cand-031/evidence/exploit.log"]}
  ],
  "edges_update": [
    {"ref": "edge:scalar-to-sql", "status": "verified",
     "verification_refs": ["mini-audit/findings/cand-031/evidence/exploit.log"]}
  ],
  "blocked_paths_reopen": [
    {"ref": "bp:cand-031-array-validation", "priority": "high",
     "attempt_refs": ["agents/agent-L5-01/scratch/investigation.md"]}
  ],
  "candidate_updates": [
    {"candidate_id": "cand-031", "research": {
      "local_validity": "verified", "role": "chain_seed", "chain_potential": "high",
      "requires_capabilities": ["control_scalar_parameter"],
      "grants_capabilities": ["control_sql_expression"]}}
  ]
}
```

Two things to know before copying that block:

* `assumptions_update` is a mutation with a **side effect**: a disproved
  assumption emits a derived event `blocked_path_reopenable`; the model's
  own `blocked_paths_reopen` decides what to do with it (see §4). It is not
  a runtime action — the runtime only reports the mechanical fact.
* `candidate_updates` requires the candidate to already exist and is refused
  otherwise (`UNKNOWN_CANDIDATE`), which is why the round-1 template omits it —
  the other eleven operations apply cleanly to a fresh audit, and a template that
  fails out of the box would be worse than an incomplete one.

### Semantic keys vs canonical ids

| | Supplied by | Purpose | Example |
|---|---|---|---|
| **semantic key** | the author | idempotency address, and the name you may use in references | `assumption:author_exclude-int-array` |
| **canonical id** | the runtime | stable identifier for tools and reports | `A-012`, `CAP-003`, `BP-003`, `OQ-004`, `INT-021` |

A reference may use either form, and may point at an object created **in the same
delta** — forward references resolve before anything is written. This is what
makes one delta able to say "create this capability and this edge that starts at
it".

**A key is unique across the whole namespace**, not per kind. `fact:shared` and
`assumption:shared` cannot coexist: references resolve by key first, so a second
binding would silently make every reference to `shared` ambiguous. Violating this
is `RESEARCH_KEY_CONFLICT`, and it rejects the whole delta.

### Identity fields decide conflicts; mutable fields merge

| Kind | Identity | Mutable |
|---|---|---|
| Fact | `claim` | `evidence_refs`, `source_refs`, `confidence` |
| Assumption | `claim` | `status`, `evidence_refs`, `source_refs` |
| Capability | `name` + `principal` | `status`, `evidence_refs`, `source_candidates`, `source_edges`, `confidence` |
| Blocked Path | `candidate_id` + `blocker.type` + `blocker.claim` (and `blocker.assumption_ref` when present) | `status`, `priority`, `evidence_refs`, `reopen_if`, `attempt_refs` |
| Open Question | `question` | `priority`, `status`, `reason`, `evidence_refs`, `reopen_if`, `attempt_refs`, `blocked_path_ref`, `related_candidates`, `related_capabilities` |
| Intent | `question_ref` + `strategy` | `priority`, `status`, `reason`, `assigned_agent`, `attempt_refs` |
| Graph Edge | `from` + `to` + `relation` + `via_candidate` | `status`, `evidence_refs`, `verification_refs`, `confidence` |

Same key + identity fields agree → merge the mutable fields. Same key + any
identity field differs → refuse the **entire** delta. Partial application is
never an option: an agent that cannot tell which of its claims took effect cannot
correct them, and the failure would not be reproducible.

`blocker.claim` is part of the identity deliberately — one candidate can carry
two blockers of the same `type`, and keying on type alone would merge them.

### Candidates keep their own ids

`candidate_id` (`^cand-[a-z0-9-]{3,}$`) stays author-supplied; candidates are not
migrated onto semantic keys. `candidate_updates` patches only the `research`
block, and the patch must resolve to a real candidate — an orphan patch is
refused. Two id spaces coexist on purpose, and the blocked path's `candidate_id`
is the bridge between them.

Because the `research` block has no identity fields, its merge is a plain
scalar-overwrite / list-union: reclassifying a candidate from `standalone` to
`chain_seed` is exactly what that operation is for.

### Transaction semantics, exactly

The runtime guarantees:

* **Validated staged transaction under an exclusive lock, with atomic per-file
  replacement.** The full delta is parsed, schema-validated, key-resolved,
  conflict-checked and reference-checked in memory; every artifact is written
  only if all of that succeeded; each file is replaced atomically (temp + fsync +
  rename).
* **All-or-nothing from the caller's perspective.** Success, or zero state
  change. There is no partial outcome to inspect.
* **Idempotence.** Re-applying a delta is a no-op, because keys are the identity.

What it does **not** guarantee: a crash *between* two file writes leaves one
artifact updated and the other not. That is not a database, and this update does
not add one. The mitigation is `generation`: `search-ledger.json` and
`attack-graph.json` carry the same integer, bumped together by every
`research apply`. Readers compare them and **fail closed** on a mismatch
(`RESEARCH_GENERATION_MISMATCH`) rather than reasoning over two different
snapshots. A writer that legitimately touches only one artifact — an objective
revision records a ledger fact but deliberately leaves the graph alone —
preserves the value instead of manufacturing a mismatch.

---

## 4. Lifecycle rules that matter

### A blocked path is not a rejected candidate

```text
locally real bug, missing a prerequisite
  → blocked path, with blocker + reopen_if + priority
  → NOT rejected
```

"The current path is obstructed" and "this bug is disproved" are different
claims, and only the second justifies discarding work.

### Assumptions move paths in both directions

* assumption → `disproved`: blocked paths whose `blocker.assumption_ref` names it
  are **reopened**.
* assumption → `supported`: those same paths are **closed**, with
  `close_reason = blocker_supported`. Their priority may drop.

Neither direction touches the candidate's verdict. Reopening a path does not
re-confirm a bug, and closing one does not disprove it.

### Dangling candidate references

A graph edge naming a `via_candidate` that does not exist is a **warning** at
`research apply` time (parallel research may legitimately build the graph before
the candidate record exists) and a **hard failure** at L7 closure. That asymmetry
is deliberate; do not collapse it in either direction.

---

## 5. The objective

`audit-objective.json` is the control plane, and it is the one artifact whose
change invalidates the meaning of everything else — "three edges from the goal"
is only meaningful against a fixed goal.

* An agent proposes: `agents/<id>/scratch/objective-proposal.json`
  (template: `templates/objective-proposal.json`).
* The orchestrator promotes: `mini-audit-runtime objective init --from-proposal <path>`.
* After that it is **immutable**. Changing it requires
  `objective replace --from <file> --force --reason "..."` — `--force` without
  `--reason` fails, and `init` refuses to overwrite an existing objective.
* A replacement bumps `revision`, appends a `supersedes` entry carrying the
  previous content hash and the reason, and writes a **system fact into the
  ledger**. It does **not** reopen blocked paths: a scope change is recorded, not
  acted on. Nothing may silently re-point the search at a new target.
* `init` seeds the graph with the principal, the initial capabilities and a goal
  node per target capability. `replace` deliberately does not re-seed — doing so
  would strand capabilities the search had already established.

The L1 gate requires both `audit-objective.json` and `search-ledger.json` to
exist and validate. An audit with no declared target does not advance.

---

## 6. What a worker returns

Into `agents/<id>/scratch/research-delta.json` (template:
`templates/research-delta.json`):

* **facts** it established, each with an `evidence_refs` entry pointing at
  something real;
* **assumptions** it identified — especially the ones other conclusions silently
  rest on. An assumption is a first-class object precisely so it can be attacked
  later;
* **open questions** it could not answer, with the priority it believes they
  deserve;
* **blocked paths** for anything locally real but currently unusable — with the
  blocker, the reopen condition, and a priority;
* **capabilities** the attacker gains, with `source_candidates`, and **edges**
  recording how one capability converts into another (`via_candidate` is how a
  primitive becomes the provenance of a conversion without the finding carrying a
  candidate list);
* **candidate research updates** — `local_validity`, `role`, `chain_potential`,
  `requires_capabilities`, `grants_capabilities`, `blocked_by`.

What it must **not** do: propose a capability it cannot point at evidence for, or
record a conversion as `verified` on the strength of reading code. `proposed` is
the honest status for a conversion that has not been demonstrated, and it is not
a lesser answer — it is a different and useful one.

---

## 7. Related documents

* `references/methodology/search-governance.md` — how the next round is chosen from this state.
* `references/methodology/permission-delta-judging.md` — the security verdict,
  which is a separate judgement from anything in this document.
* `SKILL.md` § "Skill / Harness boundary", § "The audit round loop".
