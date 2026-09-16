<!-- Loaded by mini-audit skill: search governance policy -->
<!-- Used in phase(s): every probe round (L5/P8); L7 closure review; P12 variant hunting; X1-X3 longshot; I1-I3 reinvest -->
<!-- Source: policy extracted from the Search Governance v1 design series; replaces the withdrawn runtime/search_governor.py -->

# Search Governance policy (搜索治理策略)

> **Core principle (one line):**
> Choose the next round of investigation by reading the research state, not by
> scanning more code. Ask which single unanswered question would change the most
> conclusions if answered — and let everything else wait.

This is the **planning half** of Search Governance, and it is a policy, not a
program. There is deliberately no `runtime/search_governor.py`: the main agent
runs this document each round. What stays in code is the part that must not vary
between runs — schema validation, the delta transaction, graph traversal, the
closure check and the saturation floor. Ranking is judgement, so it lives here.

That split is the point. A ranking rule expressed as Python is a rule only the
runtime can apply, and it freezes a decision that is still being learned. A
ranking rule expressed here is one the agent applies with the code in front of
it, and it can be corrected by editing a paragraph.

---

## 1. Inputs

Read all seven before generating anything. They are cheap to read and expensive
to guess; five of the seven have a command that answers the question directly.

| # | Input | What you take from it | How to read it |
|---|---|---|---|
| 1 | **Audit Objective** | the principal, the capabilities it starts with, the goals it is trying to reach, and the invariants it must not be able to break — this is the origin of every "distance to goal" judgement | `mini-audit-runtime objective show` |
| 2 | **Research State** | facts, assumptions (and their status), open questions, blocked paths (and their reopen conditions), existing intents | `mini-audit-runtime research status` |
| 3 | **Attack Graph** | what capabilities are *verified* as held, what edges are proposed vs verified vs blocked, and where the frontier is. `graph show` gives the shape (counts, start nodes, goals), `graph frontier` the reachable set and the next boundary edges, `graph goals` the goal reachability and distances; the node names themselves are in `mini-audit/attack-graph.json`, which is canonical state and readable | `mini-audit-runtime graph show` / `graph frontier` / `graph goals` |
| 4 | **Coverage Ledger** | what portions of the target have not been examined at all — the honest baseline for "have we even looked" | `mini-audit/coverage-ledger.json` |
| 5 | **Candidates** | locally real primitives, their `research.role`, `chain_potential`, declared `requires_capabilities` / `grants_capabilities` | `mini-audit/candidates/*.json` |
| 6 | **Remaining budget** | how many rounds/agents are left, and therefore how much of the below is affordable | your own phase position and lease budget |
| 7 | **Change set** *(incremental rounds only)* | what changed recently, and how risky each change is. Read it *against* inputs 2 and 3, never instead of them: the value of a diff is that it can make an old blocked path actionable, and that only shows up in the reconciliation | `mini-audit/diff-scope.json`, plus `diff-d3/d4/d5.json` when the round has budget for them |

**On the change set.** A diff is an extra input, not an extra planner. It adds
triggers to the rules below (§3.1, §3.2) and it changes nothing else. The one
thing it must never do is shorten the reading list: "only a few files changed"
is exactly the situation in which the assumptions, blocked paths and capability
edges in inputs 2 and 3 are most likely to have been invalidated, and they are
not in the diff. See `methodology/diff-audit.md` for the reconciliation step and
the ten questions that turn a change into research state.

**On goal distance.** `graph goals` reports reachability over *verified* edges.
That is the only reading that supports a claim. But under the strict reading
nothing is "close to a goal" until the goal has already been taken, which makes
the near-goal rules below dead letters for almost the whole audit. So use
`graph frontier` and the graph's `proposed`/`blocked` edges for *ranking*, and
the verified reading only for *asserting*. Never let a potential path become the
basis of a reported claim.

---

## 2. Output: Next Intents

An intent is a question plus the reason it outranks the alternatives. Nothing
else — it is a proposal to investigate, not a result.

```json
{
  "key": "intent:prerequisite-search:BP-003",
  "priority": "P0",
  "question": "Can the blocker of BP-003 be broken: 'normal REST path only accepts integer arrays'?",
  "reason": "high-priority blocked path BP-003 keeps candidate cand-031 out of the chain; its reopen_if conditions are ['an alternate caller bypasses REST validation']",
  "strategy": "prerequisite-search",
  "related_questions": ["OQ-004"],
  "related_blocked_paths": ["BP-003"],
  "related_capabilities": ["CAP-002", "CAP-003"],
  "related_candidates": ["cand-031"]
}
```

| Field | Rule |
|---|---|
| `key` | `intent:<strategy>:<slug>` — stable, so re-proposing is a no-op rather than a duplicate |
| `priority` | exactly `P0` / `P1` / `P2`. There is no score, no float, no weighted sum |
| `question` | one question, answerable by a bounded investigation. "Audit the auth system" is not an intent |
| `reason` | which object in the research state makes this the next thing — name the BP/OQ/CAP/candidate ids. A reason that cannot cite one is a hunch and belongs in P2 |
| `strategy` | the *kind* of search: `reopen-blocked-path`, `prerequisite-search`, `verify-frontier-edge`, `unblock-open-question`, `close-reported-capability-path`, `assumption-verification`, `chain-extension`, `capability-consumer-search`, `coverage-exploration`, `variant-search`, `longshot-exploration` |
| `related_*` | ids or semantic keys. These are the machine-traceable part; the reason text is for humans |

---

## 3. Priority rules

### P0 — spend the next round here

| Rule | Condition | Strategy |
|---|---|---|
| Reopened blocked path | a high-priority blocked path is `reopened` — its blocker was invalidated | `reopen-blocked-path` |
| Blocked path one prerequisite away | a high-priority blocked path is still `blocked` | `prerequisite-search` |
| Frontier edge | an edge at the boundary of the verified region is `proposed` or `blocked`, and its far side is close to a goal | `verify-frontier-edge` |
| Question blocking a chain | an open question that is itself P0, or that blocks a capability on a path near a goal | `unblock-open-question` |
| Reported chain that does not close | a `confirmed` finding whose `boundary.capability_refs` do not resolve to a reachable capability — resolve each ref with `graph path` from the objective principal; the L7 gate is the enforcement, but a failure found at L7 has already cost the round | `close-reported-capability-path` |

The reopened case is the one that is easy to get wrong. When a blocked path
reopens, the question is **"does the original primitive now compose with the
newly available prerequisite?"** — not "let us scan the repository again".
Reopening is a statement that a specific missing condition appeared; the next
round exists to test that composition.

### P1 — do it when the next round has room

| Rule | Condition | Strategy |
|---|---|---|
| Prerequisite for a strong lead | a candidate with `chain_potential: high` whose declared `requires_capabilities` are not in the verified reachable set | `prerequisite-search` |
| Consumer for a held capability | a capability is `verified` and nothing consumes it: no verified or proposed conversion starts there, and it is not a goal | `capability-consumer-search` |
| Core assumption | an assumption is `unverified` and several blocked paths depend on it | `assumption-verification` |
| Chain extension | a candidate's prerequisites are all held and it declares what it grants, but nothing records the conversion as verified | `chain-extension` |

`capability-consumer-search` is the rule that distinguishes this from
vulnerability-class hunting. Given `control_sql_expression`, the question is not
"is there SQL injection here" but "which mechanism consumes SQL control and
converts it upward — database write, credential read, privileged state
mutation?" You are searching for *consumers of a capability*, not for instances
of a class.

### 3.1 Diff-mode triggers — the rules above, applied to a change-set

When the audit is in `diff` mode the same strategies fire, but the conditions
are read against `mini-audit/diff-scope.json` and the per-stage artifacts
(`diff-d3.json`, `diff-d4.json`, `diff-d5.json`, `diff-d6.json`) instead of
against the code alone. The reconciliation step in `methodology/diff-audit.md`
§5 is what makes these triggers actionable — a changed file is only interesting
because the *old* research state said something about it. The table below names
the strategy for each situation; the rows above describe the strategy itself.

| Tier | Situation (diff-shaped) | Strategy |
|---|---|---|
| **P0** | the change invalidates the blocker of a high-priority blocked path (new caller, lifted guard, widened type signature, removed coercion) | `reopen-blocked-path` |
| **P0** | changed code is on the path of a `verified` edge near a goal — capability provenance includes a modified file | `verify-frontier-edge` (as a `REVALIDATE` question) |
| **P0** | changed code supports a `confirmed` finding (source / guard / validator / sink / capability path / proof artifact) | `close-reported-capability-path` (as a revalidation question) |
| **P1** | a new caller of a held capability appeared in the diff — no consumer was recorded before | `capability-consumer-search` |
| **P1** | a changed parser / serializer / validator may invalidate a shared assumption other modules depend on | `assumption-verification` |
| **P2** | low-risk changed files that nobody has looked at since the last audit | `coverage-exploration` |

The P0 rows are the ones an incremental audit exists for. Each one asks a
question that **cannot be answered from the diff alone**: it requires reading
the old state. Skipping the reconciliation step (§5 of `diff-audit.md`) and
going straight to "what changed" turns the diff into a smaller full audit with
all of its blind spots and none of its history.

### P2 — breadth, and the first thing to drop

| Rule | Condition | Strategy |
|---|---|---|
| Coverage gaps | units still `planned` or `in_progress` | `coverage-exploration` |
| Variant search | units that are `blocked` or `deferred` — a variant elsewhere may not share the blocker | `variant-search` |
| Cheap single-dependency assumption | `unverified`, exactly one dependent | `assumption-verification` |
| Diversity | every P0/P1 intent this round uses one strategy | `longshot-exploration` |

The diversity rule reads the *shape of the intent set*, not the target. Three
intents that all say `prerequisite-search` is a statement about how the search
is being conducted, and the correction is an independent direction — state
machine, parser, cache, serialization, concurrency, configuration boundary —
not a fourth prerequisite search.

---

## 4. Ranking discipline

Five properties keep the ordering honest. Each was learned by breaking it.

1. **Cap per strategy, not per tier.** If you take the top N of the concatenated
   list, whichever rule runs first crowds the later ones out of the window
   entirely. This happened: the governor's own questions, promoted to P0 debt the
   following round, pushed out the intent about a confirmed finding whose chain
   did not close — the highest-consequence item on the list. Cap each strategy at
   a handful instead.

2. **Do not re-report your own questions.** Questions you authored carry the
   `oq:governor:` key prefix. They are the *output* of the previous round; if
   they rank themselves as newly urgent, the agent talks to itself and the real
   rules starve. Outstanding P0 debt is reported by `search saturation`, not by
   the ranking.

3. **`requires` is walked backwards.** It points from a capability to its
   prerequisite, so *holding the prerequisite* is what unlocks the dependent.
   Read forwards it means "holding C-17 grants you its prerequisite", and the
   `prerequisite` role — and therefore the whole reopen mechanism — becomes
   meaningless.

4. **Only `verified` counts as held, for nodes and edges alike.** A `proposed`
   edge is a hypothesis, `blocked` is a known obstacle, `refuted` is a dead end.
   A `refuted` capability is not held merely because some edge points at it. The
   runtime enforces this in `graph path` / `graph frontier`; do not re-derive it
   locally and drift.

5. **A reason must cite research state.** "This looks suspicious" is a P2
   coverage note. Every P0 must name the BP/OQ/CAP/finding that makes it P0 —
   otherwise the ranking is unfalsifiable and the next round cannot be reviewed.

---

## 5. The round loop

This is the main loop of the audit. It is stated in full in SKILL.md
("The audit round loop"); the governor's contribution is steps 3 and 7.

```text
1. Read the Objective.
2. Read canonical Research State (and skimming Coverage / Candidates as needed).
3. Identify the highest-value unanswered question, using §3 above.
4. Spawn independent workers for that question — one question, several angles.
5. Workers return research deltas. Workers never edit canonical state.
6. The orchestrator validates and merges the deltas (`research apply`).
7. Re-evaluate: assumptions, blocked paths, new capabilities,
   capability consumers, goal distance.
8. Promote only mature paths to verification. A verified primitive with no
   consumer is not mature; it is a lead.
9. Permission Delta decides reportability.
10. Repeat until budget-aware saturation.
```

Steps 3 and 7 are where this document is used. Step 7 is not optional
book-keeping: a delta that disproves an assumption changes which blocked paths
are actionable, a new capability changes what is worth consuming, and a newly
verified edge changes the frontier. Skipping the re-evaluation means the audit
keeps answering last round's question — which is the failure mode Search
Governance exists to remove.

---

## 6. Handoff: intents → research delta

The proposal is not canonical until it goes through the runtime, and the
existing rule holds: **the orchestrator is the only writer.** Write the intents
to `mini-audit/agents/<orchestrator-id>/scratch/research-delta.json` (template:
`templates/research-delta.json`) and apply it:

```bash
mini-audit-runtime research apply <delta.json> --agent <id>
```

Each intent becomes two objects — a question and the intent that answers it:

```json
{
  "schema_version": 1,
  "agent_id": "orchestrator",
  "phase": "L5",
  "questions_add": [
    {
      "key": "oq:governor:bp-003-prerequisite",
      "question": "Can the blocker of BP-003 be broken: 'normal REST path only accepts integer arrays'?",
      "priority": "P0",
      "related_candidates": ["cand-031"],
      "related_capabilities": ["CAP-002", "CAP-003"]
    }
  ],
  "intents_add": [
    {
      "key": "intent:prerequisite-search:BP-003",
      "question_ref": "oq:governor:bp-003-prerequisite",
      "strategy": "prerequisite-search",
      "priority": "P0",
      "reason": "high-priority blocked path BP-003 keeps cand-031 out of the chain"
    }
  ]
}
```

Notes that save a rejected delta:

* `question_ref` may be the **key** of a question created in the same delta —
  forward references resolve before anything is written.
* The `oq:governor:` prefix on the question key is not decoration; it is what
  rule 2 of §4 matches on next round.
* An intent cannot carry `related_blocked_paths` — the schema does not have that
  field. The machine-traceable link to a blocked path lives **on the blocked
  path**: when a worker investigates one, record `attempt_refs` (or reopen it)
  via the same entry, and the saturation report can then see the path was worked
  on. The intent's `reason` naming the BP id is the human trail.
* Proposing the same intent twice is safe: keys are the idempotency address and
  re-applying a delta is a no-op.

**A deliberate cost.** This conversion used to be done by code
(`search next --output` emitted an applicable delta). It is now the agent's job,
because the round's intent set and its delta are the same decision stated twice,
and having them in one place is what the refactor is for. If agents repeatedly
produce malformed deltas here, this one transformation is the first candidate to
sink back into a helper — that is the intended direction of travel: prove the
policy works, then move only the parts the model keeps getting wrong.

---

## 7. Deterministic queries — run these, do not re-derive them

| Question | Command |
|---|---|
| What does the graph look like — counts, start nodes, goals? | `graph show` |
| What do we hold? | `graph frontier` → `reachable` (node names are in `attack-graph.json`) |
| How far is each capability from a goal? | `graph goals` → `distance` |
| Is there a verified path from here to there? | `graph path --from <id\|key> --to <id\|key>` |
| What is the next edge at the boundary? | `graph frontier` → `frontier` |
| Is the audit's floor met, and what research debt is left? | `search saturation` |
| Does a confirmed finding's chain close? | `graph path` from the objective principal to each `boundary.capability_refs` entry; enforced by the L7 gate (`reported_capability_paths_closed`) |

These are the parts of ranking that must not vary between runs. Do not
re-implement them in prose reasoning and do not trust a hand-derived answer over
the command's: a plausible-looking path that walks a `proposed` edge is exactly
what the runtime refuses to report, and it will be caught at L7 — after the round
has been spent.

---

## 8. Budget

Budget decides **how many** intents are spawned and **whether P2 runs at all**.
It must never change what counts as evidence:

* Tight budget: spawn workers for the P0s only. Drop P2 first; coverage
  exploration is the most deferrable work in the system.
* A P0 that cannot be finished within budget becomes `deferred` **with a reopen
  condition and an attempt record** — the same bar the saturation gate enforces.
  It does not become `resolved` because the round ended.
* Never reclassify a question's priority to make the floor easier to reach.
  Saturation counts what is there, and a `42 deferred / 0 resolved` report is
  readable as exactly that. It is not a pass for the search; it is a pass for
  the *minimum completion gate*, under the current budget.

---

## 9. Failure modes this policy exists to prevent

| Failure | What it looks like | Which rule prevents it |
|---|---|---|
| Premature rejection | a locally real primitive is discarded because it is not exploitable *yet* | blocked path instead of `rejected`; P1 prerequisite search keeps it alive |
| Lost lead | a verified capability nobody consumes is never revisited | P1 `capability-consumer-search` |
| Self-consumption | the agent spends rounds restating its own open questions | §4 rule 2 (`oq:governor:` exclusion) |
| Starved rule | one high-volume rule crowds out the highest-consequence one | §4 rule 1 (cap per strategy) |
| Unfalsifiable ranking | intents with no citation into research state | §4 rule 5 |
| Claim from hypothesis | a `proposed` edge treated as a held capability | §4 rule 4; L7 closure |
| Silent goal drift | the search optimises toward a target that changed | objective revision records a ledger fact; re-read the Objective each round |

---

## 10. Related documents

* `references/methodology/research-state.md` — the state this policy reads: the five canonical
  objects, the worker write protocol, the single-writer contract, and the delta
  transaction.
* `references/methodology/permission-delta-judging.md` — whether a candidate is a
  real boundary crossing. That judgement is **not** made here: a capability
  records what the attacker can now do, and only permission-delta turns a
  primitive into a reportable finding.
* `SKILL.md` § "The audit round loop" (the loop in full) and § "Skill / Harness
  boundary" (which layer owns which responsibility).
