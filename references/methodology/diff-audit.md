<!-- Loaded by mini-audit skill: incremental (diff) audit policy -->
<!-- Used in phase(s): diff mode D0-D6; the reconciliation step of every incremental round; P12 variant hunting after a security-fix commit; I1-I3 reinvest over a changed tree -->
<!-- Source: Incremental Audit v1 design; selector semantics implemented in runtime/diff_scope.py::resolve_diff_range -->

# Incremental audit policy (增量审计策略)

> **Core principle (one line):**
> A diff is not a smaller full audit. It is **one new fact applied to research
> state you already have** — which is why the most valuable thing an incremental
> audit can do is reopen a path it was blocked on months ago, not re-read three
> changed files.

This is a policy, not a program. There is deliberately no `diff_governor.py`,
no `commit_scanner.py` and no PR service: the runtime resolves the change-set
and validates state, and everything else here is judgement applied by the main
agent. Diff mode is **a source of scope**, not a second audit pipeline.

---

## 1. What a diff audit is, and what it is not

The pipeline is:

```text
git change
    ↓
changed symbols            D1 + D2
    ↓
direct blast radius        D4 (callers, consumers, validators)
    ↓
security blast radius      D4 + your judgement (Tier 2 below)
    ↓
affected assumptions / capabilities / invariants   ← reconciliation
    ↓
the normal research workflow you already have
```

It is **not** "feed the changed lines to a model". That framing loses the only
thing a diff gives you that a full audit cannot: it tells you *what changed
recently*, and recency is what makes an old blocked path actionable.

Diff mode must reuse, unchanged:

| Reused as-is | Not forked |
|---|---|
| `Candidate` (`mini-audit/candidates/*.json`) | `DiffCandidate` |
| research delta (`research apply`) | `DiffDelta` |
| `Assumption`, `Blocked Path`, `Capability` | `CommitAssumption`, `PRCapability` |
| Attack Graph edges | `churn.score` graph |
| Review Chamber → Verifier → Permission Delta | `IncrementalVerdict` |
| `Finding` (`mini-audit/findings.json`) | `DiffFinding` |

A diff produces **Candidates, Facts and research deltas**. Nothing else. The
verdict plane is reached the same way it is in a full audit, or not at all.

---

## 2. D0 — choosing the change-set

Three selectors, one meaning each. Resolve it with the runtime; do not
hand-compute a range.

| You mean | Selector | Resolved as |
|---|---|---|
| "audit this commit" | `--commit=<sha>` | `baseline = <sha>^`, `target = <sha>` |
| "audit everything since my baseline" | `--since=<sha\|tag>` | `baseline = <ref>`, `target = HEAD` |
| "audit this branch / PR" | `--base=<x> --head=<y>` | `baseline = git merge-base x y`, `target = <y>` |

```bash
mini-audit-runtime diff scope  --repo-root <path> --commit  <sha>      --audit-root mini-audit
mini-audit-runtime diff scope  --repo-root <path> --since   <sha|tag>  --audit-root mini-audit
mini-audit-runtime diff scope  --repo-root <path> --base main --head feature --audit-root mini-audit
mini-audit-runtime diff stage  --repo-root <path> --commit <sha> --stage D3 --stage D4 --stage D5 --stage D6
```

**The merge base is not a detail.** `base..head` describes the difference
between two *tips*, so every commit the base branch landed since the fork shows
up as if this branch had undone it — a deleted file that the PR never touched, a
reverted feature that was never yours. The result is a plausible-looking diff
over the wrong question, and it is the single most common way an incremental
audit goes wrong before it starts. `--base`/`--head` resolves the merge base for
you; `--baseline`/`--target` remain as an escape hatch for a revision expression
the three selectors do not express, and they are passed through verbatim.

D0 also records what you asked for. `mini-audit/diff-scope.json` carries
`scope_type`, `selector` and (for a PR) `merge_base` alongside the two resolved
SHAs, because "which question was this audit answering" is not recoverable from
two bare commit ids, and a resumed audit needs it.

**A commit with no parent** resolves its baseline to the empty tree, which is
what `git diff --root` does. "Audit the first commit of this repository" stays
answerable instead of erroring.

**Out of scope for v1:** `--staged` and `--working-tree`. Committed change-sets
only. Do not widen this by improvising; a dirty-tree audit needs its own
provenance story (what exactly was reviewed), and it is not this one.

---

## 3. Three tiers of scope — `git diff` is not a boundary

The change-set is where you **start**, not where you stop. Widen in three tiers,
and stop when the budget runs out rather than when the diff does.

### Tier 0 — changed scope (mandatory)

Everything the resolved range touched:

```text
changed files · changed lines · changed functions · changed classes
changed routes · changed config · changed schema
```

The first question is **not** "do the changed lines contain a bug". It is:

> What behaviour changed?

`diff-scope.json` gives you `changed` (with `added`/`modified`/`deleted`/
`renamed`), `line_ranges` (the added-line spans, per file) and `risk_ranked`
(security-relevant and newly-added paths first). Read them; do not re-derive
them.

### Tier 1 — direct semantic blast radius (mandatory for every Tier 0 item that matters)

```text
callers · callees · interfaces · validators
serializers / deserializers · authorization checks
configuration consumers · tests · schemas
```

The two questions that make this tier worth the budget:

> Who depends on the changed behaviour?
> Who still assumes the old behaviour holds?

This is where D4 helps: `mini-audit/diff-d4.json` classifies each reference to a
symbol you name by locality (same file / same module / cross module), whether
the caller looks like an entrypoint, and whether it sits in security-sensitive
code. Name the symbols yourself — the runtime traces what you ask about, it does
not guess what matters.

### Tier 2 — security blast radius (budget permitting, and always for high-risk changes)

```text
attacker-reachable entrypoints · privileged consumers · trust boundaries
security invariants · sibling implementations · alternate callers
variant locations · capability consumers
```

Tier 2 is why "we only changed one line" is not an answer. A one-line change to
a validator can invalidate an assumption that a dozen other call sites depend
on, and those call sites are not in the diff.

---

## 4. The ten questions, per security-relevant change

Answer these for each change worth widening. The answers become Facts,
Assumption updates, Open Questions, Blocked Path reopens, Capabilities and
Edges — **never** a Finding directly.

1. What behaviour changed?
2. What assumption was true before?
3. What assumption is true after the change?
4. Which principal gains or loses capability?
5. Which trust boundary consumes this changed behaviour?
6. Which unchanged callers or consumers depend on the old assumption?
7. Which security invariant may now be invalid?
8. Does this change satisfy the prerequisite of an existing Blocked Path?
9. Does this change invalidate an existing Assumption?
10. Does this change invalidate evidence supporting an existing Finding or a
    verified Capability edge?

Questions 8–10 are the ones that make this an *incremental* audit rather than a
small one. They cannot be answered by reading the diff; they are answered by
reading the research state §5 describes.

---

## 5. Reconciliation — read the old state first

If the audit root already holds a research plane, read it **before** looking at
the diff:

```bash
mini-audit-runtime objective show
mini-audit-runtime research status
mini-audit-runtime graph show ; graph goals ; graph frontier
cat mini-audit/candidates/*.json
cat mini-audit/findings.json
```

Then, for each Tier 0/1 item, walk the old state and ask:

| Question | Where the answer lives |
|---|---|
| Which old assumptions does this change invalidate? | `search-ledger.json` → `assumptions[]`, `status` |
| Which blocked paths may now reopen? | `blocked_paths[]` → `blocker`, `reopen_if` |
| Which verified capability edges relied on changed code? | `attack-graph.json` → `edges[]` → `evidence_refs` |
| Which confirmed findings relied on changed evidence? | `findings.json` → `boundary`, trace refs |
| Which rejected/deferred candidate deserves reconsideration? | `candidates/*` → `research.role`, `status` |

So an incremental audit is:

```text
old Research State  +  new Change Set  →  Research State Reconciliation
```

and **not** "ignore the old audit, scan the diff from scratch". Skipping the
reconciliation is the failure this whole mode exists to fix: without it you get
a fresh audit of recent code, which is strictly worse than a full audit because
it has all the same blind spots plus a smaller scope.

The five objects and who may write them are defined in
`methodology/research-state.md`. A worker never writes them; it writes
`agents/<id>/scratch/research-delta.json` and the orchestrator applies it.

---

## 6. Blocked Path reopen is a first-class outcome

This is the highest-value thing an incremental audit does.

The scenario:

```text
Old version       dangerous_query() is locally real, but every caller coerces
                  its input first.
Old audit         candidate role = chain_seed
                  assumption   = "all callers enforce integer coercion"
                  blocked path = "dangerous_query needs a raw scalar caller"
                  → the candidate is BLOCKED, never rejected

New commit        import_route() → dangerous_query(raw_input)
```

The correct incremental reasoning:

```text
new caller observed
    ↓  it does not coerce
old assumption is no longer true      → assumptions_update: status = disproved
    ↓  the runtime reopens every blocked path whose blocker names it
old blocked path is reopened          → status = reopened
    ↓
REUSE the old candidate               → do not re-discover dangerous_query()
    ↓
verify the composition                → the normal chamber / verifier path
```

Two rules make this work, and both are already runtime-enforced:

* **Do not reject a locally real primitive because it is currently
  unusable.** `blocked` exists for exactly this. A rejection throws away the
  work, and the reopen machinery has nothing left to reopen.
* **You do not reopen the path by hand.** Write the fact that disproves the
  assumption (`assumptions_update` with `status: "disproved"`); the runtime
  reopens every path that depended on it. Setting `blocked_paths_reopen`
  directly is also supported, but only when the blocker changed for a reason no
  assumption records.

Disproving an assumption is an **event**, not a field edit, and it has a
direction: `disproved` reopens dependent paths, while `supported` *strengthens*
them and closes them with `close_reason = blocker_supported`. Neither direction
ever rewrites a candidate's own verdict — "this route is obstructed" is not
"this bug is disproved".

**How to spot the reopen candidates in a diff:** a new caller of a symbol that
an old blocker mentions, a removed or loosened guard, a new route or
deserializer reaching privileged code, a widened type signature, a lifted
length/type check. Each is a candidate for `assumptions_update`.

---

## 7. Capability revalidation — four states, no automatic engine

An attack-graph edge that was `verified` before the change is not automatically
still verified after it. Classify each affected edge, and say which:

| State | Meaning | Action |
|---|---|---|
| **UNCHANGED** | no changed file is in the edge's provenance | nothing to do |
| **AFFECTED** | changed code is on the path, but the claim still looks sound | record a Fact; no status change |
| **REVALIDATE** | the supporting validator / parser / caller changed | raise an Open Question; the edge is **not** trusted until re-checked |
| **NEW** | the change creates a capability conversion that did not exist | new capability + proposed edge |

`REVALIDATE` is the important one and the tempting one to skip. An edge whose
supporting code changed is a claim whose evidence moved; continuing to treat it
as verified is how a report ends up citing a precondition that no longer holds.

**Do not build an invalidation engine.** Decide from `source_identity`, the diff
scope, `evidence_refs` and `via_candidate`, and write a research delta that
raises the revalidation question. If real harness runs show agents getting this
wrong repeatedly, *then* it is a candidate for a deterministic helper — not
before. The `proposed` status is what holds an edge that has not been
re-established.

---

## 8. Finding revalidation

When a diff touches a confirmed finding's:

```text
source location · entrypoint · guard · validator · sink
proof artifact dependency · capability path (boundary.capability_refs)
```

raise a `revalidate-existing-finding` Open Question. Then:

* do **not** close the finding because code moved — nothing was disproved;
* do **not** keep it `confirmed` by default — its evidence moved.

Only a verifier re-establishes the verdict. A finding whose `capability_refs`
path is no longer reachable is a closure failure, which the L7 gate
(`reported_capability_paths_closed`) already refuses — so this is a case where
the honest output is usually an Open Question plus a `REVALIDATE` edge, not a
new finding.

---

## 9. Security-fix commits

D3 scores commit history and flags subjects matching security-fix vocabulary
(`security`, `cve-YYYY-NNNN`, `auth`, `permission`, `bypass`, `injection`,
`revert`, `regression`, `hotfix`, …). Treat that as a **search signal, not a
conclusion** — the runtime must never decide that a commit is a fix, and you must
never decide a fix is broken because its message says `security`.

A fix commit gets three reviews, not one:

```text
fix correctness review     is the invariant actually restored?
regression review          did the fix break something the old behaviour relied on?
variant search             where else does the same old logic still live?
```

Questions worth asking every time:

* Which invariant was this fix trying to restore?
* Is there an **alternate caller** that bypasses the fix?
* Is there a **sibling implementation** that still has the old logic?
* Does a **legacy endpoint** still reach the old path?
* Does a **different parser or serializer** bypass the new guard?
* Does the fix cover **one entry point** while other consumers of the same
  behaviour remain?

A fix that closes one door is a very common source of a still-open one. Route
these through P12 variant hunting once the fix itself is understood.

---

## 10. Where diff mode plugs into Search Governance

Diff mode does not own a planner. Once the change-set is derived, the next round
is chosen by `methodology/search-governance.md` as always — the diff is simply
an additional input to it. The diff-shaped rules there are:

**P0**

| Situation | Intent |
|---|---|
| the change invalidates the blocker of a high-priority blocked path | `reopen-blocked-path` |
| changed code affects a verified edge near a goal | `revalidate-frontier-edge` |
| changed code supports a confirmed finding | `revalidate-reported-chain` |

**P1**

| Situation | Intent |
|---|---|
| a new consumer of a held capability appeared | `capability-consumer-search` |
| a changed parser/serializer may invalidate a shared assumption | `assumption-verification` |

**P2**

| Situation | Intent |
|---|---|
| low-risk changed files nobody has looked at | `coverage-exploration` |

---

## 11. Scanners in diff mode

A scanner may run against the changed files, the high-risk files, or the
blast-radius files. That choice is yours; the constraint is not:

```text
scanner output → Candidate        (always)
scanner output → Finding          (never)
```

Scanner results enter through the same normalization as any other scan
(`sarif normalize` → `candidates/*.json`), and then face the same chamber,
verifier and permission-delta judgement. A diff narrows *where* a scanner looks;
it does not change what its output is worth.

---

## 12. Division of labour

| Question | Answered by | Artifact / command |
|---|---|---|
| What is the change-set? | runtime | `diff scope` → `mini-audit/diff-scope.json` |
| Which lines changed? | runtime | `line_ranges` in the same file |
| How risky are these paths? | runtime | `risk_ranked` in the same file |
| History and regression signals? | runtime | `diff stage --stage D3` → `diff-d3.json` |
| What is the blast radius of symbol X? | runtime | `diff stage --stage D4 --symbol X` → `diff-d4.json` |
| Which changed paths have no test? | runtime | `diff stage --stage D5` → `diff-d5.json` |
| What should be adversarially checked? | runtime proposes, you execute | `diff stage --stage D6` → `diff-d6.json` |
| What behaviour changed, and what does it mean? | **you** | this document |
| Which old assumption is now false? | **you** | research delta → ledger |
| Is the finding still real? | chamber + verifier | the normal path |

The runtime stops at "here is the change-set and here is the evidence
requirement". It does not decide what changed semantically, and it must not.

---

## 13. Failure modes this policy exists to prevent

| Failure | What it looks like | Guard |
|---|---|---|
| Wrong range | PR audited as `base..head`; base branch's own work reported as this branch's | `--base`/`--head` resolves the merge base; D0 records which selector was used |
| Diff as boundary | only changed lines reviewed; the callers that depended on the old behaviour never checked | Tier 1/2 widening |
| Amnesia | old blocked paths, assumptions and capabilities ignored; the audit restarts | §5 reconciliation before looking at the diff |
| Re-discovery | the old primitive found "again" as a new candidate | §6 reuse via reopened blocked path |
| Stale closure | a reported finding's capability path no longer holds after the change | §7 `REVALIDATE` + §8 revalidation question + L7 closure gate |
| Fix-induced blind spot | security-fix commit marked "handled" without variant search | §9 three reviews |
| Forked pipeline | `DiffFinding` and friends; two verdict planes to keep in sync | §1 |

---

## 14. Related documents

* `references/methodology/search-governance.md` — how the next round is chosen; diff scope is one of its inputs.
* `references/methodology/research-state.md` — the five canonical objects, the worker write protocol, and the delta transaction.
* `references/methodology/permission-delta-judging.md` — the verdict, which a diff never produces directly.
* `SKILL.md` § diff mode, § "The audit round loop", § "Phase catalog".
