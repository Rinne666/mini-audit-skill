---
name: mini-audit
description: Multi-phase security audit pipeline (Q0-Q4 lite / L1-L7 balanced / P1-P17 deep / V1-V7 confirm / R0-R11c revisit / M1-M7 merge / X1-X3 longshot / I1-I3 reinvest / KB0-K2 knowledge-base) with sub-agent scheduling, resumable state via on-disk canonical artifacts owned by the deterministic runtime, and Review Chamber debate protocol. Use when user asks "/mini-audit-lite", "/mini-audit-balanced", "/mini-audit-deep", "/mini-audit-confirm", "/mini-audit-revisit", "/mini-audit-diff", "/mini-audit-merge", "/mini-audit-longshot", "/mini-audit-reinvest", "/mini-audit-knowledge-base", "/mini-audit-status", "/mini-audit-resume", "/mini-audit-export", "/mini-audit-smoke", "/mini-audit-help", or "run a security audit on this repo".
allowed-tools:
  - Bash
  - Read
  - Write
  - Edit
  - Glob
  - Grep
  - Task
  - TaskList
  - TaskCreate
  - TaskUpdate
  - AskUserQuestion
---

# mini-audit — Multi-phase security audit pipeline (Piolium port to MiniMax Code)

A port of the Piolium security-audit pipeline (originally a Pi coding-agent extension) to MiniMax Code's skill + sub-agent harness. The Piolium phase catalog is preserved verbatim — phase IDs are a stable on-disk contract and must not be renamed.

## Architecture — deterministic layer (Runtime Hardening v1) + the Skill/Harness boundary

This skill ships a three-layer architecture: **Reasoning** (LLM agents), **Policy** (permission-delta judging, verification methodology, and — since Search Governance v1 — the "what to investigate next" rules, all in `references/`), and **Deterministic** (Python runtime at `runtime/`). The deterministic layer owns state, schema, gates, fingerprinting, coverage, and export. LLM "I'm done" never advances phase state on its own — the runtime validates the expected artifacts, parses them, schema-validates them, and only then permits a state transition.

The skill loads the runtime as a Python package at `<skill>/runtime/` and exposes it via `scripts/mini-audit-runtime`.

```text
The agent (main agent + sub-agents) is responsible for:
  reasoning, code understanding, hypothesis generation,
  tracing, adversarial review, remediation reasoning,
  deciding what to investigate next (references/methodology/search-governance.md)

The deterministic runtime is responsible for:
  state, schema, gates, artifact validation, fingerprinting,
  deduplication, coverage accounting, export,
  the research-delta transaction, graph traversal,
  the closure check and the saturation floor

The harness — not this skill — is responsible for:
  spawning and scheduling agents, concurrency, retries,
  timeouts, worker lifecycle, recovery, budget
```

### Skill / Harness / Plugin — who owns what (frozen)

| Side | Owns | Where it lives |
|------|------|----------------|
| **Skill** | methodology, state protocol, decision rules, deterministic validators | `SKILL.md`, `references/**`, `schemas/**`, `templates/**`, `runtime/**` |
| **Harness** | agent scheduling, concurrency, execution, retries, recovery, tool invocation, budget | the agent runtime; *not* this repo |
| **Plugin** | how the skill is packaged, loaded and shipped | `SKILL.md` front matter, `scripts/mini-audit-runtime` launcher resolution, `references/MANIFEST.json`, `_meta.json` |

Three rules follow from that split, and they are the reason the split is written
down at all:

1. **A rule that must not vary between runs goes in code; a rule that is still
   being learned goes in `references/`.** Ranking the next round is judgement, so
   it is `references/methodology/search-governance.md`, not a module.
2. **Nothing in the skill may assume it can control the harness.** The skill
   declares what must be true (a single canonical writer, a hard timeout on the
   sandbox) and enforces what it can; it does not manage agents.
3. **Deterministic state is only ever written by the runtime, under one lock.**
   Workers read canonical state and write proposals into their own scratch
   directory. See `references/methodology/research-state.md`.

### Runtime Diet — per-module classification (Skill-First Refactor v1)

| Module | Class | Why |
|--------|-------|-----|
| `atomic_io.py`, `schema.py` | **keep** | pure primitives; nothing to shrink |
| `objective.py`, `research_state.py`, `attack_graph.py` | **keep** | validate / normalize / merge / dedupe / reference resolution / graph query — the pure deterministic duties |
| `state.py`, `gates.py`, `findings.py`, `coverage.py`, `fingerprint.py`, `source_identity.py`, `sarif.py`, `diff_scope.py`, `export.py` | **keep** | deterministic artifact work, each answering one question with no policy |
| `sandbox.py`, `sandbox_backend.py` | **keep** | isolation enforcement plus the differential canary that proves it. `run_command_with_timeout` is what makes the `hard_timeout` control real rather than declared |
| `search_closure.py`, `search_saturation.py` | **keep** | the two L7 validators: does a reported chain close, and has the audit met its floor |
| `search_lock.py` (`SearchGovernanceLock`) | **keep for now** | see the exit criterion below |
| `process_control.py` — `run_command_with_timeout` | **keep** | the only deterministic safety primitive the runtime owns about processes. Used by the sandbox policy to enforce `hard_timeout_verified=True` |
| `search_governor.py` | **withdrawn** | ranking is a policy now: `references/methodology/search-governance.md`. A rule only the runtime can apply is a rule that cannot be corrected by editing a paragraph |

**Exit criteria, so these are decisions and not drift.** Delete the lock when the
harness can *guarantee* a single writer (not merely be expected to honour it);
until then keep it, because a violated convention corrupts state silently.
Agent scheduling, concurrency, and worker lifecycle belong to the Harness;
the runtime's `scheduler` module was deleted in Skill-First Refactor v2.x
because every scheduler primitive other than `run_command_with_timeout`
was a Harness responsibility. The process-group deadline primitive lives
in `runtime.process_control.py` and is the only one the runtime still owns.
Sink a `references/` rule back into code only after the model is observed
getting it wrong repeatedly — prove the policy first, then move the part
that keeps failing.

### Layers

| Layer | Lives in | Authoritative for |
|-------|----------|-------------------|
| Reasoning | `references/<role>.md` (Piolium inlined), `sub-agent prompts` | hypothesis, debate, trace |
| Policy | `references/methodology/permission-delta-judging.md`, `references/methodology/search-governance.md`, `references/methodology/research-state.md` | boundary crossing, severity, verdict, next-round ranking |
| Deterministic | `runtime/` (Python 3.9+, stdlib) | state, schema, gates, fingerprint, coverage, export, scan→candidate normalization, diff scope, research-delta transaction, graph traversal, closure + saturation checks |

### Canonical artifacts (owned by the runtime)

| File | Owner | Purpose |
|------|-------|---------|
| `mini-audit/audit-state.json` | runtime | single source of truth for run state (Spec §5) |
| `mini-audit/findings.json` | runtime | canonical findings (Spec §10, §11) |
| `mini-audit/coverage-ledger.json` | runtime | subsystem × boundary × class coverage (Spec §20) |
| `mini-audit/candidates/<source>-candidates.json` | runtime | normalized SARIF candidate records (Spec §28) |
| `mini-audit/audit-objective.json` | runtime | what the audit is trying to prove — control plane (Search Governance v1, R2-3) |
| `mini-audit/search-ledger.json` | runtime | what the search knows / suspects / is blocked on / intends (R2-1) |
| `mini-audit/attack-graph.json` | runtime | capability nodes and how they convert into one another (R2-6) |
| `mini-audit/search-saturation.json` | runtime (`search saturation`) | derived: the completion gate verdict and the remaining research debt |
| `mini-audit/scanner/capabilities.json` | `scripts/detect-tools.sh` | what scanners/sandbox are available (Spec §27) |
| `mini-audit/sandbox/probe.json` | `scripts/sandbox-check.sh` | sandbox pre-flight (Spec §25) |
| `mini-audit/agents/<id>/task.json` | runtime | per-lease metadata (Spec §23) |
| `mini-audit/agents/<id>/result.json` | runtime | per-lease result |

Sub-agents write only to `mini-audit/agents/<id>/scratch/`. Promotion into canonical artifacts happens via runtime CLI after gate validation. For the research plane that channel is specifically a **research delta** (`research apply`), which applies whole or not at all — an agent never edits `search-ledger.json` or `attack-graph.json` directly.

### Runtime CLI contract (Spec §7)

```bash
mini-audit-runtime state init --repo-root <path> [--mode balanced]
mini-audit-runtime state show
mini-audit-runtime phase {start|complete|fail|skip} <PHASE> [--error "..."]
mini-audit-runtime gate <PHASE> [--workdir DIR]
mini-audit-runtime finding validate <file>
mini-audit-runtime finding upsert <file>
mini-audit-runtime coverage {init <plan>|validate}
mini-audit-runtime export --format {json|md|sarif} [--verdict V] [--min-severity S] [--class C] [--since ISO] [--output PATH]
mini-audit-runtime source {capture|diff} --repo-root <path>
mini-audit-runtime sarif normalize <file> --source <scanner>
mini-audit-runtime diff scope --repo-root <path> --baseline <sha> --target <sha> [--symbol X ...]
mini-audit-runtime snapshot [--audit-root PATH] [--out PATH]
mini-audit-runtime objective init --from-proposal <path> [--agent ID]
mini-audit-runtime objective replace --from <file> --force --reason "..." [--agent ID]
mini-audit-runtime objective show
mini-audit-runtime research apply <delta.json> [--agent ID]
mini-audit-runtime research status
mini-audit-runtime graph show
mini-audit-runtime graph path --from <id|key> --to <id|key>
mini-audit-runtime graph goals
mini-audit-runtime graph frontier
mini-audit-runtime search saturation [--workdir DIR]
```

### Search Governance (v1, R2-1 … R2-7)

An audit now maintains a research plane beside its verdict plane:

```text
Audit Objective (control plane)     what this audit is trying to prove
        │
Search Ledger  ──── Attack Graph    what is known / suspected / blocked, and how
        │                           capabilities convert into one another
        └── research delta ──── one all-or-nothing transaction
```

The rules that matter operationally:

* **Agents propose, the runtime canonicalises.** An L1 agent writes `agents/<id>/scratch/objective-proposal.json`; `objective init --from-proposal` promotes it. After that the objective is immutable — replacing it needs `--force` **and** `--reason`, bumps `revision`, appends to `supersedes` with the previous content hash, and records a system fact in the ledger. Nothing reopens automatically on a scope change; the change is recorded, not acted on.
* **A semantic key is an idempotency address; the runtime allocates the id.** Re-submitting the same delta is a no-op. Two objects sharing a key must agree on their identity fields (`claim`; `candidate_id + blocker.type + blocker.claim`; `name + principal`; `from/to/relation/via_candidate`) — otherwise the *whole* delta is refused, never partially applied.
* **A locally valid bug that cannot be exploited yet is `blocked`, not `rejected`.** A blocked path records its blocker, evidence, reopen conditions and priority. When the assumption it depends on becomes `disproved` the runtime reopens it; when that assumption becomes `supported` the path is closed with `close_reason = blocker_supported`. Neither direction touches the candidate's verdict.
* **`research` is optional in `candidate.schema.json` but required by the L6 gate** for candidates the chamber accepted, so scanner-normalized `untriaged` records stay valid.
* **One lock covers the whole research transaction.** `SearchGovernanceLock` (`.search-governance.lock`, `LOCK_EX` for writers, `LOCK_SH` for multi-artifact readers, 5s timeout) is a *write lock*, distinct from the scheduler's `Lease`, which is a concurrency quota. A busy lock exits **3** with a machine-readable holder.
* **Only `principal`, `capability` and `goal` are node types.** A node type the runtime cannot verify would repeat the "declared but unchecked" failure v1.1.1 removed.

#### Six things that are easy to confuse, and are not the same thing

| Layer | Question it answers | Artifact / module |
|---|---|---|
| Coverage Ledger | *Where have we looked?* | `coverage-ledger.json` |
| Search Ledger | *What do we know, suspect, and where are we stuck?* | `search-ledger.json` |
| Attack Graph | *How do the capabilities we hold convert into one another?* | `attack-graph.json` |
| Search Governance | *What is most worth investigating next?* | `references/methodology/search-governance.md` (policy, applied by the agent each round) |
| Review Chamber | *Is this candidate locally real?* | chamber workspace + L6 gate |
| Permission Delta | *Is there a real, unpermitted boundary crossing?* | `finding.verdict` + `disposition_reason` |

A **Capability is not a Finding.** A capability records what the attacker can now do; only the permission-delta judgement turns a candidate into a finding, and a finding is the only thing that gets reported. The single bridge between the two planes is `boundary.capability_refs`, which the L7 closure check resolves.

#### Traversal rules (what the graph queries enforce)

* Only `verified` edges carry a claim. `proposed` is a hypothesis, `blocked` is a known obstacle, `refuted` is a dead end. None of them can make a capability "reachable".
* **The destination node must also be `verified`.** An inbound verified edge does not promote a hypothesis: otherwise a `refuted` capability would still be reported as held, and the node status enum would be decorative.
* **`requires` is walked backwards.** It points from a capability to its prerequisite, so holding the prerequisite is what unlocks the dependent. Read forwards it would mean "holding C-17 grants you its prerequisite", and the `prerequisite` role — and therefore blocked-path reopening — would mean nothing.
* `verified_reachable` / `verified_path` use the strict reading. `goal_distance` also offers a *potential* reading (`POTENTIAL_STATUSES`) for ranking, because under the strict reading every node is "unreachable to goal" until the goal is finally taken.

#### Next-round ranking is a policy, not a module

Choosing what to investigate next is judgement, so it lives in
**`references/methodology/search-governance.md`** and the main agent applies it every round.
There is deliberately no `search_governor.py`: a ranking rule expressed as Python
is a rule only the runtime can apply, and it freezes a decision that is still
being learned. The summary below is orientation; the policy document is
authoritative and carries the reasoning behind each rule.

| Tier | Rules |
|---|---|
| P0 | a high-priority blocked path was reopened, or is one prerequisite away; a frontier edge; an open question blocking a path near a goal; a confirmed finding whose chain does not close |
| P1 | a high-chain-potential candidate missing a prerequisite; an unverified assumption several blocked paths depend on; a verified capability nothing consumes; a candidate whose prerequisite is satisfied and which grants something new |
| P2 | unresolved coverage; variant search over blocked/deferred coverage; single-dependent assumptions; diversification when every P0/P1 intent points the same way |

Two properties keep the ranking honest, both learned by breaking them. Intents
are capped **per strategy**, not per tier — a single cap over the concatenated
list lets whichever rule runs first crowd a later rule out of the window
entirely, which is how an intent about a confirmed finding with an unclosed chain
got pushed out by questions the ranking had itself raised. And questions carrying
the `oq:governor:` prefix are not re-reported as newly urgent: they are the
previous round's output, and outstanding P0 debt is saturation's job to report,
not the ranking's.

The proposal is not canonical until it goes through the runtime. The orchestrator
writes the intents into `agents/<id>/scratch/research-delta.json` (template:
`templates/research-delta.json`) and applies them with `research apply`; the
mapping and the traps are in the policy document § 6. This handoff used to be done
by code (`search next --output`); it is the agent's job now, on the principle that
a transformation is sunk into code only after the model is seen getting it wrong
— not before.

#### Saturation — the completion floor

Exactly two hard conditions, both mechanically checkable:

1. coverage — planning complete, units planned, none still `planned` or `in_progress`;
2. no P0 open question — terminal states are `resolved` / `refuted` / `deferred`, and each must carry evidence: a resolution needs a reason plus a reference that resolves to a real file; a deferral needs a reason, a reopen condition, and either an attempted investigation or a blocker that is still standing (a blocked path whose assumption is `supported` — a *reopened* path is actionable, not a reason to wait).

Everything else — open high-chain candidates, unverified assumptions, unreachable goals — is reported in `search-saturation.json` and does not block. A passing gate is called `search_saturated_under_current_budget`, never "exhausted": it proves a floor, not a ceiling.

#### L7 closure — the bridge to the verdict plane

For a Search Governance-enabled audit (objective **and** graph present — detected, not asserted by a flag), every `confirmed` finding must declare `boundary.capability_refs`, and each ref must resolve to a capability node that is reachable from the objective's principal over verified edges, with every edge's `via_candidate` resolving to a real candidate and every `evidence_refs` / `verification_refs` resolving to a real file. An audit without those artifacts is untouched. There is no string comparison against `after_capability` — that would break on the first rewording and make the check advisory in practice.

#### How the audit phases feed it

* **L1** — the agent writes `agents/<id>/scratch/objective-proposal.json` plus a research delta carrying the initial assumptions, facts and invariants; the orchestrator runs `objective init --from-proposal` and `research apply`. The L1 gate requires both canonical artifacts, so an audit cannot advance without a declared target.
* **L5** — besides `probe-summary.md`, each probe agent writes `agents/<id>/scratch/research-delta.json` (facts, assumptions, questions, blocked paths, capabilities, edges, candidate research updates). The **orchestrator** decides what to `research apply`; the L5 gate does not scan scratch directories, because a gate that consumed agent scratch directly would be promoting agent output without review — the failure §7 exists to prevent.
* **L6** — an accepted candidate must carry `local_validity`, `role` and `chain_potential`; one claiming `chain_seed` or `prerequisite` must additionally name at least one of `requires_capabilities`, `grants_capabilities`, `blocked_by`, or the role is a label with no structural meaning.
* **P12 (variant hunting)** — two searches, not one: the root-cause variant *and* "which mechanism consumes this capability?".
* **X1–X3 (longshot)** — diversity. If every P0/P1 intent shares one strategy, that says something about the search, not the target; longshot covers the independent directions (state machine, parser, cache, serialization, concurrency, configuration boundary).
* **I1–I3 (reinvest)** — mainly blocked-path reopening: which old blockers have been invalidated, and which new capability satisfies an old candidate's prerequisite.
* **L7** — `reported_capability_paths_closed` and `search_saturation_hard_gate` on top of the existing checks; `search saturation` writes the debt report.

One asymmetry is deliberate and must be preserved: a dangling candidate reference at **apply** time is a warning (parallel research may build the graph before the candidate exists), while at **L7 closure** it is a hard failure.

The launcher resolves the runtime package via three strategies: `MINI_AUDIT_RUNTIME_HOME` env → `$MAVIS_SKILLS_DIR/mini-audit` → relative to the script.

---

## Conceptual audit stages (the agent's primary ontology)

The agent reasons in four conceptual stages. The legacy phase IDs (`L*`, `P*`, `V*`, `R*`, `M*`, `X*`, `I*`, `D*`) remain the on-disk and runtime contract; they are *storage compatibility identifiers*, not the agent's primary reasoning vocabulary.

| Stage | What the agent is doing here | Phase IDs (storage compat) |
|---|---|---|
| **Scope** | What are we auditing, for whom, against which invariants. Lock the objective, capture source identity, plan coverage units. | Q0, Q1, L1, P1 |
| **Discover** | Build the attack surface, run the search governance loop, gather facts/assumptions/blocked paths/intents, decide what to investigate next. | Q2, Q3, L2, L3, L4, L5, L6, L6b, L6c, P2, P3, P4, P5, P6, P7, P8, P9, P10, P11, P12, P13, X1, X2, X3, I1, I2, I3, D0, D1, D2, D3, D4, D5, D6 |
| **Verify** | Promote candidates to findings; capture evidence; build & run PoCs in isolation; commit findings. | Q4, L7, P14, P15, P16, P17, V1, V1.5, V2, V3, V4, V5, V6, V7 |
| **Report** | Re-investigate, merge, judge, export. | R0, R5, R7, R8, R9, R10, R10k, R11, R11b, R11c, M1, M2, M3, M4, M5, M6, M7, J1, J2, KB0, K1, K2 |

**Rule**: legacy phase IDs are storage/runtime compatibility identifiers, not the primary reasoning ontology. The four stages above are how the agent talks to itself; phase IDs are how the runtime talks to the audit log.

**Rule**: each round the agent picks a stage, picks a phase ID *within* that stage, runs the snapshot read, decides, and submits a decision. Crossing from one stage to the next is a phase transition (see §Phase transition protocol below).

---

## Consuming the Skill (without the runtime)

> **Boundary statement (do not weaken):**
> The deterministic layer in `runtime/` is the Skill's private engine.
> Consumers (humans, other agents, CI, hooks) only ever talk to the Skill
> itself — through a slash command, a natural-language request, or the
> `--action=run --mode=<mode>` invocation. Anything you can do at the
> Skill boundary you should do there. The runtime CLI is not a public API.

### Entry points (the only ones consumers should use)

```text
slash command   /mini-audit-{lite | balanced | deep | confirm | revisit | diff
                              | merge | longshot | reinvest | knowledge-base
                              | status | resume | export | help}

natural language  "audit this repo" / "review commit <sha>" / "review this PR"
                  / "continue last audit" / "revisit F-007" / "give me the report"

file trigger      .workbuddy/mini-audit-trigger.json → starts an audit automatically

CI / harness      /skill:mini-audit --action=run --mode=<mode> [--...]
                  Provide the intent; the Skill decides which runtime call, if any,
                  is needed. CI never translates the intent itself.
```

### Modes — what to pick when

```text
/mini-audit-lite          5–15 min   quick SAST + secrets + per-finding PoC
/mini-audit-balanced      30–60 min  default depth — 6 sub-agents × 7 phases
/mini-audit-deep          hours      balanced's 17-stage follow-up (incl. P12 variants)
/mini-audit-confirm                 live verification + real PoC in an isolated container
/mini-audit-revisit                 re-audit an old finding (anti-anchoring)
/mini-audit-diff         (this v1)   incremental audit over a commit / since / PR
/mini-audit-merge                   merge multiple audit outputs deterministically
/mini-audit-status                  human-readable progress, last failure, no JSON to read
/mini-audit-resume                  continue from the phase index in audit-state.json
/mini-audit-export                  Markdown / SARIF / JSON output
/mini-audit-help                    command list + which modes are currently usable
```

### Status, resume and export

```text
/mini-audit-status                         current phase, progress, last failure
/mini-audit-status --finding <id>          single-finding status + reachability proof
/mini-audit-export --out report.md        Markdown
/mini-audit-export --format sarif --out x  for downstream scanners
/mini-audit-export --format json  --out x  for programmatic consumers
```

Every confirmed finding ships with `boundary.capability_refs` — a verified path
from the principal to the privileged capability, not a "may exist" claim.

### What NOT to do (this boundary is enforced by the Skill, not by documentation alone)

```text
❌  Don't call the runtime CLI yourself.                Skill is the only public entry; the runtime
                                                       CLI is the engine under the hood.
❌  Don't hand-edit audit-state files.                  Schema validation rejects writes from outside
                                                       the runtime's transaction.
❌  Don't write research deltas by hand.                 Agent drafts go through `research apply`;
                                                       the runtime is the single writer of the ledger.
❌  Don't `rm -rf` the audit root to start over.         Use `/mini-audit-resume --fresh` or pick a
                                                       different `--audit-root`.
❌  Don't commit audit artifacts into the target repo.   Audit state belongs to the auditing tool,
                                                       not to the audited object.
❌  Don't translate intent into runtime calls in CI / hooks. Provide the intent; let the Skill translate.
```

### When to escalate to the runtime (the only legitimate reasons)

```text
- You are extending the Skill itself (new mode, new phase, new canonical artifact).
- You are fixing a Skill bug that the Skill cannot diagnose from inside.
- You are writing the Skill's own tests / evals / CI.

In all three cases, the changes go through `runtime/`, `references/methodology/`,
`schemas/`, `tests/`, or `evals/` — not through consumer-facing commands.
```

### TL;DR

```text
enter   : /mini-audit-*   or   "audit X / review commit Y / continue last audit"
observe : /mini-audit-status, /mini-audit-export
forbid  : direct runtime CLI calls, hand-editing audit-state, committing audit
          artifacts to the target repo, translating intent into runtime calls in CI
```

---

## The audit round loop (the spine of this skill)

Every audit runs this loop. It is the operational form of the Skill/Harness split
above: the agent reasons, the harness executes, the runtime validates and writes.

```text
1.  Read the Objective.
2.  Read the canonical Research State.
3.  Identify the highest-value unanswered research question.
4.  Spawn independent workers for that question.
5.  Workers return research deltas, never canonical edits.
6.  The orchestrator validates and merges deltas.
7.  Re-evaluate:
      - assumptions
      - blocked paths
      - new capabilities
      - capability consumers
      - goal distance
8.  Promote only mature paths to verification.
9.  Permission Delta decides reportability.
10. Repeat until budget-aware saturation.
```

| Step | Owner | Where the output goes | The rule that makes it work |
|---|---|---|---|
| 1–2 | main agent | — | read the objective every round: a scope change makes "three edges from the goal" mean something else |
| 3 | main agent | `agents/<id>/scratch/research-delta.json` | the ranking rules are `references/methodology/search-governance.md` § 3 |
| 4 | harness (spawning), agent (briefing) | `agents/<worker-id>/` | one question, several independent angles — not one worker, several questions |
| 5 | worker agents | `agents/<worker-id>/scratch/research-delta.json` | worker read-only on canonical state; `references/methodology/research-state.md` § 2 |
| 6 | orchestrator + runtime | canonical artifacts, via `research apply` | the orchestrator is the single canonical writer; the delta applies whole or not at all |
| 7 | main agent | the next round's intents | a delta that disproves an assumption changes which blocked paths are actionable; skipping this means answering last round's question |
| 8 | main agent → L6/L6b | chamber + verification artifacts | a verified capability with no consumer is a lead, not a finding. Maturity is having a *chain*, not having one node |
| 9 | Policy layer | `finding.verdict` + `disposition_reason` | `references/methodology/permission-delta-judging.md` — a capability is not a finding |
| 10 | main agent + runtime | `mini-audit/search-saturation.json` | two hard conditions (coverage closed; no unanswered P0 question) plus a debt report. A pass is `search_saturated_under_current_budget`, never "exhausted" |

Step 7 is the one that gets skipped under time pressure and the one that makes the
rest worth having. A new fact can invalidate an assumption and reopen a path
nobody is working on; a new capability changes what is worth consuming; a newly
verified edge moves the frontier. Re-evaluating is what turns a pile of deltas
into a search.

Nothing in this loop requires a new runtime module. The loop *is* the product;
the deterministic layer exists to make steps 5, 6 and 10 non-negotiable.

### Phase gates, fingerprint, chamber-and-verifier, coverage, verdict, scanner, sandbox, export, provenance, tests

These subsections are mechanical and stable. See [`references/methodology/orchestration/runtime-call-cheatsheet.md`](references/methodology/orchestration/runtime-call-cheatsheet.md) for scanner / sandbox / export / coverage / fingerprint / default security invariant / verdict model; [`references/methodology/orchestration/chamber-and-filter.md`](references/methodology/orchestration/chamber-and-filter.md) for chamber + verifier + cold-verifier + permission-delta + 12-category demotion; and `references/MANIFEST.json` + `references/PROVENANCE.json` for reference provenance (regenerated by `scripts/manifest.py`, strict-checked by `scripts/check-manifest.py --strict`). SKILL.md only carries the headline; the orchestration files are authoritative.

The 38-phase gate-coverage table and the lint of ungated-but-deliberate phases (`P4–P7, P11` write into shared documents; `V1.5–V6` are per-finding; `R5–R11c / M1–M7 / I1, I3 / KB0` are optional or no documented artifact path) live in the same place the runtime owns them: `runtime/gates.py::gated_phases(mode)` / `ungated_phases(mode)`, with `scripts/doc_counts.py` verifying the count quoted in SKILL.md and `tests/unit/test_gate_coverage.py` failing CI if a phase is silently moved from one set to the other.

### Unit tests + evals

```bash
python -m pytest tests/unit -q        # unit tests for the runtime
python scripts/manifest.py --check    # reference manifest is current
python scripts/check-manifest.py --strict
python scripts/doc_counts.py --check  # docs quote no stale counts
python evals/run.py                   # regression eval (baseline predictor)
python evals/run.py --oracle          # ceiling: corpus self-consistency
python evals/run.py --self-check      # fixture sanity
```

Eval corpus under `evals/{positive,negative,ambiguous,}` exercises the permission-delta judging and verifier escalation rules. `evals/run.py` scores TP/FP/FN, Precision/Recall/F1, NeedsValidation rate and HardBugRecall against `evals/expected.json`, and `evals/score.py` fails CI when a threshold regresses.

<!-- BEGIN auto-counts — generated, do not edit by hand
| Metric | Value |
|--------|-------|
| reference files (4 sub-directories) | 110 |
| manifest items (incl. inline agents) | 140 |
| inline agent templates | 28 |
| per-class hunting methodologies | 58 |
| per-class vulnerability references | 29 |
| operator methodologies | 18 |
| runtime wordlists | 5 |
| eval fixtures (positive / negative / ambiguous) | 30 |
| long-horizon replay scenarios | 1 |
| incremental replay scenarios | 1 |
| first-class roles | 7 |
| phase gates declared | 38 |
| runtime version | 1.4.0 |
| commands: full / partial / stub | 9 / 4 / 4 |
<!-- END auto-counts -->

Refresh the block with `python scripts/doc_counts.py --write`; `--check` fails CI when it (or a known prose claim) goes stale.

### What the SKILL still does (Reasoning + Policy layers)

* Decide which mode to run, in what order.
* Dispatch sub-agents to the right phase.
* Read runtime state to render `--action=status` and decide what's next.
* Run the Review Chamber debate (LLM responsibility).
* Apply permission-delta methodology (Policy layer).
* The SKILL **never** writes to `audit-state.json`, `findings.json`, or `coverage-ledger.json` directly. It only shells out to `mini-audit-runtime`.

## Slash command mapping (Piolium → mini-audit)

| Piolium slash command | mini-audit invocation |
|----------------------|----------------------|
| `/piolium-help` | `/skill:mini-audit --action=help` | ✗ stub (Piolium parity, no impl) |
| `/piolium-status [--dir=PATH]` | `/skill:mini-audit --action=status [--dir=PATH]` | ✗ stub (Piolium parity, no impl) |
| `/piolium-smoke [task]` | `/skill:mini-audit --action=smoke [task]` | ✗ stub (Piolium parity, no impl) |
| `/piolium-lite [--fresh] [--dir=PATH]` | `/skill:mini-audit --action=run --mode=lite [--fresh] [--dir=PATH]` | ✓ full |
| `/piolium-balanced [--fresh] [--dir=PATH]` | `/skill:mini-audit --action=run --mode=balanced [--fresh] [--dir=PATH]` | ✓ full |
| `/piolium-deep [--fresh] [--dir=PATH] [P5 P7 …]` | `/skill:mini-audit --action=run --mode=deep [--fresh] [--dir=PATH] [--only=P5,P7]` | ✓ full |
| `/piolium-knowledge-base [--fresh] [--dir=PATH]` | `/skill:mini-audit --action=run --mode=knowledge-base [--fresh] [--dir=PATH]` | ◐ partial (described, never run E2E) |
| `/piolium-confirm [--fresh] [--dir=PATH] [--repo=URL] [URL]` | `/skill:mini-audit --action=run --mode=confirm [--fresh] [--dir=PATH] [--repo=URL] [URL]` | ✓ full |
| `/piolium-diff [--since=SHA] [--dir=PATH]` | `/skill:mini-audit --action=run --mode=diff [--commit=SHA\|--since=SHA\|--base=X --head=Y] [--dir=PATH] [--stage=D0..D6]` | ✓ full (D0–D6 phases; selector resolved by `resolve_diff_range`; changset + blast radius + adversarial plan all live in `mini-audit/diff-{scope,d4,d5,d6}.json`; reconciliation driven by `methodology/diff-audit.md`) |
| `/piolium-revisit [--fresh] [--dir=PATH]` | `/skill:mini-audit --action=run --mode=revisit [--fresh] [--dir=PATH]` | ✓ full |
| `/piolium-merge --dir=A --dir=B` | `/skill:mini-audit --action=run --mode=merge --dir=A --dir=B` | ✓ full |
| `/piolium-longshot [--limit=N] [--timeout=ms] [--langs=py,go] [--include-tests]` | `/skill:mini-audit --action=run --mode=longshot [...]` | ◐ partial (described, never run E2E) |
| `/piolium-reinvest [--fresh] [--dir=PATH]` | `/skill:mini-audit --action=run --mode=reinvest [--fresh] [--dir=PATH]` | ◐ partial (described, never run E2E) |
| `/skill:mini-audit --action=run --mode=judge [--dir=PATH] [--finding=<id>]` | meta-audit re-judge of existing findings against the permission-delta framework (J1 per-finding verdict, J2 aggregate) | ✓ full (NEW) |
| `/piolium-resume` | `/skill:mini-audit --action=resume` | ◐ partial (resume state is on-disk canonical; source-identity guard implemented, crash recovery not yet exercised E2E) |
| `/piolium-export [--format=json\|md-dir] [--out=PATH] [--min-severity=high] [--only-severity=high,crit] [--confirmed-only] [--exclude-fp] [--since=ISO] [--require-owner]` | `/skill:mini-audit --action=export [...]` | ✓ full (runtime `export --format json\|md\|sarif`; Piolium-only flags not yet ported) |
| `/piolium-learn [--apply]` | `/skill:mini-audit --action=learn [--apply]` | ✗ stub (Piolium parity, no impl) |

**Status legend**: ✓ full = orchestrator recipe + inline templates + artifact gates specified; ◐ partial = described in SKILL.md but never run E2E or some piece is missing; ✗ stub = Piolium parity only, no impl. Of the 17 commands, 9 are full (lite/balanced/deep/confirm/diff/revisit/merge/judge/export), 4 are partial (knowledge-base/longshot/reinvest/resume), 4 are stub (help/status/smoke/learn).

## Phase catalog (DO NOT RENAME — persisted on-disk contract)

```yaml
lite:          [Q0, Q1, Q2, Q3, Q4]
balanced:      [L1, L2, L3, L4, L5, L6, L6b, L6c, L7]
deep:          [P1, P2, P3, P4, P5, P6, P7, P8, P9, P10, P11, P12, P13, P14, P15, P16, P17]
diff:          []                          # dynamically derived from change set
confirm:       [V1, V1.5, V2, V3, V4, V5, V6, V7]
revisit:       [R0, R5, R7, R8, R9, R10, R10k, R11, R11b, R11c]
merge:         [M1, M2, M3, M4, M5, M6, M7]
longshot:      [X1, X2, X3]
reinvest:      [I1, I2, I3]
knowledge-base:[KB0, K1, K2]
judge:         [J1, J2]                # permission-delta meta-audit re-judgment
```

## Per-phase agent mapping (Piolium specialist → mini-audit role)

The 35 Piolium specialist agents are surfaced as 7 first-class mini-audit roles (6 ported from Piolium plus the new `mini-audit-judge`) that are loaded by default. 28 further agents are shipped as inline markdown templates under `references/` and referenced by name in phase task prompts, dispatched via `Task(subagent_type=...)` (the orchestrator decides whether to instantiate them or fold the prompt inline).

### Default first-class roles (load via `mavis agent list` and use as `subagent_type`)

The full role table (role → Piolium agent → phase) is the same source of truth as `inline-roles.md`. For the inline dispatch pattern see [`references/methodology/orchestration/inline-roles.md`](references/methodology/orchestration/inline-roles.md).

| Role | Piolium agent | Phase |
|------|---------------|-------|
| `mini-audit-ideator` | attack-ideator | Ideation round of every Review Chamber |
| `mini-audit-tracer` | code-tracer | Tracing round of every Review Chamber |
| `mini-audit-advocate` | devils-advocate | Challenge round of every Review Chamber |
| `mini-audit-synthesizer` | chamber-synthesizer | Synthesis round + the only role that writes finding drafts |
| `mini-audit-cold-verifier` | cold-verifier | L7 / V6 cold verification (zero-context isolation) |
| `mini-audit-static-analyzer` | static-analyzer | L4 / P4 SAST orchestration |
| `mini-audit-judge` | (new) | J1 / J2 permission-delta meta-audit re-judgment of existing findings |

**Model selection**: `mavis agent create` does not currently accept a `model` field, so the per-agent model is whatever mavis dispatches with (typically the main orchestrator's model). **The orchestrator (the main model running the skill) is responsible for picking the right `subagent_type` at dispatch time** — we do not pin model per role. If a phase needs a stronger model for a hard sub-task, the orchestrator can dispatch `general` sub-agents with explicit model instructions in the task prompt instead of relying on the first-class agent.

### Per-vulnerability-class knowledge base (110 reference files in 4 sub-directories)

`references/` contains 110 reference files in 4 sub-directories. The orchestrator reads them on-demand based on the hypothesis class.

| Sub-directory | Files | Source | Role in mini-audit |
|--------------|-------|--------|---------------------|
| `references/*.md` (28 inline agents) | 28 | `/Users/rinne/Desktop/piolium/agents/*.md` (frontmatter + codex-trim stripped) | Piolium specialist roles, inlined into `Task` prompts |
| `references/hunting/hunt-<class>.md` | 58 | cybermes `Claude-BugHunter/skills/hunt-*/SKILL.md` | Active hunting methodology for each vuln class (how to find it) |
| `references/vuln-classes/<class>.md` | 29 | strix `strix/skills/vulnerabilities/*.md` | Class reference (what X looks like, DBMS primitives, framework risks) |
| `references/methodology/<name>.md` | 8 | 7 from cybermes `Claude-BugHunter/skills/<name>/SKILL.md` + 1 original (`permission-delta-judging.md`) | Operator methodology (redteam mindset, evidence hygiene, report writing) |
| `references/wordlists/<name>.txt` | 5 | cybermes `tools/wordlists/*.txt` | Runtime enumeration resources (read via `Bash cat`) |

**Cross-reference**: `references/_hunt-class-map.md` maps 53 vuln classes to their corresponding hunting + vuln-classes pair, and to mini-audit's `attack-ideator` 8 modes.

### Context budget discipline (CRITICAL — read first)

The 110 reference files total ~1.7MB on disk. None of that enters context unless the orchestrator explicitly reads a file. Per sub-agent call, inline at most **1 hunting + 1 vuln-classes + 1 inline agent** file = 10-30KB ≈ 3-8K tokens. Opus 200K context is enough headroom for 17 phases.

For the full NEVER/ALWAYS discipline, cost model, per-phase compression rules, class-aware chamber dispatch pattern, pre-flight loads, and wordlist usage, see [`references/methodology/orchestration/context-budget.md`](references/methodology/orchestration/context-budget.md). That file is the authoritative source — SKILL.md only carries the headline.

### Inline agent templates (28 files at `references/<name>.md`)

The 28 Piolium specialist agents that are not first-class mavis roles live as inline templates under `references/`. The full role table, dispatch pattern, hard limits and the "no upstream sync" rationale are in [`references/methodology/orchestration/inline-roles.md`](references/methodology/orchestration/inline-roles.md). SKILL.md only summarises the headline: inline role + per-phase task prompt → `subagent_type: "general"`.

**Hard limits carried over from Piolium** (apply to inline role dispatches):

- `poc-builder` — 3 min wall-clock cap per finding (lite) / 5 min (balanced)
- `static-analyzer` (first-class) — 5 min wall-clock (lite) / 15 min (balanced)
- Review Chamber hard limits (already enforced by `mini-audit-synthesizer`): max 7 hypotheses/batch, max 3 rounds/hypothesis, max 6 rounds/chamber

**No Piolium upstream tracking** (architectural decision): the 28 inline agent templates and 7 first-class agent prompts are a **one-time import**. We do NOT maintain bidirectional sync with Piolium. If a Piolium update lands new patterns of interest, the user re-imports manually. The 108 substitution renames (rounds 1-3) are also a one-time cost — the user has accepted that this fork will drift from Piolium over time.

**Hard limits carried over from Piolium** (apply to inline role dispatches):

- `poc-builder` — 3 min wall-clock cap per finding (lite) / 5 min (balanced)
- `static-analyzer` (first-class) — 5 min wall-clock (lite) / 15 min (balanced)
- Review Chamber hard limits (already enforced by `mini-audit-synthesizer`): max 7 hypotheses/batch, max 3 rounds/hypothesis, max 6 rounds/chamber

**No Piolium upstream tracking** (architectural decision): the 28 inline agent templates and 7 first-class agent prompts are a **one-time import**. We do NOT maintain bidirectional sync with Piolium. If a Piolium update lands new patterns of interest, the user re-imports manually. The 108 substitution renames (rounds 1-3) are also a one-time cost — the user has accepted that this fork will drift from Piolium over time.

## State machine (on-disk canonical, runtime-owned; Hardening v1.1)

Each phase has status: `pending` → `in_progress` → `complete` | `failed` | `skipped`.

As of Runtime Hardening v1 (see [§ Runtime Hardening](#runtime-hardening-v1-deterministic-layer)), the **canonical state lives on disk at `<cwd>/mini-audit/audit-state.json`**, owned by the deterministic runtime. Agent memory may still hold a snapshot for fast cache reads, but it is **not** the resume authority. All writes to `audit-state.json` go through the `mini-audit-runtime` CLI; the SKILL never edits the JSON directly.

Phase entry shape (mirrored by `runtime.state.PhaseState`):

```yaml
audit_id: <iso-ts>
mode: <mode>
status: <in_progress|complete|incomplete|blocked>
source:
  repository: <git remote or null>
  root: <abs path>
  commit: <sha>
  branch: <name>
  dirty: <bool>
  tree_hash: <sha>
runtime:
  version: "1.0.0"
  agent_sdk: mavis
  model: <name>
phases:
  L1:
    name: L1
    status: complete
    attempt: 1
    max_attempts: 2
    started_at: <iso>
    completed_at: <iso>
    heartbeat_at: <iso>
    artifacts:
      - { path: mini-audit/attack-surface/intent-corpus.json, sha256: ... }
    last_error: null
```

**Forbid**:

* `pending → complete` (must go through `in_progress`)
* `failed → complete` (must re-enter `in_progress`)
* `complete → complete` (no-op)

**Allowed recovery**:

* `failed → in_progress → complete`

The orchestrator does NOT hand-edit state. It shells out to:

```bash
mini-audit-runtime state init --repo-root <path> --audit-root mini-audit
mini-audit-runtime phase start L5
mini-audit-runtime phase complete L5
mini-audit-runtime phase fail L5 --error "..."
mini-audit-runtime phase skip L5
mini-audit-runtime gate L5
mini-audit-runtime state show
```

### Resume protocol

Before resuming (`--action=resume`), the runtime captures a fresh `SourceIdentity` and compares against the stored one:

```bash
mini-audit-runtime source diff --repo-root <path> --audit-root mini-audit
```

| `commit` / `worktree_hash` change | Behavior |
|------------------------------|----------|
| both unchanged | reuse complete phases; resume from first non-terminal |
| either changed | `SOURCE_CHANGED`; refuse to silently reuse; require `--accept-source-change` to acknowledge; artifact-only phases may be re-validated, source-derived phases must rerun |

`worktree_hash` covers the tracked diff **and** untracked (non-ignored) files, so an uncommitted working-tree edit — not just a new commit — trips `SOURCE_CHANGED` and blocks a silent resume. `tree_hash` (committed tree) alone could not see that.

### Why both memory and disk?

* Disk (`audit-state.json`) is the **durable truth** — survives process death, cross-host portability, gates, fingerprinting, coverage ledger all read from it.
* Memory is a **read cache** for the orchestrator so it can render status without re-parsing JSON on every tool call. Writes always go to disk via the CLI.

See [§ Runtime Hardening](#runtime-hardening-v1-deterministic-layer) for the full architecture.

## Artifact gate (deterministic, not the agent's word)

After every phase, the orchestrator must check the gate artifact on disk before marking the phase `complete`. **The agent's "I'm done" is not sufficient.** Phase X is `complete` only when its required artifact exists.

### Lite mode gates

| Phase | Required artifact(s) |
|-------|----------------------|
| Q0 | `mini-audit/attack-surface/recon-report.md`, `mini-audit/attack-surface/candidates-summary.md`, `mini-audit/attack-surface/candidates.jsonl` |
| Q1 | `mini-audit/attack-surface/lite-q1-summary.md` |
| Q2 | `mini-audit/attack-surface/lite-q2-summary.md`, `mini-audit/attack-surface/unauthenticated-surface.md` |
| Q3 | `mini-audit/attack-surface/lite-consolidation-manifest.json` (one `poc.*` or `poc.theoretical.md` per promoted finding) |
| Q4 | `mini-audit/attack-surface/lite-verification-summary.md` |

### Balanced mode gates

| Phase | Required artifact |
|-------|-------------------|
| L1 | `mini-audit/attack-surface/intent-corpus.json` |
| L2 | `mini-audit/attack-surface/knowledge-base-report.md`, `mini-audit/attack-surface/sbom.json` |
| L3 | (advisories written to KB) |
| L4 | (env provisioning log in KB) |
| L5 | `mini-audit/probe-workspace/*/probe-summary.md` (one per high-risk slice) |
| L6 | `mini-audit/chamber-workspace/*/debate.md` (CLOSED), `mini-audit/findings-draft/p10-*.md` (one per VALID) |
| L6b | `mini-audit/findings/<id>-<slug>/draft.md` (one per promoted) |
| L6c | one `poc.{py,sh,js,rb,go}` or `poc.theoretical.md` per finding |
| L7 | `mini-audit/findings/<id>-<slug>/cold-verify-verdict.md` (CRIT/HIGH only), `mini-audit/findings/<id>-<slug>/report.md` (all), `mini-audit/final-audit-report.md` |

### Deep mode gates (P1–P17)

- P1 advisories: `mini-audit/attack-surface/advisories.md`
- P1.5 env: `mini-audit/attack-surface/env-provisioning.md`
- P2 intent: `mini-audit/attack-surface/intent-corpus.json` (deep variant)
- P3 attack surface: `mini-audit/attack-surface/knowledge-base-report.md` (full DFD/CFD)
- P4 SAST: `## Static Analysis Summary`, `## CodeQL Structural Analysis`, `## SAST Enrichment` sections of `knowledge-base-report.md`
- P5/P6/P7: probe results
- P8 deep-probe: `mini-audit/probe-workspace/*/probe-summary.md`
- P9 spec gap: `mini-audit/attack-surface/spec-gap.md`
- P10 chamber: as in L6
- P11 cold verify: as in L7
- P12 variant hunt: `mini-audit/attack-surface/variant-candidates.md`
- P13 PoC: `mini-audit/findings/<id>-<slug>/poc.{py,sh,js,rb,go}`
- P14 report: `mini-audit/findings/<id>-<slug>/report.md`
- P15 final: `mini-audit/final-audit-report.md`
- P16 patch-bypass: `mini-audit/findings/<id>-<slug>/patch-bypass.md` (per finding with a known fix)
- P17 cleanup: `mini-audit/attack-surface/cleanup-manifest.json` (transient paths removed)

### Gate coverage

**Gate coverage: 38 phases declare a deterministic gate** — the ungated
remainder is listed below rather than assumed away.

| Mode | Gated | Ungated (no dedicated artifact) |
|------|-------|----------------------------------|
| lite | Q0, Q1, Q2, Q3, Q4 | — |
| balanced | L1, L2, L3, L4, L5, L6, L6b, L6c, L7 | — |
| deep | P1, P1.5, P2, P3, P8, P9, P10, P12, P13, P14, P15, P16, P17 | P4, P5, P6, P7, P11 |
| confirm | V1, V7 | V1.5, V2, V3, V4, V5, V6 |
| revisit | R0 | R5, R7, R8, R9, R10, R10k, R11, R11b, R11c |
| merge | — | M1, M2, M3, M4, M5, M6, M7 |
| longshot | X1, X2, X3 | — |
| reinvest | I2 | I1, I3 |
| diff | — | D0, D1, D2, D3, D4, D5, D6 |
| knowledge-base | K1, K2 | KB0 |
| judge | J1, J2 | — |

A phase is gated when it writes a **dedicated artifact file** the runtime can
`stat`, parse and schema-check on disk. The ungated set is deliberate:

- **P4–P7, P11** write *sections* into a shared document
  (`knowledge-base-report.md`, `probe-workspace/*/probe-summary.md`,
  `findings/*/cold-verify-verdict.md`) that other phases also write, so a
  per-phase existence gate would be satisfied by a sibling phase's output.
- **V1.5, V2–V6** are per-finding and optional (V1.5 is skipped when no intent
  corpus exists; V2–V5 only run for findings with a runnable PoC).
- **R5–R11c, M1–M7, I1, I3, KB0** re-run agents over an existing finding set
  or are optional intake steps with no documented artifact path.

Gating those would block legitimate completion, which is worse than an honest
gap. `runtime/gates.py` owns the canonical sets (`gated_phases(mode)` /
`ungated_phases(mode)`), `scripts/doc_counts.py` verifies the count quoted here,
and `tests/unit/test_gate_coverage.py` fails if a phase is silently moved from
one set to the other.

## Hard filter at the gate (mandatory, no finding escapes these three)

Before any finding is promoted to `findings-draft/` (or any report), the
chamber-synthesizer (and later the judge) must pass **all three** of:

1. **Privilege Delta != None** — the boundary sentence can be filled
   with two distinct capabilities. If "before" and "after" describe the
   same capability, or the attacker could already do the "after"
   through normal features, Delta is None.
2. **Boundary Sentence complete** — the 21st-section template
   (filling-the-blanks: "an attacker who could only X can now Y, but
   the product's permission model did not allow Y") is filled in
   concretely. No "TBD", no "see report", no abstract phrases.
3. **Six FP gate all answered** — DEFAULT / AUTHORITY / DEPENDENCIES /
   DERIVATION / SPEC / DELTA each have a concrete answer. Any
   "unknown" → the gate fails.

**Demotion (when any of the three fails)**:

| Failed condition | Demote to |
|---|---|
| Privilege Delta None (counterfactual passed = same effect via normal features) | `NO_NEW_SECURITY_CAPABILITY` |
| Privilege Delta None because admin can already do this | `PREREQUISITE_DOMINATES_IMPACT` |
| Six FP — DEFAULT shows effective value is safe | `INTENDED_BEHAVIOR` |
| Six FP — AUTHORITY shows admin opt-in required | `ADMIN_MISCONFIGURATION` |
| Six FP — SPEC shows only SHOULD/BCP violation, no boundary crossing | `SPEC_COMPLIANT_WEAK_DEFAULT` / `LEGACY_SECURITY_DEFAULT` / `HARDENING_OPPORTUNITY` |
| Six FP — DEPENDENCIES shows depth >= 2 | downgraded confidence; usually `HARDENING_OPPORTUNITY` |
| Six FP — DERIVATION shows constrained source | typically `HARDENING_OPPORTUNITY` (the constrained value reaches the sink safely) |
| 14-item report gate fails on multiple boxes | `INSUFFICIENT_EVIDENCE` / `FALSE_POSITIVE` |

**The chamber-synthesizer's `Pre-Finding Quality Gate` (in its agent
prompt) implements this as step 4, between the existing 5 checks and
the severity calibration. The convergence table maps every outcome to
a 12-category label, not the old VALID / FALSE POSITIVE dichotomy.**

A finding that fails the hard filter is **not** written to
`findings-draft/`. It is logged in `chamber-workspace/<id>/debate.md`
with its 12-category label, and the audit-state records it as
"demoted" rather than "promoted". The user still sees all demoted items
in the final report, but they go to the misconfiguration / hardening /
false-positive appendix, not the vulnerability list.

This is a **hard gate**, not a soft warning. It is what stops
over-confirmation from contaminating the report.

## Concurrency cap (Swarm Burst Cap)

Default 3 concurrent sub-agents, overridable via `--max-agents=N` or env `MINI_AUDIT_MAX_AGENTS`. The cap is per-phase, not global. For batch dispatches, cap the in-flight count. Piolium's `Scheduler` (FIFO with `maxConcurrent` + per-task `AbortSignal` + timeout) maps to mavis's `Task` tool with the appropriate batching. The full reasoning is in [`references/methodology/orchestration/chamber-and-filter.md`](references/methodology/orchestration/chamber-and-filter.md).

## Review Chamber debate protocol (L6 / L10 / V5)

The four-role chamber dispatch, hard limits (7 hypotheses/batch, 3 rounds/hypothesis, 6 rounds/chamber), and the permission-delta gate (one-sentence + counterfactual tests) live in [`references/methodology/orchestration/chamber-and-filter.md`](references/methodology/orchestration/chamber-and-filter.md). SKILL.md carries the headline; that file is authoritative.

## Cold verifier isolation rule (L7 / P11 / V6)

What cold-verifier reads, what it does not read, and how its verdict reconciles with the chamber's are in [`references/methodology/orchestration/chamber-and-filter.md`](references/methodology/orchestration/chamber-and-filter.md). SKILL.md carries the headline: cold-verifier loads `permission-delta-judging.md` (the meta-rule both roles share) but not the chamber workspace, probe workspace, prior verdicts, or class-specific references.

## Hard filter at the gate (mandatory, no finding escapes these three)

Before any finding is promoted to `findings-draft/` (or any report), the chamber-synthesizer (and later the judge) must pass all three filters: **stable fingerprint** (Spec §12), **permission delta** (one-sentence + counterfactual), and **evidence ground** (concrete, reproducible, truthful). The convergence table maps every outcome to a 12-category label, not the old VALID / FALSE POSITIVE dichotomy. A finding that fails is logged in `chamber-workspace/<id>/debate.md` with its label and recorded in audit-state as "demoted" rather than "promoted". The full filter, demotion categories, and the chamber-synthesizer Pre-Finding Quality Gate step-4 implementation are in [`references/methodology/orchestration/chamber-and-filter.md`](references/methodology/orchestration/chamber-and-filter.md).

## Resume protocol (`--action=resume`)

Resume reads `<cwd>/mini-audit/audit-state.json` from disk (the resume authority) and continues from the first phase whose status is not `complete`. The full protocol, the canonical state machine, and the "disk vs memory" boundary are in [`references/methodology/orchestration/orchestrator-cookbook.md`](references/methodology/orchestration/orchestrator-cookbook.md).

## Default task prompt template (lite Q2 example)

The Q2 prompt is in [`references/methodology/orchestration/default-task-prompt.md`](references/methodology/orchestration/default-task-prompt.md); every other phase's prompt is built the same way (per-phase constraints in `references/methodology/orchestration/` + per-mode orchestrator recipe). SKILL.md carries only the headline.

## Mode-specific orchestrators (delegation patterns)

The per-mode dispatch recipes (lite / balanced / deep / confirm / revisit / merge / longshot / diff / reinvest / knowledge-base / judge) are in [`references/methodology/orchestration/mode-orchestrators.md`](references/methodology/orchestration/mode-orchestrators.md). SKILL.md carries only the headline.

## CLI flag → env mapping (preserved from Piolium)

| Flag | Env | Default | Purpose |
|------|-----|---------|---------|
| `--dir=PATH` | `MINI_AUDIT_DIR` | cwd | Target repo |
| `--fresh` | `MINI_AUDIT_FRESH` | off | Restart from scratch |
| `--max-agents=N` | `MINI_AUDIT_MAX_AGENTS` | 3 | Swarm Burst Cap |
| `--phase-retries=N` | `MINI_AUDIT_PHASE_MAX_RETRIES` | 5 | Per-phase retry count |
| `--phase-backoff=ms` | `MINI_AUDIT_PHASE_BACKOFF_BASE_MS` | 5000 | Per-phase retry base backoff |
| `--phase-backoff-max=ms` | `MINI_AUDIT_PHASE_BACKOFF_MAX_MS` | 120000 | Per-phase retry max backoff |
| `--longshot-limit=N` | `MINI_AUDIT_LONGSHOT_LIMIT` | 1000 | Longshot max files |
| `--longshot-timeout=ms` | `MINI_AUDIT_LONGSHOT_TIMEOUT_MS` | 21600000 | Longshot per-file kill timer (6h) |
| `--longshot-langs=py,go` | `MINI_AUDIT_LONGSHOT_LANGS` | auto | Longshot language allowlist |
| `--longshot-include-tests` | `MINI_AUDIT_LONGSHOT_INCLUDE_TESTS` | off | Include test files |
| `--knowledge-base=PATH` | `MINI_AUDIT_KNOWLEDGE_BASE` | unset | Markdown file or docs dir as untrusted KB input |
| `--knowledge-base-raw=STRING` | `MINI_AUDIT_KNOWLEDGE_BASE_RAW` | unset | Inline markdown KB input |
| `--since=SHA` | `MINI_AUDIT_SINCE` | unset | Diff base commit (also `--commit`, `--base`, `--head` accepted; see `runtime/diff_scope.py::resolve_diff_range`) |
| `--commit=SHA` | `MINI_AUDIT_COMMIT` | unset | Diff mode single-commit selector (resolves to `<sha>^..<sha>`) |
| `--base=REF` / `--head=REF` | `MINI_AUDIT_DIFF_BASE` / `MINI_AUDIT_DIFF_HEAD` | unset | Diff mode branch/PR selector (resolves to `git merge-base base head..head`) |
| `--stage=LIST` | `MINI_AUDIT_DIFF_STAGES` | `D0,D1,D2,D3,D4,D5,D6` | Diff mode stage allowlist (comma-separated; D0 always runs as the resolver) |
| `--repo=URL` | `MINI_AUDIT_REPO` | unset | Confirm pass repo URL override |
| `--finding=<id>` | `MINI_AUDIT_FINDING_ID` | unset | `--mode=judge` only: limit J1 to a single finding (spot-check) |

The `MINI_AUDIT_*` env prefix replaces Piolium's `PIOLIUM_*` prefix. Migration scripts can `PIOLIUM_*` → `MINI_AUDIT_*` with sed.

## Orchestrator cookbook (run lifecycle, dispatch, output, quick start)

The orchestrator's procedural reference (run lifecycle, resume protocol, sub-agent dispatch shape, sub-tasks, reuse policy, output conventions, quick-start chat form, Piolium migration table) lives in [`references/methodology/orchestration/orchestrator-cookbook.md`](references/methodology/orchestration/orchestrator-cookbook.md). SKILL.md only carries the headline.

## Scanner / sandbox / export / coverage / reference provenance

The runtime-call cheatsheet (scanner integration, sandbox policy + probe, export formats, coverage accounting, reference provenance, stable fingerprint, default security invariant, verdict model, scanner integration per phase) lives in [`references/methodology/orchestration/runtime-call-cheatsheet.md`](references/methodology/orchestration/runtime-call-cheatsheet.md). SKILL.md only carries the headline.
