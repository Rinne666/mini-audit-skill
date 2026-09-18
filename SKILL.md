# mini-audit

A pure-Prompt Skill for security audits. The model reasons; the
Harness executes; this Skill is the playbook the model follows.

This Skill provides no runtime, no schema, no state machine, no
canonical-state artifact, no CLI, no scheduler. The audit state
lives in **one Markdown file** that the model edits every round
(`templates/audit-notes.md`).

## When to load this Skill

Load when the user asks for a security audit, a vulnerability
review, a threat model, a code review with security focus, or
"is this exploitable?". Do not load for general code review,
refactoring, or feature work.

## The five things this Skill teaches

1. **How to frame the audit.** Define the target, the attacker,
   the highest-value capability, and the boundary the attacker
   starts from.
2. **The four-stage loop.** Scope → Discover → Verify → Report.
   The model moves between stages freely; the notes file does
   not gate them.
3. **How to propose and disprove vulnerability hypotheses.**
   Each hypothesis names its disproof. Run the experiment, do
   not keep guessing.
4. **When to call a sub-agent or load a reference.** Use a
   sub-agent for independent verification and bounded parallel
   searches. Load a reference when the hypothesis needs class
   knowledge the model does not already have.
5. **What evidence is enough to call something a finding.** A
   finding must trace to a Verified Fact in the notes file.

## The audit loop

```text
Understand the boundary.
Find plausible violations.
Trace them end-to-end.
Try to disprove them.
Keep only evidence-backed findings.
Look once more for what you may have missed.
Stop when another round is unlikely to change the result.
```

That sentence is the entire loop. Every other piece of this Skill
serves it.

## The four stages

The stages are cognitive, not gates. The model jumps between them
as the audit demands — `Discover → Verify → Discover` is a normal
cycle. The notes file does not enforce order; the reviewer enforces
discipline by reading.

### Scope

Goal: a relevant attack-surface map and a one-sentence
permission-delta question.

Ask the audit:

- What is the application, what does it do, what is its trust model?
- Where does attacker-controlled data enter?
- What is the highest-value target capability?
- What boundary does the attacker start from?

End Scope when the **Objective** and **Attack Surface** sections
of the notes file are written and the highest-value target is
named. The map covers the surface relevant to the objective; it
expands when later evidence reveals a new reachable boundary.

### Discover

Goal: a list of plausible hypotheses, each with a disproof
condition.

Read code. Trace data flow. Read references when needed. Ask a
sub-agent for parallel variant or chain searches. Add entries to
the **Hypotheses** section, one per hypothesis, written so the
disproof is named alongside.

### Verify

Goal: promote a hypothesis to a Verified Fact or delete it.

Run the experiment named by the disproof. If the disproof fails,
the hypothesis becomes a Verified Fact. If the disproof holds,
delete the hypothesis. When the experiment is structural, ask an
independent sub-agent to confirm.

A Verified Fact is a finding candidate, not yet a finding. The
finding lives in `templates/finding.md` once Report starts.

### Report

Goal: one `templates/finding.md` per Verified Fact.

Every finding must include the four things stated in the template:
a Summary, the Location, the Preconditions, the Attack path, and
the Evidence. The remediation is the smallest change that closes
the delta. **Why existing controls missed it** is required —
without it, the report is a bug, not a fix proposal.

## How to use the notes file

Copy `templates/audit-notes.md` into the audit workspace, rename
it (e.g. `notes-{target}.md`), and edit it every round.

The notes file is the entire canonical state of this audit. There
is no schema, no IDs, no transactions, no generator. Sections
evolve as the audit evolves — the model is allowed to add new
sections when needed (e.g. a "Chain hypothesis" section when a
chain search is running). A section the audit no longer needs is
deleted.

A reviewer who reads the notes file from top to bottom should
understand the entire audit. If they cannot, the notes are
incomplete.

## When to load a reference

The Skill ships four methodology references and eight vuln-class
references. Load them only when the model is about to do work the
reference actually helps with.

Methodology:

- `references/discovery.md` — when the model is about to start
  Discovery and has not yet mapped the attack surface relevant
  to the objective.
- `references/verification.md` — when Verification has stalled
  (no Verified Facts after two cycles) or when the model is
  unsure whether an experiment is enough.
- `references/permission-delta.md` — every time a hypothesis is
  about to become a Verified Fact. Severity comes from the
  delta, not the primitive.
- `references/search-strategy.md` — when the audit has stopped
  generating new hypotheses, when a chain search is about to
  start, or when the audit is deciding whether to stop.

Vuln-class:

- `references/vuln-classes/{authz,injection,deserialization,
  path_traversal,ssrf,crypto,race_condition,cross_service_trust}.md`

Load a vuln-class reference when the model has named the bug
class and wants confirmation on where else to look, what
disproofs often fail, and how to think about the permission
delta. Do not load one to "browse." A model that loads all eight
references to "be thorough" is not auditing, it is reading.

## When to call a sub-agent

Use a sub-agent for:

- **Independent verification.** Hand the notes file and the
  code under review to a sub-agent with no prior context. If the
  sub-agent reaches the same conclusion by a different path, the
  Verified Fact stands. If they disagree, the audit is
  incomplete — go back to Discovery.
- **Bounded parallel searches.** Variant hunts and chain
  searches that can run with no shared state from the main
  audit.
- **Experiments in a clean harness.** A PoC that needs a
  controlled environment the model cannot guarantee locally —
but only inside isolation the Harness provides. The Skill
  itself provides no isolation.

Do not use a sub-agent to "look at the code." The model reads
faster than the model can spawn a sub-agent.

## Isolation and untrusted code

This Skill provides no isolated execution environment. The audit
will sometimes need to run a PoC that touches the network,
executes untrusted code, or modifies system state.

> Use isolation the Harness explicitly provides. If the Harness
> provides none, do static verification or a minimal
> non-destructive experiment instead. Never assume the Skill
> gives you a sandbox.

A sub-agent that runs a PoC without isolation is a sub-agent, not
an audit. The reviewer will not trust a finding whose evidence
chain passed through the host shell.

## Stopping the audit

Stop when one of:

- The notes file's **Remaining Questions** section is empty.
- The model is generating narrower variants without producing
  a new permission or capability delta — saturation reached.
- The next round of Verify would only re-confirm existing
  Verified Facts.

Do not stop because the model is uncertain. A hypothesis without
new evidence is a hypothesis that needs more evidence, not
silence.

## What this Skill does not do

- It does not maintain a Search Ledger, an Attack Graph, or a
  Coverage Ledger. Those were the v2.x design and were
  removed in the v3.0 collapse.
- It does not provide a CLI, a sandbox, or any runtime.
- It does not enforce phases, gates, transitions, or
  approvals. The reviewer enforces discipline.
- It does not own IDs, schemas, transactions, or generators.
  The notes file is the only state.
- It does not write architecture-eval tests. The audit is
  measured by the findings it produces, not by whether the
  implementation of the audit was correct.