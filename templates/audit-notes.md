# Audit Notes — {target}

> One Markdown file. The whole state of this audit. Edit it in place,
> every round. Evidence IDs point to captured artifacts; the file has
> no separate audit-state database or transaction system.
> The file *is* the canonical state — make it readable to a stranger.

---

## Objective

What is being audited, who is the attacker, what is the highest-value
target capability, what trust boundary does the attacker start from.
Rewrite this section when the objective shifts.

## Attack Surface

Entry points and trust boundaries the attacker can reach. One bullet
per surface, with the file path and the rough data flow. When the
model reads a new surface during Discover, add a bullet.

## Baseline Security Lenses

Before Discover, give each required lens a status and record the search strategy.
Allowed statuses: `NOT_CHECKED`, `IN_PROGRESS`, `HUNTED`, `N/A`, `NEEDS-RUNTIME`.
Keep `evidence.jsonl` and its artifact directory in the private audit workspace.
Use `runtime/evidence_log.py` for source searches and bounded reads, then cite
its IDs below. Do not commit target source excerpts.

| Category | Status | Strategy | Evidence IDs / limitation |
|---|---|---|---|
| Low-privilege writes to authentication/authorization fields | | | |
| Asserted identity to trust or access-control decision | | | |
| Callback/plugin/event output to dangerous consumer | | | |
| Security-relevant state write to cross-endpoint consumer | | | |

`N/A` requires a reason and two distinct captured zero-match searches. If a
category was not checked, use `NOT_CHECKED` or `IN_PROGRESS`, never `N/A`.

## Work Queue

The `work_queue` array in the Synthesize JSON below is the single source of
truth. Before starting a task, mark it `active`, write its next action, budget
unit, and stop condition. Keep exactly one active task; append tangents as
`queued` work with a brief impact reason. Close each task as `completed` or
`deferred` before selecting another. Before Report, no task may remain active
or queued; deferred items must explain the reason and resulting limitation.
Complete a bounded pass for each baseline category before deep dives, and
record a completed `final_review` task for `N/A`, `DISPROVED`, and high-impact
guard decisions before Report.

## Security Decision Points

For each authentication, authorization, ACL decision, or security-sensitive
state consumer, record its inputs, source, attacker control, parsed/runtime
types, and the independent check made at the consumer. Include supported
configuration states that alter the trust boundary.

## Guard Evaluation Ledger

Record every guard claimed to protect a dangerous sink or security decision:

| Protected consumer | Guard `file:line` | Exact expression | Attacker input type/shape | Evaluated result | Verdict |
|---|---|---|---|---|---|

Do not write "standard check exists". Evaluate the expression for attacker-
controlled types and values. If no guard was found, record two distinct
queries and their results.

## Verified Facts

Statements the audit has already proven with code or runtime evidence.
Each fact names the file path, the line, and the experiment (if any)
that proves it. A fact without a pointer is just a hypothesis — move
it to Hypotheses.

## Hypotheses

Plausible vulnerability hypotheses the audit is currently trying to
prove or disprove. One bullet each, written as a single sentence of
the form:

> If `<condition>` is true at `<location>`, then `<attacker
> capability>` follows because `<data path>`.

State the disproof condition alongside the hypothesis. If you cannot
state the disproof, the hypothesis is too vague to test — rewrite it.
Retain high-impact disproved or downgraded hypotheses with their original
statement, evidence that killed them, and any configuration that could unblock
the chain. Do not erase them after changing status.

## Blocked Leads

Attack chains that are blocked on a single unverified precondition,
where the precondition might become verifiable later. Each lead says
exactly what would unblock it. Do not lose this list when the lead
seems unproductive — that is the point.

## Remaining Questions

The one question, if answered, would most likely change the audit
conclusion. Update this list as the audit progresses. When the answer
matters less than it used to, replace it.

An empty list is not a stop signal by itself. Stop only after all baseline
lenses, entry points, security decision points, guards, and high-impact
disproofs have evidence-backed statuses.

---

## Synthesize Pairing Table

Include the machine-readable JSON object required by
`schemas/pairing-table.schema.json`. List discovered source-to-consumer
relationships, all four required `class_coverage` categories with statuses,
`guard_checks`, the work queue, and evidence IDs returned by
`runtime/evidence_log.py`. The ledger makes completed and deferred work
reviewable; it does not prove that uncaptured tool use did not occur or that
the search was semantically complete.

## How to use this file

1. **Scope round.** Fill in Objective + Attack Surface + Baseline Security
   Lenses + Security Decision Points and create one bounded queue task per
   baseline category. Stop when the target, attacker boundary, and initial
   evidence-backed lens statuses are recorded.
2. **Discover round.** Select one active queue task. Add Hypotheses. Each hypothesis names its
   disproof. Read code, trace data flow, read references, ask an
   independent sub-agent. When evidence proves a hypothesis, move it
   to Verified Facts. Preserve high-impact disproved hypotheses with their
   evidence instead of deleting their audit trail.
3. **Verify round.** For every Verified Fact, ask: is the evidence
   strong enough that another auditor, with no prior context, would
   agree? If not, run another experiment or escalate to an
   independent sub-agent. Move weak claims to Hypotheses.
4. **Report round.** Every finding in the final report must trace
   back to a Verified Fact in this file. If it does not, it is not
   ready.

The model can jump between rounds. The file does not enforce a
state machine. The reviewer enforces it by reading.
