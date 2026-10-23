# Triage Notes — {target}

> One Markdown file. The whole state of this triage. Edit it in place,
> every round. Evidence IDs point to captured artifacts; the file has
> no separate state database.
> The file *is* the canonical state — make it readable to a stranger.

---

## Objective

What is being disclosed, to whom, on which channel, and what the
maintainer's acceptance model is understood to be. Rewrite this section
when the objective shifts.

## Trust Ladder

The roles of this target, and what each is allowed to reach. Take it
from the project's own documentation and the audit's architecture notes
— not from a generic template. Mark the source:

- `stated` — the project publishes this model (cite the document).
- `derived` — the triage inferred it. Say so in the report; you cannot
  cite an authority you invented.

| Rung | Role in this target | How it is obtained | May reach |
|---|---|---|---|
| L0 | | | |
| L1 | | | |
| L2 | | | |
| L3 | | | |
| L4 | | | |
| L5 | | | |

**Acceptance policy source**: `{SECURITY.md path / advisory page / none}`.
**Source of authority**: `stated | derived`.

## Upstream Prior Classification

How this project has classified similar issues before. This is the
strongest boundary evidence available. Fill from its published
advisories and release notes; leave a row empty rather than guessing.

| Prior issue | Classified as | Source | Shape overlap with which current finding |
|---|---|---|---|
| | `Security fix / Bug fix / Hardening` | | |

**Prior submissions of ours**: `{none / GHSA-xxx, closed, reason: "..."}`.
A closure is the project's boundary model in its own words — extract the
rule and apply it to every remaining record.

## Attack Surface (for disclosure purposes)

Only what a maintainer needs to navigate: the entry points and trust
boundaries the reported findings sit on. One bullet per surface, with
the file path and the rough data flow.

## The Three Questions — Coverage Ledger

Every confirmed finding needs all three answered with cited evidence.
`HUNTED` needs a captured source read. `NEEDS-RUNTIME` means the
question could not be answered from source and must not be used to
support a `send`.

| Finding | Q1 Premise | Q2 Boundary | Q3 Divergence | Evidence IDs / limitation |
|---|---|---|---|---|
| | | | | |

## Premise Ledger

Every claim a disposition depends on, with the location that was read.
"Do not write 'standard check exists'": record the exact condition
asserted and where it was read.

| Protected consumer / claim | Premise `file:line` | Exact condition asserted | Attacker-controlled shape | Evaluated result | Verdict | Evidence IDs |
|---|---|---|---|---|---|---|
| | | | | | | |

Do not write "standard check exists". If no evidence was found, record
two distinct queries and their results.

## Verified Facts

Statements this triage has already proven against the source. Each
fact names the file path, the line, and the reading that proves it. A
fact without a pointer is just a hypothesis — move it to Hypotheses.

## Hypotheses

Plausible vulnerability hypotheses the triage is currently trying to
confirm or refute — typically a candidate divergence that has not been
checked on both sides yet. One bullet each, written as a single
sentence of the form:

> If `<condition>` is true at `<location>`, then `<attacker
> capability>` follows because `<data path>`.

State the disproof condition alongside the hypothesis. If you cannot
state the disproof, the hypothesis is too vague to test — rewrite it.
Retain disproved or downgraded hypotheses with their original statement
and the evidence that killed them. Do not erase them.

## Blocked Leads

Chains blocked on a single unverified precondition, where the
precondition might become verifiable later. Each lead says exactly what
would unblock it. Do not lose this list when the lead seems
unproductive — that is the point.

## Remaining Questions

The one question, if answered, would most likely change the triage
outcome. Update this list as the triage progresses. When the answer
matters less than it used to, replace it.

An empty list is not a stop signal by itself. Stop only after every
finding has all three questions answered, every premise is cited, and
the send order is fixed.

---

## Triage Table

Include the machine-readable JSON object required by
`schemas/triage-table.schema.json`. List every confirmed finding with
its disposition, the three question-answers, the subject it will be
reported under, and the evidence IDs returned by
`runtime/evidence_log.py`. The ledger makes decisions reviewable; it
does not prove that uncaptured tool use did not occur or that the
maintainer will accept the result.

## Send Order and Channel

**Channel**: `{name}` — **why this one**: `{reason}`.
Two channels mean duplicate intake.

| Order | Finding | Disposition | Subject (the invariant) | Why here |
|---|---|---|---|---|
| 1 | | | | |

## How to use this file

1. **Triage round.** Fill in Objective, Trust Ladder, Upstream Prior
   Classification, and Attack Surface. Read the project's acceptance
   policy before answering any question — a disposition judged against
   the wrong acceptance model is worse than no disposition. Then answer
   the three questions for every confirmed finding, and record each
   answer in the coverage ledger and the Premise Ledger.
2. **Frame round.** For each finding that survives, state the subject
   as an invariant. Record the rewrite where the original framing was
   a consequence. Fix the send order and the channel.
3. **Deliver round.** Write one `templates/advisory.md` per reportable
   finding. Every finding in the final report must trace back to a
   Verified Fact and a Premise Ledger row in this file. If it does not,
   it is not ready.

The model can jump between rounds. The file does not enforce a state
machine. The reviewer enforces it by reading.
