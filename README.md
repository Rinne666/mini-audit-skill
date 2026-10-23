# mini-adjudication

A prompt-led **vulnerability claim adjudicator**. The model takes a claim —
from a scanner, a colleague, an upstream issue, a bounty report, or its own
reading — and decides two separate things with evidence: **whether the claim
holds**, and **whether it would be accepted if submitted**. A small stdlib
runtime validates the adjudication structure, re-checks the absence evidence,
and cross-checks CVSS; it is not an audit state machine and cannot prove a
maintainer will accept a report.

> This skill does **not** find vulnerabilities. It judges claims it is given.
> If you have no claim yet, you need an audit, not this skill. It also does
> not submit anything: it produces drafts and checks, and every externally
> visible action stays with the submitter.

## What you get

- `SKILL.md` — the skill itself. How the model runs an adjudication.
- `references/claim-decomposition.md` — splitting a claim into assertions
  that can each be true or false, and choosing the assertion type that
  carries the claim's uncertainty.
- `references/validity-assessment.md` — killing a claim: the refutation
  catalogue, proving absence, and when a fact genuinely cannot come from
  source.
- `references/acceptance-policy.md` — reading the upstream's scope document,
  its published advisories, and its prior classifications.
- `references/premise-analysis.md` — Question 1, in depth: who creates the
  precondition that makes the claim reachable.
- `references/report-writing.md` — the disclosure form of a finding, the
  wording red lines, advisory-form mechanics, and the pre-send list.
- `references/ordering-and-channels.md` — delivery order, channel choice,
  and re-adjudication after a closure.
- `templates/adjudication-notes.md` — the single Markdown file the model
  maintains during the adjudication.
- `templates/advisory.md` — the one-report-per-file disclosure template.
- `templates/refutation.md` — the written finding for a claim that does not
  hold, cannot be settled, or is already fixed.
- `schemas/adjudication.schema.json` and `runtime/validate_adjudication.py` —
  structural checks for the assertion ledger, the evidence citations, the
  mechanical derivations of both verdicts, work-queue closure, and channel.
- `runtime/evidence_log.py` — bounded, read-only source search/read capture
  that writes evidence artifacts and a hash-bearing JSONL ledger.
- `runtime/cvss31.py` — a second implementation of the CVSS v3.1 base score,
  used to cross-check a stated score against its vector.

## How to use it

1. Load `SKILL.md`.
2. Copy `templates/adjudication-notes.md` into the adjudication workspace and
   rename it for the target.
3. Run the three-stage loop (Adjudicate → Assess → Deliver).
   - **Adjudicate** splits each claim into assertions, tests each one with a
     refutation attempt, and records a validity verdict.
   - **Assess** answers the three acceptance questions — premise, declared
     boundary, same-version divergence — for the claims that hold.
   - **Deliver** produces the artifact each verdict calls for, and only that
     artifact.
4. Before delivery, run the structural check and fix what it reports:

   ```text
   python runtime/validate_adjudication.py path/to/adjudication-notes.md \
       --evidence-ledger path/to/evidence.jsonl
   ```

## Two verdicts, kept apart

| | Question | Vocabulary |
|---|---|---|
| **Validity** | Is the claim technically true and does it cross a boundary? | `holds` / `does_not_hold` / `needs_more_evidence` / `already_fixed` |
| **Acceptability** | Would the maintainer accept it if submitted? | `accept` / `accept_after_rewrite` / `decline` |

A claim that does not hold is **not** "unacceptable" — it is not a
vulnerability, and the right output for it is a written finding, not a
report. Only a claim whose validity is `holds` reaches the acceptance
questions at all.

## The three acceptance questions

Every claim that holds gets all three answered, with `file:line` evidence.

1. **Premise** — can the attacker cause the precondition alone?
   `attacker_only`, or one of the three operator/ambient/third-party kinds
   that carry the rejection risk.
2. **Boundary** — has the product declared this behaviour? Evidence comes
   from the product: its scope document, its code comments, the commit that
   introduced the behaviour, and above all its own prior advisories and how
   it classified similar issues.
3. **Divergence** — does the same version refuse on one path what it allows
   on another? This is the framing that survives review, because it needs no
   argument about intent.

## The verdicts are derived, not asserted

Neither verdict is a matter of tone. The validity verdict follows
mechanically from the assertion verdicts, and the acceptability verdict
follows from the three answers. The validator recomputes both and rejects a
file where they disagree.

One consequence is worth stating plainly: an unresolved **precondition**
does not block validity (it says how often the trigger fires, and belongs to
the premise question), while an unresolved **consequence** does (the report
would assert a harm you cannot show).

## What the runtime actually enforces

- Every cited evidence ID exists, is untruncated, and its artifact still
  matches its recorded hash.
- A `confirmed` or `refuted` assertion cites a captured source read, not only
  a search.
- Every recorded zero-match search is **re-run** against the source it
  names; a ledger that claims "no matches" for a pattern that does match is
  rejected.
- An absence claim cites two distinct zero-match searches. The same search
  run twice is not a second check.
- Both verdicts are derived, and the action matches the verdict.
- A claim that does not hold carries no acceptance verdict and is never
  actioned as a report.
- A reportable claim's subject is an invariant, not a consequence.
- All six coverage sections are present, the work queue is closed, and a
  completed `final_review` task challenged the negative verdicts.

`runtime/test_adjudication_counterexamples.py` takes the correct fixture,
breaks it ten ways, and asserts each broken version is rejected. A validator
that only ever sees valid input proves nothing.

## What this Skill is not

- It does not audit. It does not hunt, scan, or map attack surface. It
  adjudicates claims it is given.
- It does not submit anything. It produces drafts and checks. Submission and
  credit acceptance require the submitter's explicit confirmation.
- It does not provide a sandbox. It reasons over claims and reads source to
  test them.
- It does not prove the maintainer will accept a report. It proves the
  adjudication is evidenced, internally consistent, and policy-aligned.
- The runtime checks the *structure* of the adjudication, not the truth of
  its conclusions. A structurally valid adjudication is not a validated
  finding.

## Isolation

This Skill does not execute target code. If verifying a claim requires
running it, use isolation the Harness already provides; if none is
provided, record the verdict as `needs_more_evidence` rather than asserting
it.
