# mini-disclosure-skill

A prompt-led disclosure-preparation Skill. The model reasons about an
audit's **existing findings** and decides which ones to report, how to
frame them, and on which channel. A small stdlib runtime validates
the triage-note structure, the CVSS cross-check, and skill freshness;
it is not a full audit state machine and cannot prove that a maintainer
will accept a report.

> This is the **post-audit** half of a two-skill workflow. The audit
> skill produces confirmed findings; this skill decides what to do with
> them. It does not find vulnerabilities, and it does not submit
> anything.

## What you get

- `SKILL.md` — the skill itself. How the model runs a triage.
- `references/acceptance-policy.md` — reading the upstream's scope
  document, its published advisories, and its prior classifications.
- `references/premise-analysis.md` — Question 1, in depth: who creates
  the precondition that makes a finding reachable.
- `references/report-writing.md` — the disclosure form of a finding, the
  wording red lines, advisory-form mechanics, and the pre-send list.
- `references/ordering-and-channels.md` — send order, channel choice,
  and re-triage after a closure.
- `templates/triage-notes.md` — the single Markdown file the model
  maintains during the triage.
- `templates/advisory.md` — the one-report-per-file disclosure
  template.
- `schemas/triage-table.schema.json` and `runtime/validate_triage.py` —
  structural checks for the three-question coverage, premise
  citations, work-queue closure, send order, and channel.
- `runtime/cvss31.py` — a second implementation of the CVSS v3.1 base
  score, used to cross-check a stated score against its vector.
- `runtime/evidence_log.py` — bounded, read-only source search/read
  capture that writes evidence artifacts and a hash-bearing JSONL
  ledger.

## How to use it

1. Load `SKILL.md`.
2. Copy `templates/triage-notes.md` into the triage workspace and
   rename it for the target.
3. Run the three-stage loop (Triage → Frame → Deliver). Triage records
   the upstream's acceptance model, then answers the three questions —
   premise, declared boundary, same-version divergence — for every
   confirmed finding, with cited evidence. Frame restates each
   surviving finding as an invariant. Deliver writes the advisories.
4. Before Deliver, run the structural check and fix what it reports:

   ```text
   python runtime/validate_triage.py path/to/triage-notes.md \
       --evidence-ledger path/to/evidence.jsonl
   ```

## The three questions

Every confirmed finding gets all three answered, with `file:line`
evidence. A finding fails if any question fails.

1. **Premise** — can the attacker cause the precondition alone?
   `attacker_only`, or one of the three operator/ambient/third-party
   kinds that carry the rejection risk.
2. **Boundary** — has the product declared this behaviour? Evidence
   comes from the product: its scope document, its code comments, the
   commit that introduced the behaviour, and above all its own prior
   advisories and how they classified similar issues.
3. **Divergence** — does the same version refuse on one path what it
   allows on another? This is the framing that survives review,
   because it needs no argument about intent.

Each finding ends in one disposition: `send`, `rewrite_then_send`, or
`convert_to_hardening`.

## What this Skill is not

- It does not perform the audit. It consumes the audit's findings.
- It does not submit anything. It produces drafts and checks. Submission
  and credit acceptance require the submitter's explicit confirmation.
- It does not provide a sandbox. It reasons over an existing audit and
  reads source to verify claims.
- It does not prove the maintainer will accept a report. It proves the
  triage is internally consistent, evidenced, and policy-aligned.
- The runtime checks the *structure* of the triage, not the truth of its
  conclusions. A structurally valid triage is not a validated
  disclosure.

## Isolation

This Skill does not execute target code. If verifying a claim requires
running it, use isolation the Harness already provides; if none is
provided, state the claim as `NEEDS-RUNTIME` rather than asserting it.
