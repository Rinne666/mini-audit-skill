# mini-adjudication

A prompt-led **post-audit vulnerability acceptance standard**. The audit
finds; this skill judges. It loads **after an audit has produced
findings** and decides two separate things with evidence: **whether each
finding holds**, and **whether it would be accepted if submitted** — by
the maintainer's advisory flow, a CVE CNA, CNVD, an SRC, or a bounty
platform. For open-source targets it verifies every holding claim
one-by-one against the project's own record: security policy, commit
timeline, historical similar vulnerabilities, and maintainer preference.
It closes with the submission summary — core business, developer
awareness, trigger configuration, boundary crossed, and the target list.
A small stdlib runtime validates the adjudication structure, re-checks
the absence evidence, and cross-checks CVSS; it is not an audit state
machine and cannot prove a maintainer will accept a report.

> This skill does **not** find vulnerabilities. It judges claims it is
> given — normally the output of a finished audit (`security-audit` or
> equivalent). If no findings exist yet, you need an audit, not this
> skill. It also does not submit anything: it produces drafts, checks,
> and the submission summary; every externally visible action stays
> with the submitter.

## What you get

- `SKILL.md` — the skill itself. How the model runs an adjudication.
- `references/claim-decomposition.md` — splitting a claim into assertions
  that can each be true or false, and choosing the assertion type that
  carries the claim's uncertainty.
- `references/validity-assessment.md` — killing a claim: the refutation
  catalogue, proving absence, and when a fact genuinely cannot come from
  source.
- `references/acceptance-policy.md` — reading the upstream's scope
  document, its published advisories, and its prior classifications.
- `references/premise-analysis.md` — Question 1, in depth: who creates the
  precondition that makes the claim reachable.
- `references/commit-timeline.md` — tracing the introducing commit, the
  releases that carry the defect, the fix state, and whether it is
  already published — and what each fact decides downstream.
- `references/historical-similarity.md` — finding near-identical prior
  issues and their classification, reading the maintainer's demonstrated
  preference, and checking whether the developers already noticed and
  commented.
- `references/submission-targets.md` — the distilled acceptance rules of
  every submission target: maintainer advisory flows (GHSA), CVE via
  CNA scope rules, CNVD 通用型/事件型, the CN SRCs' common core, and the
  bounty platforms' report anatomy (HackerOne quality bar, Bugcrowd
  VRT) — plus the mapping from claim shape to target fit.
- `references/submission-summary.md` — the four summary dimensions
  (core business, developer awareness, trigger configuration, boundary
  crossed) and how they assemble into the submittable list.
- `references/report-writing.md` — the disclosure form of a finding, the
  wording red lines, advisory-form mechanics, and the pre-send list.
- `references/ordering-and-channels.md` — delivery order, channel
  choice, and re-adjudication after a closure.
- `templates/adjudication-notes.md` — the single Markdown file the model
  maintains during the adjudication.
- `templates/advisory.md` — the one-report-per-file disclosure template.
- `templates/submission-summary.md` — the 可申报总结: what is
  submittable, where, why each one is safe, and what blocks the rest.
- `templates/refutation.md` — the written finding for a claim that does not
  hold, cannot be settled, or is already fixed.
- `schemas/adjudication.schema.json` and `runtime/validate_adjudication.py` —
  structural checks for the assertion ledger, the evidence citations, the
  mechanical derivations of both verdicts, the target profile, the
  OSS verification block, the submission block, work-queue closure, and
  channel.
- `runtime/evidence_log.py` — bounded, read-only source search/read capture
  that writes evidence artifacts and a hash-bearing JSONL ledger.
- `runtime/cvss31.py` — a second implementation of the CVSS v3.1 base score,
  used to cross-check a stated score against its vector.

## How to use it

1. Run the audit first (`security-audit` or equivalent). This skill's
   intake is the audit's findings; with no findings, stop and say so.
2. Load `SKILL.md`.
3. Copy `templates/adjudication-notes.md` into the adjudication
   workspace and rename it for the target; record the target profile
   (kind, policy source, demonstrably-used channel).
4. Run the three-stage loop (Adjudicate → Assess → Deliver).
   - **Adjudicate** splits each claim into assertions, tests each one
     with a refutation attempt, and records a validity verdict.
   - **Assess** answers the three acceptance questions — premise,
     declared boundary, same-version divergence — for the claims that
     hold; for an open-source target it also completes the OSS
     verification: policy check, commit timeline, similar issues,
     maintainer preference.
   - **Deliver** produces the artifact each verdict calls for, and only
     that artifact — plus, when anything is reportable, the submission
     summary.
5. Before delivery, run the structural check and fix what it reports:

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

## OSS verification, one by one

For an open-source target, every holding claim is additionally verified
against the project's own record — policy, commit timeline
(`introducing_commit` / `released_in` / `fix_state` / `published_as`,
each a cited fact or an explicit `untraced — reason`), historical
similar issues with their classification (`security_fix` / `hardening`
/ `bug_fix` / `wontfix`), and the maintainer's demonstrated preference.
A technically correct claim that skips this can still be a duplicate of
a published advisory, a re-litigated wontfix, or a report into a
channel the project never reads.

## The submission summary

Every reportable claim carries four answers a triager asks first —
core business, developer awareness (`aware` / `false` / `unknown`,
with evidence), trigger configuration (cross-checked mechanically
against the premise: `special_config_required: true` cannot coexist
with an `attacker_only` premise), and the boundary crossed — plus a
target list with exactly one `primary` among `vendor_advisory`,
`cve_cna`, `cnvd`, `src_platform`, `bounty_platform`,
`hardening_channel`. The distilled acceptance rules behind that list
live in `references/submission-targets.md`.

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
- The target profile is present and complete (kind, name, policy source,
  preferred channel).
- An open-source holding claim carries its oss_verification block, with a
  complete timeline and at least one similar issue (or the none-found
  entry naming what was searched).
- A reportable claim's submission block is complete, its
  trigger-configuration answer agrees with its derived premise, and its
  target list names exactly one primary.
- Both verdicts are derived, and the action matches the verdict.
- A claim that does not hold carries no acceptance verdict and is never
  actioned as a report.
- A reportable claim's subject is an invariant, not a consequence.
- All eight coverage sections are present, the work queue is closed, and a
  completed `final_review` task challenged the negative verdicts.

`runtime/test_adjudication_counterexamples.py` takes the correct fixture,
breaks it fourteen ways, and asserts each broken version is rejected. A
validator that only ever sees valid input proves nothing.

## What this Skill is not

- It does not audit. It does not hunt, scan, or map attack surface. It
  adjudicates the findings an audit already produced — it refuses to
  start without them.
- It does not submit anything. It produces drafts, checks, and the
  submission summary. Submission and credit acceptance require the
  submitter's explicit confirmation.
- It does not provide a sandbox. It reasons over claims and reads source to
  test them.
- It does not prove the maintainer will accept a report. It proves the
  adjudication is evidenced, internally consistent, and policy-aligned.
- The runtime checks the *structure* of the adjudication, not the truth of
  its conclusions. A structurally valid adjudication is not a validated
  finding.
- Platform acceptance rules (SRC/CNA/CNVD/bounty) are distilled into
  `references/submission-targets.md` as a baseline; they change without
  notice, and the live rules page wins. Re-read it before submitting.

## Isolation

This Skill does not execute target code. If verifying a claim requires
running it, use isolation the Harness already provides; if none is
provided, record the verdict as `needs_more_evidence` rather than asserting
it.
