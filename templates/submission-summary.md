# Submission Summary — {target}

> The 可申报总结: what is submittable, where, and why each one is safe
> to submit. Produced at the Deliver stage for every claim whose action
> is `report` or `rewrite_then_report`. Claims whose validity is not
> `holds` never appear here — a claim that does not hold is not
> "unsubmittable", it is not a vulnerability.

**Target**: `{name}` · kind `{open_source / closed_product /
web_service}` · policy `{stated / derived / none}` ·
adjudicated at `{commit / tag}`.

## Submittable

One row per reportable claim, in delivery order (reception likelihood,
not severity). Every cell cites or points at the adjudication.

| Order | Claim | Subject (invariant) | Core business | Developer aware | Special config | Boundary crossed | Primary target | Secondary / unsuitable |
|---|---|---|---|---|---|---|---|---|
| 1 | C1 | | yes/no — evidence | aware/false/unknown — evidence | required? — default | from → to | `target` — reason | `target` — reason · `target` — reason |

## Hardening offers

Claims that hold but whose acceptability is `decline`: patches to
offer the maintainer, not reports.

| Claim | Why it will not be accepted as a report | The offer |
|---|---|---|

## Blocking facts

What stands between a blocked claim and submittability, stated so the
submitter can act on it:

- `needs_more_evidence` claims: the exact missing fact and the safe
  way to observe it.
- Any `developer_awareness: aware` finding and the re-framing it
  forces.
- Any timeline field that is `untraced`, and what a trace would change
  (affected range, already_fixed, publication status).

## Timeline (per submittable claim)

From `oss_verification.commit_timeline` — cited facts or explicit
`untraced — reason`.

| Claim | Introduced | First release with it | Fix state | Published as |
|---|---|---|---|---|

## Decision points for the submitter

Not part of any report body. Recorded here because only the submitter
can decide them:

- Channel confirmation (one channel; the alternatives considered).
- Credit / anonymity decision.
- AI-assistance disclosure state (several platforms now require it).
- CNVD / CNNVD double-filing intent, if any — two submissions by
  design, never by accident.
- **Confirmation that nothing has been submitted by this Skill.**
  Submission and every externally visible action stay with the
  submitter.
