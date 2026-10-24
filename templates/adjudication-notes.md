# Adjudication Notes — {target}

> One Markdown file. The whole state of this adjudication. Edit it in
> place, every round. Evidence IDs point to captured artifacts; the file
> has no separate state database.
> The file *is* the canonical state — make it readable to a stranger.

---

## Claims Under Adjudication

One block per claim. A claim arrives from somewhere — a scanner, a
colleague, a published advisory, a bug bounty report, a suspicion from
code reading. Its origin does not make it true.

| # | Claim (one sentence) | Source of the claim | Current source status |
|---|---|---|---|
| 1 | | | `live / fixed / unknown` |

**Why this claim is being adjudicated**: {one line — what decision it
unblocks}.

## Target and Source Ref

- **Target**: {repository / product}
- **Target kind**: `open_source / closed_product / web_service` — an
  open-source target carries the OSS Verification section below;
  the others state "not applicable" there and say why.
- **Source ref adjudicated**: `{commit / tag}`. Every verdict is relative
  to this ref; a claim verified against a different revision is a
  different claim.
- **Upstream acceptance policy**: `{SECURITY.md path / advisory page /
  none}`. **Source of authority**: `stated | derived`.
- **Published advisories already checked**: `{yes — N advisories / no}`.

## Claim Decomposition

Each claim split into the parts that can each be true or false. An
assertion without a `file:line` or a concrete named fact is not ready
to test — record what is missing instead.

### Claim 1 — {short name}

| # | Assertion | Type | Anchor | Notes |
|---|---|---|---|---|
| A1 | | `defect / reachability / consequence / precondition` | `file:line` or named fact | |

## Assertion Ledger

Every assertion, with the refutation attempt that was made against it
and the result. "Searched for a guard with these two patterns, found
none" requires two distinct captured zero-match searches — re-running
the same command is not a second check.

| Claim | Assertion | Verdict | Refutation attempted | Result | Evidence IDs |
|---|---|---|---|---|---|
| 1 | A1 | `confirmed / refuted / unresolved / fixed` | | | |

An assertion that was never refuted because no attempt was made is
`unresolved`, not `confirmed`.

## Acceptance Answers

Only for claims whose validity is `holds`. Three questions, each with
cited evidence. A claim that does not hold never reaches this section.

| Claim | Q1 Premise | Q2 Boundary | Q3 Divergence | Acceptability | Rationale |
|---|---|---|---|---|---|
| 1 | | | | `accept / accept_after_rewrite / decline` | |

## OSS Verification

Required when the target kind is `open_source`; for every claim that
holds. This is where the audit result is checked one-by-one against
the project's own record — its security policy, its commit timeline,
its advisory history, and its demonstrated preference. A target that
is not open source states "not applicable" here with the reason.

| Claim | Policy check | Introducing commit | First release | Fix state | Published as | Similar issues | Maintainer preference |
|---|---|---|---|---|---|---|---|
| 1 | what the policy says about this shape, with ref | sha + date, or `untraced — reason` | tag, or untraced | none / sha / partial | advisory id, or "none found — searched …" | ref → classification | pattern, cited |

Every cell is a cited fact or an explicit `untraced / none found`
with what was searched. A guessed cell fails the validator and, in a
report, fails the maintainer.

## Verdict Table

The machine-readable decision. Row order is the delivery order.

| # | Claim | Validity | Acceptability | Subject (the invariant) | Action | Evidence IDs |
|---|---|---|---|---|---|---|
| 1 | | | | | | |

**Action vocabulary**: `report` (write the draft) / `rewrite_then_report`
/ `hardening_note` (offer as a patch) / `no_report` (state the
refutation) / `needs_evidence` (name the missing fact) / `already_fixed`
(note the fix).

## Submission Summary

The 可申报总结, distilled from `references/submission-summary.md`. One
row per reportable claim; the full artifact is
`templates/submission-summary.md`.

| Claim | Core business | Developer aware | Special config | Boundary crossed | Primary target | Secondary / unsuitable |
|---|---|---|---|---|---|---|
| 1 | yes/no — evidence | aware/false/unknown — evidence | required? — default cited | from → to | one target — reason | others — reasons |

Exactly one primary target per claim. Two primaries mean duplicate
intake. A `special_config_required: true` claim cannot carry an
`attacker_only` premise — the validator rejects the combination.

## Work Queue

One bounded item per assertion group plus a final review. Before
delivery, no item may be `active` or `queued`; deferred items explain
the reason and the limitation. A `final_review` task must be completed
after challenging the `does_not_hold` and `needs_more_evidence` verdicts.

## Refutations Considered and Rejected

Refutation attempts that looked promising but did not hold up, with the
reason. A reviewer reading only this section should be able to see
what was tried, not only what was concluded.

| Claim | Attempted refutation | Why it did not refute |
|---|---|---|

## Remaining Questions

The one question, if answered, would most likely change a verdict.
Update as the adjudication progresses. When the answer matters less
than it used to, replace it.

An empty list is not a stop signal by itself. Stop only after every
claim has a validity verdict and every claim that reached the Assess
stage has all three acceptance answers.

---

## Adjudication Table

Include the machine-readable JSON object required by
`schemas/adjudication.schema.json`. List every claim with its
decomposition, its assertion verdicts, its two verdicts, its subject
where it holds, and the evidence IDs returned by
`runtime/evidence_log.py`.

## Delivery Plan

**Channel**: `{name}` — **why this one**: `{reason}`.
Two channels mean duplicate intake.

| Order | Claim | Action | Artifact | Why here |
|---|---|---|---|---|
| 1 | | | | |

## How to use this file

1. **Adjudicate round.** For each claim: confirm it is live in the
   current source, split it into assertions, and test each one. Try to
   kill it. Record the validity verdict with cited evidence.
2. **Assess round.** For claims that hold: read the project's
   acceptance policy, answer the three acceptance questions, and —
   when the target is open source — complete the OSS Verification
   row: policy check, commit timeline, similar issues, maintainer
   preference.
3. **Deliver round.** Produce the artifact the verdict calls for, and
   only that artifact. A claim that does not hold gets a written
   finding, not a report. Every reportable claim gets its submission
   row and the summary closes with the submittable list.

The model can jump between rounds. The file does not enforce a state
machine. The reviewer enforces it by reading.
