# Report Writing

> Load this when writing the advisory body for a claim whose validity is
> `holds`, and before every submit.
>
> This document is **not** the tool for a claim that does not hold. For
> those, use `templates/refutation.md` — the artifact is a written
> finding, not a report, and sending a refuted claim as a report is
> worse than sending nothing.

Everything here came from a real submission and its real outcome. The
goal is to remove the ways a correct report gets lost in a queue.

---

## 1. The subject is the invariant, not the consequence

This is the single highest-leverage edit in the whole workflow.

| Weak subject (consequence) | Strong subject (invariant) |
|---|---|
| "Unauthenticated attacker can become super admin" | "The provider layer permits a second administrator to be created; there is no first-admin-only constraint" |
| "Share ownership is not preserved after restore" | "Restore overwrites the live share owner and its authorization policy on SQL providers" |
| "Password may be overwritten by external auth" | "An empty external-auth response rewrites the stored password instead of failing the authentication closed" |

A consequence subject makes the report an argument about deployment, and
deployment arguments are what maintainers overrule. An invariant subject
keeps the code as the object of the claim, and it stays true even if the
maintainer disagrees about reachability.

The validator rejects the obvious consequence shapes in a subject
(`attacker can`, `leads to`, `allows compromise`, …). That is a blunt
instrument on purpose: it forces the rewrite, and the rewrite is where
the value is.

---

## 2. Wording red lines

**Never** write "as you know", "you already know", "you already fixed",
or any variation. If the project previously touched this behaviour they
classified it, and the classification was not "security". The sentence
does not persuade; it tells the reviewer their classification is being
contested, and they will close on that ground regardless of the
evidence that follows.

**Never** write "reproduced by me" or "I confirmed" in the body. The
submitter of the report cannot vouch for the reporter's reproduction.
Use "the following steps reproduce", and state the version.

**Never** present an unverified version range as verified.

**Never** include a claim you cannot demonstrate with your own data. If
real user data was reachable, state "confirmed reachable; contents not
retrieved" and move on. Taking the data is both wrong and unnecessary.

**Never** argue with a prior closure inside a new report. New reports do
not cite prior reports as leverage. If a closure materially changes the
analysis, that belongs in the adjudication notes, not in the report.

**Do** state the assumed trust model when the project publishes no
policy, so the maintainer can correct it rather than dismiss the whole
thing.

---

## 3. Form mechanics — GitHub private vulnerability reporting

These are measured behaviours, not guesses. Re-verify per form
revision; the DOM changes.

### The textarea trap

Filling a textarea on the advisory form can submit the entire form.
Observed in practice: a bulk fill on the Summary field jumped straight
to the newly created advisory page and produced a report ID.

Practical rules:

- Fill exactly one field, then read the page URL and title before
  continuing.
- If the URL changed to an advisory detail page, a report was submitted
  — stop and report the new advisory ID immediately.
- Prefer per-keyboard typing over bulk fill for text that must survive a
  re-render; bulk-fill state can be dropped by a re-render and leave the
  field silently empty.

### Severity and vector string are mutually exclusive

- Selecting a manual severity label clears the vector string field.
- Writing a vector string switches severity to the automatic
  `cvss_v3` mode, and the badge then shows the computed value.

Decide which is authoritative *before* filling. If the manual label is
what was asked for, take the manual label and put the vector string plus
the score in the body text. Read the badge after the field loses focus —
it recomputes on blur, so a badge read too early shows a stale value.

### Select option values are lowercase

Severity options are `low` / `moderate` / `high` / `critical` /
`cvss_v3` / `cvss_v4`. Sending `"High"` fails with a not-found error.
Ecosystem values are lowercase too — Go is `go`, not `Go`.

### Version fields

- **Patched version**: only a version that exists in a release. If the
  fix is on `main` but unreleased, say so in the body with the commit
  SHA and leave the field empty rather than guessing the next number.
- **Affected version**: the range is inferred from when the defect was
  introduced. Check the introducing commit is in the tagged release you
  name.

### Where the numbers live

A private report becomes a draft advisory. The advisory's own metadata
may differ from the report body — the severity badge, the summary
paragraph, and the impact paragraph are separate fields. A number fixed
in one is not automatically fixed in the others. After any correction,
re-read every field that carries a number.

---

## 4. CVSS discipline

The platform's own calculator is authoritative. A second implementation
is a cross-check against implementation mistakes, not an authority.

```text
python runtime/cvss31.py --selftest
python runtime/cvss31.py "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N"
```

The most common hand-computation error is omitting the `ISS`
multiplication on the impact sub-score — `Impact = 6.42 × ISS`, not
`6.42 + ISS`. It moves a score by roughly a full point and is invisible
without a second implementation.

**Run the script on every vector you write and confirm the score it
prints equals the score you state.** A vector and its score drifting
apart is the most common defect in a submitted report, and it is
trivially checkable.

Justify each non-obvious metric choice in one clause — `AC:H` because
…, `A:N` because … — and score against the conditions that actually
hold, not the theoretical ceiling. The maintainer will check the
reasoning, not just the number.

**Severity and impact must agree.** A "critical" severity with an
impact paragraph describing a limited blast radius invites a severity
re-classification, which becomes a dispute. If the demonstrated impact
does not support the severity, lower the severity.

---

## 5. The reply path

When a maintainer responds — accepted, closed, or asked a question:

- **Answer questions directly and briefly.** A short, specific answer
  beats a long defence. If they ask for something you have not
  verified, say so and offer to verify.
- **Do not argue the classification once they have stated it.** Accepting
  a classification while surfacing the residual, unfixed part is a
  better outcome than contesting the label. If a fix landed, thank them
  for it — the fix is the goal.
- **A closure is evidence.** Extract their model from the wording and
  apply it to the remaining findings before writing anything else. See
  `premise-analysis.md` §2 and `ordering-and-channels.md` §4.
- **Surface what the closure did not cover.** If their fix addressed
  one path and left another, that residual is a separate, narrower
  follow-up — hardening plus a patch, not a new vulnerability report.
- **Keep the channel single.** Reply where the report was filed.
  Starting a second thread splits the record.

---

## 6. Pre-send checklist

Run this list literally before any submit action. Every item is a way a
report has been lost.

- [ ] The validity verdict is `holds` and the acceptability verdict is
      `accept` or `accept_after_rewrite`, and the adjudication record
      validates.
- [ ] The premise is `attacker_only`, or the report explicitly
      discloses the operator-dependent part and survives without it.
- [ ] No operator-dependent premise is hidden in the reproduction steps.
- [ ] The title states an invariant, not a consequence.
- [ ] The attacker identity sentence names a ladder rung and the
      credentials held.
- [ ] The boundary crossing is stated as "from X to Y".
- [ ] The reproduction starts from a clean state and uses only
      self-created data.
- [ ] No "you already know" / "as you know" phrasing anywhere.
- [ ] No claim of personal reproduction in the body.
- [ ] The version range was checked against the introducing commit, or
      is labelled as inferred.
- [ ] The patched version is a released version, or the field is empty
      and the body states the unreleased commit.
- [ ] The CVSS vector reproduces the stated score in the platform
      calculator **and** in `runtime/cvss31.py`.
- [ ] Severity matches the demonstrated impact.
- [ ] Exactly one reporting channel is used.
- [ ] The AI-assistance disclosure is answered truthfully.
- [ ] The credit/attribution decision is settled.
- [ ] The submitter has explicitly approved the exact text, channel,
      and severity before the submit action.
