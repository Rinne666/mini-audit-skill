# Advisory — {slug}

> One report per file, and one file per report. Keep it under one
> screen; a report that needs more room is usually arguing rather than
> showing.
>
> This template is the **disclosure** form of a finding. It is not the
> audit's internal finding record, and it is not a hardening note.

## Title

One line. The **invariant the code fails to enforce**, not the
consequence the attacker obtains.

> Weak: "Unauthenticated attacker can become super admin"
> Strong: "The provider layer permits a second administrator to be
> created; there is no first-admin-only constraint"

A consequence subject turns the report into a deployment argument.
An invariant subject keeps the code as the object of the claim, and
survives even when the maintainer disagrees about reachability.

## Affected component

- File / function / route the reporter reaches.
- Line range containing the defect.
- The config, route, or schema entry that wires the entry point to the
  vulnerable code.

## Attacker identity

One sentence, naming the trust rung and the credentials held:

> An unauthenticated network peer who knows only an existing username.
> An authenticated protocol user of the affected account.
> A holder of an API key bound to a restricted administrator.

This is the most-read sentence in the report. Make it unambiguous.

## Trust boundary crossed

> From `<L? — role>` to `<L? — capability>`.

Map it onto the project's own ladder, and name the specific resource
that becomes reachable that was not reachable before.

## Preconditions

- Attacker state: network position, credentials, prior capability.
- System state: config, deployment shape, enabled feature.
- The exact condition that unlocks the chain.
- **State the residual premise honestly.** If the attack needs the
  operator to have enabled a documented extension, say that. Do not
  hide it, and do not inflate it into "the operator weakened
  security" — configuring a supported feature correctly is not
  weakening.

If a precondition is not the vendor default, separate the default
behaviour from the behaviour in supported/common deployments, and state
the enabling configuration and who can reach the feature once enabled.
A non-default configuration is a precondition to describe, not by
itself a reason to dismiss the issue — and not a reason to hide it
either.

## Same-version behaviour divergence

The paragraph that carries the report. State both sides symmetrically:

> `<path A>` refuses the operation when `<condition>` holds
> (`file:line`).
> `<path B>` performs the operation under the same condition
> (`file:line`).

This is checkable in under a minute and cannot be dismissed by an
argument about intent. If there is no divergence, delete this section
and make sure the invariant argument stands on its own.

## Attack path

A walk through the code an independent auditor could follow. Each step
names a file path, line range, and the data value at that point. End at
the consequence — what the attacker now controls.

## Impact

What the attacker gained, concretely. Not "could lead to" — what
demonstrably happened.

Use only data the reporter created. If real user data was reachable,
state "confirmed reachable, contents not retrieved" and move on. Never
export real user data.

## Evidence

- The exact code or response that proves the defect. Quote it.
- Runtime evidence is preferred when it materially reduces uncertainty.
  A complete static proof is sufficient when entry → control → sink →
  consequence can be established from source.
- The negative control that would have disproved it, and why it did
  not.

## Severity

`{critical | high | medium | low}` with a one-line justification
grounded in the consequence, not in the difficulty of exploitation.

**CVSS v3.1**: `CVSS:3.1/...` → **`{score}` ({rating}`)**.

Justify each non-obvious metric choice in one clause — `AC:H` because
…, `A:N` because … — and score against the conditions that actually
hold, not the theoretical ceiling. The maintainer will check the
reasoning, not just the number.

## Version and scope

- **Version tested**: `{commit / tag}`.
- **Affected range**: `{range}` — or, when the introducing commit cannot
  be traced, "every build that contains this function". Never invent a
  version boundary; an unverified range invites the maintainer to find
  a boundary you did not intend.
- **Patched version**: `{released version}` — or, when the fix is
  unreleased, "unreleased on `main`, commit `<sha>`". Never guess the
  next version number.

## Why existing controls missed it

One paragraph. Naming the missing control is what turns a bug report
into a fix proposal. Prefer naming the *invariant* that was never
enforced over naming a missing check.

## Suggested remediation

The smallest change that closes the gap, enforced at the last trusted
decision point. Note any change that would not close it (a sanitizer
that does not sanitize, an allowlist that allows the bypass).

## Notes for the submitter

Not part of the report body. Record here:

- Channel and why.
- Credit / attribution decision.
- AI-assistance disclosure state.
- Anything the submitter must decide before the submit action.
- **Confirmation that the report was not submitted by this Skill.**

This Skill produces drafts and checks. Submission, credit acceptance,
and any other externally visible action require the user's explicit
confirmation.
