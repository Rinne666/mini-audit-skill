# Finding — {slug}

> Create a finding only for a `confirmed` candidate review. A
> `needs_validation` candidate belongs in the report's limitations, not in the
> confirmed findings list.

## Candidate Review

- Candidate ID:
- Independent verifier ID:
- Verdict: `confirmed`
- Evidence IDs:

## Summary

One sentence: attacker starting point, required precondition, and resulting
capability.

## Severity

`{critical | high | medium | low}` with a one-line justification grounded in
the consequence (data, integrity, availability, blast scope), not merely the
difficulty of exploitation. Assign severity only after the candidate is
confirmed and its preconditions are stated.

## Location

- File / URL / endpoint the attacker reaches.
- Line range or function containing the bug.
- Config, route, or schema entry wiring the entry point to the vulnerable code.

## Preconditions

- Attacker state (network position, credentials, prior capability).
- System state (config flag, debug mode, deployment shape).
- Default behavior and impact in supported/common deployments.
- Exact condition that unlocks the chain. A non-default configuration is a
  precondition to describe, not by itself a reason to dismiss the issue.

## Attack path

Walk the code so another auditor can reproduce it. Each step names a source
path, line range, and the value at that point. End at the consequence.

## Evidence

- Exact code or response proving the bug.
- Runtime evidence when it materially reduces uncertainty. Complete static
  proof is sufficient when entry → control → sink → consequence follows from
  source.
- Strongest disproof attempt, and why it did not hold.
- Independent verifier's source reads and conclusion.

## Why existing controls missed it

Explain which missing or ineffective control allowed the behavior.

## Remediation

The smallest change that closes the gap. Note any change that would not close
it (for example, a sanitizer that does not sanitize the dangerous form).
