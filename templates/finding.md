# Finding — {slug}

> One finding per file. Keep the file under one screen; findings that
> need more room are usually evidence-thin.

## Summary

One sentence. The attacker's starting point, the precondition they
needed, and the capability they ended up with.

## Severity

`{critical | high | medium | low}` with one-line justification grounded
in the consequence (data, integrity, availability, blast scope), not
in the difficulty of exploitation.

## Location

- File / URL / endpoint the attacker reaches.
- Line range or function that contains the bug.
- Config, route, or schema entry that wires the entry point to the
  vulnerable code.

## Preconditions

- Attacker state (network position, credentials, prior capability).
- System state (config flag on, debug mode, deployment shape).

## Attack path

A walk through the code that an independent auditor could follow.
Each step names a file path, line range, and the data value at that
point. End at the consequence — what the attacker now controls.

## Evidence

- The exact code or response that proves the bug. Quote it.
- Runtime evidence is preferred when it materially reduces
  uncertainty. A complete static proof is sufficient when
  entry -> control -> sink -> consequence can be established
  from code. A static proof has to actually be complete: the
  attacker-controlled input must be traceable to the sink,
  and the consequence must follow from the sink.
- The negative control that would have disproved the bug, and why
  it did not.

## Why existing controls missed it

One paragraph. Naming the missing control is what turns a bug report
into a fix proposal.

## Remediation

The smallest change that closes the gap. Note any change that would
not close it (sanitizers that do not sanitize, allowlists that allow
the bypass).