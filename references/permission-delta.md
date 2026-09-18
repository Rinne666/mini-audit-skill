# Permission Delta

A vulnerability is not a dangerous primitive. A vulnerability is
the **difference between** what an attacker could do before they
exploited the bug and what they can do after. This reference is
how the model thinks about that difference so that severity,
remediation, and report framing all line up.

## State the delta in one sentence

> Attacker state before: {network position, credentials, capabilities}.
> Attacker state after: {new capability, new resource, new privilege}.
> Delta: {what changed}.

Three sentences total. If the model cannot write the third, the
finding is about a dangerous primitive, not a vulnerability, and the
severity is wrong.

## What counts as a real delta

- Reading or modifying data the attacker could not reach before.
- Executing code in a context the attacker could not reach
  before.
- Bypassing an authentication, rate limit, or quota.
- Influencing another user's data or session.
- Persisting attacker-controlled state past the request boundary
  (cache, file, database row).

What does **not** count as a real delta:

- Reaching a sink (`eval`, `exec`, SQL) — only counts if the
  attacker reaches it with attacker-controlled input. A sink the
  attacker cannot reach is not a vulnerability.
- Reflecting the attacker's input back at them — only counts if
  the reflection is in a context that runs in another user's
  session (stored XSS), not the attacker's own.
- Logging the attacker's input — never a vulnerability on its
  own.

## Severity from delta, not from primitive

`critical` — full takeover, arbitrary code execution as a privileged
user, or read/write to all customer data.

`high` — read/write to all data of one other tenant; authentication
bypass; persistent stored injection in another user's context.

`medium` — read of limited data of one other tenant; one-shot
stored injection in a context that is not cross-user; significant
business-logic bypass.

`low` — reflected self-injection that requires social engineering;
information disclosure that does not cross tenant boundaries; rate
limit bypass without concrete blast radius.

The bar for `critical` is full takeover or cross-tenant read. A
finding that is "RCE" but only against the attacker's own session
is `low`, because the attacker had nothing to start with that the bug did
not give them.

## When the delta is unclear, keep investigating

Most audits under-rate findings because the model stops at the
sink. The bug is real; the delta is not yet known. The right move
is to keep going, not to lower the severity. Walk the data path
until the attacker state before / after is unambiguous.

## Remediation is the smallest constraint that closes the delta

Find the precondition the attacker needs and either:

- Reject the precondition (validate the input).
- Tighten the boundary the attacker crossed (the permission
  check that should have been there).
- Or, if neither is feasible, document the residual risk in the
  finding so the reader knows what they are accepting.

A remediation that sanitizes the wrong character set, an
allowlist that allows the bypass, or a CSP that does not cover
the injection point is not a remediation — it is a paper move.