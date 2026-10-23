# Refutations — mini-adjudication

> The written findings for the claims that did not produce a report.
> Three claims, three different reasons for not reporting.
>
> **Not a report.** Nothing here is sent to the maintainer as a
> vulnerability. Its value is that it records *why*, so the next person
> does not redo the work — and so nobody re-reports the same non-issue.

---

# C2 — "The share download path does not check the share token"

## Claim as received

> The share download path does not check the share token.

**Source of the claim**: `scanner`.

## Verdict

**`does_not_hold`**

The path compares the presented token against the expected one with
`hash_equals`, and returns before the session is read.

## What refutes it

| Assertion | Verdict | Evidence | What it shows |
|---|---|---|---|
| A5 | `refuted` | `app.php:181` | The first thing the path does is compare the presented token against the expected one |
| A6 | `refuted` | `app.php:184` | The comparison returns false and the method returns before the session is looked up |

## The refutation, in detail

The claim says the path does not check the token. The check is the
second statement of the method:

> ```php
> $expected = $this->expectedTokenFor($shareToken);
> if (!hash_equals($expected, $shareToken)) {
>     return false;
> }
> if ($this->store->sessionUser($sessionToken) === null) {
>     return false;
> }
> ```
> — `app.php:180-186`

The claim's own path runs through this check and the check holds: a
caller that presents a token whose hash does not match the expected one
returns at `app.php:182`, before the session lookup at `app.php:184` is
ever reached.

## Refutation attempts that did not refute

| Attempt | Result |
|---|---|
| Looked for a token comparison elsewhere in the path that might make the in-path check redundant | The check is in the path, and it is the only one. The claim named no line, so the question was whether a guard existed at all, and it does. |

## What would change this verdict

A different `download()` path that does not route through
`ShareService::download()` — for example a second entry point that
reaches the store directly. The claim would then be a new claim about
that path, not this one.

---

# C3 — "The login path is not rate limited"

## Claim as received

> The login path is not rate limited.

**Source of the claim**: `scanner`.

## Verdict

**`needs_more_evidence`**

The login path does consult the limiter, and the limiter's behaviour
with no configured limit is confirmed — but the value that decides
whether the limit binds is a deployment value this source cannot show.

## What refutes it

| Assertion | Verdict | Evidence | What it shows |
|---|---|---|---|
| A7 | `confirmed` | `app.php:227` | With no configured limit, the limiter permits every attempt |
| A8 | `unresolved` | `app.php:215` | The limit comes from the environment, and the source supplies no value of its own |
| A9 | `unresolved` | `app.php:101` | The login path consults the limiter; whether the limiter binds is decided by A8 |

## The refutation, in detail

The claim cannot be settled in either direction from source.

The login path does reach the limiter (`app.php:101`), and the limiter
does enforce a limit when one is configured (`app.php:231`). But the
limit itself arrives from the environment (`app.php:215`), and with the
value unset the limiter permits every attempt (`app.php:227`):

> ```php
> if ($this->limitPerMinute <= 0) {
>     // A limit of zero means "no limit configured".
>     return true;
> }
> ```
> — `app.php:227-230`

Two searches for a limit the source supplies itself — a hardcoded
numeric value, and a rate constant — were both zero-match. The value
can only arrive from the deployment, so whether the login path is rate
limited is a fact about the deployment, not about this code.

## Refutation attempts that did not refute

| Attempt | Result |
|---|---|
| Looked for a limit value the source supplies itself, which would have settled the claim | Neither a hardcoded numeric limit nor a rate constant exists anywhere in the source; the value can only arrive from the environment |

## What is missing

| Missing fact | How to observe it safely | Who can observe it |
|---|---|---|
| The value of `APP_RATE_LIMIT_PER_MINUTE` in the deployment that runs this code | Read the deployment's environment configuration for the service; no request against the running service is needed | The operator, or anyone with read access to the deployment configuration |

**Do not report this claim while this is outstanding.** The verdict
stays `needs_more_evidence` until the fact is in hand. If the value is
unset, the claim becomes a reportable one; if it is set, the claim is
refuted.

---

# C4 — "A share session stays valid after the share password is rotated"

## Claim as received

> A share session stays valid after the share password is rotated.

**Source of the claim**: `bounty report`.

## Verdict

**`already_fixed`**

The current source binds the session to the credential it was issued
against, so a rotated credential ends the session.

## What refutes it

| Assertion | Verdict | Evidence | What it shows |
|---|---|---|---|
| A10 | `fixed` | `app.php:250` | The session path compares the bound credential against the current one |
| A11 | `fixed` | `app.php:251` | A differing credential returns false, so the session is rejected |

## The refutation, in detail

The claim described the behaviour before the binding was enforced. The
current source compares the credential the session was issued against
with the credential presented now:

> ```php
> if (!hash_equals($boundCredential, $currentCredential)) {
>     return false;
> }
> ```
> — `app.php:250-252`

A rotated credential makes the two differ, the comparison returns false,
and the session ends.

## Refutation attempts that did not refute

| Attempt | Result |
|---|---|
| Looked for a second path that resolves a session without the comparison | The claim named the session path, and that path performs the comparison; a second path would be a different claim, not this one |

## Where the fix is

- The guarding line: `app.php:250`.
- Whether the fix is **complete**: it covers the session path this claim
  names. Whether any other path resolves a session is a separate claim.
- Whether the fix shipped in a release: not determinable from this
  source.

A partial fix is not the same as a fixed issue, and a partial fix may be
a new claim with a narrower subject.

## What would change this verdict

Evidence of a second path that resolves a session without comparing the
bound credential. That would be a new claim with a narrower subject.

---

## Note for the submitter

- None of these three claims is being reported to the maintainer.
- If the maintainer is already aware of one of them, a note may still be
  worth sending — but it is a note, not a report, and it is a separate
  decision from the submitter.
