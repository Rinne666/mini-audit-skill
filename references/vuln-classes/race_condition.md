# Race Conditions

A race condition is a bug the application has only when two
operations run within a window the attacker can shorten. The bug
is not the operation; it is the gap between "decide" and
"commit."

## Live bug classes

- **TOCTOU** (time-of-check to time-of-use): the application
  validates a resource and then operates on it. The attacker
  swaps the resource between the two steps.
- **Concurrent state mutation** (lost update, double-spend): two
  operations both read the same state, both decide the
  operation is valid, both commit, and the resulting state is
  inconsistent.
- **Limit bypass**: rate limit, quota, idempotency-key reuse,
  voucher redemption, withdrawal, vote, coupon application.
- **Send-order dependency**: an authentication step that grants
  capability before the verification step completes, an event
  handler that publishes before the database commits.

## Where to look

- Anything that does "check then act" on attacker-visible
  state: balance check before withdrawal, role check before
  admin action, existence check before file write, voucher
  check before redemption.
- Anything that mints a token or issues an identifier before
  persisting: webhook URLs that fire before the row exists,
  password reset emails that arrive before the reset record
  is written.
- Anything idempotent on a key the attacker controls: webhook
  handlers that process the same event twice for different
  effects, refund endpoints that credit twice.

## Disproofs that often fail

- "It's serialized by the database." Read the transaction
  isolation level. Read-committed is not serializable.
- "We use a lock." Read the lock. Does it cover the check and
  the act? Or only one of them?
- "It requires too many requests." The attacker does not need
  many requests. They need the requests to land in a window.
  Calculate the window, not the count.
- "It requires same-machine timing." Network jitter and
  container scheduling jitter are usually enough.

## The permission delta

Double-spend / multi-redemption → high to critical depending on
the value. Limit bypass that gives a free premium feature →
high. Auth bypass via race → critical. Self-only state
inconsistency → low.

A race condition that the attacker cannot shorten is not a bug
at all — measure the window before severity.