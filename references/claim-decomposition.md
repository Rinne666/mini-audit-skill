# Claim Decomposition

> Load this when a claim arrives as prose and must be split into
> falsifiable assertions.

A claim that arrives from outside arrives as a story: "the setup endpoint
can be used to create a super admin". The story bundles several things
that can each be true or false, and it is usually the story — not the
code — that is wrong. Decomposing the claim is what makes it testable.

---

## 1. Why decompose at all

Consider a real report: *"An unauthenticated attacker can become super
admin on an uninitialized instance."*

That sentence contains at least four claims:

| # | Claim | Type |
|---|---|---|
| A1 | The setup path does not re-check the administrator state when the lookup fails | `defect` |
| A2 | An unauthenticated client can reach the setup path | `reachability` |
| A3 | The account it creates holds super-admin permissions | `consequence` |
| A4 | The lookup must be failing at that moment | `precondition` |

A1 and A2 and A3 can each be verified from source. A4 cannot — it
depends on the database being unreachable, which is a deployment fact.

So the honest verdict for this report is **`needs_more_evidence`** on A4,
not "the vulnerability is real" and not "it is not a vulnerability". The
decomposition is what reveals that the report is not a single claim at
all, and therefore that it cannot get a single verdict.

Without decomposition, the reporter either asserts all four (and is
wrong about A4) or dismisses all four (and throws away a real defect in
A1). Both are how good work gets lost.

---

## 2. The four assertion types

Every assertion belongs to one of these. The type determines how you
test it.

### `defect` — the code does what the claim says

The mechanism. "The branch at `file:line` writes the presented value to
the store without re-checking."

Test it by **reading the code at the cited location** and confirming the
described behaviour is what is there. A claim whose `defect` assertion
cannot be located in the source is not a claim about this codebase.

Watch for: the behaviour existing but on a different path than the
claim names; the behaviour existing but guarded immediately before;
the behaviour being a comment or a test rather than live code.

### `reachability` — the attacker can get there

Who can reach the code, and through which interface. "An unauthenticated
client can reach the setup path through `POST /admin/setup`."

Test it by finding the route registration and the authentication
middleware on it. Record the **lowest** identity that reaches it, not
the one the claim assumes.

Watch for: the route existing but being behind authentication; the
function being called only from a test; the caller always passing a
value that makes the defect unreachable; the code being behind a build
tag or a dev-only flag.

### `consequence` — reaching it produces the claimed effect

"the created account holds super-admin permissions".

Test it by following the sink. What is actually written? What does the
account end up authorized to do? Claims about impact are where
adversarial overstatement lives, so check the sink rather than the
narrative.

Watch for: the value being sanitized before use; the effect being
bounded to the caller's own resources; the effect being self-inflicted
(an actor hurting only themselves is not a boundary crossing).

### `precondition` — what must be true for this to fire

"the administrator lookup must be failing" or "the operator must have
configured an external auth hook".

Test it by finding the condition in the code. **This is the assertion
that most often cannot be settled from source**, because it frequently
depends on a deployment, a configuration, or a runtime fact. When it
cannot be settled, the claim's validity is `needs_more_evidence` — and
that is a legitimate, valuable answer.

---

## 3. Anchors

Every assertion needs an anchor: the `file:line` it is checked against,
or the concrete named fact it depends on.

- A `defect`, `reachability`, or `consequence` assertion anchors to
  `file:line`. If you cannot produce one, the assertion is not ready.
- A `precondition` assertion may anchor to a named fact instead:
  "the database is unreachable at that moment", "the operator
  configured the external auth hook", "the reverse proxy terminates
  TLS in front of the listener".

An assertion with neither is a thought, not a testable claim. Record
what is missing rather than guessing.

---

## 4. Splitting without over-splitting

Decomposition has a failure mode in the other direction: a claim split
into forty fragments is unreadable and hides which part actually
matters.

Split on the seams where the parts can be **independently true or
false**. Two assertions that always stand or fall together are one
assertion.

A good test: for each pair, ask "can one be true while the other is
false?" If not, merge them.

Four to six assertions per claim is usually right. Fewer means the
claim was not really decomposed. More means the seams are too fine.

---

## 5. What to do with a claim that will not decompose

Some claims are not decomposable because they are not yet specific:

> "the auth code looks sketchy"
> "there might be a race in the share code"
> "this endpoint could be dangerous"

These are **not ready to adjudicate**, and the correct outcome is to say
so — not to force them into assertions and then judge the forced
version.

What to produce instead:

1. Name the specific uncertainty ("whether the share check and the
   share write can interleave").
2. Name the smallest reading that would settle it ("read
   `updateShareQuota` and the call sites that write share state
   concurrently").
3. Either do that reading, or record it as a `needs_more_evidence`
   claim with the reading as the plan.

A vague claim that gets a confident verdict is the worst possible
outcome of this skill. Saying "this is too vague to judge, here is what
to read" is a good one.

---

## 6. Checklist for a decomposition

- [ ] Every claim from the original report appears as at least one
      assertion.
- [ ] Every assertion is one of the four types, and the type matches
      how it will be tested.
- [ ] Every `defect` / `reachability` / `consequence` assertion has a
      `file:line` anchor.
- [ ] Every `precondition` assertion is either anchored to a `file:line`
      or to a named fact.
- [ ] Assertions that always stand or fall together have been merged.
- [ ] No assertion is a paraphrase of the claim rather than a testable
      restatement of it.
