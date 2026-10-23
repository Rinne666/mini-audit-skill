# Validity Assessment

> Load this when testing assertions and trying to refute them, and when
> deciding between `holds` and `needs_more_evidence`.

The goal of this stage is to **kill the claim**. A claim survives because
you failed to kill it, not because you confirmed it. Every verdict of
`holds` is a verdict of "I tried the obvious refutations and they did
not work" — which is a weaker statement than it looks, and the record
must show the attempts.

---

## 1. The asymmetry of confirming and refuting

Refutation is cheap and decisive. Confirmation is expensive and
inconclusive. A single guard in front of the vulnerable code ends the
investigation; a hundred lines of code that look right prove nothing
about the path you did not read.

So:

- **Refute with one piece of evidence.** One guard, one unreachable
  branch, one earlier check.
- **Confirm by exhaustion.** Read the whole path, and record the
  refutation attempts that failed.

An assertion with no refutation attempt recorded is **`unresolved`**,
not `confirmed`. This distinction is enforced by the validator, and it
is the single most important habit in this stage.

---

## 2. The refutation catalogue

Work through these systematically. Each is a specific thing that would
make a claim false.

### A guard runs before the vulnerable code

The most common refutation. Look for a check between the entry point and
the defect that enforces the same invariant the claim says is missing.

```
claim:  "the setup path does not check whether an admin exists"
read:   internal/httpd/server.go:686  ->  internal/httpd/server.go:696
result: server.go:696 calls HasAdmin() before rendering the setup page
```

Note what a "guard" is **not**: a comment saying the value is trusted, a
log line, a config flag that defaults to off, or a check in a
*different* function that this call path does not go through. A guard
is a comparison or predicate that runs on this path, with the
attacker-controlled value, and whose result is what decides the
outcome.

Record the **exact expression**, the **attacker-controlled shape**, and
the **evaluated result**. "Standard check exists" is not a finding; it
is a way of not looking.

### The path is unreachable from the claimed identity

The claim says "unauthenticated" or "any user". Check the route
registration and the authentication middleware. Also check:

- the function is only called from tests;
- the caller always passes a sanitized value;
- the branch is behind a build tag or a dev-only flag;
- the entry point is registered but shadowed by a more specific route.

### The defect is already fixed in the current source

The claim may describe an older revision. Compare the cited
`file:line` against the code as it is now.

- Unchanged → continue.
- Changed, defect survives → continue with the new location.
- Fixed → `already_fixed`, cite the fix.

**Check the published advisories too.** If the project already shipped
this issue, the claim is `already_fixed` even though the reporter never
knew. Re-reporting a published advisory is the fastest way to lose
credibility with a maintainer, and it costs one page of reading to
avoid.

### The effect is self-inflicted or same-principal

An actor who can only affect their own resources has not crossed a
boundary. This refutes the **consequence** assertion, not the defect:
the code may still be wrong, but it is not a security issue.

Watch for the near-miss: "a user can overwrite their own session" is
self-inflicted; "a user can overwrite *another user's* session" is not.

### The claimed impact is bounded

The sink may sanitize, truncate, or confine the value. Read the sink,
not the narrative around it.

### The value never reaches the sink

The claim may assert data flow that the code does not have. Trace it.

---

## 3. Proving absence

Some refutations are claims about what is **not** in the code: "there is
no guard here". Absence is a claim, and it needs evidence.

The standard is **two distinct captured zero-match searches** — two
different patterns, not the same command twice. A single empty grep
supports "I did not find it with this pattern", not "it does not
exist".

Use `runtime/evidence_log.py` so the searches are captured with their
exit code and output size:

```text
python runtime/evidence_log.py search \
  --ledger adjudication/evidence.jsonl --artifact-dir adjudication/evidence \
  --pattern 'requireAdmin|assertAdmin|isAdmin' --glob '*.go' internal/httpd/
```

Two different patterns over the same surface, both empty, is a
defensible absence claim. Record both evidence IDs in the assertion's
`absence_searches`.

**When a grep returns empty, suspect the pattern before concluding
absence.** Wrong glob, wrong directory, wrong case, or a different
naming convention in the codebase all produce empty results that look
exactly like "the guard does not exist".

**The absence is re-verified before delivery.** The validator re-runs
every recorded zero-match search against the source it names, and
rejects a ledger entry whose "no matches" no longer reproduces. This is
not paranoia: a ledger that merely asserts an absence is worth exactly
as much as the assertion, which is to say nothing. The re-run is what
distinguishes "the guard does not exist" from "the pattern does not
match".

---

## 4. `needs_more_evidence` is a real verdict

Some assertions cannot be settled from source. The fact lives in a
deployment, a configuration, a runtime, or a third party.

Typical cases:

- "the admin lookup was failing at that moment" — needs a runtime fact.
- "the reverse proxy forwards the request without rewriting the host
  header" — needs the proxy config.
- "the extension returns an empty body" — needs the extension's
  behaviour.
- "the token is still valid because revocation is not implemented" —
  needs the token issuer's policy.

**Which assertion carries the uncertainty decides the verdict.** The
validity verdict is derived from the assertion verdicts, not chosen:

| Assertion verdicts | Validity |
|---|---|
| any refuted | `does_not_hold` |
| any fixed | `already_fixed` |
| an unresolved defect, reachability or consequence | `needs_more_evidence` |
| otherwise | `holds` |

An unresolved **precondition** is the one that does not block. It says
how often the trigger fires, not whether the defect is there — a product
mis-handles an empty answer shape whether or not the extension produces
it every day. That uncertainty belongs to Q1 in the Assess stage, where
it decides whether the maintainer will accept the report.

An unresolved **consequence** does block. The consequence is what the
report would assert about harm; if it cannot be established, the claim
does not hold *yet*. "The login path is not rate limited", where the
limit that would bind is a deployment value, stays `needs_more_evidence`
until that value is observed — and then becomes `holds` or
`does_not_hold`.

So when a claim turns out to depend on something outside the source,
decompose it so the dependency lands on the assertion that deserves it.
Moving an uncertainty from the consequence to the precondition changes
the verdict. That is the decision, and it has to be made on purpose.

For these, the verdict is `needs_more_evidence`, and the record must
name:

1. **The exact fact** that is missing — not "more testing needed", but
   "whether the database was unreachable during the request window".
2. **A safe way to observe it** — an owner-observed check, a
   configuration inspection, a bounded local fixture. Never "send
   traffic to the deployment".
3. **Who can observe it** — the operator, the maintainer, or a local
   reproduction.

Do not upgrade `needs_more_evidence` to `holds` because the code
"looks wrong", and do not downgrade it to `does_not_hold` because you
could not find the refutation. Both are the same mistake in opposite
directions: substituting a feeling for a fact.

---

## 5. Recording the attempts

The Assertion Ledger needs, for every assertion:

- the **verdict** (`confirmed` / `refuted` / `unresolved` / `fixed`),
- the **refutation attempted** — the specific thing you looked for,
- the **result** of that attempt,
- the **evidence IDs**.

And the notes file keeps a separate section for refutation attempts
that **looked promising but did not hold up**. Without it, a reader
cannot tell the difference between a claim that was carefully killed
and one that was never really tested.

Example entry:

> *Searched for a second administrator check on the setup path* — two
> patterns over `internal/httpd/`, both zero-match (E000010, E000011).
> The absence is real for this surface; the setup path has no other
> administrator check.

That is checkable. "Looked for guards, didn't find any" is not.

---

## 6. Checklist for a validity verdict

- [ ] Every assertion has a verdict, a refutation attempt, and evidence.
- [ ] Every `confirmed` assertion cites a captured source read, not
      only a search.
- [ ] Every `refuted` assertion names the specific guard, unreachable
      branch, or earlier check that defeats it.
- [ ] Every absence claim cites two distinct zero-match searches, and
      every one of them still reproduces.
- [ ] Every unresolved assertion that rests on search evidence alone
      shows its absence explicitly.
- [ ] The claim was compared against the current source, and against
      the project's published advisories.
- [ ] The validity verdict follows from the assertion verdicts
      mechanically, not from an overall impression.
- [ ] An unresolved precondition was carried to Q1 rather than used to
      block the validity; an unresolved consequence was not waved
      through.
- [ ] If the verdict is `needs_more_evidence`, the missing fact, a safe
      way to observe it, and who can observe it are all named.
- [ ] If the verdict is `already_fixed`, the fix is cited and its
      completeness is assessed.
