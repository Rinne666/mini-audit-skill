# Premise Analysis — Acceptance Question 1

> Load this every time the premise classification is not obvious, and
> whenever Q1 is being answered for a claim whose validity is `holds`.
>
> This is the **acceptance** stage's first question, not the validity
> stage. A claim that does not hold never reaches it. The premise
> answers "who creates the gating condition" — a question about the
> maintainer's review, not about whether the code is wrong.

The upstream rejection is almost always some form of *"the window
requires an operator to have done X"*. So the useful cut is not "is it
exploitable" but **"who creates the gating condition?"**

A premise that is misclassified in either direction loses. Inflating
`attacker_only` gets the report closed for a deployment reason.
Inflating `requires_operator_decision` throws away a real finding and
spends credibility for nothing.

---

## 1. The four kinds

### `attacker_only`

The attacker, acting alone, creates every precondition. The system is
in its documented default or normally-configured state, and the
attacker's request alone moves it into the vulnerable state.

**Test**: remove the operator from the timeline entirely. Does the
vulnerability still reproduce? If yes, it is `attacker_only`.

### `requires_operator_decision`

An operator must take an action that is *unusual, risky, or contrary to
guidance* before the attacker can proceed:

- exposing a not-yet-initialized instance on a reachable interface;
- leaving a protection mechanism empty or unset that the product ships
  a way to set;
- choosing a weak value the documentation steers away from;
- choosing an unsupported or third-party component.

The distinguishing feature: a competent operator following the
documentation would not be in this state. That is exactly why upstream
calls it a deployment issue — the code behaved as designed for the
configuration the operator chose.

### `requires_ambient_state`

Needs a race window, a specific interleaving, another instance's state,
or a concurrent operation. Often the audit's `timing_dependency` or
`data_state` condition.

Two sub-cases differ sharply:

- **The window is attacker-controlled** (they can retry, spam, or hold
  it open) → closer to `attacker_only`.
- **The window is probabilistic and the attacker just retries** → the
  outcome is reliably reachable but the *moment* is not
  attacker-controlled. The defect is real (a nondeterministic
  authorization result is a real defect), but the report must lead
  with "the same request returns different authorization results",
  not with the consequence.

### `requires_third_party_misconfiguration`

An operator-configured extension misbehaves: an auth hook returns an
empty body, a plugin faults, a downstream endpoint misbehaves.

**This is the subtle one, and it is not operator weakness.**
Configuring a documented auth hook correctly is not "choosing an
insecure configuration". An extension answering with an empty body is
a normal answer shape, and the product's job is to treat that as an
authentication failure — not as "the user has no password, let me set
one".

The defect is in the product's handling of the extension's output, and
the product controls that handling. So this is closer to `attacker_only`
than the name suggests.

**But the attack's shape still needs care.** If the trigger is "the hook
is broken", the attacker is exploiting an outage rather than the
operator's configuration. Lead with the product's failure to fail
closed, and state the premise as "a configured extension answered
empty" — factual, and not an accusation against the operator.

---

## 2. Mixed premises resolve to the operator-dependent kind

If the attacker's action requires an operator decision to have happened
first, the operator's decision gates the timeline. Do not split the
difference and label it half-clean.

A real example: a bootstrap check fails open when the admin-state
query errors. The proof was exact, the reproduction worked, and the
code was wrong. But the window required an instance that was started
with no administrator and no installation code, exposed to an untrusted
network. The maintainer closed it: *"The window needs an instance
started with no admin and no installation_code, whose setup screen was
already open to anyone."*

The premise was `requires_operator_decision`, and it should have been
recorded as such before the report was written. Splitting it — "well,
the timing part is attacker-influenced" — would not have helped; the
maintainer read the operator's exposure as the boundary.

---

## 3. Classify with evidence, not with intuition

The premise kind is a claim about the code and the deployment, so it
needs a citation like any other claim:

- **The operator's action**: the config field, the startup path, the
  code that leaves the state reachable. `file:line`.
- **The attacker's action**: the request that reaches the vulnerable
  state. `file:line`.
- **The gate**: the specific point where the operator's action is
  required before the attacker's request can proceed.

When the gate cannot be located in the source, the premise is
**`NEEDS-RUNTIME`**, not a guess. An acceptability verdict needs a
classified premise, so an unresolved premise blocks the report — it
does not make the claim untrue, and it is not the validity verdict's
business.

---

## 4. What to do when the premise is operator-dependent

A claim with an operator-dependent premise is not automatically
unreportable. It is automatically **not reportable in that framing**.
Three ways forward:

1. **Find a divergence.** If another path in the same version refuses
   what this path allows, the divergence is the subject, and the
   operator-dependent part becomes a stated precondition rather than the
   whole claim. This is the strongest move.
2. **Find the operator-independent residue.** A related invariant that
   holds regardless of deployment — "the provider layer permits a second
   administrator to be created" — is a different subject with a
   different premise.
3. **Convert it to hardening.** If neither exists, the defect is still
   real and worth offering, but as a patch or a hardening note, not as a
   vulnerability report. Spending the report on it costs credibility
   that the next report needs.

Note the mapping to the acceptability verdict: a clean premise with a
divergence is `accept`; a clean premise without one is
`accept_after_rewrite`; a third-party premise with a divergence is
`accept_after_rewrite`; everything else is `decline`. The
`requires_third_party_misconfiguration` kind lands in
`accept_after_rewrite` rather than `decline` because configuring a
documented extension correctly is not an operator weakening — the
product's own handling of the extension's output is what is broken.

---

## 5. Checklist for a premise entry

- [ ] The operator's action is cited (`file:line`), or the premise is
      `attacker_only` because there is no operator action at all.
- [ ] The attacker's action is cited (`file:line`).
- [ ] The gate — where the operator's action becomes required — is
      identified.
- [ ] The premise kind matches the evidence, in both directions.
- [ ] A configured-but-correct third-party extension is **not** counted
      as operator weakening.
- [ ] A premise that cannot be located in source is `NEEDS-RUNTIME`,
      and its finding is not `send`.
- [ ] The residual premise is stated in the report, not hidden.
