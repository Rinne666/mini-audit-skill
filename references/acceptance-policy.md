# Acceptance Policy — reading what the maintainer will accept

> Load this when reading the upstream's policy, published advisories, or
> prior classifications, and when deciding what the project's trust model
> and boundaries are.

The disposition of every finding is judged against **the maintainer's
acceptance policy**, not against the quality of the evidence. A perfect
proof of a defect the maintainer considers out of scope is a closed
report.

---

## 1. Find the policy

In order of authority:

1. **`SECURITY.md`** in the target repository — the explicit scope.
2. **Published advisories** — the empirical record of what was accepted.
3. **Release notes** — the classification of each fix.
4. **Documentation** — the stated trust model.
5. **A previous closure of yours** — the model in the maintainer's own
   words, which outranks all of the above.

If none exists, the trust ladder is **derived**. Mark it derived in the
notes and state the assumed model in the report, so the maintainer can
correct it instead of dismissing the whole thing. A report that cites
an authority nobody published is worse than one that says "assuming X,
this is a violation because Y".

---

## 2. Read the scope, not just the exclusions

A scope document usually has the same shape. These parts decide the
outcome:

- **The trust model.** The roles and what each may reach. A finding that
  stays inside one role's reach is out of scope, however damaging it is
  to that role's own data.
- **The in-scope categories.** Usually the vulnerability classes the
  project will number.
- **The exclusions.** Read for the *default state* rule specifically:
  most projects exclude issues that require the researcher to put the
  target into a non-default state. Note the exceptions — shipped
  defaults, and **all officially supported deployment forms** — because
  a supported configuration is "default" for acceptance purposes.
- **The gray-zone rules.** These decide the hard cases, and they are
  usually where a report is won or lost.
- **The channel.** Which one, and whether anonymity changes the
  channel. Never use two.

### The default-state rule, precisely

A **default** state (in scope) includes:

- shipped defaults, default parameters, default credentials;
- **all officially supported databases, storage backends, protocol
  versions, and deployment shapes** the vendor documents;
- a fresh install with no changes;
- every role the product is designed to have.

A **non-default** state (possibly excluded) includes:

- debug, eval, or experimental switches the researcher had to enable;
- security-relevant settings rewritten to a weak value;
- unsupported or third-party components the researcher introduced;
- abnormal input combinations the product's normal flow never produces.

The distinction that matters most: **is the deployment the one the
vendor recommends?** A documented PostgreSQL deployment is a default
deployment. A hand-modified configuration file is not.

---

## 3. Read the advisory history as evidence

The project's published advisories are the strongest available signal,
because they show where the project's own boundary lies.

### The classification signal

| How it was released | What it means for a similar report |
|---|---|
| **Security fix** | The project treats that shape as a vulnerability. A near-identical shape will be accepted. |
| **Bug fix** | The project treats that shape as a functional defect, not a boundary violation. Reporting the same shape gets the same answer. |
| **Hardening** | The project acknowledges the weakness and declines to call it a vulnerability. The answer is already written. |

So before writing a report, search the advisory history for the
**shape** you are about to report: same component, same kind of
precondition, same consequence family. Find how it was classified
there. If it was hardening, you are writing a report whose answer
already exists — change the subject, or do not send it.

### What to extract from each advisory

- The severity the project used, and against which vector.
- Whether the affected range was a single release or a range.
- Whether the project credited the reporter, and how.
- The **shape**: the premise, the boundary crossed, the consequence.
- Whether the fix was complete or partial. A partial fix is a
  legitimate subject — but the subject is the *residual*, and you must
  show the residual is still reachable, not merely that the old text
  is gone.

---

## 4. The channel

Most projects name two alternatives. Pick **one**, and write down why.

- If a private advisory flow exists (GitHub Security Advisories, a
  private intake form), it is usually the better channel: it is
  structured, it produces a stable record, and it is the channel the
  project already uses for its published advisories. Evidence: if every
  published advisory came through that flow, that is the flow.
- Email is usually the alternative for anonymity, or for a project
  that does not use an advisory platform.

**Never use both.** Two submissions become two intakes of the same
issue, which reads as either spam or a misunderstanding, and it splits
the record so neither copy gets a clean review.

Check the channel before writing:

- Does it require a specific subject line, format, or PGP key?
- Does it forbid attachments?
- Does it ask for a disclosure timeline?
- Does it ask whether the issue is already public?

---

## 5. A worked reading

A real project (SFTPGo) ships `SECURITY.md` that offers two channels
without expressing a preference. The published record settles it: every
advisory in the project's history is a GitHub Security Advisory
published by the maintainer's own account, and the advisory page
carries a "Report a vulnerability" button pointing at the private
reporting flow. Email has never been used.

Conclusion: the private advisory flow is the channel, because it is the
one the project demonstrably uses. The only reason to choose email
would be a need for anonymity — and then switch channels entirely rather
than sending to both.

Two further facts from the same reading changed what to expect from the
outcome: the project publishes no CVE IDs, so do not expect one; and it
releases advisories in batches, so submitting several reports over time
fits its rhythm rather than looking like volume.
