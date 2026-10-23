# Ordering and Channels

> Load this when several claims are being adjudicated together and one
> must go first, or when choosing the reporting channel.

---

## 1. Order by reception likelihood, not by severity

Severity is a per-claim property. Reception is a **portfolio**
property, and the first report is where the portfolio is won.

A first report that gets accepted establishes credibility for the ones
after it. A first report that gets closed spends the project's attention
— and a maintainer who has just closed one of your reports starts the
next one already suspicious.

So the first report should be the claim whose **premise is cleanest**,
typically:

- premise `attacker_only` — the attacker alone creates the condition;
- boundary `not_declared` or `declared_and_violated` — the product does
  not already declare this behaviour;
- divergence `present` — a same-version path disagreement that can be
  checked in under a minute.

That is usually **not** the highest-severity claim. It is the one most
likely to be accepted. A medium finding that survives review buys more
than a critical one that gets argued about, because the first report
sets the tone for everything that follows.

### Ordering heuristic

1. `accept` claims with `attacker_only` + `present` divergence first, in
   ascending severity — the cleanest premise goes first, and among
   equally clean premises the lightest is the cheapest to get wrong.
2. `accept` claims with `attacker_only` but no divergence next.
3. `accept_after_rewrite` claims after those, because a rewrite means
   the report needs a restatement before it goes out, and a restatement
   should not be the first thing the maintainer sees.
4. `hardening_note` claims are not vulnerability reports at all. They
   are patches, and they do not compete for the report slot.
5. Claims whose validity is not `holds` are not in the order at all.

Record the reason for each position. The first position's reason is
the one that gets read.

---

## 2. One channel

`SECURITY.md` usually names two alternatives. Pick **one** and write
down why. Two submissions become two intakes of the same issue, which
reads as spam or a misunderstanding, and it splits the record so
neither copy gets a clean review.

Choosing between them:

- **Private advisory flow** (GitHub Security Advisories, a private
  intake form): structured, produces a stable record, and usually the
  channel the project already uses for its published advisories.
- **Email**: the alternative when anonymity is required, or for a
  project that does not use an advisory platform.

The evidence for which one a project uses is in its own advisory
history. If every published advisory came through one flow, that is the
flow.

**Never** use both. If the first channel does not work, switch — do not
duplicate.

### Credit and anonymity

Decide before submitting, because it is hard to change afterwards:

- Most projects credit the reporter by default. The advisory's credit
  field is a visible, externally-visible action.
- Anonymity is a legitimate request and most projects honour it. It is
  also a channel decision in some projects: an advisory flow identifies
  you by your account.

Settle this with the submitter before the submit action, and record the
decision in the notes.

---

## 3. What to prepare per report

One advisory file per report, from `templates/advisory.md`. Before
writing the second one, wait for an answer on the first. A batch of
reports sent at once against a project that has not yet accepted the
first one reads as volume, and the project's batching habit is not a
licence to batch your own — it is evidence of how *they* release, not an
invitation.

For a claim whose validity is `does_not_hold` or `needs_more_evidence`,
the artifact is `templates/refutation.md` instead. It is not sent to
the maintainer as a report; it is the written answer for the people who
raised the claim.

---

## 4. Re-adjudicate after a closure

A closure is the best boundary evidence you will ever get, because it
is the project stating its model in its own words.

1. **Extract the model.** Write the closure reason as a general rule.
   Real example: *"The window needs an instance started with no admin
   and no installation_code, whose setup screen was already open to
   anyone"* → the rule is *"an instance's initialization state is
   per-instance and the setup screen is public by design; a race across
   instances is a deployment concern, not a code defect."*
2. **Apply the rule to the remaining claims.** Which of them depend on
   the same model? A claim whose premise also needs the operator to
   expose or misconfigure something will likely be closed the same way.
3. **Look for the divergence under the new model.** The closure rejected
   the *cross-instance* framing. It did not necessarily reject the
   *provider-layer invariant*. Ask whether a second path in the same
   version enforces that invariant. If yes, that divergence is a
   different claim the closure did not address.
4. **Record what changed**, and say plainly which claims moved because
   of the closure.

A verdict flip with no explanation reads as inconsistency. With the
explanation it reads as the adjudication learning — which is exactly
what it is.

---

## 5. Checklist for the order and the channel

- [ ] The delivery order is recorded, with a reason per position.
- [ ] The first claim's reason explains the premise cleanliness, not
      the severity.
- [ ] Exactly one channel is named, with the reason.
- [ ] The alternative channel was considered and is recorded.
- [ ] The credit/attribution decision is recorded.
- [ ] No claim whose validity is not `holds` appears in the report
      order.
- [ ] No `hardening_note` claim appears in the report order.
