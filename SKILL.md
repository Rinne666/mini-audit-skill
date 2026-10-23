---
name: mini-adjudication
description: |
  Judge whether a reported vulnerability claim actually holds, and whether it would
  be accepted if submitted. Use when you have a vulnerability claim — from a scanner,
  a colleague, an upstream issue, a security advisory, or your own reading — and
  need to know whether it is real and whether reporting it is worthwhile. Triggers on
  "这个漏洞成立吗", "会不会被收录", "判断一下这个报告", "这个 issue 值得报吗",
  "is this a real vulnerability", "is this reportable", "should I report this",
  "validate this finding", "受理裁定", "报不报得上去".
  Does NOT perform an audit, hunt for vulnerabilities, or submit anything.
---

# mini-adjudication

Two separate questions, and conflating them is the most common way good
research gets wasted:

1. **Does the claim hold?** Is the described behaviour real, reachable, and
   does it actually cross a security boundary? A claim can be technically
   wrong, already fixed, unreachable, or a self-inflicted issue.
2. **Would it be accepted?** Even a real defect can be outside the
   maintainer's scope, and a real defect that nobody will accept is a
   wasted report.

Answering (1) with (2)'s reasoning — or skipping (1) entirely — produces
reports that are closed, and burns the reporter's credibility with the
project for the reports that follow.

This skill takes **claims**, not findings. A claim arrives from somewhere:
a scanner, a colleague, a published advisory, a bug bounty report, a
half-formed suspicion during code reading. Its origin does not make it
true. Your job is to decide, with evidence, what it is.

The adjudication state lives in **one Markdown file** that the model edits
every round (`templates/adjudication-notes.md`). The runtime validates
output structure, evidence citations, and skill freshness. None proves
the verdict is correct.

## When to load this Skill

Load when a **specific claim** needs adjudication — "is this real",
"would they accept this", "should I report this", "这个漏洞成立吗",
"会不会被收录", "这个 issue 值得报吗", "is this reportable".

Do **not** load to *find* vulnerabilities. This skill never hunts, never
scans, and never proposes new attack surface. If you do not yet have a
claim, you need an audit instead. Do not load to write the final report
prose for a claim already judged and accepted; this skill produces the
**verdict** and the **disposition**, and the report draft that follows
from it.

## Session-start check (Runtime enforcement)

Before adjudication starts, the Harness should run:

```text
python runtime/check_skill_loaded.py
```

Exit 0 means the SKILL.md / references / templates / schemas in the
current context match HEAD of this repo. Exit non-zero means the agent
is reasoning over a stale or partial skill. The script is stdlib-only
and takes milliseconds.

The check uses `runtime/skill_manifest.json`. After editing any tracked
file, run with `--refresh` to recompute hashes.

## The two verdicts

Every claim receives **two independent verdicts**, each with its own
evidence. They are not the same question and must not be collapsed.

| | Question | Outcome vocabulary |
|---|---|---|
| **Validity** | Is the claim technically true and does it cross a boundary? | `holds` / `does_not_hold` / `needs_more_evidence` / `already_fixed` |
| **Acceptability** | Would the maintainer accept it if submitted? | `accept` / `accept_after_rewrite` / `decline` |

The four combinations:

| Validity ↓ / Acceptability → | `accept` | `accept_after_rewrite` | `decline` |
|---|---|---|---|
| **`holds`** | Report it | Report it, restated | Don't report; offer it as hardening |
| **`does_not_hold`** | — | — | Doesn't apply; say so plainly |
| **`needs_more_evidence`** | — | — | Blocked; name the missing fact |
| **`already_fixed`** | — | — | Already fixed upstream; check the fix, don't re-report |

Note the empty cells. A claim that does not hold is not "unacceptable" —
it is **not a vulnerability**, and reporting it as one is worse than
staying silent. Saying "I checked and it does not hold, here is why" is
a complete and valuable result.

## The three stages

### Adjudicate

Goal: decide whether the claim holds.

**Step 1 — Restate the claim as a falsifiable assertion.**

A claim arriving from outside arrives as prose: "the setup endpoint can be
used to create a super admin". Before testing anything, split it into
the parts that can each be true or false, and write each as an
assertion with a `file:line` or a concrete fact attached.

Typical decomposition:

- **The defect** — "the setup path does not re-check the administrator
  state when the lookup fails" (`file:line`).
- **The reachability** — "an unauthenticated client can reach the setup
  path" (`file:line` or the route registration).
- **The consequence** — "the created account holds super-admin
  permissions" (`file:line`).
- **The precondition** — "this requires the lookup to be failing at that
  moment".

**A claim that cannot be decomposed into checkable parts is not ready to
adjudicate.** Say so, and state what is missing. A vague claim cannot
be refuted, and an unrefutable claim cannot be confirmed either.

**Step 2 — Test each assertion, and try to kill it.**

For each assertion, look for the thing that would make it false:

- a guard that runs before the vulnerable code and blocks it;
- a condition that makes the path unreachable;
- an earlier check that already enforces the same invariant;
- a code path that is dev-only, test-only, or behind a build tag;
- a caller that always supplies the value safely.

**Finding the refutation is the goal, not a side effect.** A claim
survives because you failed to kill it, not because you confirmed it.
Record the specific refutation attempt and its result — including
"searched for a guard with these two patterns, found none", which
requires two distinct zero-match searches, not the same command twice.

The absence is re-checked. The validator re-runs every recorded
zero-match search against the source it names, and rejects a ledger
whose "no matches" no longer reproduces. A pattern that misses for the
wrong reason — wrong directory, wrong glob, wrong case — looks exactly
like a guard that does not exist, and only the re-run tells the two
apart.

**Step 3 — Classify the validity.**

| Verdict | When |
|---|---|
| `holds` | The defect, the reachability and the consequence are confirmed, and the refutation attempts failed. An unresolved **precondition** does not stop this — it says how often the trigger fires, not whether the defect is there. |
| `does_not_hold` | A specific assertion is refuted with cited evidence. Name which one and why. |
| `needs_more_evidence` | The **defect, the reachability or the consequence** cannot be established from the source — it depends on a deployment, a configuration, or a runtime fact. Name the exact missing fact and a safe way to observe it. |
| `already_fixed` | The defect existed but the current source no longer contains it. Cite the fix. |

**A precondition and a consequence are not interchangeable.** A
`precondition` assertion says what must hold for the trigger to fire; an
unresolved one changes only how likely the trigger is, and that
uncertainty belongs to Q1 in the Assess stage, where it decides whether
the maintainer will accept the report. A `consequence` assertion says
what the defect actually causes — and if you cannot establish it, the
claim does not hold, because the report would assert a harm you cannot
show.

So "the login path is not rate limited", where the limit that would bind
comes from a deployment value, is `needs_more_evidence` until that value
is observed; with the value observed it is `holds` or `does_not_hold`.
The same claim, decomposed differently, would not decompose differently
by accident: the assertion that carries the uncertainty decides the
verdict, and choosing it is the whole job.

**`needs_more_evidence` is a real verdict, not a failure.** Do not
upgrade it to `holds` because the code "looks wrong", and do not
downgrade it to `does_not_hold` because you could not find the
refutation. Say which fact is missing and how to observe it.

**Step 4 — Check whether the claim is still live.**

Before anything else, confirm the claim applies to the current source.
Compare the claim's `file:line` against the code as it is now. Three
outcomes:

- the code is unchanged → continue;
- the code changed but the defect survives → continue, with the new
  location;
- the defect was fixed → `already_fixed`, cite the fixing commit or the
  guarding line.

Also check whether the project has already **published** this issue. A
known-and-fixed issue is `already_fixed` even if the reporter never
knew. Re-reporting a published advisory is the fastest way to lose
credibility, and it is trivially avoidable.

### Assess

Goal: decide whether the maintainer would accept it — assuming it holds.

This stage is only reached for a claim that holds. A claim that does not
hold is not "unacceptable"; it is not a vulnerability, and it never
reaches this stage.

**Read the project's acceptance policy first.** `SECURITY.md`, the
project's documentation, its published advisories and how they
classified similar issues, and the maintainer's own prior refusals all
define the boundary. A report judged against the wrong acceptance model
is worse than no report. If the project publishes no policy, derive the
model from its documentation and mark it **derived** — and say so in
the report, because you cannot cite an authority you invented.

Then answer the **three acceptance questions**, each with cited
evidence:

**Q1 — Premise: can the attacker cause the precondition alone?**

Classify the premise into exactly one of:

| Premise kind | Meaning |
|---|---|
| `attacker_only` | The attacker alone creates the condition. |
| `requires_operator_decision` | An operator must expose an uninitialized instance, disable a control, weaken a setting, or choose a risky configuration. |
| `requires_ambient_state` | Needs a race window, a specific ordering, or another system's state. |
| `requires_third_party_misconfiguration` | A configured extension misbehaves (a hook returning empty, a plugin faulting). |

The last three carry the rejection risk. **A premise that is partly
attacker-controlled and partly operator-dependent is an
operator-dependent premise** — the operator's action gates the
attacker's timeline, and the maintainer will read it that way.

The fourth kind is *not* operator weakness. Configuring a documented
extension correctly is not "choosing an insecure configuration"; an
extension answering with an empty body is a normal answer shape, and
the defect is the product failing to fail closed. Classify honestly in
both directions — inflating `attacker_only` loses the report, and
inflating `requires_operator_decision` discards a real finding.

**Q2 — Boundary: has the project declared this behaviour?**

If the project documents this exact behaviour as its design, the
behaviour sits inside the declared boundary. Record
`declared_and_violated` (a declared boundary exists and is crossed),
`declared_and_consistent` (the product declares this behaviour — not a
vulnerability), or `not_declared`.

Evidence comes from the product: `SECURITY.md`, documentation, code
comments, the commit that introduced the behaviour, and **the project's
own published advisories**. How the project classified a near-identical
issue is the strongest signal available — if a similar shape was
released under *Hardening* or *Bug fixes* rather than *Security fixes*,
the answer is already written.

**Q3 — Divergence: does the same version behave differently?**

A divergence is the strongest framing that survives review: in the same
version, one path refuses what another path allows. It is
self-evidencing — it needs no argument about intent, because intent is
whatever the two paths disagree about.

Look for the same invariant enforced on two paths, the same operation
across providers/dialects/backends/protocols, two routes to the same
state, or a check-then-write pair whose write does not re-assert the
condition. Record `present` with **both** `file:line` sides, or
`absent` — and `absent` requires two distinct captured zero-match
searches.

`absent` is not fatal, but it means the report rests on your
interpretation of intent alone, which is exactly what a maintainer
will overrule.

**Acceptability verdict.**

| Verdict | When |
|---|---|
| `accept` | Premise is `attacker_only`, boundary is not `declared_and_consistent`, divergence is `present`, and the subject is already an invariant. |
| `accept_after_rewrite` | The defect holds and would be accepted, but the subject is currently framed as a consequence. Restate it as the invariant. |
| `decline` | The premise is operator/ambient/third-party dependent with no divergence to carry it, or the boundary is `declared_and_consistent`. |

**The rewrite.** The subject is the highest-leverage edit in the whole
workflow. A subject phrased as a consequence makes the report an
argument about deployment, and deployment arguments are what maintainers
overrule. A subject phrased as an invariant makes the code the object of
the claim, and it survives even when the maintainer disagrees about
reachability.

| Weak subject (consequence) | Strong subject (invariant) |
|---|---|
| "Unauthenticated attacker can become super admin" | "The provider layer permits a second administrator to be created; there is no first-admin-only constraint" |
| "Password may be overwritten by external auth" | "An empty external-auth response rewrites the stored password instead of failing the authentication closed" |
| "Share ownership is not preserved after restore" | "Restore overwrites the live share owner and its authorization policy on the SQL providers" |

Prefer the narrowest defensible claim. A narrow claim that survives
review is worth more than a wide one that gets closed.

### Deliver

Goal: produce the artifact the verdict calls for, and nothing else.

The verdict determines the artifact. Do not produce a report for a claim
that does not hold, and do not quietly write a report because the claim
sounded serious.

| Validity | Acceptability | Artifact |
|---|---|---|
| `holds` | `accept` | A report draft, ready for the submitter to review and submit. |
| `holds` | `accept_after_rewrite` | A report draft whose subject is the rewritten invariant. |
| `holds` | `decline` | A hardening note for the maintainer — optional, and often worth sending as a patch. |
| `does_not_hold` | — | A short written finding: the refuting evidence, and what would change the verdict. No report. |
| `needs_more_evidence` | — | A list of the exact missing facts and a safe way to observe each. No report. |
| `already_fixed` | — | A note: the fix location, and whether the fix is complete or partial. No report. |

**The report draft** (`templates/advisory.md`) must contain the things
the project's own policy demands: affected component, attacker identity
(one sentence naming the trust rung and the credentials held), the
trust boundary crossed, the reproduction, the impact, and a suggested
fix. Impact evidence uses only data you created; if real user data was
reachable, say "confirmed reachable, contents not retrieved" and move
on.

**Mechanical rules that are cheap to get wrong:**

- **CVSS**: compute with the platform's own calculator. Cross-check with
  `runtime/cvss31.py`, a second implementation of the v3.1 formula — use
  it to catch a dropped metric (a forgotten `ISS` multiplication
  silently changes the score), never as the authority. **Run it on
  every vector and confirm the score it prints equals the score you
  state.** Justify each non-obvious metric choice in one clause
  (`AC:H` because …, `A:N` because …).
- **Severity vs. vector string are often mutually exclusive** in
  advisory forms. When one overwrites the other, pick one as
  authoritative and put the vector string in the body text.
- **Patched version**: only a version that exists in a release. If the
  fix is unreleased, write "unreleased on `main`, commit `<sha>`" and
  leave the field empty — never guess the next version number.
- **Affected range**: derive it from the commit that introduced the
  defect. When the introducing commit cannot be traced, state the range
  as "every build that contains this function" rather than inventing a
  boundary.
- **Never write** "as you know" or "you already know". A maintainer who
  fixed a behaviour classified it as a bug fix or hardening, and the
  phrasing closes the door.
- **Never write** "reproduced by me" in prose the submitter cannot back.
- **One channel only.** Two submissions become duplicate intake.
- **This skill never submits.** It produces drafts and checks.
  Submission, credit acceptance, and any other externally visible action
  require the submitter's explicit confirmation.

## How to use the notes file

Copy `templates/adjudication-notes.md` into the adjudication workspace,
rename it (e.g. `adjudication-{target}.md`), and edit it every round.

The notes file is the entire canonical state. A reviewer who reads it
from top to bottom should understand every claim's verdict, the
evidence behind it, and what happens next. If they cannot, the
adjudication is incomplete.

## When to load a reference

- `references/claim-decomposition.md` — when a claim arrives as prose
  and must be split into falsifiable assertions.
- `references/validity-assessment.md` — when testing assertions and
  trying to refute them; when deciding between `holds` and
  `needs_more_evidence`.
- `references/acceptance-policy.md` — when reading the project's policy,
  advisories, and prior classifications.
- `references/premise-analysis.md` — every time Q1 is answered, and
  whenever the premise classification is not obvious.
- `references/report-writing.md` — when writing a report draft, and
  before every submit.
- `references/ordering-and-channels.md` — when several claims are
  being adjudicated together and one must go first.

## When to call a sub-agent

Use a sub-agent for:

- **Independent refutation.** Give a reviewer the claim and the source,
  without the author's verdict. Ask them to kill it. A reviewer who
  finds a refutation has earned more than a reviewer who agrees —
  agreement is not evidence, and a refutation is decisive.
- **Bounded parallel searches** for a missing guard: two or three
  candidate patterns, each searched with no shared state. Require
  `file:line` for every conclusion.
- **Reading the project's advisory history** to classify a near-
  identical prior issue.

Do not use a sub-agent to "look at the code". The model reads faster
than the model can spawn a sub-agent.

## Isolation and untrusted code

This skill does not execute target code. It reasons over claims and
reads source to test them. If verifying a claim requires running target
code, use isolation the Harness explicitly provides; if none is
provided, record the verdict as `needs_more_evidence` rather than
asserting a result you did not observe.

A verdict built on a claim that was never verified against the source
is a guess wearing a `file:line` costume. Every assertion must cite a
location that was actually read.

## Stopping

Do not stop because the claim queue is empty. Before delivering:

- Every claim has a validity verdict with cited evidence, or is
  explicitly deferred with a reason.
- Every claim that reached the Assess stage has all three acceptance
  answers with cited evidence.
- Every `does_not_hold` names the specific assertion that was refuted.
- Every `needs_more_evidence` names the exact missing fact and a safe
  way to observe it.
- Every `already_fixed` cites the fix.
- Every `holds` claim has a subject stated as an invariant.
- Every absence claim cites two distinct zero-match searches, and every
  one of them still reproduces.
- The notes file carries all six coverage sections: Claims Under
  Adjudication, Claim Decomposition, Assertion Ledger, Acceptance
  Answers, Verdict Table, Refutations Considered.
- Every CVSS vector was cross-checked and matches its stated score.
- The delivery artifact matches the verdict — no report for a claim
  that does not hold.
- The work queue is closed, with a completed `final_review` task that
  challenged the `does_not_hold` and `needs_more_evidence` verdicts.

Record remaining uncertainty explicitly. A claim left unadjudicated is
not a neutral claim; it is a claim someone will later act on.

## What this Skill does not do

- It does not audit. It does not hunt, scan, map attack surface, or
  propose new findings. It adjudicates claims it is given. If you have
  no claim, you need an audit, not this skill.
- It does not submit anything. It produces drafts and checks.
- It does not provide a sandbox.
- It does not prove the maintainer will accept a report. It proves the
  adjudication is evidenced, internally consistent, and policy-aligned.
- It does not maintain a Search Ledger, an Attack Graph, or a Coverage
  Ledger.

### Hard Gate: Deliver cannot be skipped

Delivery requires the adjudication notes file to contain a claim table
with both verdicts, an assertion ledger with per-assertion evidence, a
closed work queue with a completed `final_review` task, and a channel
decision.

Every claim needs at least one **assertion** row, and every assertion
needs a verdict from a closed vocabulary. A claim with no assertions
is an unadjudicated claim.

The validity verdict must follow from the assertions mechanically:

- any assertion refuted → `does_not_hold`;
- any assertion fixed → `already_fixed`;
- an unresolved defect, reachability or consequence → `needs_more_evidence`;
- otherwise → `holds`, and an unresolved **precondition** does not block
  it.

The acceptability verdict must follow from the three answers:

- premise `attacker_only` + boundary not `declared_and_consistent` +
  divergence `present` → `accept` or `accept_after_rewrite`;
- premise operator/ambient/third-party dependent with no divergence, or
  boundary `declared_and_consistent` → `decline`.

Every claim that is `accept` or `accept_after_rewrite` must cite a
captured source read, and its subject must be phrased as an invariant
rather than a consequence.

Capture source searches and bounded reads with `runtime/evidence_log.py`
and cite their IDs. Treat uncaptured tool output as exploratory unless
the notes preserve a reviewable artifact. Before delivery, run:

```text
python runtime/validate_adjudication.py path/to/adjudication-notes.md \
    --evidence-ledger path/to/evidence.jsonl
```

The validator checks cited IDs and hashes, captured reads for asserted
claims, two distinct zero-match searches for any `absent` divergence and
for any unresolved assertion that rests on search evidence alone, the
reproduction of every recorded zero-match search, the mechanical
validity and acceptability derivations, the invariant subject, all six
coverage sections, and work-queue closure. Exit 0 means the structure is
sound; it does not certify that the verdict is correct. The reviewer
still challenges every verdict.

For end-to-end verification across sessions, `runtime/regression.py`
runs the derivation tests, the counter-example tests,
validate-adjudication and check-skill-loaded against every fixture in
`fixtures/`. A regression failure means the framework's expected output
has drifted.

`runtime/test_adjudication_counterexamples.py` is the half that matters
most: it takes the correct fixture, breaks it ten ways — an absence that
does not reproduce, a verdict asserted instead of derived, a
non-vulnerability dressed up as an unacceptable one, a subject written as
a consequence, the same search counted twice — and asserts that each
broken version is rejected. A validator that only ever sees valid input
proves nothing.

This Hard Gate exists because the failure it prevents is the common
one: a claim that sounded serious, was never refuted, and was reported
as a vulnerability when it was not one — or was one that the maintainer
had already classified as hardening and closed.
