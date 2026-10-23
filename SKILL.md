# mini-disclosure

A prompt-led Skill for **preparing** an audit's findings for disclosure.
The model reasons; the Harness executes; this Skill is the playbook the
model follows.

It runs **after** the audit. The audit already produced a set of
confirmed findings; this Skill decides **which ones to report, how to
frame them, and on which channel** — before any report text is written.

The triage state lives in **one Markdown file** that the model edits
every round (`templates/triage-notes.md`). The runtime checks validate
output structure and skill freshness. None proves semantic correctness.

> **Why this Skill exists.** A confirmed vulnerability and an
> *acceptable report* are different things. The gap between them is
> where reports die: the maintainer reads the premise, finds it
> requires the operator to have made an unusual decision, and closes
> the report as a deployment concern — even when the code evidence
> was perfect. That classification cannot be undone, and the first
> report sets the credibility for everything after it.

## When to load this Skill

Load when an audit has produced findings and the next task is **reporting
them** — "which of these should we report", "write a vulnerability
report", "prepare this for upstream", "the maintainer closed our
report, what now", "triage these findings", "受理裁定", "这些发现该报
哪条", "写一份漏洞报告", "准备提交给上游".

Do **not** load to *find* vulnerabilities (use the audit skill), to
submit a Chinese SRC report against 大厂/中小/政府 targets (use `6kskill`),
or to write generic hardening advice with no intent to report.

**Load this Skill after the audit, not during it.** If the audit is still
running, this Skill has nothing to triage. It consumes the audit's
output; it does not replace or extend it.

## Session-start check (Runtime enforcement)

Before triage starts, the Harness should run:

```text
python runtime/check_skill_loaded.py
```

Exit 0 means the SKILL.md / references / templates / schemas
in the current context match HEAD of this repo. Exit non-zero
means the agent is reasoning over a stale or partial skill.
The script is stdlib-only and takes milliseconds.

The check uses `runtime/skill_manifest.json`. After editing
any tracked file, run with `--refresh` to recompute hashes.
The list of tracked files is in `runtime/skill_manifest.json`.

## The four things this Skill teaches

1. **How to frame a finding for a maintainer.** A report is judged
   against the maintainer's acceptance policy, not against its own
   evidence quality.
2. **The three-stage loop.** Triage → Frame → Deliver. The model moves
   between stages freely, but Deliver requires a closed triage ledger.
3. **How to decide a finding is reportable.** Three questions —
   premise, declared boundary, behavioural divergence — and what
   happens when each one fails.
4. **What makes a report survive review.** The subject must be an
   invariant the code fails to enforce, not a consequence the attacker
   obtains. Consequence subjects invite deployment arguments; invariant
   subjects make the code the object of the claim.

## The triage loop

```text
Know what the maintainer will accept.
Decide which findings clear that bar.
State each claim as an invariant.
Write only what survives.
```

That sentence is the entire loop. Every other piece of this Skill
serves it.

## The three stages

The stages are cognitive, not gates. The model jumps between them as
the evidence demands — `Triage → Frame → Triage` is a normal cycle.
The notes file does not enforce order; the reviewer enforces discipline
by reading.

### Triage

Goal: one disposition per confirmed finding, and a send order.

Read the upstream's own acceptance policy first. `SECURITY.md`, the
project's documentation, its published advisories, and the maintainer's
own prior classifications define what counts. If the project publishes
no policy, derive the trust ladder from the audit's architecture notes
and mark it **derived, not stated** — you cannot cite an authority you
invented, and the report must say which model it assumes.

Then apply the **three questions** to every confirmed finding. A
finding fails if any question fails. Each question is answered with
`file:line` evidence, not with a judgement.

**Question 1 — Premise: can the attacker cause the precondition alone?**

If the attacker is the only motivated party, can they reach the
vulnerable state without the operator doing anything unusual? Classify
the premise into exactly one of:

| Premise kind | Meaning |
|---|---|
| `attacker_only` | The attacker alone creates the condition. |
| `requires_operator_decision` | An operator must expose an uninitialized instance, disable a control, weaken a setting, or choose a risky configuration. |
| `requires_ambient_state` | Needs a race window, a specific ordering, or another system's state. |
| `requires_third_party_misconfiguration` | A configured extension misbehaves (a hook returning empty, a plugin faulting). |

The last three are the rejection risk. **A premise that is partly
attacker-controlled and partly operator-dependent is an
operator-dependent premise** — the operator's action gates the
attacker's timeline, and the maintainer will read it that way.

Note the fourth kind is *not* the same as operator weakness. Configuring
a documented auth hook correctly is not a risky decision; an extension
answering with an empty body is a normal answer shape, and the defect
is the product failing to fail closed. Classify the premise honestly
in both directions — inflating `attacker_only` loses the report, and
inflating `requires_operator_decision` throws away a real finding.

**Question 2 — Boundary: has the product declared this behaviour?**

If the product documents this exact behaviour as its design, the
behaviour sits inside the declared boundary and re-reporting it as a
vulnerability loses the report. Record `declared_and_violated` (a
declared boundary exists and is crossed), `declared_and_consistent`
(the product declares this behaviour — not a vulnerability report), or
`not_declared`.

Evidence comes from the product, not from the model: `SECURITY.md`,
documentation, code comments, the commit message that introduced the
behaviour, and **the project's own published advisories**. How the
project classified a near-identical issue is the strongest signal
available — if a similar shape was released under *Hardening* or
*Bug fixes* rather than *Security fixes*, the answer is already written.

**Question 3 — Divergence: does the same version behave differently?**

A divergence is the strongest framing that survives review: in the same
version, one path refuses what another path allows. It is
self-evidencing — it needs no argument about intent, because intent is
whatever the two paths disagree about.

Look for the same invariant enforced on two paths, the same operation
across providers/dialects/backends/protocols, two routes to the same
state, or a check-then-write pair whose write does not re-assert the
condition. Record `present` with **both** `file:line` sides, or
`absent`.

`absent` is not fatal, but it means the report rests on the model's
interpretation of intent alone — which is exactly what a maintainer
will overrule. It is the main reason to prefer `rewrite_then_send`.

**Disposition.** Exactly one per finding:

| Disposition | When |
|---|---|
| `send` | Premise is `attacker_only`, boundary is not `declared_and_consistent`, divergence is `present`, and a clean framing exists. |
| `rewrite_then_send` | The defect is real but the current framing loses. Restate the subject as the invariant, then send. |
| `convert_to_hardening` | The premise is operator-, ambient- or third-party dependent **and** no divergence can carry it. Offer it as a patch, not a report. |

**Send order.** Order by *reception likelihood*, not by severity. The
first report establishes credibility for the ones after it; a first
report that gets closed spends the project's attention. The first
report should therefore be the record with the cleanest premise —
typically `attacker_only` with `present` divergence — even when
another record has a higher severity. Severity is a per-record
property; reception is a portfolio property, and the first report is
where the portfolio is won.

**Prior submissions are evidence.** A closed report is not a finding to
re-send; it is the project's boundary model stated in its own words.
Extract the model from the closure, apply it to the remaining records,
and re-run the three questions. A closure that moves a record's
disposition must be recorded as such, with the reason.

### Frame

Goal: restate each surviving finding as an invariant the code fails to
enforce.

This is where most reports are lost. A finding whose subject is a
**consequence** ("the setup endpoint can create a super admin") makes
the report an argument about deployment, and deployment arguments are
what maintainers overrule. A finding whose subject is an **invariant**
("the provider layer permits a second administrator to be created;
there is no first-admin-only constraint") makes the code the object of
the claim, and that survives even when the maintainer disagrees about
reachability.

Rewrite rules:

- Lead the title with the invariant, not the consequence.
- Put the operator-independent part of the claim in the title if any
  exists.
- Strip every premise that depends on an operator decision, and state
  the residual premise explicitly and honestly.
- Prefer the narrowest defensible claim over the widest one. A narrow
  claim that survives review is worth more than a wide one that gets
  closed.
- Never write "you already know about this" or "as you know". A
  maintainer who fixed a behaviour labelled it a bug fix or hardening,
  not a vulnerability, and the phrasing closes the door.
- Never claim "reproduced by me" in prose the submitter cannot back.
- Never assert a version range that was not verified. When the
  introducing commit cannot be traced, state the range as "every build
  that contains this function" rather than inventing a boundary — an
  unverified range invites the maintainer to find a boundary you did
  not intend, and they will then stop reading the rest.
- A `present` divergence is the paragraph that carries the report.
  State both sides symmetrically with line numbers: "path A refuses
  when `<condition>` holds (`file:line`); path B performs the
  operation under the same condition (`file:line`)". That is
  checkable in under a minute and cannot be dismissed by an argument
  about intent.

**Score the first report against the conditions that actually hold**,
not the theoretical ceiling. If the attack needs a configured
extension to answer in a particular shape, that is `AC:H`; if a
service can be degraded but an administrator can restore it, that is
`A:N`. A first report that claims the maximum severity and then
explains why the maximum does not apply reads as an inflated number,
and the maintainer has to reconcile that before reading anything else.

### Deliver

Goal: one `templates/advisory.md` per reportable finding, plus the
pre-send checks.

The advisory must contain the things the project's own policy demands:
affected component, attacker identity (one sentence naming the trust
rung and the credentials held), the trust boundary crossed, the
reproduction, the impact, and a suggested fix. Impact evidence uses
only data the researcher created; if real user data was reachable, say
"confirmed reachable, contents not retrieved" and move on.

Mechanical rules that are cheap to get wrong:

- **CVSS**: compute with the platform's own calculator. Cross-check
  with `runtime/cvss31.py`, which is a second implementation of the
  v3.1 formula — use it to catch a dropped metric (a forgotten `ISS`
  multiplication silently changes the score), never as the authority.
  **Run it on every vector and confirm the score it prints equals the
  score stated in the report.** A vector and its score drifting apart
  is the most common defect in a submitted report. Justify each
  non-obvious metric choice in one clause (`AC:H` because …, `A:N`
  because …): the maintainer will check the reasoning, not just the
  number.
- **Severity vs. vector string are often mutually exclusive** in
  advisory forms. When one overwrites the other, pick one as
  authoritative and put the vector string in the body text.
- **Patched version**: only a version that exists in a release. If the
  fix is unreleased, write "unreleased on `main`, commit `<sha>`" in
  the body and leave the field empty — never guess the next version
  number.
- **One channel only.** `SECURITY.md` usually names two alternatives;
  pick one and note why. Two channels mean duplicate intake, and it
  reads as spam.
- **AI-assistance disclosure**: answer truthfully; do not leave a
  checkbox in a state that cannot be supported.
- **This Skill never submits.** It produces drafts and pre-send checks.
  Submission, credit acceptance, and any other externally visible
  action require the user's explicit confirmation.

## How to use the notes file

Copy `templates/triage-notes.md` into the triage workspace, rename it
(e.g. `triage-{target}.md`), and edit it every round.

The notes file is the entire canonical state of this triage. A reviewer
who reads it from top to bottom should understand the whole decision —
which findings are reportable, why, in what order, and on what channel.
If they cannot, the triage is incomplete.

## When to load a reference

Load them only when the model is about to do work the reference
actually helps with.

- `references/acceptance-policy.md` — when reading the upstream's
  policy, published advisories, or prior classifications, and when
  deciding what the project's trust model and boundaries are.
- `references/premise-analysis.md` — every time Question 1 is being
  answered, and whenever the premise classification is not obvious.
- `references/report-writing.md` — when writing the advisory body, and
  before every submit.
- `references/ordering-and-channels.md` — when choosing the send order
  and the channel, and when a prior report was closed.

## When to call a sub-agent

Use a sub-agent for:

- **Independent review of a disposition.** Give the reviewer the
  finding, the three answers, and the relevant code — without the
  author's conclusion. For a downgrade review, provide the original
  hypothesis but withhold the downgrade rationale until the reviewer
  has formed a view. Agreement does not promote a finding; it only
  shows the disposition is not obviously wrong.
- **Bounded parallel searches** for a divergence: two or three
  candidate paths to compare, each searched with no shared state from
  the main triage. Require output to include the searched surface and
  `file:line` for every conclusion.
- **Reading the project's advisory history** to classify a near-
  identical prior issue.

Do not use a sub-agent to "look at the code". The model reads faster
than the model can spawn a sub-agent.

## Isolation and untrusted code

This Skill does not execute target code. It reasons over an audit's
existing findings and reads source to verify claims. If verifying a
claim requires running target code, use isolation the Harness
explicitly provides; if none is provided, state the claim as
`NEEDS-RUNTIME` rather than asserting it.

A disposition built on a claim that was never verified against the
source is a guess wearing a `file:line` costume. Every premise,
boundary, and divergence answer must cite a location that was actually
read.

## Stopping the triage

Do not stop because the remaining records look unimportant. Before
Deliver, close this checklist:

- Every confirmed finding has exactly one disposition, and every
  disposition has the three question-answers with cited evidence.
- The trust ladder is recorded, and marked as *stated* by the project
  or *derived* by the triage.
- The channel is recorded, with the reason that channel was chosen.
- The send order is recorded, with the reason the first record is first.
- Every finding whose disposition changed because of a prior closure
  says so explicitly, and names the closure.
- Every `send` and `rewrite_then_send` finding has a subject stated
  as an invariant, and the rewrite is recorded where it happened.
- Every CVSS vector was cross-checked and matches its stated score.
- Every version range is either verified or explicitly marked
  unverified.
- Every claim that would become a universal negative ("no X in Y",
  "X is safe") carries the list of guards that were not independently
  verified. Such a sentence, written while any guard is unverified, is
  itself a false negative.

After this checklist closes, stop when no remaining record's
disposition would change with more evidence. Record remaining
uncertainty as `NEEDS-RUNTIME` or an explicit limitation rather than
silently calling the remaining findings unreportable. A triage that
ends with zero reports is a complete triage, not a failed one.

## What this Skill does not do

- It does not perform the audit. It consumes the audit's findings and
  does not verify them from scratch; where a disposition depends on a
  claim the audit never verified, that claim is `NEEDS-RUNTIME`.
- It does not submit anything. It produces drafts and checks.
- It does not provide a sandbox.
- It does not own workflow state in a database. The notes file is the
  canonical triage state.
- It does not prove the maintainer will accept a report. It proves the
  triage is internally consistent, evidenced, and policy-aligned.
- It does not maintain a Search Ledger, an Attack Graph, or a
  Coverage Ledger. Those were the v2.x audit design.

### Hard Gate: Deliver stage cannot be skipped

Deliver cannot start until the triage notes file contains a triage
table, a class-coverage ledger with all three questions marked for
every finding, a closed work queue with a completed `final_review`
task, and a Premise Ledger. Every triage row connects a **finding**
with a **disposition** and the three answers that produced it.

Three questions are mandatory for every confirmed finding. Record each
in `question_coverage` as `HUNTED` or `NEEDS-RUNTIME`; a finding whose
premise cannot be classified is `NEEDS-RUNTIME` and cannot be
`send`.

Each non-hardening row is `send`, `rewrite_then_send`, or
`convert_to_hardening`. `convert_to_hardening` requires a cited reason
and a suggested change. "The maintainer might not like it" is not a
permitted reason; the premise kind, the boundary state, and the
divergence state are.

Every claim used by a disposition must appear in the Premise Ledger
with its `file:line`, the exact condition it asserts, and the
reviewer's verdict. A disposition with an unverified premise is a
guess.

Capture source searches and bounded reads with
`runtime/evidence_log.py` and cite their IDs in the JSON ledger. Keep
the ledger and artifacts in the private triage workspace; do not commit
target source excerpts. Treat uncaptured tool output as exploratory
unless the notes preserve a reviewable artifact. Before Deliver, run:

```text
python runtime/validate_triage.py path/to/triage-notes.md --evidence-ledger path/to/evidence.jsonl
```

The validator checks cited IDs and hashes, captured reads for hunted
questions and triage rows, premise expressions against cited source
reads, and work-queue closure. Exit 0 means these structural
requirements passed; it does not certify that the maintainer will
accept the report. The reviewer still challenges every disposition and
every premise verdict.

For end-to-end verification across sessions, `runtime/regression.py`
runs validate-triage and check-skill-loaded against every fixture in
`fixtures/`. A regression failure means the framework's expected output
has drifted and the triage prompt is operating against a wrong target
shape.

This Hard Gate was added after a real report was closed as "not a
security issue" because its premise depended on an operator decision
that was never classified, and because the divergence that would have
carried it was never searched for.
