---
name: mini-audit
description: Use for security audits, vulnerability reviews, and security-focused code reviews of source repositories. Builds source-derived coverage units, requires independent omission reviews and candidate verification, and reports unresolved scope as incomplete.
---

# mini-audit

A prompt-led Skill for security audits. The model reasons; the
Harness executes; this Skill is the playbook the model follows.

The audit state lives in **one Markdown file** that the model edits
every round (`templates/audit-notes.md`). Runtime checks validate the
coverage and review records and skill freshness; helpers capture bounded
source reads/searches and generate stable coverage IDs. None proves semantic
completeness.

## When to load this Skill

Load when the user asks for a security audit, a vulnerability
review, a threat model, a code review with security focus, or
"is this exploitable?". Do not load for general code review,
refactoring, or feature work.

## Session-start check (Runtime enforcement)

Before the audit starts, the Harness should run:

```text
python runtime/check_skill_loaded.py
```

Exit 0 means the SKILL.md / references / templates / schemas / required
audit helpers match HEAD of this repo. Exit non-zero
means the agent is reasoning over a stale or partial skill;
the audit is at risk of the React 19 long-chain failure mode
(post-mortem 2026-09-25, second failure mode: "session did
not load the revised skill"). The script is stdlib-only and
takes milliseconds.

The check uses `runtime/skill_manifest.json`. After editing
any tracked file, run with `--refresh` to recompute hashes.
The list of tracked files is in `runtime/skill_manifest.json`;
it covers every instruction, reference, template, schema, and required
audit helper the agent must use to audit correctly.

## The five things this Skill teaches

1. **How to frame the audit.** Define the target, the attacker,
   the highest-value capability, the attacker's starting boundary,
   and baseline security lenses that must be considered even when
   the initial hypothesis does not suggest them.
2. **The five-stage loop.** Scope → Discover → Verify →
   Synthesize (chaining) → Report. The model moves between
   stages freely; the notes file does not gate them, but
   Synthesize must run at least once before Report.
3. **How to propose and disprove vulnerability hypotheses.**
   Each hypothesis names its disproof. Run the experiment, do
   not keep guessing.
4. **When to call a sub-agent or load a reference.** Use a
   sub-agent for independent verification and bounded parallel
   searches. Load a reference when the hypothesis needs class
   knowledge the model does not already have.
5. **What evidence is enough to call something a finding.** A
   finding must trace to a Verified Fact in the notes file.

## The audit loop

```text
Understand the boundary.
Find plausible violations.
Trace them end-to-end.
Try to disprove them.
Keep only evidence-backed findings.
Look once more for what you may have missed.
Stop when another round is unlikely to change the result.
```

That sentence is the entire loop. Every other piece of this Skill
serves it.

## The five stages

The stages are cognitive, not gates. The model jumps between them
as the audit demands — `Discover → Verify → Discover` is a normal
cycle. The notes file does not enforce order; the reviewer enforces
discipline by reading.

### Scope

Goal: a relevant attack-surface map and a one-sentence
permission-delta question.

Ask the audit:

- What is the application, what does it do, what is its trust model?
- Where does attacker-controlled data enter?
- What is the highest-value target capability?
- What boundary does the attacker start from?

Before ending Scope, make a first-pass inventory of these security
decision lenses, even if the user named a different bug class:

- **Sensitive writes and authorization consumers:** who can change
  roles, ownership, tenant IDs, authentication modes, permissions,
  or other fields that later affect authentication or authorization?
- **Identity assertions and trust decisions:** who can assert an IP,
  hostname, user, tenant, role, or service identity (including
  proxy headers, PROXY protocol, DNS/PTR, tokens, and peer
  credentials), and which ACL or authorization decisions consume it?
- **Persisted state across boundaries:** which endpoint, callback, or
  job writes security-relevant state, and which other endpoint or
  process later trusts it?
- **Callbacks and dangerous consumers:** can plugin, event, template,
  or callback output reach deserialization, code execution, file,
  permission, or other security-sensitive consumers?

Put each lens in the notes file as `NOT_CHECKED`, `IN_PROGRESS`,
`HUNTED`, `N/A`, or `NEEDS-RUNTIME`, with the strategy and evidence.
`N/A` is a conclusion to support, not a blank cell; unreviewed work
must stay visibly unreviewed. Load the relevant class references while scoping, before
Discover, so the model does not need to name an unfamiliar class
before receiving the checklist that would help it recognize the
class. Treat these lenses as a baseline, not an exhaustive list; add
target-specific classes suggested by the architecture.

For every identity or security-relevant value, record its source,
attacker control, parsed/runtime type, consumer, and the independent
check performed at that consumer. A configuration flag or a manual
deployment recommendation is a precondition, not proof that the
enabled path is safe. Mark unverified external claims about intended
behavior, documentation, or upstream fixes as `[prior]`; do not use
them to disprove a hypothesis until verified against the target or
an authoritative source.

**Attention and budget control.** Before hunting, set a hard budget in
`budget` and reserve capacity for at least one independent coverage critic
and candidate verification. Turn the source-derived attack-surface map into
`coverage_units`, one per material combination of surface, trust boundary,
subsystem, attack class, and (when relevant) lifecycle. Generate each stable
ID with `python runtime/coverage_id.py`; IDs exclude line numbers, ownership,
wave, and status so source movement does not silently create new work.

At the start of a work cycle, select one coverage unit and make it the only
active unit. Its task, owner, wave, budget unit, paths, and stop condition
must be written before tool use. Finish or explicitly defer that unit before
switching. Record newly discovered surfaces as new units in a later wave;
do not let a tangent replace the active unit. After every hunter wave, a
separate cold-start critic checks the current source inventory for unmapped
ingress, alternate protocol entries to known primitives, unchecked consumers,
trust boundaries, and lifecycle paths. Every gap becomes a later-wave unit.
A final independent clean review covers every current unit. If the Harness
cannot provide a separate reviewer, record the self-review as non-independent
and set `run_status: incomplete`.

When the budget is exhausted, stop hunting, preserve unfinished units as
`deferred` or `blocked`, state the remaining scope in `incomplete_reasons`,
and do not claim complete coverage. Prior runs can seed hypotheses but do not
count as current-source coverage; re-map and re-review the checked-out target.

End Scope when the **Objective** and **Attack Surface** sections
of the notes file are written, the highest-value target is named,
and the baseline lenses have an evidence-backed initial status. The
map covers the surface relevant to the objective and expands when
later evidence reveals a new reachable boundary.

### Discover

Goal: a list of plausible hypotheses, each with a disproof
condition.

Read code. Trace data flow. Read references when needed. Ask a
sub-agent for parallel variant or chain searches. Add entries to
the **Hypotheses** section, one per hypothesis, written so the
disproof is named alongside.

Balance sink-driven searches with the baseline authorization and
trust-decision lenses. Allocate deep-dive effort by potential
permission delta, reachability, and uncertainty, not by whether code
looks central, admin-only, or easy to grep. Use the `coverage_units` ledger in
the notes: one active unit, a source-derived scope, an explicit stop condition,
and a recorded budget unit for each pass.
A new tangent becomes a later-wave unit; it does not silently replace the
active unit. A release-note/CVE checklist is one
search strategy, not a scope boundary. Treat security-related `TODO`,
`FIXME`, and `XXX` comments as review signals, not completed analysis.

### Verify

Goal: promote a hypothesis to a Verified Fact or delete it.

Attempt the strongest plausible disproof. Promote the hypothesis
only when:

- evidence establishes the claim end-to-end, and
- the attempted disproof does not hold.

Failure to disprove alone is not proof. If the disproof holds,
delete the hypothesis. When the experiment is structural, ask an
independent sub-agent to corroborate.

**Guard rule**: every claimed *guard* ("the id is validated",
"the manifest restricts lookups", "this path is dev-only") must be
verified with the same `file:line` evidence standard as a hop.
An unverified guard is a hypothesis, not a fact — asserting one
without reading the guard's implementation is how false negatives
are manufactured. When a grep returns empty, suspect the pattern
before concluding absence; retry with a broader pattern.
(Added 2026-09-25 after a scan that found a chain's skeleton but
asserted a manifest guard that did not exist, downgrading a
CRITICAL RCE to "design boundary" until re-examined.)

**Guard semantics rule**: reading the guard and finding its line is
only the start. Record the exact comparison or predicate, the
attacker-controlled value's type and shape after parsing, and the
predicate's result for that value. Check coercion, normalization,
null/boolean cases, and collection element types where relevant.
Name the sink or decision the guard is meant to protect. A guard is
effective only if it blocks every relevant attacker-controlled form
at that consumer. Do not summarize this as "standard check exists";
put it in the Guard Evaluation Ledger in the notes. If evaluation is
uncertain, keep the hypothesis open or mark it `NEEDS-RUNTIME`.

**Absence recheck.** "X does not exist" is itself a claim that
requires evidence. A grep that returns empty is a query-failure
signal first, an absence signal second. Before writing "X is
absent" or "no such call site", retry with a broader pattern,
an alt path syntax, or a different tool. Two empty greps with
two independent patterns support absence; one does not.
Record each query and its result in the class-coverage ledger so a
reviewer can distinguish an empty result from an unrun search.
(Added 2026-09-25 after a scan whose Flow-syntax literal `case
'F':` was missed by a single-pattern grep and treated as
absent, hiding a `decodeReply` entry to the same primitive
that `decodeAction` walked.)

**Coverage rule.** Reaching a primitive from one attacker-
controlled entry point does not exhaust the primitive. Every
protocol marker that can deliver payload to the same primitive
must be enumerated before any of them is verified. Uncovered
entries are not absent; they are `NEEDS-RUNTIME`. A primitive's
chain table is incomplete while any of its known protocol
entries has no entry in that table. (Added 2026-09-25 after a
scan verified only the `$ACTION_*` form-field path of
`loadServerReference` and missed the `$F` reply-model path
that reached the same primitive.)

**Downgrade symmetry.** Lowering a severity rating requires
evidence at the same strength as raising one. "We have end-
to-end proof of the chain but it is just an app-layer issue"
must cite `file:line` for the application-layer enforcement
*and* an unblock condition that survives the audit. Severity
is not a one-way street. Keep the original hypothesis and the
disproof evidence in the notes; do not erase a lead merely because
it was downgraded. Treat config flags, deployment advice, and
expected usage as preconditions until their security effect is
demonstrated in code. (Added 2026-09-25 after a scan
downgraded a CRITICAL RCE to "design boundary" on a single
unverified guard.)

A Verified Fact is a finding candidate, not yet a finding. The
finding lives in `templates/finding.md` once Report starts.

### Synthesize (chaining - mandatory before Report)

Goal: pairwise-combine benign / LOW findings and unproven
primitives into chains that cross a boundary no component
crosses alone.

This stage is **mandatory, not optional**: isolated primitives
are how real high-link vulnerabilities hide. Run it once after
the first Verify cycle, and again before Report when new
Verified Facts landed.

**Entry-point census (before Verify on any attacker-controlled
primitive).** Identify every protocol-level entry point that
reaches the primitive: form fields, query params, headers,
redirects, event handlers, template includes, sub-protocol
markers ($X, $Y, type codes), RPC fields. Walk each one before
declaring the primitive exhausted. Single-entry verification is
how multi-entry bugs (`$F` vs `$ACTION_*` reaching the same
`loadServerReference`) get downgraded to "single known call
site". Coverage is verified by writing it down, not by reading
more code.

The list above (form fields, query params, ...) is illustrative,
not exhaustive. The entry-point shape of a target is derived
from the target's surface, not from this paragraph: signal
handlers, IOCTL, file-descriptor events, IPC, environment
variables, hardware interrupts, IPC queues, and similar
non-HTTP ingress surfaces are first-class entry points on
their respective targets. The principle - enumerate every
attacker-controlled ingress before any one of them is verified
- transfers; the named patterns do not.

Deterministic procedure:

1. **Build the chain table.** List every finding, primitive,
   and weak control with: attacker prerequisite (auth / write
   access / network position / config state). One row each,
   no merging.
2. **Precondition elimination.** For each row, search the
   codebase for *another* primitive that grants that row's
   prerequisite or relaxes its guard. A hit **upgrades** the
   row, never downgrades.
3. **Pairwise composition.** For each pair (A, B), ask: can A
   supply what B requires, or remove what B guards?
   Specifically test: A writes what B deserializes; A degrades
   what B trusts (cache / meta / session / config); A forges
   what B authenticates.
4. **Prove each hop.** Every hop in a surviving chain must
   cite `file:line`. A hop that cannot be proven statically
   is `NEEDS-RUNTIME` for the whole chain - the chain is
   never reported at the strength of its weakest proven hop.
5. **Score the delta.** The chain's severity is the permission
   delta between the attacker's starting boundary and the
   chain's end capability - never the sum of the individual
   severities.

A chain that survives is a finding candidate like any other;
a chain that dies is recorded as a disproven hypothesis with
the hop that killed it.

### Report

Goal: one `templates/finding.md` per Verified Fact.

Every finding must include the four things stated in the template:
a Summary, the Location, the Preconditions, the Attack path, and
the Evidence. The remediation is the smallest change that closes
the delta. **Why existing controls missed it** is required —
without it, the report is a bug, not a fix proposal.

For configuration-dependent findings, separate default behavior from
supported/common deployment behavior. State the exact enabling
configuration and who can reach the feature once enabled; do not
silently downgrade a finding because its precondition is not the
default.

## How to use the notes file

Copy `templates/audit-notes.md` into the audit workspace, rename
it (e.g. `notes-{target}.md`), and edit it every round.

The notes file is the entire canonical state of this audit. The machine-
readable pairing, coverage-unit, coverage-review, candidate-review, budget,
and run-status records are governed by `schemas/pairing-table.schema.json`;
other sections can evolve with the audit. Keep the prose and records
consistent. A section the audit no longer needs can be deleted.

A reviewer who reads the notes file from top to bottom should
understand the entire audit. If they cannot, the notes are
incomplete.

The notes file must contain, for every dangerous primitive,
a **Coverage paragraph**: the protocol entries that reach it
(form field / reply marker / template include / event handler /
sub-protocol marker / RPC field) and the verification status of each
(`verified` / `disproven` / `NEEDS-RUNTIME`), linked to its coverage-unit ID.
The ledger also names each unit's source refs, owner, wave, paths reviewed,
outcome, and evidence. This makes omissions inspectable; it does not prove
every entry was found.

## When to load a reference

The Skill ships four methodology references and eight vuln-class
references. Load them only when the model is about to do work the
reference actually helps with.

Methodology:

- `references/discovery.md` — when the model is about to start
  Discovery and has not yet mapped the attack surface relevant
  to the objective.
- `references/verification.md` — when Verification has stalled
  (no Verified Facts after two cycles) or when the model is
  unsure whether an experiment is enough.
- `references/permission-delta.md` — every time a hypothesis is
  about to become a Verified Fact. Severity comes from the
  delta, not the primitive.
- `references/search-strategy.md` — when the audit has stopped
  generating new hypotheses, when a chain search is about to
  start, or when the audit is deciding whether to stop.

Vuln-class:

- `references/vuln-classes/{authz,injection,deserialization,
  path_traversal,ssrf,crypto,race_condition,cross_service_trust}.md`

During Scope, load `authz.md` and `cross_service_trust.md` as the
baseline lenses, even if the initial hypothesis names another class.
Load other vuln-class references when the architecture or evidence
suggests them. These references should help recognize classes, not
only confirm a class already named. Do not load all references to
"be thorough"; choose by the baseline lenses and target evidence.

## When to call a sub-agent

Use a sub-agent for:

- **Independent review.** Give a sub-agent minimal target context
  and relevant code, without the author's conclusion. For a downgrade
  review, provide the original hypothesis but withhold the downgrade
  rationale until the reviewer has formed a view. Independent review
  is corroboration, not proof. Agreement does not promote a hypothesis;
  promotion still requires sufficient code or runtime evidence.
  Disagreement means the claim needs more verification.
- **Bounded parallel searches.** Variant hunts and chain
  searches that can run with no shared state from the main
  audit. Require output to include searched surface, search strategy,
  and `file:line` for every conclusion; a timeout or unsupported external
  claim means the subtask is incomplete. Re-run a smaller bounded task
  serially when budget allows. Independently inspect high-impact SAFE,
  `N/A`, and downgrade conclusions.
- **Experiments in a clean harness.** A PoC that needs a
  controlled environment the model cannot guarantee locally —
but only inside isolation the Harness provides. The Skill
  itself provides no isolation.

Do not use a sub-agent to "look at the code." The model reads
faster than the model can spawn a sub-agent.

## Isolation and untrusted code

This Skill provides no isolated execution environment. The audit
will sometimes need to run a PoC that touches the network,
executes untrusted code, or modifies system state.

> Use isolation the Harness explicitly provides. If the Harness
> provides none, do static verification or a minimal
> non-destructive experiment instead. Never assume the Skill
> gives you a sandbox.

A sub-agent that runs a PoC without isolation is a sub-agent, not
an audit. The reviewer will not trust a finding whose evidence
chain passed through the host shell.

## Stopping the audit

Do not stop solely because Remaining Questions is empty, because
the model feels saturated, or because another round seems unlikely
to add a finding. Before Report, close the following checklist:

- All four baseline categories have an explicit status and corresponding
  coverage units. `HUNTED` units cite captured source reads; `N/A` units need
  a reason and two distinct zero-match searches. `NOT_CHECKED`, `IN_PROGRESS`,
  and `NEEDS-RUNTIME` make the run incomplete.
- Every identified dangerous sink and security decision point has
  an entry/producer inventory, relevant consumers, and a status.
- Every claimed guard has a Guard Evaluation Ledger row with the
  exact expression, attacker input type, evaluated result, and
  protected consumer.
- Every downgraded or disproved high-impact hypothesis retains its
  original statement and the evidence that killed it.
- Configuration-dependent chains record the default state and at
  least one supported/common deployment state; a disabled-by-default
  feature is not itself a disproof.
- A separate final cold-start reviewer challenges unverified `[prior]`
  claims, universal negatives, each `N/A` and `DISPROVED` row, and every
  coverage unit. Without an independent reviewer, record the limitation and
  mark the run `incomplete`; a second self-review cannot satisfy this gate.
- Every `coverage_units` entry has a canonical ID derived from its dimensions.
  Before Report, no unit is `planned`, `in_progress`, `blocked`, `deferred`,
  or `out_of_scope` in a run marked `complete`. Deferred units state the
  reason and remaining limitation.
- Every candidate ID linked from a unit has an independent verifier record.
  `needs_validation` candidates remain unresolved and force `incomplete`.
- `budget.spent_units` does not exceed the declared maximum. A complete run
  has a clean final coverage review, terminal candidate dispositions, no open
  units, and an empty `incomplete_reasons` list.

After this checklist closes, stop when additional work produces no
new reachable capability delta. Record remaining uncertainty as
`NEEDS-RUNTIME` or an explicit limitation rather than silently
calling the target safe. A hypothesis without new evidence is not a
finding, but an unclosed category is not saturation either.

**Universal-negative guardrail.** Reports containing universal-
negative conclusions ("no X in Y", "X is safe", "Y has no
independent vulnerability") must carry an explicit
unverified-guards list. A summary line of that form, written
while any guard in the chain table is unverified, is itself a
false negative. (Added 2026-09-25 after a scan wrote "no
independent upgradeable React library vulnerability" while a
manifest guard on `resolveServerReference` had never been
read.)

## What this Skill does not do

- It maintains a lightweight coverage-unit ledger and review records in the
  notes file. It does not maintain a general-purpose Search Ledger or Attack
  Graph, and it does not prove semantic completeness.
- It does not provide a sandbox or the v2.x audit Runtime
  (L1-L7 phase catalog, search ledger, attack graph, scheduler,
  phase gates). It provides three lightweight runtime checks and one
  bounded evidence-capture and coverage-ID helpers:
  `runtime/validate_notes.py` checks pairing, coverage-unit identity and
  closure, review independence declarations, candidate dispositions, run
  status, budget bounds, cited evidence artifacts, and selected ledger
  invariants; `runtime/check_skill_loaded.py` checks the session-start load;
  `runtime/regression.py` checks fixtures. `runtime/evidence_log.py` records only reads and searches made through it; `runtime/coverage_id.py` generates stable unit IDs;
  neither can prevent other tools from being used or prove the inventory
  is complete.
  A structurally valid notes file is not a validated security
  conclusion.
- It does not enforce phases or control which tool the model uses.
  The unit and evidence checks make omissions visible at the Report gate;
  the reviewer still enforces semantic discipline.
- It does not own workflow state in a database. The notes file is the
  canonical audit state; the evidence ledger stores captured outputs and
  hashes as supporting artifacts.
- It does not write architecture-eval tests. The audit is
  measured by the findings it produces, not by whether the
  implementation of the audit was correct.

### Hard Gate: Synthesize stage cannot be skipped

Report stage cannot start until the audit notes file contains a pairing table,
the four baseline roll-ups, source-derived coverage units, a post-wave critic
record for every wave, a final-clean coverage review, candidate review records
for all candidate IDs, a budget record, and a Guard Evaluation Ledger. If any
completion condition is unavailable, report `incomplete` with the specific
coverage limitation instead of presenting the audit as complete. Every pairing
row connects a **trust-source** with a **trust-consumer**:

```text
trust-source    : some component produces / writes / trusts value X
trust-consumer  : some component reads / consumes X; record whether
                  its independent check covers X and the resulting action
attacker reach  : attacker can drive X from trust-source to
                  trust-consumer
```

Four baseline lenses are mandatory. Record each in `class_coverage`
as `NOT_CHECKED`, `IN_PROGRESS`, `HUNTED`, `N/A`, or `NEEDS-RUNTIME`.
An `N/A` needs two distinct captured zero-match searches and a reason.
Add pairing rows for relationships discovered within those categories.
Do not infer that a category is absent because it did not arise from
the initial audit strategy. Each category is an abstract pattern;
the per-class reference has detailed methodology.

1. **security-sensitive field write x authentication/authorization
   consumer.** A low-privilege or less-trusted path writes a field
   that later changes login, identity, ownership, role, tenant, or
   permission decisions. Compare input types and field-level access
   controls across every API reaching the same write primitive. See
   `references/vuln-classes/authz.md`.

2. **identity assertion x trust or access-control decision.** A
   header, PROXY-protocol value, DNS/PTR result, token, peer identity,
   or other asserted identity reaches an ACL or authorization
   decision. Record who may assert it and whether the consumer
   independently verifies it. This includes trust decisions within
   a single daemon, not only between services. See
   `references/vuln-classes/cross_service_trust.md`.

3. **callback x dangerous sink.** A plugin / event / template
   callback returns a value (or has its return persisted); a
   `unserialize` / `include` / `eval` / file-write /
   permission-decision sink later consumes that value. See
   `references/vuln-classes/deserialization.md` and
   `references/vuln-classes/injection.md`.

4. **state write x cross-endpoint state consumer.** Endpoint A
   writes state under A's authorization; endpoint B reads that state
   and acts on it without re-checking authorization. See
   `references/vuln-classes/authz.md` and
   `references/discovery.md` (Trace across endpoints).

Each category must appear in the machine-readable `class_coverage`
ledger, including when marked `N/A`. Pairing rows name the category,
source, consumer, attacker reach, status, evidence, and rationale. Every
guard claimed to protect a paired consumer must also have a Guard
Evaluation Ledger entry. Category presence is a completeness prompt,
not proof that the category was truthfully or fully searched.

Each non-N/A row is `upgraded`, `DISPROVED`, or `NEEDS-RUNTIME`.
`DISPROVED` requires a cited control or hop and the concrete
attacker input against which it was evaluated. `N/A` requires a
reason and two distinct captured zero-match searches in the
class-coverage ledger. Re-running the same search command does not count
as two checks. "The bundled component happens to be clean" is not a
permitted escape.

Capture source searches and bounded reads with `runtime/evidence_log.py`
and cite their IDs in the JSON ledger. Keep the ledger and artifacts in
the private audit workspace; do not commit target source excerpts. Treat
uncaptured tool output as exploratory unless the notes preserve a reviewable
artifact. Before Report, run:

```text
python runtime/validate_notes.py path/to/notes.md --evidence-ledger path/to/evidence.jsonl
```

The validator checks cited IDs and hashes, zero-match search results,
captured reads for hunted categories, coverage-unit IDs and statuses, wave
review coverage and declared reviewer separation, candidate dispositions,
budget bounds, guard expressions against cited source reads, and the complete
versus incomplete gate. Exit 0 means these
structural requirements passed; it does not certify search truth or
completeness. The logger sees only use through that helper, and its local
files are not tamper-proof. The reviewer still challenges category
inventory, every `N/A` and `DISPROVED` row, and every guard verdict.

For end-to-end verification across sessions, `runtime/regression.py`
runs validate-notes and check-skill-loaded against every
fixture in `fixtures/`. A regression failure means the
framework's expected output has drifted and the audit prompt
is operating against a wrong target shape.

This Hard Gate was added after the DokuWiki 2026-07-14a audit
missed a cross-endpoint CWE-502 chain. Later FlaskBB, rsync, and GLPI audits
showed that a non-empty table alone is insufficient. The coverage-unit and review gates were added after comparing
Cloudflare's omission controls: dimensions-based coverage, critics after each
wave, a clean final pass, explicit incomplete status, and independent
candidate disposition. These checks improve traceability; they still cannot
force the model to discover an unenumerated surface.
