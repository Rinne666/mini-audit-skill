# Audit Notes — {target}

> One Markdown file is the canonical state of the audit. Edit it every round.
> Evidence IDs point to artifacts in the private audit workspace; do not commit
> target source excerpts.

---

## Run Status and Budget

Set a hard budget before hunting. Pick a unit the Harness can count consistently
(for example, bounded source-read/search batches). Reserve at least one unit for
an independent post-wave/final coverage review and one for each expected
candidate-verification pass. Record actual spend. If the budget runs out, stop
and set the run to `incomplete` with the remaining scope named explicitly.

Current status: `incomplete` until every completion gate is met.

## Objective

What is being audited, who is the attacker, what is the highest-value target
capability, and what trust boundary does the attacker start from. Rewrite this
section if the objective changes.

## Attack Surface

List externally or otherwise attacker-reachable surfaces and trust boundaries.
Use source-derived references (routes, handlers, protocol markers, IPC endpoints,
callbacks, jobs, configuration paths); expand this list whenever a later pass
finds a new boundary.

## Baseline Security Lenses

Give each required lens a roll-up status. Keep `evidence.jsonl` and its artifact
directory in the private audit workspace. Capture reads and searches with
`runtime/evidence_log.py`.

| Category | Status | Strategy | Evidence IDs / limitation |
|---|---|---|---|
| `authz_sensitive_write` | | | |
| `identity_to_decision` | | | |
| `callback_to_sink` | | | |
| `state_cross_endpoint` | | | |

`N/A` requires a reason and two distinct captured zero-match searches. A
category with open units is not `HUNTED`. Use `NOT_CHECKED`, `IN_PROGRESS`, or
`NEEDS-RUNTIME` when work remains; any such status makes the run incomplete.

## Business Process Security Review

Set the `business_logic_review` record in Synthesize JSON to `REVIEWED`,
`N/A`, `IN_PROGRESS`, or `NOT_CHECKED`. For each security-relevant workflow,
record source-backed actors, protected assets, invariants, state transitions,
failure/retry cases, abuse cases checked, evidence IDs, and linked
`business_logic` coverage-unit IDs. Keep the review focused on security
consequences; do not turn undocumented product expectations into findings.

`N/A` requires a reason and two distinct captured zero-match searches over the
scoped source inventory. Any unchecked or unresolved review makes the run
incomplete. Load `references/business-logic.md` for the workflow method.

## Coverage Units

The `coverage_units` array in the Synthesize JSON below is the single source of
truth for review scope and progress. Create one unit for each material
combination of:

- externally reachable surface or protocol entry;
- trust boundary crossed;
- subsystem or security decision point;
- baseline or target-specific attack class; and
- lifecycle stage when it changes the security behavior (for example,
  request-to-request persistence or startup-to-runtime).

For each material security-sensitive business workflow, add a target-specific
unit with `dimensions.attack_class: "business_logic"`; link it from the
corresponding flow in `business_logic_review`. Keep distinct authorization or
cross-endpoint units when they cover different code paths.

Generate `coverage_id` with `python runtime/coverage_id.py`, passing those
canonical dimensions. IDs must not include line numbers, reviewer, owner, wave,
or status. Put stable source-derived symbols/paths in `source_refs`; list
concrete ingress paths and files in `entry_points` and `paths_in_scope`.

Before starting a unit, record its owner, wave, next task, budget unit, and stop
condition. Work one unit at a time. A newly discovered boundary or unchecked
parallel path becomes a unit in a later wave. Close units as `covered`,
`candidate`, or `not_applicable`; otherwise record why they are `blocked`,
`deferred`, or `out_of_scope`. Those open states prevent a complete run.

## Coverage Reviews

After every hunter wave, a separate cold-start reviewer reads the current
source and challenges the unit inventory: unmapped ingress, alternate protocol
entries to known primitives, unchecked consumers, missing lifecycle paths,
missing workflow transitions, alternate actors, retries, and recovery paths,
and unsupported exclusions. A gap must be added as a later-wave unit and
reviewed in that wave. Mark each review's `independent` field explicitly. The
`final_clean` reviewer must cover every current unit and be different from
every unit owner and independent post-wave critic. If no independent reviewer
is available, record `independent: false` or omit that review and keep the run
incomplete. A self-review is not independent.

## Security Decision Points

For each authentication, authorization, ACL decision, or security-sensitive
state consumer, record its inputs, source, attacker control, parsed/runtime
types, and the independent check at the consumer. Include supported
configuration states that alter the trust boundary.

## Guard Evaluation Ledger

Record every guard claimed to protect a dangerous sink or security decision:

| Protected consumer | Guard `file:line` | Exact expression | Attacker input type/shape | Evaluated result | Verdict |
|---|---|---|---|---|---|

Do not write "standard check exists". Evaluate the expression for attacker-
controlled types and values. If no guard was found, record two distinct
queries and their results.

## Verified Facts

Facts proven with code or runtime evidence. Each fact names the source path,
line, and experiment (if any). A fact without a pointer is a hypothesis.

## Hypotheses

One testable sentence per hypothesis, with its disproof condition:

> If `<condition>` is true at `<location>`, then `<attacker capability>`
follows because `<data path>`.

Retain high-impact disproved or downgraded hypotheses with their original
claim, evidence that killed them, and any configuration that could unblock the
chain.

## Blocked Leads

List attack chains blocked on an unverified precondition and name exactly what
would unblock each one.

## Remaining Questions

Keep the one question most likely to change the conclusion. An empty list is
not a stop signal.

## Coverage Paragraph

For every dangerous primitive, enumerate every protocol entry that reaches it
(form field, reply marker, template include, event handler, sub-protocol marker,
RPC field, IPC, signal, file descriptor, or other target-specific ingress).
Link each entry to a coverage-unit ID and give its verification status:
`verified`, `disproven`, or `NEEDS-RUNTIME`.

## Synthesize JSON

Include one JSON object conforming to `schemas/pairing-table.schema.json` with
these top-level records:

- `rows`: discovered source-to-consumer trust pairings;
- `class_coverage`: exactly the four baseline lens roll-ups;
- `business_logic_review`: a reviewed workflow inventory or evidence-backed N/A;
- `coverage_units`: the complete source-derived work and coverage map;
- `coverage_reviews`: one post-wave review per wave and, for a complete run,
  one final-clean review;
- `candidate_reviews`: an independent disposition for every candidate ID;
- `budget`, `run_status`, and `incomplete_reasons`;
- `guard_checks` and `coverage_paragraph_present: true`.

A candidate linked from a unit must be reread and challenged by a verifier
other than the unit owner or coverage critics; record `independent: true` only
when the Harness supplied genuinely separate context. If that is unavailable,
record a non-independent or missing review and keep the run incomplete.
Use `confirmed` only when the stated claim and its preconditions are evidenced;
use `rejected` when a specific disproof holds; use `needs_validation` when an
external precondition or decisive check remains unresolved. Only `confirmed`
candidates belong in the final findings. Any `needs_validation` candidate
keeps the overall run incomplete.

## How to use this file

1. **Scope.** Write the objective and attack-surface map, set the hard budget,
   create the four baseline roll-ups and business-process review record, and
   seed source-derived units. Generate IDs with `runtime/coverage_id.py`.
2. **Discover.** Work one unit at a time. Add hypotheses with explicit
   disproofs. Add newly found boundaries or alternate paths as later-wave
   units; preserve high-impact disproved hypotheses.
3. **Review each wave.** Ask a separate cold-start critic to find missing
   units. Link every discovered gap to a later wave. Do not mark that wave
   clean while a gap remains unassigned.
4. **Verify candidates.** A verifier other than the unit owner and coverage
   critics rereads the cited source and records the strongest disproof attempt.
5. **Report.** Run `runtime/validate_notes.py`. A structurally valid ledger is
   not proof of semantic completeness. Report `complete` only when all units
   are terminal, the business-process review is `REVIEWED` or evidenced `N/A`,
   all candidates have terminal independent verdicts, the final coverage review
   is clean, and budget and evidence gates pass. Otherwise report `incomplete`
   with concrete limitations.
