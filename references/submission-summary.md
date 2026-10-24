# Submission Summary

> Load this at the Deliver stage. Every claim the adjudication will
> send gets one `submission` block answering four questions a triager
> asks in the first ninety seconds — is this the product's core
> business, did the developers already know, does it need a special
> configuration to fire, and what boundary does it cross — plus the
> target list. Together they are the 可申报总结: the submittable list,
> with the reason each claim is submittable and where.

The four dimensions are recorded per claim, each with cited evidence.
Three of them are judged; one of them (`trigger_configuration`) is
cross-checked mechanically against the premise the Assess stage already
derived.

---

## 1. Core business — is the defect in the product's main line?

What decides it:

- **The project's own scope statement** — README's first paragraph,
  the package description, SECURITY.md's scope section. The
  authentication path of an auth product is core; the demo app in
  `examples/` is not.
- **Where the code lives** — the main module/tree vs `contrib/`,
  `examples/`, `test/`, an optional plugin directory.
- **Whether it ships in the default build** — default `make`/`pip
  install`/image contents vs a compile flag or optional extra.
- **Install base** — for libraries, the dependency graph weight; for
  products, deployment counts where knowable (CNVD's multiple-instance
  bar for 通用型 lives here).

`in_core: true` raises impact and reception weight everywhere: SRCs
weight 核心业务 higher, CNVD 影响面 scoring counts it, and maintainers
fix their advertised function faster than their demos. `in_core:
false` is not a rejection — but it belongs in the report's framing,
and the CNVD/影响面 case for it must be made honestly.

## 2. Developer awareness — did they notice and comment?

Answered from source and history (see
`references/historical-similarity.md` §4): comments, TODO/FIXME,
partial guards, linked issues. Record `aware` / `false` / `unknown`
with the citation. An `aware` finding re-frames the report — "the
check you started is missing on this path" — and predicts the
wontfix closure if ignored.

## 3. Trigger configuration — does it need a special setup?

Two fields:

- `special_config_required` — a boolean: can the attacker reach the
  defect on the vendor's default, documented configuration?
- `default_configuration` — one sentence on what the default actually
  is, cited (config file default, README deployment guide, the read
  that showed it).

**The mechanical cross-check** the validator enforces: if
`special_config_required` is true, the premise the Assess stage derived
cannot be `attacker_only` — an attacker-only premise means the
attacker creates the condition alone, on the default configuration.
Conversely a `requires_operator_decision` premise with
`special_config_required: false` deserves a second look at either the
premise or the config answer. The two answers describe the same fact
from two sides; disagreement means one of them is wrong.

Platform reality: a defect behind a non-default configuration is
usually hardening, not a report (SRCs scope it out; maintainers
classify it hardening; CNVD verification cannot reproduce it). State
the enabling configuration honestly and let the target matrix carry
the consequence — hiding it is the fastest route to a closed report
and a burned channel.

## 4. Boundary crossed — the one sentence

`from → to`, on the project's own trust ladder, naming the capability
that becomes reachable: "from an unauthenticated network client to
rewriting the stored credential of any named account". This is the
most-read sentence of the whole submission (the advisory template
carries the long version); the summary carries the one-line version.
A claim with no boundary crossing is a functional bug, not a
vulnerability, and belongs nowhere in the submittable list.

## 5. The target list

Per `references/submission-targets.md`: one `primary`, everything else
`secondary` or `unsuitable`, each with its reason. The primary is the
one channel that receives the submission; the reasons are part of the
record because "why not the other channel" is the first question a
careful submitter asks.

## 6. Assembling the summary

The final artifact (`templates/submission-summary.md`) is one table,
one row per submittable claim:

| Claim | Core | Aware | Special config | Boundary crossed | Primary target | Order |

- Rows are **only** claims whose action is `report` or
  `rewrite_then_report`. `hardening_note` claims are listed separately
  as patches to offer; negative verdicts do not appear at all.
- Row order follows `references/ordering-and-channels.md` — reception
  likelihood, not severity.
- Under the table: the blocking facts. Any `needs_more_evidence` claim
  with its missing fact; any `aware` finding with its re-framing; any
  timeline `untraced` field with what a trace would change.

The summary is the last thing written and the first thing the
submitter reads. If it does not answer "what do I submit, where, and
why is each one safe to submit", it is not done.
