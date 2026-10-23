# Triage Notes — mini-triage

> Fixture: the expected output of a correct disclosure triage for
> `fixtures/mini-triage/app.php`. It locks the disposition format, the
> three-question coverage, the premise citations, the send order, and
> the channel discipline.
>
> It shows two findings on purpose: one that must be sent, and one that
> must not be — the second is the shape that a maintainer closed in a
> real project.

---

## Objective

Disclose the two findings in `fixtures/mini-triage/app.php` to the
project's maintainer, privately, on the channel the project uses. The
attacker starts unauthenticated in both cases. The highest-value
capability is administrator control of the service.

## Trust Ladder

| Rung | Role in this target | How it is obtained | May reach |
|---|---|---|---|
| L0 | Anonymous HTTP client | — | The login endpoints and the setup endpoint |
| L1 | Authenticated protocol user | Valid credentials | Its own account resources |
| L2 | — | — | — |
| L3 | — | — | — |
| L4 | Administrator | Administrative login | Everything the service exposes |
| L5 | — | — | — |

**Acceptance policy source**: `SECURITY.md` in the target repository
(snapshot `fixtures/mini-triage/SECURITY.md`).
**Source of authority**: `stated`.

## Upstream Prior Classification

| Prior issue | Classified as | Source | Shape overlap with which current finding |
|---|---|---|---|
| Setup check races across instances | `Hardening` | v2.6.4 release notes, "Hardening" section | The bootstrap finding below — same shape: the setup state is per-instance |
| Empty external-auth answer rewrites the stored password | `Security fix` | GHSA-2f7x-4cqm-9h3d | The authentication finding below — same shape, fixed on the admin path only |

**Prior submissions of ours**: one report on the bootstrap finding was
closed with: *"The window needs an instance started with no admin and
whose setup screen was already open to anyone."* The rule extracted
from that closure: **the setup state is per-instance by design, and
exposing an uninitialised instance is an operator deployment decision.**

## Attack Surface (for disclosure purposes)

- `AuthService::login` — the protocol-user login path. Reachable by an
  anonymous client that knows a username. `fixtures/mini-triage/app.php:70`
- `AuthService::probe` — the pre-login probe. `fixtures/mini-triage/app.php:104`
- `AdminService::login` — the administrative login path. `fixtures/mini-triage/app.php:120`
- `SetupService::createFirstAdmin` — the anonymous setup endpoint.
  `fixtures/mini-triage/app.php:158`

## The Three Questions — Coverage Ledger

| Finding | Q1 Premise | Q2 Boundary | Q3 Divergence | Evidence IDs / limitation |
|---|---|---|---|---|
| `auth.empty-external-answer-rewrites-stored-password` | `attacker_only` | `declared_and_violated` | `present` | E000001, E000002, E000003 |
| `setup.bootstrap-fails-open-on-unknown-admin-state` | `requires_operator_decision` | `declared_and_consistent` | `absent` | E000004, E000005, E000006, E000007 |

## Premise Ledger

Every claim a disposition depends on, with the location that was read.

| Protected consumer / claim | Premise `file:line` | Exact condition asserted | Attacker-controlled shape | Evaluated result | Verdict | Evidence IDs |
|---|---|---|---|---|---|---|
| Stored credential of an existing account | `fixtures/mini-triage/app.php:76` | The extension answer is compared against the empty string; an empty answer takes the rewrite branch | The presented password, unauthenticated | The branch writes `password_hash($password)` over the stored hash, so any presented password verifies | ineffective | E000001 |
| Pre-login probe | `fixtures/mini-triage/app.php:106` | The extension answer is compared against the empty string; an empty answer returns false | Same | Returns false — refuses what the login path accepts | effective | E000002 |
| Administrative login | `fixtures/mini-triage/app.php:122` | The extension answer is compared against the empty string; an empty answer returns false | Same | Returns false — refuses what the login path accepts | effective | E000003 |
| Administrator existence | `fixtures/mini-triage/app.php:170` | The administrator count is compared against zero; a failed lookup returns false | Not attacker-controlled; the operator's deployment state gates it | The failed lookup is indistinguishable from "no administrator exists" | ineffective | E000004 |

## Verified Facts

- The protocol-user login path rewrites the stored credential when the
  extension answers empty, and then verifies the presented password
  against the hash it just wrote. `fixtures/mini-triage/app.php:76`
- The pre-login probe refuses the same empty answer.
  `fixtures/mini-triage/app.php:106`
- The administrative login path refuses the same empty answer.
  `fixtures/mini-triage/app.php:122`
- The bootstrap check reports a failed administrator lookup as "no
  administrator exists". `fixtures/mini-triage/app.php:170`
- The bootstrap state is held in a per-process field and is never
  persisted or shared. `fixtures/mini-triage/app.php:158`

## Hypotheses

- If the stored credential rewrite in `AuthService::login` is reachable
  by an anonymous client, then the attacker authenticates as the target
  user because the presented password is verified against a hash the
  same request created. Read at `fixtures/mini-triage/app.php:76`.
  *Disproof*: the branch is unreachable for an existing account, or a
  later check rejects the rewritten hash. **Not disproved** — the
  branch writes and returns unconditionally.
- If a second code path in this version refuses to create a first
  administrator while `SetupService::createFirstAdmin` allows it, then
  the bootstrap behaviour is a same-version divergence.
  *Disproof*: no such path exists. **Disproved** — E000005 and E000006
  are two distinct captured zero-match searches over the target, and
  neither the admin plane nor a persisted/shared administrator state
  exists in this target. The finding therefore rests on the operator
  premise alone.

## Blocked Leads

- Whether the project has a build that persists the administrator state
  across instances. If it does, the bootstrap finding's divergence
  question would need re-running against that build. Not resolvable
  from this target.

## Remaining Questions

Whether the project treats an empty external-auth answer as "no
opinion" in its published contract. The code's own comment says it
does, and the admin path implements it, so the answer is effectively
established for the triage.

---

## Triage Table

```json
{
  "rows": [
    {
      "fingerprint": "auth.empty-external-answer-rewrites-stored-password",
      "title": "An empty external-auth response rewrites the stored password instead of failing the authentication closed",
      "disposition": "send",
      "premise_kind": "attacker_only",
      "boundary_state": "declared_and_violated",
      "divergence_state": "present",
      "divergence_sides": [
        {
          "file_line": "fixtures/mini-triage/app.php:76",
          "behavior": "AuthService::login treats an empty extension answer as a request to set the password, rewriting the stored hash"
        },
        {
          "file_line": "fixtures/mini-triage/app.php:122",
          "behavior": "AdminService::login refuses the same empty extension answer"
        }
      ],
      "subject": "An empty external-authentication response must fail authentication closed; it must never cause the stored credential to be derived from the credential presented by an unauthenticated client.",
      "rationale": "The attacker is anonymous and holds only a username. The extension answering empty is a normal answer shape, not an operator weakening: the product must handle it. The product's own comment and the admin path both state the intended contract, and the login path violates it.",
      "evidence_ids": ["E000001", "E000002", "E000003"]
    },
    {
      "fingerprint": "setup.bootstrap-fails-open-on-unknown-admin-state",
      "title": "The bootstrap check reports an unknown administrator state as an uninitialised instance",
      "disposition": "convert_to_hardening",
      "premise_kind": "requires_operator_decision",
      "boundary_state": "declared_and_consistent",
      "divergence_state": "absent",
      "divergence_absence_searches": [
        {"evidence_id": "E000005"},
        {"evidence_id": "E000006"}
      ],
      "subject": "The bootstrap check must distinguish an unknown administrator state from an instance that has no administrator.",
      "rationale": "The window requires an instance started with no administrator whose setup screen was already open to a reachable network, which is an operator deployment decision. The project already treats this shape as hardening, and no second path in this version refuses to create a first administrator, so there is no divergence to carry a report.",
      "hardening_suggestion": "Make the bootstrap check fail closed on a failed administrator lookup, and report the unknown state to the operator instead of offering the setup screen.",
      "closure_driven": true,
      "evidence_ids": ["E000004", "E000005", "E000006", "E000007"]
    }
  ],
  "question_coverage": [
    {
      "question": "premise",
      "status": "HUNTED",
      "strategy": "Read the login and bootstrap paths and located the exact point where the operator's action becomes required before the attacker's request can proceed.",
      "evidence": ["fixtures/mini-triage/app.php:76", "fixtures/mini-triage/app.php:170"],
      "evidence_ids": ["E000001", "E000004"]
    },
    {
      "question": "boundary",
      "status": "HUNTED",
      "strategy": "Read the project's SECURITY.md and the code's own statements of the intended contract, then compared the two findings against the upstream's prior classification of the same shapes.",
      "evidence": ["fixtures/mini-triage/SECURITY.md", "fixtures/mini-triage/app.php:74"],
      "evidence_ids": ["E000001", "E000003"]
    },
    {
      "question": "divergence",
      "status": "HUNTED",
      "strategy": "Searched for a second path that refuses the same operation under the same condition, across the login plane and the setup plane.",
      "evidence": ["fixtures/mini-triage/app.php:122", "fixtures/mini-triage/app.php:170"],
      "evidence_ids": ["E000002", "E000003", "E000005", "E000006"]
    }
  ],
  "work_queue": [
    {
      "id": "W1",
      "category": "premise",
      "task": "Classify the premise for both findings against the source",
      "priority": "high",
      "reason": "The premise decides whether a report survives review at all",
      "budget_unit": "one read per finding branch",
      "stop_condition": "Both findings have a located gate and a cited kind",
      "status": "completed",
      "outcome": "Login finding is attacker_only; setup finding requires an operator decision",
      "evidence_ids": ["E000001", "E000004"]
    },
    {
      "id": "W2",
      "category": "boundary",
      "task": "Establish the project's acceptance model and prior classification of both shapes",
      "priority": "high",
      "reason": "A disposition judged against the wrong acceptance model is worse than no disposition",
      "budget_unit": "one policy read plus one advisory-history read",
      "stop_condition": "Both shapes are matched to a prior classification",
      "status": "completed",
      "outcome": "Login shape was released as a security fix on the admin path; setup shape was released as hardening",
      "evidence_ids": ["E000001", "E000003"]
    },
    {
      "id": "W3",
      "category": "divergence",
      "task": "Search for a second path that refuses what the reported path allows",
      "priority": "high",
      "reason": "A divergence is the framing that needs no argument about intent",
      "budget_unit": "two captured zero-match searches per shape",
      "stop_condition": "Both sides are cited, or absence is recorded with two distinct searches",
      "status": "completed",
      "outcome": "Login finding has a three-sided divergence; setup finding has no second path and absence is recorded",
      "evidence_ids": ["E000002", "E000003", "E000005", "E000006"]
    },
    {
      "id": "W4",
      "category": "ordering",
      "task": "Choose the send order and the channel",
      "priority": "medium",
      "reason": "The first report establishes credibility for the rest",
      "budget_unit": "one pass over the reportable set",
      "stop_condition": "One channel and a per-position reason are recorded",
      "status": "completed",
      "outcome": "One reportable finding; the private advisory flow is the channel the project uses",
      "evidence_ids": ["E000001"]
    },
    {
      "id": "W5",
      "category": "final_review",
      "task": "Challenge the N/A, hardening, and closure-driven conclusions",
      "priority": "medium",
      "reason": "A downgrade must be as evidenced as an upgrade",
      "budget_unit": "one independent pass over the hardening record",
      "stop_condition": "The hardening conclusion is confirmed against the cited absence searches",
      "status": "completed",
      "outcome": "Confirmed: the setup finding depends on an operator decision and has no divergence, and the upstream already classified this shape as hardening",
      "evidence_ids": ["E000005", "E000006", "E000007"]
    }
  ],
  "premise_checks": [
    {
      "claim": "The protocol-user login path derives the stored credential from the presented password when the extension answers empty",
      "protected_consumer": "The stored credential of an existing account",
      "location": "fixtures/mini-triage/app.php:76",
      "expression": "$answer === '' then store->save(username, password_hash($password), is_admin) and return true",
      "attacker_shape": "An arbitrary password string presented by an unauthenticated client that knows a username",
      "evaluated_result": "The stored hash is replaced and the function returns true, so the presented password verifies against the hash the same request wrote",
      "verdict": "ineffective",
      "evidence_ids": ["E000001"]
    },
    {
      "claim": "The pre-login probe refuses the same empty extension answer",
      "protected_consumer": "The pre-login probe",
      "location": "fixtures/mini-triage/app.php:106",
      "expression": "$answer === '' then return false",
      "attacker_shape": "The same empty extension answer",
      "evaluated_result": "Returns false; the probe refuses what the login path accepts",
      "verdict": "effective",
      "evidence_ids": ["E000002"]
    },
    {
      "claim": "The administrative login path refuses the same empty extension answer",
      "protected_consumer": "The administrative login plane",
      "location": "fixtures/mini-triage/app.php:122",
      "expression": "$answer === '' then return false",
      "attacker_shape": "The same empty extension answer",
      "evaluated_result": "Returns false; the admin plane refuses what the login path accepts",
      "verdict": "effective",
      "evidence_ids": ["E000003"]
    },
    {
      "claim": "A failed administrator lookup is reported as an uninitialised instance",
      "protected_consumer": "The administrator-existence decision",
      "location": "fixtures/mini-triage/app.php:170",
      "expression": "if ($this->queryFails) return false; else return $this->store->countAdmins() > 0;",
      "attacker_shape": "Not attacker-controlled; the operator's deployment state gates the window",
      "evaluated_result": "A failed lookup is indistinguishable from an empty administrators table, so the setup endpoint is offered",
      "verdict": "ineffective",
      "evidence_ids": ["E000004"]
    }
  ],
  "send_order": [
    {
      "position": 1,
      "fingerprint": "auth.empty-external-answer-rewrites-stored-password",
      "disposition": "send",
      "reason": "Cleanest premise in the set: the attacker is anonymous and creates every condition alone, and the divergence is checkable in under a minute. It goes first because it is the most likely to be accepted, not because it is the most severe."
    }
  ],
  "channel": {
    "name": "private-advisory-flow",
    "reason": "The project's SECURITY.md offers two channels without a preference, but every published advisory came through the private advisory flow, so that is the flow the project demonstrably uses.",
    "alternative_considered": "Email to the maintainer address, reserved for a case where anonymity is required."
  },
  "coverage_paragraph_present": true
}
```

## Send Order and Channel

**Channel**: `private-advisory-flow` — **why this one**: the project publishes
its advisories through this flow, and `SECURITY.md` names it as the
alternative it actually uses. Email is reserved for a case where
anonymity is required, and the two are never mixed.

| Order | Finding | Disposition | Subject (the invariant) | Why here |
|---|---|---|---|---|
| 1 | `auth.empty-external-answer-rewrites-stored-password` | `send` | An empty external-authentication response must fail authentication closed; it must never cause the stored credential to be derived from the credential presented by an unauthenticated client. | Cleanest premise in the set and a three-sided divergence. It goes first because it is the most likely to be accepted. |

## How to use this file

1. **Triage round.** Fill in Objective, Trust Ladder, Upstream Prior
   Classification, and Attack Surface. Read the project's acceptance
   policy before answering any question. Then answer the three questions
   for every confirmed finding, and record each answer in the coverage
   ledger and the Premise Ledger.
2. **Frame round.** For each finding that survives, state the subject as
   an invariant. Record the rewrite where the original framing was a
   consequence. Fix the send order and the channel.
3. **Deliver round.** Write one `templates/advisory.md` per reportable
   finding. Every finding in the final report must trace back to a
   Verified Fact and a Premise Ledger row in this file. If it does not,
   it is not ready.

The model can jump between rounds. The file does not enforce a state
machine. The reviewer enforces it by reading.
