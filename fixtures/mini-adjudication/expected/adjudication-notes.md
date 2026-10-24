# Adjudication Notes — mini-adjudication

> Fixture: the expected output of a correct adjudication for
> `fixtures/mini-adjudication/app.php`.
>
> It covers four claim shapes that produce four different verdicts:
> one that holds and would be accepted, one that does not hold, one
> that cannot be settled from source, and one that is already fixed.
> A framework that can only produce "report" is not an adjudication
> framework, so the negative cases are the point of this fixture.

---

## Claims Under Adjudication

| # | Claim (one sentence) | Source of the claim | Current source status |
|---|---|---|---|
| 1 | An empty external-auth response rewrites the stored password, so any password authenticates | our own reading | `live` |
| 2 | The share download path does not check the share token | scanner | `live` |
| 3 | The login path is not rate limited | scanner | `live` |
| 4 | A share session stays valid after the share password is rotated | bounty report | `fixed` |

**Why these claims are being adjudicated**: a batch of candidate
reports arrived from mixed sources, and each one needs a verdict before
any of them is written up.

## Target and Source Ref

- **Target**: the fixture service.
- **Target kind**: `open_source` — the service ships as source with a
  repository, so the OSS Verification section applies.
- **Source ref adjudicated**: the fixture at its current revision.
- **Upstream acceptance policy**: `fixtures/mini-adjudication/SECURITY.md`.
  **Source of authority**: `stated`.
- **Published advisories already checked**: yes — two prior advisories
  recorded in that policy, one classifying the empty-response shape as
  a security fix (ADV-0001, the admin plane) and one classifying the
  setup-window shape as hardening (ADV-0002).

## Claim Decomposition

Each claim is split into the parts that can each be true or false. An
assertion without a `file:line` or a concrete named fact is not ready
to test.

### Claim 1 — empty external-auth response

| # | Assertion | Type | Anchor | Notes |
|---|---|---|---|---|
| A1 | The login path writes the presented password's hash over the stored credential when the extension answers empty | `defect` | `fixtures/mini-adjudication/app.php:116` | |
| A2 | An unauthenticated client reaches the login path | `reachability` | `fixtures/mini-adjudication/app.php:99` | The login entry takes a username and a password and nothing else |
| A3 | The client is then authenticated as that account | `consequence` | `fixtures/mini-adjudication/app.php:117` | The branch returns true immediately after the write |
| A4 | The configured extension answers with an empty body | `precondition` | the configured extension's own response behaviour — not present in this source | Not settleable from this source |

### Claim 2 — share token not checked

| # | Assertion | Type | Anchor | Notes |
|---|---|---|---|---|
| A5 | The download path does not compare the presented share token against the expected one | `defect` | `fixtures/mini-adjudication/app.php:181` | |
| A6 | A caller without a valid share token can therefore download | `reachability` | `fixtures/mini-adjudication/app.php:184` | |

### Claim 3 — login path not rate limited

| # | Assertion | Type | Anchor | Notes |
|---|---|---|---|---|
| A7 | The limiter provides no protection when no per-minute limit is configured | `defect` | `fixtures/mini-adjudication/app.php:227` | The zero-limit branch returns true |
| A8 | The deployment leaves the per-minute limit unconfigured | `precondition` | `fixtures/mini-adjudication/app.php:215` | The value is read from the environment |
| A9 | Authentication attempts are therefore not rate limited | `consequence` | `fixtures/mini-adjudication/app.php:101` | The login path does consult the limiter; whether the limiter binds is decided by A8 |

### Claim 4 — session survives credential rotation

| # | Assertion | Type | Anchor | Notes |
|---|---|---|---|---|
| A10 | The session path accepts a session without comparing it to the current credential | `defect` | `fixtures/mini-adjudication/app.php:250` | The current source compares them |
| A11 | A rotated credential therefore leaves old sessions usable | `consequence` | `fixtures/mini-adjudication/app.php:251` | The comparison returns false, so the session is rejected |

## Assertion Ledger

| Claim | Assertion | Verdict | Refutation attempted | Result | Evidence IDs |
|---|---|---|---|---|---|
| 1 | A1 | `confirmed` | Read the empty-answer branch and looked for a check between the empty test and the write | The write is unconditional; no check intervenes | E000001 |
| 1 | A2 | `confirmed` | Looked for authentication in front of the login entry | The entry takes a username and a password only | E000001 |
| 1 | A3 | `confirmed` | Read the branch's return path and looked for a second credential comparison | There is none; the method returns true right after the write | E000001 |
| 1 | A4 | `unresolved` | Looked for an implementation of the extension in this source | Two distinct patterns, both zero-match; the extension's behaviour is outside this source | E000007, E000008, E000009 |
| 2 | A5 | `refuted` | Read the download path for a token comparison | The path compares the presented token against the expected one with hash_equals | E000004 |
| 2 | A6 | `refuted` | Followed the control flow past the comparison | The comparison returns false and the method returns before the session is read | E000004 |
| 3 | A7 | `confirmed` | Read `allow()` for a branch that denies, including one that survives a configured limit | The only denying path is the one a configured limit takes, and the zero-limit path returns true | E000005 |
| 3 | A8 | `unresolved` | Searched for a limit the source hardcodes or defines as a constant | Two distinct patterns, both zero-match; the value can only come from the environment | E000005, E000010, E000011 |
| 3 | A9 | `unresolved` | Read the login path to confirm the limiter is consulted there, then followed the decision to the configuration value it depends on | The consultation is confirmed; the value that decides whether the limiter binds is not observable from source | E000001, E000005 |
| 4 | A10 | `fixed` | Compared the cited line with the current source | The current source compares the bound credential against the current one | E000006 |
| 4 | A11 | `fixed` | Read the comparison's outcome | The comparison returns false, so the session is rejected | E000006 |

An assertion that was never refuted because no attempt was made is
`unresolved`, not `confirmed`.

## Acceptance Answers

Only claim 1 holds, so it is the only claim that reaches this stage.

| Claim | Q1 Premise | Q2 Boundary | Q3 Divergence | Acceptability | Rationale |
|---|---|---|---|---|---|
| 1 | `attacker_only` | `declared_and_violated` | `present` | `accept` | The attacker is anonymous and holds only a username. The extension answering empty is a documented answer shape, not an operator weakening, and the product's own interface says it means "no opinion" — so the login path violates a rule the product already states, while the probe and the admin plane both honour it. |

## OSS Verification

Only claim 1 holds, so it is the only claim verified against the
project's own record.

| Claim | Policy check | Introducing commit | First release | Fix state | Published as | Similar issues | Maintainer preference |
|---|---|---|---|---|---|---|---|
| 1 | SECURITY.md scope covers the extension's answer shapes; the declared-invariant rule makes an empty answer treated as other than "no opinion" a security fix | untraced — the fixture ships as a single-revision sample; no introducing commit exists to trace | not released — no version tags exist for the fixture | none — the write at `app.php:116` still happens on the empty answer | none found — the policy's advisory table lists ADV-0001 and ADV-0002; neither covers the login path | ADV-0001 → `security_fix` (same empty-answer shape, admin plane) · ADV-0002 → `hardening` (setup window) | Classified by the declared-invariant rule, not severity; both advisories came through the private advisory flow with published credit |

## Verdict Table

| # | Claim | Validity | Acceptability | Subject (the invariant) | Action | Evidence IDs |
|---|---|---|---|---|---|---|
| 1 | empty external-auth response | `holds` | `accept` | An empty external-authentication response must fail authentication closed; it must never cause the stored credential to be derived from the credential presented by an unauthenticated client. | `report` | E000001, E000002, E000003, E000007 |
| 2 | share token not checked | `does_not_hold` | — | — | `no_report` | E000004 |
| 3 | login path not rate limited | `needs_more_evidence` | — | — | `needs_evidence` | E000001, E000005, E000010, E000011 |
| 4 | session survives rotation | `already_fixed` | — | — | `already_fixed` | E000006 |

**Action vocabulary**: `report` / `rewrite_then_report` / `hardening_note` /
`no_report` / `needs_evidence` / `already_fixed`.

## Submission Summary

| Claim | Core business | Developer aware | Special config | Boundary crossed | Primary target | Secondary / unsuitable |
|---|---|---|---|---|---|---|
| 1 | yes — SECURITY.md scope names the authentication paths and the extension's answer shapes | false — no comment, TODO, or partial guard on the login path (E000001); the sibling paths guard the same answer without marking this one known-risk | not required — an extension answering empty is documented normal operation (app.php:77-83), not a weakened configuration | from an unauthenticated network client holding only a username, to rewriting the stored credential of any named account and authenticating as it | `vendor_advisory` — the policy names the private advisory flow and every published advisory used it | `cve_cna` secondary — via the maintainer's published advisory · `cnvd` unsuitable — not a distributed product with internet instances · `src_platform` unsuitable — not a vendor asset |

## Work Queue

| id | category | task | priority | reason | budget_unit | stop_condition | status | outcome | evidence_ids |
|---|---|---|---|---|---|---|---|---|---|
| W1 | validity | Decompose and test every claim's assertions | high | A claim that cannot be decomposed cannot be judged | one read per assertion | Every assertion has a verdict with evidence | completed | Four claims adjudicated; one holds, one is refuted, one needs evidence, one is fixed | E000001, E000004, E000005, E000006 |
| W2 | acceptance | Read the policy and answer the three questions for holding claims | high | A verdict against the wrong acceptance model is worse than no verdict | one policy read plus three reads | The holding claim has all three answers | completed | Claim 1 is attacker_only, boundary violated, divergence present | E000002, E000003, E000007 |
| W3 | artifact | Produce the artifact each verdict calls for | medium | The artifact must match the verdict, not the claim's tone | one artifact per claim | Every claim has its artifact | completed | One advisory, three written findings | E000001, E000004, E000005, E000006 |
| W4 | ordering | Choose the delivery order and the channel | medium | The first report sets the credibility for the rest | one pass over the reportable set | One channel and a per-position reason | completed | One reportable claim; the private advisory flow is the channel the project uses | E000001 |
| W5 | final_review | Challenge the does_not_hold and needs_more_evidence verdicts | medium | A downgrade must be as evidenced as an upgrade | one independent pass per negative verdict | Each negative verdict is confirmed against its evidence | completed | Confirmed: the share path compares the token, and the rate limit is a deployment value this source cannot settle | E000004, E000005, E000010, E000011 |

## Refutations Considered and Rejected

| Claim | Attempted refutation | Why it did not refute |
|---|---|---|
| 1 | Looked for a check between the empty test and the write that rejects the presented password | The branch writes and returns unconditionally; there is no intervening check |
| 1 | Looked for a second guard on the login path that rejects an empty extension answer | Two sibling paths have exactly that guard, which is why their presence is the divergence rather than a refutation of this claim |
| 2 | Looked for a token comparison elsewhere in the path that might make the in-path check redundant | The check is in the path, and it is the only one; the claim named no line, so the question was whether the guard existed at all, and it does |
| 3 | Looked for a limit value that the source supplies itself, which would have settled the claim | Neither a hardcoded numeric limit nor a rate constant exists anywhere in the source; the value can only arrive from the environment |

## Remaining Questions

Whether the configured extension in the real deployment ever answers
with an empty body, and if so how often. This does not change claim 1's
verdict — the defect is that the product mishandles that answer shape —
but it changes the practical urgency, and the report states it as a
precondition rather than a certainty.

---

## Adjudication Table

```json
{
  "target": {
    "kind": "open_source",
    "name": "the fixture service",
    "security_policy": {
      "source": "stated",
      "ref": "fixtures/mini-adjudication/SECURITY.md"
    },
    "preferred_channel": "private-advisory-flow"
  },
  "claims": [
    {
      "id": "C1",
      "claim": "An empty external-auth response rewrites the stored password, so any password authenticates",
      "claim_source": "our own reading",
      "source_ref": "fixture at current revision",
      "assertions": [
        {
          "id": "A1",
          "type": "defect",
          "statement": "The login path writes the presented password's hash over the stored credential when the extension answers empty",
          "anchor": "fixtures/mini-adjudication/app.php:116",
          "verdict": "confirmed",
          "refutation_attempted": "Read the empty-answer branch and looked for a check between the empty test and the write",
          "evidence_ids": ["E000001"]
        },
        {
          "id": "A2",
          "type": "reachability",
          "statement": "An unauthenticated client reaches the login path",
          "anchor": "fixtures/mini-adjudication/app.php:99",
          "verdict": "confirmed",
          "refutation_attempted": "Looked for authentication in front of the login entry",
          "evidence_ids": ["E000001"]
        },
        {
          "id": "A3",
          "type": "consequence",
          "statement": "The client is then authenticated as that account, because the branch returns true immediately after the write",
          "anchor": "fixtures/mini-adjudication/app.php:117",
          "verdict": "confirmed",
          "refutation_attempted": "Read the branch's return path and looked for a second credential comparison",
          "evidence_ids": ["E000001"]
        },
        {
          "id": "A4",
          "type": "precondition",
          "statement": "The configured extension answers with an empty body",
          "anchor": "the configured extension's own response behaviour, which is not present in this source",
          "verdict": "unresolved",
          "refutation_attempted": "Looked for an implementation of the extension in this source with two distinct patterns; both were zero-match",
          "absence_searches": [
            {"evidence_id": "E000008"},
            {"evidence_id": "E000009"}
          ],
          "evidence_ids": ["E000007", "E000008", "E000009"]
        }
      ],
      "validity": "holds",
      "validity_rationale": "The defect, the reachability and the consequence are all confirmed in source. The precondition is unresolved, but it is a precondition of the trigger, not of the defect: the product mishandles the empty answer shape regardless of how often the extension produces it.",
      "acceptance": {
        "premise_kind": "attacker_only",
        "premise_evidence": "fixtures/mini-adjudication/app.php:99 — the login entry takes a username and a password and nothing else",
        "boundary_state": "declared_and_violated",
        "boundary_evidence": [
          "fixtures/mini-adjudication/app.php:78 — the extension's own interface says an empty string means 'no opinion'",
          "fixtures/mini-adjudication/app.php:135 — the pre-login probe refuses the same empty answer",
          "fixtures/mini-adjudication/app.php:157 — the admin plane refuses the same empty answer"
        ],
        "divergence_state": "present",
        "divergence_sides": [
          {
            "file_line": "fixtures/mini-adjudication/app.php:108",
            "behavior": "The login path reads the empty answer as a request to set the password, writes the hash of what the client presented, and authenticates the client"
          },
          {
            "file_line": "fixtures/mini-adjudication/app.php:156",
            "behavior": "The admin plane reads the same empty answer as no opinion and refuses the login"
          }
        ],
        "acceptability": "accept",
        "rationale": "The attacker is anonymous and holds only a username. The extension answering with an empty body is a documented answer shape rather than an operator weakening, and the product's own two sibling paths refuse it, so the intent is not in question.",
        "oss_verification": {
          "policy_verified": "SECURITY.md puts the authentication paths and the extension's answer shapes in scope, and its declared-invariant rule classifies a path that treats an empty answer as other than 'no opinion' as a security fix (the ADV-0001 precedent on the admin plane).",
          "commit_timeline": {
            "introducing_commit": "untraced — the fixture ships as a single-revision sample; no introducing commit exists to trace",
            "released_in": "not released — the fixture is not distributed under version tags",
            "fix_state": "none on main — the write at app.php:116 still happens on the empty answer",
            "published_as": "none found — the policy's advisory table lists ADV-0001 and ADV-0002; neither covers the login path"
          },
          "historical_similar": [
            {
              "ref": "ADV-0001 (SECURITY.md advisory table)",
              "classification": "security_fix"
            },
            {
              "ref": "ADV-0002 (SECURITY.md advisory table)",
              "classification": "hardening"
            }
          ],
          "maintainer_preference": "The project classifies by the declared-invariant rule rather than severity: a stated rule violated on one path is a security fix (ADV-0001), a control the product never claimed to have is hardening (ADV-0002). Both advisories came through the private advisory flow with published credit.",
          "evidence_ids": ["E000001", "E000002", "E000003", "E000007"]
        },
        "evidence_ids": ["E000001", "E000002", "E000003", "E000007"]
      },
      "subject": "An empty external-authentication response must fail authentication closed; it must never cause the stored credential to be derived from the credential presented by an unauthenticated client.",
      "action": "report",
      "artifact": "expected/advisory.md",
      "submission": {
        "core_business": {
          "in_core": true,
          "evidence": "SECURITY.md scope names the authentication paths, including the external authentication extension's answer shapes; the login path is the service's advertised entry"
        },
        "developer_awareness": {
          "aware": "false",
          "evidence": "No comment, TODO, or partial guard between the empty-answer test and the write (E000001); the sibling paths guard the same answer shape without marking this one as known-risk"
        },
        "trigger_configuration": {
          "special_config_required": false,
          "default_configuration": "Default operation: the extension interface ships in-source and an empty answer is a documented shape (app.php:77-83), so the trigger is normal operation, not a weakened configuration",
          "evidence": "fixtures/mini-adjudication/app.php:77-83 — the interface documents the empty string as a normal answer"
        },
        "boundary_crossed": {
          "from": "an unauthenticated network client holding only a username",
          "to": "rewriting the stored credential of any named account and authenticating as it"
        },
        "targets": [
          {
            "target": "vendor_advisory",
            "fit": "primary",
            "reason": "SECURITY.md names the private advisory flow and every published advisory came through it"
          },
          {
            "target": "cve_cna",
            "fit": "secondary",
            "reason": "Reached through the maintainer's published advisory when it publishes; a CVE follows the advisory rather than preceding it"
          },
          {
            "target": "cnvd",
            "fit": "unsuitable",
            "reason": "The 通用型 bar is not met: the fixture is not a distributed product with multiple internet instances, and no PoC against real deployments exists"
          },
          {
            "target": "src_platform",
            "fit": "unsuitable",
            "reason": "Not a vendor asset; no SRC covers this project"
          }
        ]
      },
      "evidence_ids": ["E000001", "E000002", "E000003", "E000007"]
    },
    {
      "id": "C2",
      "claim": "The share download path does not check the share token",
      "claim_source": "scanner",
      "source_ref": "fixture at current revision",
      "assertions": [
        {
          "id": "A5",
          "type": "defect",
          "statement": "The download path does not compare the presented share token against the expected one",
          "anchor": "fixtures/mini-adjudication/app.php:181",
          "verdict": "refuted",
          "refutation_attempted": "Read the download path for a token comparison",
          "evidence_ids": ["E000004"]
        },
        {
          "id": "A6",
          "type": "reachability",
          "statement": "A caller without a valid share token can therefore download",
          "anchor": "fixtures/mini-adjudication/app.php:184",
          "verdict": "refuted",
          "refutation_attempted": "Followed the control flow past the comparison",
          "evidence_ids": ["E000004"]
        }
      ],
      "validity": "does_not_hold",
      "validity_rationale": "The download path compares the presented token against the expected one with hash_equals and returns before the session is read, so both the defect assertion and the reachability assertion are refuted by the same guard.",
      "action": "no_report",
      "artifact": "expected/refutation.md",
      "evidence_ids": ["E000004"]
    },
    {
      "id": "C3",
      "claim": "The login path is not rate limited",
      "claim_source": "scanner",
      "source_ref": "fixture at current revision",
      "assertions": [
        {
          "id": "A7",
          "type": "defect",
          "statement": "The limiter provides no protection when no per-minute limit is configured",
          "anchor": "fixtures/mini-adjudication/app.php:227",
          "verdict": "confirmed",
          "refutation_attempted": "Read allow() for a branch that denies, including one that survives a configured limit",
          "evidence_ids": ["E000005"]
        },
        {
          "id": "A8",
          "type": "precondition",
          "statement": "The deployment leaves the per-minute limit unconfigured",
          "anchor": "fixtures/mini-adjudication/app.php:215",
          "verdict": "unresolved",
          "refutation_attempted": "Searched for a limit the source hardcodes or defines as a constant with two distinct patterns; both were zero-match",
          "absence_searches": [
            {"evidence_id": "E000010"},
            {"evidence_id": "E000011"}
          ],
          "evidence_ids": ["E000005", "E000010", "E000011"]
        },
        {
          "id": "A9",
          "type": "consequence",
          "statement": "Authentication attempts are therefore not rate limited",
          "anchor": "fixtures/mini-adjudication/app.php:101",
          "verdict": "unresolved",
          "refutation_attempted": "Read the login path to confirm the limiter is consulted there, then followed the decision to the configuration value it depends on",
          "evidence_ids": ["E000001", "E000005"]
        }
      ],
      "validity": "needs_more_evidence",
      "validity_rationale": "The limiter's behaviour is confirmed: with no configured limit it permits every attempt, and the login path does consult it. What this source cannot settle is the deployment value that decides whether the limit binds — the source only shows where the value is read, and neither a hardcoded limit nor a rate constant exists anywhere in it. The consequence the claim asserts is therefore not established, and an unestablished consequence does not leave the claim holding.",
      "action": "needs_evidence",
      "artifact": "expected/refutation.md",
      "evidence_ids": ["E000001", "E000005", "E000010", "E000011"]
    },
    {
      "id": "C4",
      "claim": "A share session stays valid after the share password is rotated",
      "claim_source": "bounty report",
      "source_ref": "fixture at current revision",
      "assertions": [
        {
          "id": "A10",
          "type": "defect",
          "statement": "The session path accepts a session without comparing it to the current credential",
          "anchor": "fixtures/mini-adjudication/app.php:250",
          "verdict": "fixed",
          "refutation_attempted": "Compared the cited line with the current source",
          "evidence_ids": ["E000006"]
        },
        {
          "id": "A11",
          "type": "consequence",
          "statement": "A rotated credential therefore leaves old sessions usable",
          "anchor": "fixtures/mini-adjudication/app.php:251",
          "verdict": "fixed",
          "refutation_attempted": "Read the comparison's outcome",
          "evidence_ids": ["E000006"]
        }
      ],
      "validity": "already_fixed",
      "validity_rationale": "The current source compares the bound credential against the current one and returns false when they differ, so a rotated credential ends the session. The claim described the behaviour before that comparison was added.",
      "action": "already_fixed",
      "artifact": "expected/refutation.md",
      "evidence_ids": ["E000006"]
    }
  ],
  "work_queue": [
    {
      "id": "W1",
      "category": "validity",
      "task": "Decompose and test every claim's assertions",
      "priority": "high",
      "reason": "A claim that cannot be decomposed cannot be judged",
      "budget_unit": "one read per assertion",
      "stop_condition": "Every assertion has a verdict with evidence",
      "status": "completed",
      "outcome": "Four claims adjudicated; one holds, one is refuted, one needs evidence, one is fixed",
      "evidence_ids": ["E000001", "E000004", "E000005", "E000006"]
    },
    {
      "id": "W2",
      "category": "acceptance",
      "task": "Read the policy and answer the three questions for holding claims",
      "priority": "high",
      "reason": "A verdict against the wrong acceptance model is worse than no verdict",
      "budget_unit": "one policy read plus three reads",
      "stop_condition": "The holding claim has all three answers",
      "status": "completed",
      "outcome": "Claim 1 is attacker_only, boundary violated, divergence present",
      "evidence_ids": ["E000002", "E000003", "E000007"]
    },
    {
      "id": "W3",
      "category": "artifact",
      "task": "Produce the artifact each verdict calls for",
      "priority": "medium",
      "reason": "The artifact must match the verdict, not the claim's tone",
      "budget_unit": "one artifact per claim",
      "stop_condition": "Every claim has its artifact",
      "status": "completed",
      "outcome": "One advisory, three written findings",
      "evidence_ids": ["E000001", "E000004", "E000005", "E000006"]
    },
    {
      "id": "W4",
      "category": "ordering",
      "task": "Choose the delivery order and the channel",
      "priority": "medium",
      "reason": "The first report sets the credibility for the rest",
      "budget_unit": "one pass over the reportable set",
      "stop_condition": "One channel and a per-position reason",
      "status": "completed",
      "outcome": "One reportable claim; the private advisory flow is the channel the project uses",
      "evidence_ids": ["E000001"]
    },
    {
      "id": "W5",
      "category": "final_review",
      "task": "Challenge the does_not_hold and needs_more_evidence verdicts",
      "priority": "medium",
      "reason": "A downgrade must be as evidenced as an upgrade",
      "budget_unit": "one independent pass per negative verdict",
      "stop_condition": "Each negative verdict is confirmed against its evidence",
      "status": "completed",
      "outcome": "Confirmed: the share path compares the token, and the rate limit is a deployment value this source cannot settle",
      "evidence_ids": ["E000004", "E000005", "E000010", "E000011"]
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

## Delivery Plan

**Channel**: `private-advisory-flow` — **why this one**: the project publishes
its advisories through this flow, and `SECURITY.md` names it as the
alternative it actually uses. Email is reserved for a case where
anonymity is required, and the two are never mixed.

| Order | Claim | Action | Artifact | Why here |
|---|---|---|---|---|
| 1 | C1 | `report` | `expected/advisory.md` | The only claim that holds, and its premise is clean enough to open the relationship |
| — | C2 | `no_report` | `expected/refutation.md` | Not a vulnerability; recorded so the scanner's report is not re-raised |
| — | C3 | `needs_evidence` | `expected/refutation.md` | Blocked on a deployment fact; not reportable until it is observed |
| — | C4 | `already_fixed` | `expected/refutation.md` | Fixed in the current source; re-reporting would be a duplicate |

## How to use this file

1. **Adjudicate round.** For each claim: confirm it is live in the
   current source, split it into assertions, and test each one. Try to
   kill it. Record the validity verdict with cited evidence.
2. **Assess round.** For claims that hold: read the project's
   acceptance policy, answer the three acceptance questions, and —
   when the target is open source — complete the OSS Verification
   row: policy check, commit timeline, similar issues, maintainer
   preference.
3. **Deliver round.** Produce the artifact the verdict calls for, and
   only that artifact. A claim that does not hold gets a written
   finding, not a report. Every reportable claim gets its submission
   row and the summary closes with the submittable list.

The model can jump between rounds. The file does not enforce a state
machine. The reviewer enforces it by reading.
