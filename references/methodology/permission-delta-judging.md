<!-- Loaded by mini-audit skill: methodology (pre-flight + chamber + cold-verifier) -->
<!-- Used in phase(s): pre-flight for every audit; mandatory reference for L6/L10/V5 chamber (synthesizer + advocate + ideator) and L7/P11/V6 cold-verifier -->
<!-- Source: distilled from repeated administrator rejections of over-eager findings -->

# Permission-delta judging framework (权限增量判定)

> **Core principle (one line):**
> Do not judge a vulnerability by how dangerous the final effect looks. Judge whether the attacker obtained a **new capability the product did not originally grant them** — i.e. whether they truly crossed a security boundary.

This is the cross-class **judging meta-rule** for mini-audit. It does not replace
class-specific hunting methodology (`hunting/hunt-<c>.md`) or class-specific
technical reference (`vuln-classes/<c>.md`); it sits one layer above and answers
the question "is this a real boundary crossing at all?".

## Decision chain (use this, not the traditional one)

The agent's final judgment should center on this chain:

```
Actor → Existing Authority → Intended Security Invariant
     → Attacker-Controlled Input → Missing/Broken Check
     → Boundary Crossed → New Capability
```

Not the traditional:

```
Input → Dangerous API → Scary Impact
```

The traditional chain over-weights the sink ("`Runtime.exec` was reached, RCE!")
and under-weights the privilege delta ("the attacker already had admin, this is
post-compromise"). The permission-delta chain inverts the priority: the boundary
crossing and the new capability are the only things that can promote a finding
to a real vulnerability.

## Hard rule (compressed)

A finding is a confirmed security vulnerability **only when all of these are
true**:

1. Attacker-controlled input **bypasses a provable** auth / identity / tenant /
   isolation / resource-access **constraint** the product explicitly maintains
   for that surface; AND
2. The bypass produces a **real privilege delta** (the attacker can do something
   they could not do before through any normal feature); AND
3. The behavior is **not explicitly designed** into the product; AND
4. The behavior is **not equivalent** to a capability the attacker already
   has through their pre-existing authority; AND
5. The behavior is **not post-compromise** — i.e. it does not require a
   precondition (root, shell, arbitrary DB write, admin control) that
   already grants the same or greater impact.

If any of (1)–(5) fails, the finding is at most a hardening item, a feature
request, a documentation gap, or a post-compromise artifact — not a confirmed
vulnerability.

## Attacker identification (mandatory)

State the attacker concretely. The following categories are the minimum
vocabulary; use them verbatim and reject any finding that uses only the word
"attacker":

- Unauthenticated internet user (no account, no token, no link)
- Holder of a public-by-design link / share token
- Authenticated ordinary user (lowest privilege tier)
- Authenticated user with elevated tier (e.g. team lead, channel moderator)
- Workspace / tenant administrator
- System administrator of the deployment
- Local CLI user (machine shell, not network)
- User with arbitrary read/write to Redis / MySQL / object store
- User with arbitrary code execution on a host (already shell)
- Internal service identity (east-west traffic)

If the finding does not name a specific attacker category, the chamber cannot
evaluate the privilege delta and must return `INSUFFICIENT_CONTEXT`.

## Security boundary inventory (where to look)

For each finding, identify the boundary it claims to cross. Common boundaries
that **must** be present in the analysis when applicable:

- Unauthenticated ↔ authenticated
- Ordinary user ↔ administrator
- User A ↔ user B (horizontal authz)
- Tenant A ↔ tenant B (multi-tenancy isolation)
- Workspace ↔ arbitrary host filesystem
- Public ↔ private resource visibility
- Restricted script ↔ host execution environment (e.g. sandbox escape)
- External network ↔ internal network
- Read-only ↔ write
- Browser sandbox ↔ OS / native (XSS → RCE on a sensitive action)
- HTTP-only ↔ token-bearing WebSocket / SSE

A finding that does not name the boundary it crosses is, at best, a sink
discovery — not a vulnerability.

## Privilege delta, not dangerous sinks

`Runtime.exec`, `eval`, 302 redirect, "any URL accepted", file read, SQL
concatenation, deserialization, `document.write` — **none of these prove a
vulnerability on their own**. Each one can be reached legitimately.

A finding must prove the attacker **used the sink to do something their
existing role could not do through the normal API**. The proof is the delta
in capability, not the existence of the sink.

## Equivalence test

Ask: *without using this finding, would a user with the same pre-existing
authority reach basically the same effect through normal features?*

Example: an admin can already run arbitrary scripts. If the finding shows an
admin path through `Nashorn` to `Runtime.exec`, the privilege delta is
approximately zero — the admin could have run the same code via the legitimate
admin console. This is not a vulnerability.

## Pre-condition swallowing impact test

If the exploit requires the attacker to already have one of:

- root / shell on the target host
- arbitrary write to the production database
- arbitrary write to Redis / cache
- full admin control of the product
- an account that can sign and distribute code

…and that precondition already grants the same or greater impact, then the
finding is **post-compromise behavior, not a new vulnerability**. Document the
behavior under the relevant threat model, but do not promote it to a finding.

## By-design is not a vulnerability

If the product documentation explicitly states a behavior, that behavior is
not a vulnerability, even if it looks bad in isolation. Examples:

- An "Anyone with the link" share that grants read without login → anonymous
  read is by design; the real question is whether the share ID is
  predictable, enumerable, or survives revocation.
- The first user registered against an empty database becoming admin → this
  is empty-bootstrap initialization, not privilege escalation.
- A workspace admin being able to install unverified apps → admin-tier
  capability, not a sandbox escape.

When a finding rests on a documented behavior, the chamber must mark it
`INVALID — by-design` and surface the behavior name + doc reference in the
debate log.

## Default config and permission threshold must be verified

Demonstrating that *an admin can enable a dangerous mode* is not a
vulnerability. The chamber must additionally verify:

- Is the dangerous mode **off by default** in a fresh install?
- Can a non-admin toggle it, or is the toggle admin-gated?
- Do API endpoints strip the relevant field for non-admin callers?
- Does the configuration require an admin to explicitly authorize it?

A PoC that succeeds under admin authority does not generalize to a normal
attacker. State explicitly which authority class the PoC was run under.

## User-initiated execution is not a boundary bypass

Phishing a user into running a malicious CLI command, installing a malicious
package, or executing a script the user has the right to execute anyway is
the user exercising a capability they already had. This is social
engineering, not a product security boundary bypass — unless the product
removes or distorts the consent signal (e.g. silently re-running a command
the user did not invoke, or hiding a privileged operation behind an unrelated
UI element).

The rule: a finding must show the user **did not consent to the specific
operation that crossed the boundary**, not merely that the operation is
dangerous if a user were tricked into running it.

## Bearer URLs and tokens may be by-design

If the product treats the URL itself as a bearer capability, then "knowing the
share ID and reading without login" is the intended access model. The
vulnerability is in the **properties of the bearer**:

- Predictable / sequential IDs
- Enumerable across users
- Cross-user acquisition (e.g. by guessing another tenant's namespace)
- No revocation or stale-after-rotation
- No expiration
- Private resource accessible through the public share path

Do not write a finding whose claim is "I read a file I had the URL for". Write
the finding around the broken property of the bearer (predictability,
enumeration, revocation gap, etc.).

## Hardening is not a vulnerability

The following are **hardening or feature requests**, not security
vulnerabilities, unless they are the proximate cause of a broken boundary:

- Missing confirmation dialog
- Missing audit log
- Missing rate limiting
- Missing expiration on a token / link
- Missing default-off toggle for a dangerous mode
- Inconsistent default vs. documented behavior
- Poor privacy UX (data leakage through thumbnails, logs, etc.)
- Insecure default that the admin can immediately flip

A finding must demonstrate that the **omission directly causes a product-
promised boundary to fail**, not that the omission is a bad smell.

## Real client behavior must be verified, not assumed

Common over-confident claims that the chamber must reject without
executable evidence:

- "Referer leaks the path" — verify that the current default referrer policy
  of the affected browsers actually leaks the path; verify with a real
  request capture.
- "302 redirect shows the new URL in the address bar" — verify on a real
  browser; some redirect chains hide the new URL.
- "`<img src=javascript:...>` renders" — modern browsers do not.
- "`<a download>` will save an arbitrary file" — verify the
  Content-Disposition and origin behavior.
- "Service worker can intercept cross-origin requests" — verify scope and
  registration flow.

Speculation is not evidence. The finding must cite the request, response,
or DOM observation that supports the claim.

## Real affected scope must be verified

- Channel members ≠ internet users
- Workspace members ≠ tenant-crossing attackers
- Authenticated users in a tier ≠ all authenticated users
- v1.2.0 behavior ≠ current behavior (if the bug was fixed in v1.2.1)
- Endpoint behind a feature flag ≠ endpoint in general availability

A finding must state the **specific deployment shape** under which the
impact holds, and call out the configurations / versions / tiers where it
does not.

## Permission model must be accurate

Inventing permissions that do not exist (e.g. claiming there is a
`webhook.write` ordinary user capability that does not appear in the product
docs) destroys the credibility of the entire report. Before writing a
finding:

- Enumerate the actual permission names from the product's RBAC source
- Enumerate the actual scopes from the OAuth / API token model
- Enumerate the actual channel / workspace roles from the product

If a permission is not on the list, the finding must not invoke it.

## PoC can only prove what was actually verified

Do not let a PoC slide into:

- "This likely depends on isolation level" → "race verified end-to-end"
- "If the request races" → "two simultaneous registrations produced two
  admins"
- "In theory the attacker can" → "the PoC sent this payload and got this
  response"
- "The sink is reachable" → "the sink is reachable from an unauthenticated
  attacker-controlled input and the gate does not check it"

The finding body and CVSS must reflect **what the PoC actually did**, not
what the PoC *could have done* under unspecified conditions.

## Title, impact, and CVSS must align to the actual privilege delta

High-severity keywords (`RCE`, `admin`, `chat content`, `production DB`,
`shell`) are not free. A finding is high severity only if the privilege delta
matches:

- `RCE` requires unauthenticated or low-privilege attacker reaching code
  execution on a host they otherwise cannot reach.
- "Read all chat content" requires crossing the user-A / user-B boundary for
  an ordinary user, not an admin reading their own workspace.
- "Privilege escalation" requires a documented authority tier above the
  attacker's pre-existing tier.

If the boundary is not crossed, or the crossed capability is already
available to the attacker's tier, the CVSS does not deserve a high rating.
Round the score down and explain the rationale in the finding.

## Fix recommendations must not prove the vulnerability

A fix recommendation of the form "add a confirmation dialog", "turn it off
by default", "add an audit log", "add an expiration" is **not** evidence
that the current state is a vulnerability. It only makes sense if the
current state already crosses a boundary the product is supposed to
maintain.

If the recommendation is "make the current behavior less dangerous" but the
current behavior is:

- already admin-only
- already default-off
- already explicit / consented
- already documented as by-design

…then the recommendation is hardening, and the finding should be
re-classified accordingly.

## "Bad design" vs "broken boundary" — separate categories

| Category | Examples | Verdict |
|----------|----------|---------|
| Bad design (hardening) | Dangerous default, missing audit, inconsistent UX, privacy smell, config friction | Hardening item, not a vulnerability |
| Broken boundary (vuln) | Ordinary user reads another user's private data; low-privilege script escapes to host; tenant A operates on tenant B; user self-promotes to admin; private resource exposed via public share path | Confirmed vulnerability |

These are not on the same axis. Do not promote a bad-design finding into a
broken-boundary finding because the impact would look better in the report.

## Final counterfactual test (mandatory before any `VALID` verdict)

> **After the proposed fix is applied, but with the attacker's pre-existing
> privileges unchanged, can the attacker still reach the same effect
> through normal product features?**

If **yes**, the finding has no independent security value — the fix is
hardening, not a boundary repair. Reject the finding as `INVALID —
equivalent capability` or `INVALID — post-compromise behavior`.

If **no**, the finding is a real boundary crossing and may be promoted.

## One-sentence gate (mandatory)

A finding can only be confirmed if the chamber can fill in both blanks of
this sentence cleanly:

> "An attacker who could previously only **________**, through this finding,
> can now **________**, which the product's permission / isolation model
> did not allow."

If the two blanks describe essentially the same capability, or if either
blank cannot be filled concretely, the finding is not a confirmed
vulnerability.

## Anti-patterns (do not write findings like these)

These are common over-eager patterns the chamber should reject on sight:

1. **Sink-driven**: "`Runtime.exec` reachable from user input" — without
   proving the attacker is not already authorized to run commands.
2. **Keyword CVSS**: severity raised because the word "admin" or "RCE"
   appears, regardless of the privilege delta.
3. **Hypothetical chain**: PoC reaches step 2 of 5, finding writes
   "this is an unauthenticated RCE" assuming steps 3-5 work.
4. **Default-state confusion**: "the dangerous toggle exists" written as
   "any user can flip it" without verifying the default and the authz.
5. **By-design as vuln**: documented behavior written as a vulnerability
   with no engagement of the documentation.
6. **Same-privilege escalation**: finding shows admin doing admin things
   through an unusual path, written as privilege escalation.
7. **Post-compromise as vuln**: shell-on-host attacker reaches an
   additional data sink, written as a new boundary crossing.
8. **Invented permission**: claim invokes a role / scope / permission that
   does not exist in the product.
9. **Fix-as-proof**: "we recommend adding a confirmation dialog" used
   as evidence that the current behavior is unsafe.
10. **Speculative client behavior**: claim about Referer, redirect,
    Service Worker, or download behavior without an executable test.

## What this means for chamber roles

- **attack-ideator** — When generating hypotheses, gate each candidate against
  the one-sentence test. If you cannot fill both blanks, drop the hypothesis
  before dispatching the chamber.
- **code-tracer** — When marking a hypothesis REACHABLE, also state the
  attacker's pre-existing authority and the boundary that would be crossed.
  A REACHABLE sink is not enough.
- **devils-advocate** — Apply the anti-patterns list above as your
  checklist. If a finding matches any of them, your job is to break it
  before the synthesizer promotes it.
- **chamber-synthesizer** — The one-sentence test and the counterfactual
  test are gate conditions for `VALID`. A draft that cannot pass both is
  `INVALID — <category from the list above>`.
- **cold-verifier** — Load this file (class-agnostic meta-rule) but **not**
  the chamber debate log. Apply the rules independently. The isolation
  property is preserved by what you *don't read* (chamber workspace, probe
  workspace, prior verdicts), not by skipping this methodology.
- **static-analyzer** — When SAST flags a sink, also flag the missing
  authority / boundary check that would make the sink reachable from an
  attacker-controlled input. A reachable sink without a missing check is a
  hardening signal, not a vulnerability.

## `judge` mode (J1 + J2) — meta-audit re-judgment phase

This methodology is also the primary standard for the **`judge`** mode
(`--action=run --mode=judge`), which is a meta-audit run against an existing
audit's findings. The two-phase protocol:

### J1 — per-finding re-judgment

The orchestrator dispatches `mini-audit-judge` once per
`mini-audit/findings/<id>-<slug>/` directory. Each dispatch is a fresh agent
session with only this methodology file inlined; the agent does not see the
chamber debate, the probe workspace, the audit state, or other findings'
verdicts. The agent writes a `<id>-<slug>/judge-verdict.md` per finding, with
the structure documented in the `mini-audit-judge` agent prompt.

The verdict categories are an extension of this methodology's hard rule:

- `VALID` — passes 5-condition + one-sentence + counterfactual + no
  unrefuted anti-patterns
- `INSUFFICIENT-CONTEXT` — attacker not named; kick back to chamber
- `INVALID-by-design` — documented behavior
- `INVALID-equivalent-capability` — counterfactual failed
- `INVALID-post-compromise` — requires shell / DB-write that already grants
  the same impact
- `INVALID-invented-permission` — role / scope / permission not in product
- `INVALID-keyword-cvss` — severity assigned from dangerous keywords alone
- `INVALID-hypothetical-chain` — PoC reached step 2 of N, claim assumes N
- `INVALID-default-state-confusion` — admin can toggle, but off by default
  and admin-gated
- `INVALID-speculative-client-behavior` — claim about browser behavior
  without executable evidence
- `INVALID-fix-as-proof` — finding exists to justify its own fix

### J2 — aggregate report

The orchestrator (not a sub-agent) walks all `judge-verdict.md` files and
writes `mini-audit/judge-report.md` with the **full per-finding table** and
the proposed re-classifications. **J2 produces ONE aggregated re-classification
table covering all findings, NOT per-finding prompts.** The user reviews the
full table once at the end and either accepts all proposed re-classifications,
accepts with edits, or rejects and keeps the original chamber verdict. J2 is
the **only phase in mini-audit that pauses for explicit user approval** of
a finding re-classification; the other phases surface a report but proceed
automatically. If the audit has zero conflicts (chamber + cold-verifier +
judge all agree), the user is shown a one-line "no re-classification
proposed" message and the audit completes without pause.

### Re-classification rules (apply in J2)

| Judge verdict | Default re-classification |
|---------------|---------------------------|
| `VALID` (matches chamber + cold-verifier) | keep, no change |
| `VALID` (judge disagrees with chamber) | surface disagreement, ask user |
| `INSUFFICIENT-CONTEXT` | `→ re-dispatch` (specific gap named) |
| `INVALID-by-design` | `→ drop` (or `→ hardening` if it has independent value) |
| `INVALID-equivalent-capability` | `→ hardening` |
| `INVALID-post-compromise` | `→ drop` |
| `INVALID-invented-permission` | `→ re-dispatch` (cite real permission model) |
| `INVALID-keyword-cvss` | `→ keep-with-adjusted-severity` |
| `INVALID-hypothetical-chain` | `→ re-dispatch` (which step missing) |
| `INVALID-default-state-confusion` | `→ drop` |
| `INVALID-speculative-client-behavior` | `→ re-dispatch` (require executable test) |
| `INVALID-fix-as-proof` | `→ drop` |

### When to run judge mode

- After `balanced` or `deep` whenever the user wants a sanity check on the
  chamber's confidence.
- After `confirm` (V-series) to re-check the confirm pass against the
  framework.
- After `revisit` (R-series) to verify the anti-anchoring pass did not
  introduce new FPs.
- On a static set of findings shipped from another audit (e.g. legacy
  Piolium output) before exporting them through `--action=export`.
- **Not** as a substitute for chamber or cold-verifier. The judge reads
  completed artifacts; it does not run a new attack.

### What judge mode is NOT

- It is **not** a new audit. It does not generate hypotheses, run probes,
  or build PoCs. It reads existing artifacts and re-judges.
- It is **not** a debate. The judge issues verdicts; there is no
  advocate response. If the judge says `INVALID-equivalent-capability`,
  that is the verdict.
- It is **not** a rubber stamp. A 0% INVALID rate on a non-trivial
  audit is itself a sign the framework is not being applied. Judge mode
  exists to catch the cases the chamber missed, and on most non-trivial
  audits it will catch at least a few.

## Effective Runtime Value chain (mandatory for any config-based finding)

For any finding whose impact depends on a security configuration value, you
must resolve the full chain from raw input to the value that actually reaches
the runtime check:

```
Configured value
  → Default value (when configured is null / unset / empty)
  → Derived value (computed from other configs)
  → Normalization (casing, trailing slash, scheme coercion, dedup)
  → Validation (regex allowlist, denylist, range check)
  → Effective runtime value
```

**Forbidden shortcuts**: never assume `unset → disabled`, `null → safe`,
`empty → no-op`, `optional → off by default`, `missing → uses system
default`. Each shortcut is wrong in a different product.

**Worked example**: a finding claims `webOrigins = unset` leads to
unrestricted CORS.

- `unset` ≠ `["*"]`. Follow the chain.
- `unset → defaultWebOrigins() → derived from redirectUris[] → filter to
  HTTPS → dedup → concrete whitelist`.
- The "unrestricted" claim dies at step 2. Effective value is a concrete
  whitelist, not `*`.

**Output (mandatory for the finding body)**:

```
Configured value:
Default behavior:
Derived value:
Effective runtime value:
```

**Only when the effective runtime value is actually dangerous does the
finding continue to vulnerability review.**

## Misconfiguration depth (mandatory for opt-in / admin-enabled features)

Enumerate the independent admin-side decisions an attacker depends on
before the finding's exploit path is reachable:

```
depth = 0  default deployment triggers the finding
depth = 1  finding requires one dangerous admin config
depth >= 2 finding requires multiple independent admin misconfigurations
```

**Higher depth = lower confidence**. A finding that requires the admin to
enable a feature, register an attacker-controlled domain, and lower a
default-deny rule is depth 3, not a single CVSS 7.5.

**Reference to the prerequisite-dominance test** (see §"Pre-condition
swallowing impact test"): if the admin actions required for depth > 0
already grant the same impact through normal admin features, the finding
folds into `PREREQUISITE_DOMINATES_IMPACT` and is not a vulnerability.

## Normative Requirement Levels (mandatory for spec-based findings)

For findings that depend on a standard (OAuth / OIDC / SAML / HTTP /
browser / FAPI / RFC), explicitly classify the violation level. The
hierarchy is strict:

| Level | Meaning | Implication |
|---|---|---|
| **MUST / MUST NOT** | Hard normative requirement | Violation is a candidate vulnerability only if it also crosses a boundary |
| **SHALL** | Equivalent to MUST in RFC 2119 | Same as MUST |
| **SHOULD / SHOULD NOT** | Recommended but disallowable | Violation is at most `LEGACY_SECURITY_DEFAULT` or `HARDENING_OPPORTUNITY` |
| **MAY** | Optional behavior | Violation is `SPEC_COMPLIANT_WEAK_DEFAULT` |
| **BCP** | Best current practice, not normative | Violation is `HARDENING_OPPORTUNITY` |
| **FAPI / high-assurance profile** | Optional strict profile | Violation is `HARDENING_OPPORTUNITY` unless the product claims FAPI compliance |

**Forbidden inference**: `"doesn't follow latest BCP" = "current
implementation has a vulnerability"`. A spec-compliant but weak
implementation is `SPEC_COMPLIANT_WEAK_DEFAULT` / `LEGACY_SECURITY_DEFAULT`
/ `HARDENING_OPPORTUNITY`. Boundary crossing still has to be proven
separately.

**Output (mandatory)**:

```
Normative MUST violation:    Yes / No
SHOULD violation:            Yes / No
BCP hardening gap:           Yes / No
Optional profile violation:  Yes / No
```

## Owner-Controlled Resource (special case)

When a finding is "admin sets a dangerous value, the server uses it",
ask whether the admin is acting on a resource they own. If yes:

- `channel manager` controlling own webhook
- `project admin` configuring own redirect URL
- `realm admin` setting own webOrigins

…this is usually **not** a boundary crossing. The admin has authority
over the resource; the server honoring that authority is the contract.

To re-classify as a vulnerability, the finding must show that the admin's
configuration affects a **third party** outside their control:

- another user's data
- another tenant's resources
- identity impersonation across users
- privilege escalation beyond the admin's own scope
- confidentiality / integrity / availability impact on a different actor

Without a third-party impact, owner-controlled state changes are not
boundary crossings. They are `INTENDED_BEHAVIOR` (admin in control of
their own resource) or at most `HARDENING_OPPORTUNITY` (admin should be
warned at config time).

## Six-question false-positive gate (compact replacement for the 10-anti-patterns list)

The 10 anti-patterns list above is a "what bad looks like" reference. The
**six-question gate** is a "what you must answer before any finding is
promoted" checklist. Use this as the primary gate at the chamber
synthesizer and judge stages; refer to the 10 anti-patterns list for
worked examples.

For every finding, answer all six:

1. **DEFAULT** — what is the effective runtime value when the relevant
   config is unset / null / empty / default?
2. **AUTHORITY** — who can create the dangerous state? Is admin
   opt-in required?
3. **DEPENDENCIES** — does the attack depend on a second or third
   independent misconfiguration?
4. **DERIVATION** — is the dangerous value derived from a constrained
   source? Trace A → derive → B and check who controls A.
5. **SPEC** — does this violate MUST, or only SHOULD / BCP / hardening?
6. **DELTA** — what is the new attacker capability? Is it None?

**Any one of these unanswered → lower confidence, do not promote**. If
two or more are unanswered → demote to `INSUFFICIENT_EVIDENCE` /
`HARDENING_OPPORTUNITY` / `FALSE_POSITIVE` directly.

## 12-category final classification (report-level)

Replace the 11 audit-level categories with the 12 report-level
categories when emitting a finding's final verdict. The 11 audit-level
categories (in the judge agent prompt) are detailed failure modes used
during review; the 12 report-level categories are the user-facing
classification that goes into `report.md` and is shown to the user.

```
CONFIRMED_BOUNDARY_CROSSING    明确证明存在安全边界突破
LIKELY_BOUNDARY_CROSSING      高度疑似,但仍缺少部分验证
INSUFFICIENT_EVIDENCE         目前证据不足
INTENDED_BEHAVIOR             行为符合产品明确设计
ADMIN_MISCONFIGURATION        只有管理员主动危险配置后才成立
SPEC_COMPLIANT_WEAK_DEFAULT   符合协议规范,但默认安全水位较低
LEGACY_SECURITY_DEFAULT       默认值符合旧安全模型,但落后于现代 BCP
HARDENING_OPPORTUNITY         值得增强安全性,但未证明漏洞
PREREQUISITE_DOMINATES_IMPACT 利用前置权限已经覆盖主要最终影响
POST_COMPROMISE_ONLY          只有系统已经失陷后才有意义
NO_NEW_SECURITY_CAPABILITY    没有产生实际权限增量
FALSE_POSITIVE                代码表象危险,但有效运行路径不存在问题
```

**Mapping** (audit-level → report-level): the chamber's `VALID` is
`CONFIRMED_BOUNDARY_CROSSING`; `INVALID-by-design` is
`INTENDED_BEHAVIOR`; `INVALID-equivalent-capability` is
`NO_NEW_SECURITY_CAPABILITY`; `INVALID-post-compromise` is
`PREREQUISITE_DOMINATES_IMPACT`; `INVALID-invented-permission` is
`INSUFFICIENT_EVIDENCE`; `INVALID-default-state-confusion` is
`ADMIN_MISCONFIGURATION`; `INVALID-keyword-cvss` is typically
`HARDENING_OPPORTUNITY`; etc. The 12-category form is the final
user-facing report; the 11-category form is the internal review label.

## Finding Output Template (mandatory structured output)

Every finding's `draft.md` (chamber-synthesizer output) and every
`judge-verdict.md` (judge output) must include the following fields.
Missing fields are a hard failure of the structured-output gate.

```yaml
Finding:                        [name]
Affected component:             [component / endpoint / function]
Attacker before exploitation:   [concrete identity, NOT "attacker"]
Existing privileges:            [concrete permissions held]
Attacker-controlled input:      [what the attacker can manipulate]
Default configuration:          [the config as written, including unset]
Effective runtime configuration: [the resolved value after chain]
Who can create the vulnerable state: [admin? owner? anyone?]
Additional prerequisites:       [every precond, including admin configs]
Misconfiguration depth:         [0 / 1 / 2 / ...]
Security invariant:             [the product-promised boundary]
Security boundary:              [which boundary is crossed]
Exploit path:                   [source → validation → authorization → sink]
Capability before:              [concrete, not abstract]
Capability after:               [concrete, not abstract]
Privilege delta:                [None / Sandbox-to-Host / etc.]
Equivalent capability without finding: Yes / No / Partially
Prerequisite dominates impact:  Yes / No / Partially
Behavior documented:            Yes / No / Unknown
Likely intended behavior:       Yes / No / Unclear
Specification status:           [MUST / SHOULD / BCP / optional profile / none]
Default behavior vulnerable:    Yes / No / Unknown
Browser/client behavior verified: Yes / No / N/A
Actual affected audience:       [concrete audience, not "users"]
Current-version status:         [branch / commit / release / patch status]
Counterfactual:                 [修复后攻击者能否用原始权限达到同样效果]
Boundary sentence:
  "一个原本只能 ______ 的攻击者,通过该 finding 可以 ______,
  而产品本来不允许后者。"
Verdict:                        [12-category label]
Confidence:                     [0-100%]
Why:                            [only the security boundary + delta, no scary keywords]
Missing evidence:               [what would raise confidence]
Recommended validation:         [max 3 most valuable verifications]
```

The chamber-synthesizer writes this template into `draft.md`; the judge
fills it (and may override the verdict) into `judge-verdict.md`.

## Final 14-item report gate

A finding is promoted to a formal `vulnerability report` only when **all
14** are checked:

```
[ ] Real attacker-controlled input exists
[ ] Current-version path is reachable
[ ] Attacker identity is concrete (not "attacker")
[ ] Default and effective config have been resolved
[ ] All prerequisites are enumerated
[ ] Behavior is not documented as intended
[ ] Not a single admin dangerous-config decision
[ ] Not merely a missing modern hardening
[ ] A real Security Invariant exists
[ ] The Invariant is provably broken
[ ] A real Privilege Delta exists
[ ] Impact has been actually verified
[ ] Affected party and scope are accurate
[ ] UI / permission / browser / config facts in the report are verified
```

**If any box cannot be checked → do not generate the vulnerability report**.
Demote to one of: `INSUFFICIENT_EVIDENCE`, `HARDENING_OPPORTUNITY`,
`ADMIN_MISCONFIGURATION`, `INTENDED_BEHAVIOR`, `NO_NEW_SECURITY_CAPABILITY`,
`FALSE_POSITIVE`.

## Final principles (orchestrator-level)

> "没有启用更强的安全措施" ≠ "存在安全漏洞"
> "代码最终到达危险 sink" ≠ "攻击者跨越安全边界"
> "最终结果看起来很严重" ≠ "攻击者获得了新的安全能力"

The goal is **not** to find dangerous APIs. The goal is to find: **a
low-privilege actor violating a product-promised security invariant, in
order to obtain a capability they did not previously have**.

## See also

- `methodology/redteam-mindset.md` — DO NOT STOP + 9 corrections
- `methodology/evidence-hygiene.md` — cookie redaction, PII black-bar, HAR
  sanitization
- `methodology/bug-bounty.md` — only when scope is bounty / external
- `methodology/triage-validation.md` — finding triage workflow
- `~/.minimax/agents/mini-audit-judge/agent.md` — the Finding Review Agent
  system prompt (the canonical 26-section review protocol); the
  methodology file is the cross-class shared reference, the agent
  prompt is the role-specific protocol
- `methodology/report-writing.md` — pentest-style report format
