<!-- mini-audit/references/_hunt-class-map.md
     Cross-reference: hunting/ ↔ vuln-classes/ ↔ mini-audit attack-ideator 8 modes
     Source: Piolium does not have per-vuln-class hunting methodology. strix and Claude-BugHunter fill the gap. -->

# Hunt-class map (hunting/ ↔ vuln-classes/ ↔ attack-ideator modes)

This is the cross-reference the mini-audit orchestrator uses to decide which `hunting/<name>.md` and `vuln-classes/<name>.md` to load for each hypothesis.

## Coverage

- **58 hunting methodologies** (from `cybermes/knowledge/Claude-BugHunter/skills/hunt-*/`) — "active hunting" prompts
- **29 vulnerability class references** (from `strix/strix/skills/vulnerabilities/`) — "what is X, what does the code look like" knowledge
- **53/58 hunts** have a direct 1:1 match to a vuln class
- **5 hunts** are extra (no vuln-classes counterpart): `hunt-exceptional-conditions`, `hunt-fintech-graphql`, `hunt-graphql`, `hunt-misc`, `hunt-oauth`
- **3 vuln classes** are extra (no hunt counterpart): `argument_injection`, `header_injection`, `semantic_confusion`

## Mapping table (53 paired classes)

When a hypothesis belongs to one of the classes below, load both `hunting/<hunt>` and `vuln-classes/<vuln>` into the corresponding agent.

| Class (key) | hunting/ file | vuln-classes/ file | attack-ideator Mode |
|-------------|---------------|-------------------|---------------------|
| sqli | `hunting/hunt-sqli.md` | `vuln-classes/sql_injection.md` | Mode 6 (Parser Differential) + Mode 1 (Chaining) |
| nosqli | `hunting/hunt-nosqli.md` | `vuln-classes/nosql_injection.md` | Mode 6 + Mode 5 (Trust Boundary) |
| xss | `hunting/hunt-xss.md` | `vuln-classes/xss.md` | Mode 4 (Second-Order) + Mode 6 |
| csrf | `hunting/hunt-csrf.md` | `vuln-classes/csrf.md` | Mode 5 (Trust Boundary Confusion) |
| idor | `hunting/hunt-idor.md` | `vuln-classes/idor.md` | Mode 2 (Business Logic) |
| ssrf | `hunting/hunt-ssrf.md` | `vuln-classes/ssrf.md` | Mode 5 + Mode 6 |
| rce | `hunting/hunt-rce.md` | `vuln-classes/rce.md` | Mode 1 (Chaining) + Mode 8 (Supply Chain) |
| path_traversal | `hunting/hunt-lfi.md` | `vuln-classes/path_traversal_lfi_rfi.md` | Mode 1 (Chaining) |
| ssti | `hunting/hunt-ssti.md` | `vuln-classes/ssti.md` | Mode 6 (Parser Differential) |
| xxe | `hunting/hunt-xxe.md` | `vuln-classes/xxe.md` | Mode 6 (Parser Differential) |
| deserialization | `hunting/hunt-deserialization.md` | `vuln-classes/insecure_deserialization.md` | Mode 4 (Second-Order) + Mode 6 |
| race | `hunting/hunt-race-condition.md` | `vuln-classes/race_conditions.md` | Mode 3 (Race / TOCTOU) |
| open_redirect | `hunting/hunt-open-redirect.md` | `vuln-classes/open_redirect.md` | Mode 1 + Mode 5 |
| http_request_smuggling | `hunting/hunt-http-smuggling.md` | `vuln-classes/http_request_smuggling.md` | Mode 6 (Parser Differential) |
| graphql | `hunting/hunt-graphql.md` | `vuln-classes/n/a` | Mode 6 + Mode 5 |
| oauth | `hunting/hunt-oauth.md` | `vuln-classes/n/a` | Mode 6 (URL parser differential bypass) + Mode 7 |
| authentication_jwt | `hunting/hunt-jwt-crypto.md` | `vuln-classes/authentication_jwt.md` | Mode 6 + Mode 7 (Token Replay) |
| authentication | `hunting/hunt-auth-bypass.md` + `hunt-mfa-bypass.md` + `hunt-session.md` + `hunt-saml.md` | `vuln-classes/n/a` | Mode 5 (Trust Boundary) + Mode 7 (State Machine) |
| browser_security | `hunting/hunt-clickjacking.md` + `hunt-cors.md` | `vuln-classes/browser_security.md` | Mode 5 (Trust Boundary) |
| subdomain_takeover | `hunting/hunt-subdomain.md` | `vuln-classes/subdomain_takeover.md` | Mode 8 (Supply Chain) |
| broken_function_level_authorization | `hunting/hunt-api-misconfig.md` + `hunt-shadow-api.md` + `hunt-spa-api.md` + `hunt-grpc.md` | `vuln-classes/broken_function_level_authorization.md` | Mode 5 (Trust Boundary) |
| insecure_file_uploads | `hunting/hunt-file-upload.md` | `vuln-classes/insecure_file_uploads.md` | Mode 4 + Mode 1 (Chaining) |
| information_disclosure | `hunting/hunt-source-leak.md` + `hunt-tls-network.md` + `hunt-cicd.md` | `vuln-classes/information_disclosure.md` | Mode 5 (Trust Boundary) |
| business_logic | `hunting/hunt-business-logic.md` | `vuln-classes/business_logic.md` + `vuln-classes/mass_assignment.md` | Mode 2 (Business Logic Abuse) |
| llm_prompt_injection | `hunting/hunt-llm-ai.md` + `hunt-rag-vector.md` | `vuln-classes/llm_prompt_injection.md` + `vuln-classes/agentic_system_security.md` | Mode 4 (Second-Order / Stored) + Mode 6 |

## Framework / stack-specific hunts (no vuln class, use strix/technologies/ + these)

| hunting/ file | Stack | Used when |
|---------------|-------|-----------|
| `hunting/hunt-nextjs.md` | Next.js | target uses Next.js |
| `hunting/hunt-nodejs.md` | Node.js / Express | target is Node.js |
| `hunting/hunt-springboot.md` | Spring Boot | target is Java Spring |
| `hunting/hunt-laravel.md` | Laravel | target is PHP Laravel |
| `hunting/hunt-aspnet.md` | ASP.NET | target is .NET |
| `hunting/hunt-sharepoint.md` | SharePoint | target is SharePoint |
| `hunting/hunt-fintech-graphql.md` | FinTech GraphQL | target is FinTech + GraphQL |
| `hunting/hunt-websocket.md` | WebSocket | target uses WebSocket |
| `hunting/hunt-ldap.md` | LDAP | target uses LDAP |
| `hunting/hunt-k8s.md` | Kubernetes | target runs on k8s |
| `hunting/hunt-cloud-misconfig.md` | Cloud IAM | target is on AWS/Azure/GCP |
| `hunting/hunt-ntlm-info.md` | NTLM | target is Windows / NTLM |
| `hunting/hunt-cicd.md` | CI/CD | `.github/workflows/` or similar |
| `hunting/hunt-dispatch.md` | (mixed) | parameter dispatch / routing layer |
| `hunting/hunt-exceptional-conditions.md` | (mixed) | error-handling edge cases |
| `hunting/hunt-misc.md` | fallback | anything not covered above |
| `hunting/hunt-ato.md` | (chain) | account-takeover chain follow-up |
| `hunting/hunt-captcha-bypass.md` | auth | CAPTCHA bypass path |
| `hunting/hunt-brute-force.md` | auth | brute-force amplification |
| `hunting/hunt-forgot-password.md` | auth | password-reset flow abuse |

## Only in vuln-classes/ (3, no hunting counterpart)

| vuln-classes/ file | Used by |
|--------------------|---------|
| `vuln-classes/argument_injection.md` | code-tracer / devils-advocate when evaluating `--` style CLI hijacks, npm-script arg injection, etc. |
| `vuln-classes/header_injection.md` | code-tracer when CR/LF injection is in scope |
| `vuln-classes/semantic_confusion.md` | devils-advocate when checking for AI model confusion (false-positive pattern in LLM-assisted triage) |

## Methodology (`methodology/`, pre-flight + on-demand)

| methodology/ file | Loaded by | When |
|-------------------|-----------|------|
| `methodology/bug-bounty.md` | mini-audit orchestrator (pre-flight) | when user signals bounty / external engagement |
| `methodology/redteam-mindset.md` | mini-audit orchestrator (pre-flight) | when scope is "external red team", "assume breach", "TIBER-style" |
| `methodology/evidence-hygiene.md` | `poc-builder` + `poc-executor` (always) | before any PoC capture, before any evidence save |
| `methodology/report-writing.md` | `report-assembler` (always) | when assembling final finding report |
| `methodology/triage-validation.md` | orchestrator (L6b / P10 triage phase) | when triaging candidate findings |
| `methodology/recon-scope-triage.md` | L5 / P8 probe-strategist | before deep-probe fan-out |
| `methodology/web2-recon.md` | L1 / P2 intent-cartographer | web app recon methodology |

**`redteam-mindset.md` and `evidence-hygiene.md` are the two non-negotiable pre-flights** — load them at the start of every mini-audit session.

## Wordlists (`wordlists/`, runtime resource)

| wordlists/ file | Lines | Use |
|-----------------|-------|-----|
| `wordlists/common.txt` | 4751 | L5 / P8 probe-strategist directory/file enumeration |
| `wordlists/burp-parameter-names.txt` | 6453 | L4 / P1.5 env-provisioner parameter fuzzing |
| `wordlists/raft-medium-directories.txt` | 29999 | L5 / P8 web-app probe fan-out |
| `wordlists/api-endpoints.txt` | 50 | L3 / P1 advisory → endpoint exposure check |
| `wordlists/bypass-headers.txt` | 19 | devils-advocate Layer 4 (Application) defense-bypass search |

These are **runtime resources, not prompt templates**. Sub-agents `Bash cat` / `Read` them as needed.

## How the orchestrator uses this map

When `mini-audit-ideator` generates a hypothesis H-NN with class `c`:

1. Read `_hunt-class-map.md` (this file) to find `hunting/<name>.md` and `vuln-classes/<name>.md` for class `c`
2. Construct the prompt:

```
You are the attack-ideator. You generated hypothesis H-<NN> with class "<c>".
You are about to be asked to actually hunt for this class on <cwd>.

=== HUNTING METHODOLOGY (Claude-BugHunter) ===
${readFileSync(`hunting/hunt-<c>.md`)}
=== END HUNTING METHODOLOGY ===

=== VULNERABILITY CLASS REFERENCE (strix) ===
${readFileSync(`vuln-classes/<c>.md`)}
=== END VULN CLASS REF ===

=== PHASE TASK ===
Ideate H-<NN+1>, H-<NN+2> in the same class. Then STOP and report.
=== END PHASE TASK ===
```

3. Similarly for `mini-audit-tracer` (load `vuln-classes/<c>.md` for the code-path patterns) and `mini-audit-advocate` (load `vuln-classes/<c>.md` for the 5-layer defense list specific to this class).

This turns Piolium's "one generalist synthesizer" into a **class-aware chamber** where every role has the deep knowledge of the specific vulnerability class being debated.

## Why we need both `hunting/` and `vuln-classes/`

- `hunting/` answers: "How do I find this bug?" (action-oriented, prompts the agent to take specific steps)
- `vuln-classes/` answers: "What does this bug look like in code?" (knowledge-oriented, gives the agent deep technical context)

The two complement each other: ideator loads `hunting/` to generate test plans, tracer loads `vuln-classes/` to recognize patterns, advocate loads `vuln-classes/` to find layer-specific defenses.

## Provenance

- `hunting/` — ported from `cybermes/knowledge/Claude-BugHunter/skills/hunt-*/SKILL.md` (MIT-like license per cybermes)
- `vuln-classes/` — ported from `strix/strix/skills/vulnerabilities/*.md` (Strix is a parallel pentest framework; sources cite HackerOne public reports)
- `methodology/` — ported from `cybermes/knowledge/Claude-BugHunter/skills/{bug-bounty,redteam-mindset,evidence-hygiene,report-writing,triage-validation,recon-scope-triage,web2-recon}/SKILL.md`
- `wordlists/` — ported from `cybermes/tools/wordlists/*.txt`

All sources come from `/Users/rinne/WorkBuddy/prompt/extracted_prompts/`. Piolium (`/Users/rinne/Desktop/piolium/`) does not have per-vuln-class hunting methodology — these are pure additions.
