<!-- mini-audit/references — index of all reference materials -->

# mini-audit references

4 sub-directories + 1 cross-reference index, total **100 reference files (~1.8MB)** plus the 28 inline Piolium agents already ported.

## Layout

```
references/
├── README.md                    ← you are here
├── _hunt-class-map.md           ← cross-reference: hunting/ ↔ vuln-classes/ ↔ attack-ideator modes
│
├── *.md (28 files)              ← inline Piolium agents (no first-class mavis role)
│                                 ↳ see Piolium-inlined below
│
├── hunting/                     ← 58 files, ~885KB
│   └── hunt-<class>.md          ← Claude-BugHunter active hunting methodology
│
├── vuln-classes/                ← 29 files, ~286KB
│   └── <class>.md               ← strix vulnerability class reference
│
├── methodology/                 ← 8 files, ~220KB
│   └── <name>.md                ← cross-class judging + Claude-BugHunter operator methodology
│
└── wordlists/                   ← 5 files, ~350KB
    └── <name>.txt               ← runtime enumeration resources
```

## How to read this

| If you are... | Read this first |
|---------------|-----------------|
| mini-audit orchestrator deciding what to load | `_hunt-class-map.md` |
| attack-ideator generating hypotheses for class X | `hunting/hunt-X.md` + `methodology/permission-delta-judging.md` (one-sentence test gate) |
| code-tracer / devils-advocate working on class X | `vuln-classes/X.md` + `methodology/permission-delta-judging.md` (anti-patterns) |
| chamber-synthesizer issuing VALID/INVALID verdict | `methodology/permission-delta-judging.md` (one-sentence test + counterfactual test) |
| mini-audit-judge re-evaluating completed findings (`--mode=judge` J1/J2) | `methodology/permission-delta-judging.md` (full framework, loaded as primary standard) |
| cold-verifier re-validating after chamber | `methodology/permission-delta-judging.md` (class-agnostic, loaded intentionally) |
| poc-builder / report-assembler about to capture evidence | `methodology/evidence-hygiene.md` + `methodology/report-writing.md` |
| L5 / P8 deep-probe fan-out | `methodology/recon-scope-triage.md` |
| Any sub-agent enumerating endpoints / params | `wordlists/common.txt` + `wordlists/raft-medium-directories.txt` |

## 28 inline Piolium agents (Piolium agents that are NOT first-class mavis roles)

These get inlined into `Task` tool prompts at runtime via the dispatch pattern in the master SKILL.md.

| File | Used in phase(s) |
|------|------------------|
| `advisory-hunter.md` | L3 / P1 / KB1 |
| `authz-auditor.md` | L6 / P8 / V5 |
| `backward-reasoner.md` | L6 / P8 |
| `commit-archaeologist.md` | L1 / P1 |
| `confirm-reporter.md` | V1-V7 / V6 |
| `contradiction-reasoner.md` | L6 / P8 |
| `cross-service-auditor.md` | L5 / P8 |
| `env-detective.md` | L4 / P1.5 |
| `env-provisioner.md` | L4 / P1.5 |
| `evidence-harvester.md` | L6 / P8 / V5 |
| `finding-reporter.md` | L7 / P15 |
| `finding-triager.md` | L6b / P10 |
| `intent-cartographer.md` | L1 / P2 / R0 |
| `knowledge-base-builder.md` | K1 / K2 |
| `knowledge-base-loader.md` | K0 |
| `longshot-aggregator.md` | X3 |
| `longshot-hunter.md` | X2 |
| `patch-bypass-checker.md` | P16 |
| `poc-builder.md` | Q3 / L6c / P13 / V3 |
| `poc-executor.md` | L7 / P13 |
| `probe-strategist.md` | L5 / P8 |
| `report-assembler.md` | L7 / P14 |
| `spec-gap-analyst.md` | L6 / P9 |
| `state-concurrency-auditor.md` | L6 / P8 |
| `test-mapper.md` | L6 / P8 |
| `variant-hunter.md` | P12 / L6 |
| `variant-scout.md` | X1 |
| `wave-verifier.md` | I2 |

## 58 hunting methodologies (Claude-BugHunter)

For each vuln class, an "active hunting" prompt with **Crown Jewel Targets** / **Attack Surface Signals** / **Step-by-Step Hunting Methodology** / **Payload & Detection Patterns** / **Bypass Techniques** / **Gate 0 Validation** / **Real Impact Examples** / **Related Skills & Chains**.

```
hunting/hunt-api-misconfig.md      hunting/hunt-html-injection.md
hunting/hunt-aspnet.md             hunting/hunt-http-smuggling.md
hunting/hunt-ato.md                hunting/hunt-idor.md
hunting/hunt-auth-bypass.md        hunting/hunt-jwt-crypto.md
hunting/hunt-brute-force.md        hunting/hunt-k8s.md
hunting/hunt-business-logic.md     hunting/hunt-laravel.md
hunting/hunt-cache-poison.md       hunting/hunt-ldap.md
hunting/hunt-captcha-bypass.md     hunting/hunt-lfi.md
hunting/hunt-cicd.md               hunting/hunt-llm-ai.md
hunting/hunt-clickjacking.md       hunting/hunt-mfa-bypass.md
hunting/hunt-cloud-misconfig.md    hunting/hunt-misc.md
hunting/hunt-cors.md               hunting/hunt-nextjs.md
hunting/hunt-csrf.md               hunting/hunt-nodejs.md
hunting/hunt-deserialization.md    hunting/hunt-nosqli.md
hunting/hunt-dispatch.md           hunting/hunt-ntlm-info.md
hunting/hunt-dom.md                hunting/hunt-oauth.md
hunting/hunt-exceptional-conditions.md  hunting/hunt-open-redirect.md
hunting/hunt-file-upload.md        hunting/hunt-race-condition.md
hunting/hunt-fintech-graphql.md    hunting/hunt-rag-vector.md
hunting/hunt-forgot-password.md    hunting/hunt-rce.md
hunting/hunt-graphql.md            hunting/hunt-saml.md
hunting/hunt-grpc.md               hunting/hunt-session.md
hunting/hunt-host-header.md        hunting/hunt-shadow-api.md
hunting/hunt-sharepoint.md         hunting/hunt-source-leak.md
hunting/hunt-spa-api.md            hunting/hunt-springboot.md
hunting/hunt-sqli.md               hunting/hunt-ssrf.md
hunting/hunt-ssti.md               hunting/hunt-subdomain.md
hunting/hunt-tls-network.md        hunting/hunt-websocket.md
hunting/hunt-xss.md                hunting/hunt-xxe.md
hunting/hunt-rce.md                (see top)
```

## 29 vulnerability class references (strix)

For each class, a "what is X" reference with **Attack Surface** / **Detection Channels** / **DBMS Primitives** (where applicable) / **Code Patterns to look for** / **Framework-specific risks**.

```
vuln-classes/agentic_system_security.md      vuln-classes/llm_prompt_injection.md
vuln-classes/argument_injection.md           vuln-classes/mass_assignment.md
vuln-classes/authentication_jwt.md          vuln-classes/nosql_injection.md
vuln-classes/broken_function_level_authorization.md   vuln-classes/open_redirect.md
vuln-classes/browser_security.md            vuln-classes/path_traversal_lfi_rfi.md
vuln-classes/business_logic.md              vuln-classes/prototype_pollution.md
vuln-classes/csrf.md                        vuln-classes/race_conditions.md
vuln-classes/header_injection.md            vuln-classes/rce.md
vuln-classes/http_request_smuggling.md      vuln-classes/semantic_confusion.md
vuln-classes/idor.md                        vuln-classes/sql_injection.md
vuln-classes/information_disclosure.md      vuln-classes/ssrf.md
vuln-classes/insecure_deserialization.md    vuln-classes/ssti.md
vuln-classes/insecure_file_uploads.md       vuln-classes/subdomain_takeover.md
vuln-classes/weak_password_detection.md     vuln-classes/xss.md
vuln-classes/xxe.md
```

## 8 methodologies (1 cross-class judging + 7 Claude-BugHunter)

```
methodology/permission-delta-judging.md ← cross-class meta-rule: Actor→Boundary→Delta; one-sentence test; counterfactual test; 10 anti-patterns (MUST-LOAD pre-flight for chamber + cold-verifier)
methodology/bug-bounty.md            ← cluster hunting protocol, A→B→C chains
methodology/redteam-mindset.md       ← 9 corrections, DO NOT STOP directive
methodology/evidence-hygiene.md      ← cookie redaction, PII black-bar, HAR sanitization
methodology/report-writing.md        ← disclosure-ready report structure
methodology/triage-validation.md     ← candidate finding triage
methodology/recon-scope-triage.md    ← scope enumeration for probe fan-out
methodology/web2-recon.md            ← web-app recon methodology
```

`redteam-mindset.md`, `evidence-hygiene.md`, and `permission-delta-judging.md` are the **non-negotiable pre-flights** — load them at the start of every mini-audit session. The first two govern behavior, the third governs the VALID/INVALID verdict.

## 5 wordlists (runtime resources)

```
wordlists/api-endpoints.txt              (50 lines)
wordlists/burp-parameter-names.txt      (6453 lines)
wordlists/bypass-headers.txt            (19 lines)
wordlists/common.txt                    (4751 lines)
wordlists/raft-medium-directories.txt   (29999 lines)
```

Sub-agents read these via `Bash cat` or `Read` tool. They are NOT prompt templates.

## Provenance

| Sub-directory | Source |
|---------------|--------|
| Inline Piolium agents (28) | `/Users/rinne/Desktop/piolium/agents/*.md` (frontmatter + codex-trim stripped) |
| hunting/ (58) | `cybermes/knowledge/Claude-BugHunter/skills/hunt-*/SKILL.md` |
| vuln-classes/ (29) | `strix/strix/skills/vulnerabilities/*.md` |
| methodology/ (8) | 7 from `cybermes/knowledge/Claude-BugHunter/skills/{bug-bounty,redteam-mindset,evidence-hygiene,report-writing,triage-validation,recon-scope-triage,web2-recon}/SKILL.md` + 1 original (`permission-delta-judging.md`, distilled from admin FP rejections) |
| wordlists/ (5) | `cybermes/tools/wordlists/*.txt` |

Piolium has no equivalent for any of the 100 new files (the 4 sub-directories) — these are pure additions that complement the 28 inline Piolium agents already ported.

Machine-readable provenance (source repo/commit/path, license, modified flag, import date) for every one of the 130 files lives in `MANIFEST.json`; the source declarations and commit map live in `PROVENANCE.json`. Regenerate with `scripts/manifest.py`, verify with `scripts/check-manifest.py --strict`.

## Total: 100 reference files (~1.8MB)

The full audit pipeline (`mini-audit`) now has access to:
- 7 first-class mavis agents (chamber debate + SAST + cold verification + permission-delta re-judgment)
- 28 inline Piolium role specs
- 58 per-class hunting methodologies
- 29 per-class vulnerability references
- 8 operator methodology references (incl. permission-delta judging)
- 5 runtime wordlists
- 6 supporting skills (`codeql`, `semgrep`, `sarif-parsing`, `vuln-report`, `security-threat-model`, `zeroize-audit`)
