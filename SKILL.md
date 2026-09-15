---
name: mini-audit
description: Multi-phase security audit pipeline (Q0-Q4 lite / L1-L7 balanced / P1-P17 deep / V1-V7 confirm / R0-R11c revisit / M1-M7 merge / X1-X3 longshot / I1-I3 reinvest / KB0-K2 knowledge-base) with sub-agent scheduling, resumable state via on-disk canonical artifacts owned by the deterministic runtime, and Review Chamber debate protocol. Use when user asks "/mini-audit-lite", "/mini-audit-balanced", "/mini-audit-deep", "/mini-audit-confirm", "/mini-audit-revisit", "/mini-audit-diff", "/mini-audit-merge", "/mini-audit-longshot", "/mini-audit-reinvest", "/mini-audit-knowledge-base", "/mini-audit-status", "/mini-audit-resume", "/mini-audit-export", "/mini-audit-smoke", "/mini-audit-help", or "run a security audit on this repo".
allowed-tools:
  - Bash
  - Read
  - Write
  - Edit
  - Glob
  - Grep
  - Task
  - TaskList
  - TaskCreate
  - TaskUpdate
  - AskUserQuestion
---

# mini-audit — Multi-phase security audit pipeline (Piolium port to MiniMax Code)

A port of the Piolium security-audit pipeline (originally a Pi coding-agent extension) to MiniMax Code's skill + sub-agent harness. The Piolium phase catalog is preserved verbatim — phase IDs are a stable on-disk contract and must not be renamed.

## Runtime Hardening v1 — deterministic layer

This skill ships a three-layer architecture: **Reasoning** (LLM agents), **Policy** (permission-delta + verification methodology), and **Deterministic** (Python runtime at `runtime/`). The deterministic layer owns state, schema, gates, fingerprinting, coverage, scheduling, and export. LLM "I'm done" never advances phase state on its own — the runtime validates the expected artifacts, parses them, schema-validates them, and only then permits a state transition.

The skill loads the runtime as a Python package at `<skill>/runtime/` and exposes it via `scripts/mini-audit-runtime`.

```
LLM 负责:
  reasoning, code understanding, hypothesis generation,
  tracing, adversarial review, remediation reasoning

Runtime 负责:
  state, scheduling, retries, timeouts, schema, gates,
  artifact validation, fingerprinting, deduplication,
  coverage accounting, tool execution, export
```

### Layers

| Layer | Lives in | Authoritative for |
|-------|----------|-------------------|
| Reasoning | `references/<role>.md` (Piolium inlined), `sub-agent prompts` | hypothesis, debate, trace |
| Policy | `references/methodology/permission-delta-judging.md` | boundary crossing, severity, verdict |
| Deterministic | `runtime/` (Python 3.9+, stdlib) | state, schema, gates, fingerprint, coverage, scheduler, export, scan→candidate normalization, diff scope |

### Canonical artifacts (owned by the runtime)

| File | Owner | Purpose |
|------|-------|---------|
| `mini-audit/audit-state.json` | runtime | single source of truth for run state (Spec §5) |
| `mini-audit/findings.json` | runtime | canonical findings (Spec §10, §11) |
| `mini-audit/coverage-ledger.json` | runtime | subsystem × boundary × class coverage (Spec §20) |
| `mini-audit/candidates/<source>-candidates.json` | runtime | normalized SARIF candidate records (Spec §28) |
| `mini-audit/scanner/capabilities.json` | `scripts/detect-tools.sh` | what scanners/sandbox are available (Spec §27) |
| `mini-audit/sandbox/probe.json` | `scripts/sandbox-check.sh` | sandbox pre-flight (Spec §25) |
| `mini-audit/agents/<id>/task.json` | runtime | per-lease metadata (Spec §23) |
| `mini-audit/agents/<id>/result.json` | runtime | per-lease result |

Sub-agents write only to `mini-audit/agents/<id>/scratch/`. Promotion into canonical artifacts happens via runtime CLI after gate validation.

### Runtime CLI contract (Spec §7)

```bash
mini-audit-runtime state init --repo-root <path> [--mode balanced]
mini-audit-runtime state show
mini-audit-runtime phase {start|complete|fail|skip} <PHASE> [--error "..."]
mini-audit-runtime gate <PHASE> [--workdir DIR]
mini-audit-runtime finding validate <file>
mini-audit-runtime finding upsert <file>
mini-audit-runtime coverage {init <plan>|validate}
mini-audit-runtime export --format {json|md|sarif} [--verdict V] [--min-severity S] [--class C] [--since ISO] [--output PATH]
mini-audit-runtime source {capture|diff} --repo-root <path>
mini-audit-runtime sarif normalize <file> --source <scanner>
mini-audit-runtime diff scope --repo-root <path> --baseline <sha> --target <sha> [--symbol X ...]
mini-audit-runtime lease run <task> [--phase P] [--timeout N] [--max-attempts N]
```

The launcher resolves the runtime package via three strategies: `MINI_AUDIT_RUNTIME_HOME` env → `$MAVIS_SKILLS_DIR/mini-audit` → relative to the script.

### Phase gates are now declarative (Spec §9)

Default gate library (in `runtime.gates.DEFAULT_PHASE_GATES`):

| Phase | Required artifact(s) | Semantic checks |
|-------|---------------------|-----------------|
| L1 | `attack-surface/intent-corpus.json` | non_empty |
| L2 | `context/knowledge-base.md` | — |
| L3 | `scanner/capabilities.json` | — |
| L4 | `env/runtime-summary.json` | — |
| L5 | glob `probe-workspace/*/probe-summary.md` | — |
| L6 | glob `chamber-workspace/*/debate.json` | every_chamber_closed, every_valid_candidate_has_boundary_sentence |
| L6b | glob `findings-draft/*/draft.md` | — |
| L6c | glob `findings/*/poc.sh` + `findings/*/evidence/exploit.log` | — |
| L7 | `findings.json`, `final-audit-report.md`, `coverage-ledger.json` | every_confirmed_has_verifier, coverage_no_planned, audit_state_terminal_phases |

Forbidden pattern: `file exists → complete`. A real gate checks existence, size, parseability, schema, semantic consistency, source reference validity.

### Stable fingerprint (Spec §12)

Finding IDs are unstable. `compute_fingerprint(finding)` derives a SHA-256 from normalized inputs:

```
fingerprint = sha256("v1|" + vuln_class + "|" + invariant + "|" + root_cause + "|" + source_symbol + "|" + sink_symbol + "|" + boundary_type)
```

Inputs forbidden: line number, finding ID, report wording, severity, timestamp.

Two findings with the same content produce the same fingerprint across revisit/reuse/variant. `FindingStore.upsert()` dedupes by fingerprint.

### Review Chamber → Verifier → Permission-Delta (Spec §13, §15, §17)

Three-step promotion, not one-step "Review Chamber says VALID":

1. **Review Chamber** produces a `candidate` (NOT a finding) with a `promotion_recommendation` of `PROMOTE_FOR_VERIFICATION | REJECT | DEFER`.
2. **Technical Verifier** (fresh session) emits `technically_valid | rejected | needs_validation` based on entrypoint真实性, attacker control, dataflow, authn/authz, sanitization, framework protection, exploitability.
3. **Permission-Delta Judge** applies the methodology (`references/methodology/permission-delta-judging.md`) for the boundary sentence: *An actor who could previously only X can now Y, which the product's intended security model did not permit.* If the sentence cannot be filled, `cannot confirm`.

Severity policy (Spec §19): no more `pre-auth → severity +1`. Inputs are attacker prerequisites, exploit complexity, privilege level, user interaction, demonstrated impact, blast radius, repeatability. Hard invariant: `overall severity ≤ demonstrated impact`.

### Coverage accounting (Spec §20)

Coverage unit = `subsystem × boundary × attack_class`. States: `planned → in_progress → covered | candidate | blocked | deferred | out_of_scope`. Every hunter task binds to a unit. The audit cannot reach `complete` while any unit is `planned` or `in_progress`. Reports never claim "full coverage" — they print the histogram.

### Default Security Invariant (Spec §18)

For config-based findings, the runtime distinguishes:

```json
{
  "default_security": {
    "fresh_install_value": "...",
    "security_sensitive": true,
    "admin_action_required": false,
    "deployment_override_detected": false
  }
}
```

`admin explicitly enables dangerous feature` ≠ `fresh default installation starts fail-open`. The former is `ADMIN_MISCONFIGURATION`; the latter is a confirmed finding.

### Verdict model (Spec §10.2)

Top-level: `confirmed | needs_validation | rejected`. The 13 permission-delta reasons (`by_design, equivalent_capability, post_compromise, invented_permission, keyword_cvss, hypothetical_chain, default_state_confusion, speculative_client_behavior, fix_as_proof, insufficient_evidence, hardening_only, duplicate, out_of_scope`) live under `disposition_reason`.

### Scanner integration (Spec §26–28)

Scanners (Semgrep, CodeQL, Gitleaks, TruffleHog) produce SARIF. `runtime/sarif.normalize_sarif` converts SARIF 2.1.0 into candidate records. Scanner alerts are **never** directly confirmed findings; they are `untriaged` candidates that the LLM (or a deterministic triager) must evaluate.

Scanner wrappers never exec the tool directly — they go `sandbox-check → capability PASS → sandbox-run → scanner`:

```bash
scripts/detect-tools.sh   --audit-root mini-audit          # → scanner/capabilities.json
scripts/sandbox-check.sh  --audit-root mini-audit          # → sandbox/probe.json (must run first)
scripts/run-semgrep.sh --repo-root TARGET --audit-root mini-audit
scripts/run-codeql.sh  --repo-root TARGET --language python --audit-root mini-audit
```

**Read the exit code as scan health, not as a finding count** (one contract for both wrappers):

| exit | meaning | what the orchestrator should do |
|------|---------|--------------------------------|
| `0` | scan completed, SARIF written under `$AUDIT_ROOT/scanner/` | normalize the SARIF |
| `1` | the scanner ran but failed | `execution_status = failed`; do not treat as "no findings" |
| `4` | the sandbox policy blocked execution — **nothing ran** | `execution_status = blocked`, `verdict = needs_validation`; never fall back to host execution |

Findings live in the SARIF, never in the exit code — `run-semgrep.sh` deliberately does *not* pass Semgrep's `--error`, because that would make the one run that finds bugs look like a crash. stdout of each wrapper is exactly one JSON document; `run-codeql.sh` nests its per-step reports under `"steps"`.

### Sandbox policy (Spec §25)

`scripts/sandbox-check.sh` probes for sandbox availability, external network isolation, scratch writability, timeout binary, resource limits. Missing critical capabilities → `execution_status = blocked`, `verdict = needs_validation`. The runtime refuses to fall back to direct host bash execution.

What counts as *critical* depends on the execution kind, so the same probe permits a scan and refuses a PoC: `source-scan` requires only a writable scratch; `target-build` adds `sandbox_available`; `poc` and `target` additionally require external network isolation and resource limits. A capability that is critical for one kind is reported as a warning for the others.

### Export (Spec §34)

```bash
mini-audit-runtime export --format json      # canonical structured
mini-audit-runtime export --format md        # generated markdown report
mini-audit-runtime export --format sarif     # SARIF 2.1.0 for GitHub Code Scanning / DefectDojo
```

Filters: `--verdict`, `--min-severity`, `--class`, `--since`.

### Reference provenance (Spec §35, §36; Hardening v1.1 §13)

Every reference file under `references/` is listed in `references/MANIFEST.json`. As of v1.1 each item carries provenance and license metadata:

| Field | Meaning |
|-------|---------|
| `path`, `kind`, `size_bytes`, `sha256` | integrity (v1) |
| `source_repo` | logical source key, resolved against the manifest `sources` block |
| `source_commit` | upstream commit the file was imported from (per-file for Piolium, `UNKNOWN` where the upstream is not vendored) |
| `source_path` | path of the file inside the source repo |
| `license` | license of the source repo (`MIT` for Piolium, `UNKNOWN` pending confirmation elsewhere) |
| `modified` | whether the file was altered on import (inline agents: frontmatter + codex-trim stripped) |
| `imported_at` | import date for the batch |

Source declarations, path→source rules, per-file overrides and the frozen commit map live in `references/PROVENANCE.json`.

```bash
python scripts/manifest.py              # (re)generate MANIFEST.json
python scripts/manifest.py --check       # verify, no write (exit 1 on drift)
python scripts/manifest.py --resolve-commits   # refresh commits from a local checkout
python scripts/check-manifest.py --strict
```

`check-manifest.py --strict` validates that:

* all reference files are manifested
* no manifest entries point to missing files
* SHA-256 of on-disk files matches the manifest
* `_hunt-class-map.md` references resolve to existing files
* README counts match the manifest
* every item carries the full provenance tuple
* `source_repo` resolves to a declared source and `license` agrees with it

Unresolved (`UNKNOWN`) licenses — currently the non-vendored `Claude-BugHunter` / `strix` sources and the in-repo originals — are reported as warnings so they stay visible until confirmed.

CI runs `check-manifest.py --strict` and `manifest.py --check` so reference and provenance drift are caught.

### Unit tests + evals

```bash
python -m pytest tests/unit -q        # unit tests for the runtime
python scripts/manifest.py --check    # reference manifest is current
python scripts/check-manifest.py --strict
python scripts/doc_counts.py --check  # docs quote no stale counts
python evals/run.py                   # regression eval (baseline predictor)
python evals/run.py --oracle          # ceiling: corpus self-consistency
python evals/run.py --self-check      # fixture sanity
```

Eval corpus under `evals/{positive,negative,ambiguous,}` exercises the permission-delta judging and verifier escalation rules from Spec §38. `evals/run.py` scores TP/FP/FN, Precision/Recall/F1, NeedsValidation rate and HardBugRecall against `evals/expected.json`, and `evals/score.py` fails CI when a threshold regresses.

<!-- BEGIN auto-counts — generated, do not edit by hand
| Metric | Value |
|--------|-------|
| reference files (4 sub-directories) | 100 |
| manifest items (incl. inline agents) | 130 |
| inline agent templates | 28 |
| per-class hunting methodologies | 58 |
| per-class vulnerability references | 29 |
| operator methodologies | 8 |
| runtime wordlists | 5 |
| eval fixtures | 30 |
| first-class roles | 7 |
| phase gates declared | 38 |
| runtime version | 1.1.1 |
| commands: full / partial / stub | 8 / 5 / 4 |
<!-- END auto-counts -->

Refresh the block with `python scripts/doc_counts.py --write`; `--check` fails CI when it (or a known prose claim) goes stale.

### What the SKILL still does (Reasoning + Policy layers)

* Decide which mode to run, in what order.
* Dispatch sub-agents to the right phase.
* Read runtime state to render `--action=status` and decide what's next.
* Run the Review Chamber debate (LLM responsibility).
* Apply permission-delta methodology (Policy layer).
* The SKILL **never** writes to `audit-state.json`, `findings.json`, or `coverage-ledger.json` directly. It only shells out to `mini-audit-runtime`.

## Slash command mapping (Piolium → mini-audit)

| Piolium slash command | mini-audit invocation |
|----------------------|----------------------|
| `/piolium-help` | `/skill:mini-audit --action=help` | ✗ stub (Piolium parity, no impl) |
| `/piolium-status [--dir=PATH]` | `/skill:mini-audit --action=status [--dir=PATH]` | ✗ stub (Piolium parity, no impl) |
| `/piolium-smoke [task]` | `/skill:mini-audit --action=smoke [task]` | ✗ stub (Piolium parity, no impl) |
| `/piolium-lite [--fresh] [--dir=PATH]` | `/skill:mini-audit --action=run --mode=lite [--fresh] [--dir=PATH]` | ✓ full |
| `/piolium-balanced [--fresh] [--dir=PATH]` | `/skill:mini-audit --action=run --mode=balanced [--fresh] [--dir=PATH]` | ✓ full |
| `/piolium-deep [--fresh] [--dir=PATH] [P5 P7 …]` | `/skill:mini-audit --action=run --mode=deep [--fresh] [--dir=PATH] [--only=P5,P7]` | ✓ full |
| `/piolium-knowledge-base [--fresh] [--dir=PATH]` | `/skill:mini-audit --action=run --mode=knowledge-base [--fresh] [--dir=PATH]` | ◐ partial (described, never run E2E) |
| `/piolium-confirm [--fresh] [--dir=PATH] [--repo=URL] [URL]` | `/skill:mini-audit --action=run --mode=confirm [--fresh] [--dir=PATH] [--repo=URL] [URL]` | ✓ full |
| `/piolium-diff [--since=SHA] [--dir=PATH]` | `/skill:mini-audit --action=run --mode=diff [--since=SHA] [--dir=PATH]` | ◐ partial (phase catalog is empty; change-set derivation not implemented) |
| `/piolium-revisit [--fresh] [--dir=PATH]` | `/skill:mini-audit --action=run --mode=revisit [--fresh] [--dir=PATH]` | ✓ full |
| `/piolium-merge --dir=A --dir=B` | `/skill:mini-audit --action=run --mode=merge --dir=A --dir=B` | ✓ full |
| `/piolium-longshot [--limit=N] [--timeout=ms] [--langs=py,go] [--include-tests]` | `/skill:mini-audit --action=run --mode=longshot [...]` | ◐ partial (described, never run E2E) |
| `/piolium-reinvest [--fresh] [--dir=PATH]` | `/skill:mini-audit --action=run --mode=reinvest [--fresh] [--dir=PATH]` | ◐ partial (described, never run E2E) |
| `/skill:mini-audit --action=run --mode=judge [--dir=PATH] [--finding=<id>]` | meta-audit re-judge of existing findings against the permission-delta framework (J1 per-finding verdict, J2 aggregate) | ✓ full (NEW) |
| `/piolium-resume` | `/skill:mini-audit --action=resume` | ◐ partial (resume state is on-disk canonical; source-identity guard implemented, crash recovery not yet exercised E2E) |
| `/piolium-export [--format=json\|md-dir] [--out=PATH] [--min-severity=high] [--only-severity=high,crit] [--confirmed-only] [--exclude-fp] [--since=ISO] [--require-owner]` | `/skill:mini-audit --action=export [...]` | ✓ full (runtime `export --format json\|md\|sarif`; Piolium-only flags not yet ported) |
| `/piolium-learn [--apply]` | `/skill:mini-audit --action=learn [--apply]` | ✗ stub (Piolium parity, no impl) |

**Status legend**: ✓ full = orchestrator recipe + inline templates + artifact gates specified; ◐ partial = described in SKILL.md but never run E2E or some piece is missing; ✗ stub = Piolium parity only, no impl. Of the 17 commands, 8 are full (lite/balanced/deep/confirm/revisit/merge/judge/export), 5 are partial (knowledge-base/diff/longshot/reinvest/resume), 4 are stub (help/status/smoke/learn).

## Phase catalog (DO NOT RENAME — persisted on-disk contract)

```yaml
lite:          [Q0, Q1, Q2, Q3, Q4]
balanced:      [L1, L2, L3, L4, L5, L6, L6b, L6c, L7]
deep:          [P1, P2, P3, P4, P5, P6, P7, P8, P9, P10, P11, P12, P13, P14, P15, P16, P17]
diff:          []                          # dynamically derived from change set
confirm:       [V1, V1.5, V2, V3, V4, V5, V6, V7]
revisit:       [R0, R5, R7, R8, R9, R10, R10k, R11, R11b, R11c]
merge:         [M1, M2, M3, M4, M5, M6, M7]
longshot:      [X1, X2, X3]
reinvest:      [I1, I2, I3]
knowledge-base:[KB0, K1, K2]
judge:         [J1, J2]                # permission-delta meta-audit re-judgment
```

## Per-phase agent mapping (Piolium specialist → mini-audit role)

The 35 Piolium specialist agents are surfaced as 7 first-class mini-audit roles (6 ported from Piolium plus the new `mini-audit-judge`) that are loaded by default. 28 further agents are shipped as inline markdown templates under `references/` and referenced by name in phase task prompts, dispatched via `Task(subagent_type=...)` (the orchestrator decides whether to instantiate them or fold the prompt inline).

### Default first-class roles (load via `mavis agent list` and use as `subagent_type`)

| Role | Piolium agent | Use in phase |
|------|---------------|--------------|
| `mini-audit-ideator` | attack-ideator | Ideation round of every Review Chamber |
| `mini-audit-tracer` | code-tracer | Tracing round of every Review Chamber |
| `mini-audit-advocate` | devils-advocate | Challenge round of every Review Chamber |
| `mini-audit-synthesizer` | chamber-synthesizer | Synthesis round + the only role that writes finding drafts |
| `mini-audit-cold-verifier` | cold-verifier | L7 / V6 cold verification (zero-context isolation) |
| `mini-audit-static-analyzer` | static-analyzer | L4 / P4 SAST orchestration |
| `mini-audit-judge` | (new) | J1 / J2 permission-delta meta-audit re-judgment of existing findings |

**Model selection**: `mavis agent create` does not currently accept a `model` field, so the per-agent model is whatever mavis dispatches with (typically the main orchestrator's model). **The orchestrator (the main model running the skill) is responsible for picking the right `subagent_type` at dispatch time** — we do not pin model per role. If a phase needs a stronger model for a hard sub-task, the orchestrator can dispatch `general` sub-agents with explicit model instructions in the task prompt instead of relying on the first-class agent.

### Per-vulnerability-class knowledge base (100 reference files in 4 sub-directories)

`references/` contains 100 reference files in 4 sub-directories. The orchestrator reads them on-demand based on the hypothesis class.

| Sub-directory | Files | Source | Role in mini-audit |
|--------------|-------|--------|---------------------|
| `references/*.md` (28 inline agents) | 28 | `/Users/rinne/Desktop/piolium/agents/*.md` (frontmatter + codex-trim stripped) | Piolium specialist roles, inlined into `Task` prompts |
| `references/hunting/hunt-<class>.md` | 58 | cybermes `Claude-BugHunter/skills/hunt-*/SKILL.md` | Active hunting methodology for each vuln class (how to find it) |
| `references/vuln-classes/<class>.md` | 29 | strix `strix/skills/vulnerabilities/*.md` | Class reference (what X looks like, DBMS primitives, framework risks) |
| `references/methodology/<name>.md` | 8 | 7 from cybermes `Claude-BugHunter/skills/<name>/SKILL.md` + 1 original (`permission-delta-judging.md`) | Operator methodology (redteam mindset, evidence hygiene, report writing) |
| `references/wordlists/<name>.txt` | 5 | cybermes `tools/wordlists/*.txt` | Runtime enumeration resources (read via `Bash cat`) |

**Cross-reference**: `references/_hunt-class-map.md` maps 53 vuln classes to their corresponding hunting + vuln-classes pair, and to mini-audit's `attack-ideator` 8 modes.

### Context budget discipline (CRITICAL — read first)

The 100 reference files total 1.8MB on disk. None of that enters context unless the orchestrator explicitly reads a file. Per sub-agent call, inline at most **1 hunting + 1 vuln-classes + 1 inline agent** file = 10-30KB ≈ 3-8K tokens. Opus 200K context is enough headroom for 17 phases.

**NEVER** (will blow up the context window):

- `Read references/` or `Read references/hunting/` or `Read references/vuln-classes/` as a **directory read** — would load 1.2MB ≈ 250K+ tokens in one go
- `Read` more than **1 hunting/*.md** file per Task dispatch (only inline the one matching the current hypothesis class)
- `Read` more than **1 vuln-classes/*.md** file per Task dispatch
- Re-`Read` `references/_hunt-class-map.md` more than **once per session** — read it at session start, then refer to it from working memory
- Re-`Read` `references/README.md` more than **once per session**
- Inline `methodology/redteam-mindset.md` or `methodology/evidence-hygiene.md` or `methodology/permission-delta-judging.md` mid-session — they are pre-flights only

**ALWAYS**:

- At session start, `Read` `references/_hunt-class-map.md` **once** (10.6KB) to learn the class→file mapping
- At session start, `Read` `references/README.md` **once** (8.8KB) to learn the layout
- For each Task dispatch, determine the hypothesis class first, then read at most 1 hunting + 1 vuln-classes file by exact path
- Use `Glob` or `Bash ls` to verify file existence, never `cat` a whole directory
- Pre-flight load `methodology/redteam-mindset.md` and `methodology/evidence-hygiene.md` and `methodology/permission-delta-judging.md` **once** at the start of the first sub-agent dispatch
- Use `Bash cat <single-wordlist-file>` (not `Read`) for wordlists — they're runtime resources, not prompt templates

**Cost model (per phase)**:

| Component | Typical size | Tokens | When read |
|-----------|--------------|--------|-----------|
| orchestrator's own system prompt | 5-10KB | 1.5-3K | always (registered in mavis) |
| sub-agent system prompt (e.g. attack-ideator) | 5-15KB | 1.5-4K | per dispatch (mavis passes) |
| phase task prompt | 1-3KB | 0.5-1K | per dispatch |
| inline role spec (1 file) | 5-30KB | 1.5-8K | per dispatch |
| inline class reference (hunt + vuln) | 10-30KB | 3-8K | per dispatch |
| **Total per dispatch** | **~30-90KB** | **~8-25K** | — |

Opus 200K context: even with 20 dispatched sub-agents in a long audit, the orchestrator's accumulated context stays under 80-100K tokens if it doesn't re-read map/README. Each sub-agent's own context is independent (mavis session) and resets after the dispatch returns.

**When you feel tempted to bulk-read** (e.g. "let me just look at all the SQLi stuff at once"):

Stop. Use the 1 hunting + 1 vuln-classes pattern. The cost of reading more is not just tokens — it dilutes the sub-agent's attention on the specific class being debated. Class-aware loading is also a quality control mechanism.

### Context pruning between phases (CRITICAL — apply after every sub-agent return)

Class-aware loading controls what enters context **at dispatch time**. Pruning controls what **stays** in the orchestrator's working memory after a sub-agent returns. Both are required.

**After every `Task(...)` return, the orchestrator compresses the result before moving to the next phase**:

| Field | Keep | Discard |
|---|---|---|
| Status | `complete` / `failed` / `skipped` (one word) | — |
| Summary | one-line, ≤ 200 chars | long-form prose |
| Artifacts | rel paths of files created | file contents (re-read on demand) |
| IDs | hypothesis / finding / cluster ID and verdict | raw tool calls and intermediate reasoning |
| Failure hint | if failed, ≤ 100 char re-dispatch hint | full stack trace (re-derive from logs on demand) |

**Per-phase compression rules**:

- After a chamber cluster closes: keep only the verdict table, not the full `debate.md`. The next phase reads `debate.md` from disk on demand.
- After probe workspace closes: keep only the `probe-summary.md` path, not the full evidence tree.
- After cold-verifier returns: keep only the verdict line + `cold-verify-verdict.md` path, not the full report.
- After static-analyzer returns: keep only the JSON summary, not raw SARIF.
- After KB-builder returns: keep only the section headers present in `knowledge-base-report.md`, not the full body.
- After judge-verdict (J1) returns: keep only `[<finding-id>, <verdict>, <one-line>]` tuples, not the full `judge-verdict.md`.

**Concretely**: replace the verbose return in working memory with a 4-tuple
```
[<id>, <status>, <one-line summary>, <artifact-paths>]
```
before issuing the next dispatch. The verbose content lives on disk; the
orchestrator only needs the index.

**Why this matters**: a balanced audit with 5-10 threat clusters produces
~30-60 sub-agent dispatches (chamber × 4 roles × 2-3 rounds × clusters,
plus KB builders, probe fan-out, cold-verifier, judge). Without pruning,
the orchestrator's working memory grows by ~10K tokens per dispatch
return. At 30 dispatches that's 300K tokens — already past Opus 200K
capacity. Pruning caps the orchestrator's active working set at
**~30-50K tokens** for the lifetime of a long audit.

**Discipline rules**:

- **NEVER**: re-`Read` a file the orchestrator already saw, just because
  it remembers the path is "important". The `Read` itself re-loads into
  context. Use the path; the next sub-agent can `Read` if it needs the
  body.
- **NEVER**: copy a sub-agent's full output into the prompt for the next
  sub-agent. Reference the artifact path; the next sub-agent reads on
  demand.
- **NEVER**: keep long markdown bodies (debate.md, judge-verdict.md,
  full report.md) in the orchestrator's context. The orchestrator is
  the **router**, not the **reader**. It dispatches; it does not
  re-summarize.
- **ALWAYS**: at the end of a phase, drop everything from prior phases
  except the artifact index, the verdict table, and the next-phase
  task prompt.

**Dispatch pattern (class-aware chamber)**:

When `mini-audit-ideator` generates a hypothesis with class `c`:

1. Read `references/_hunt-class-map.md` to find `hunting/hunt-<c>.md` (if exists) and `references/vuln-classes/<c>.md` (if exists)
2. Construct the role dispatch:

```
You are the <role>. You are about to be asked to work on hypothesis H-<NN> with class "<c>".

=== HUNTING METHODOLOGY (active steps for class <c>) ===
${readFileSync(`hunting/hunt-<c>.md`)}   # if exists
=== END HUNTING ===

=== VULN CLASS REFERENCE (technical deep-dive) ===
${readFileSync(`vuln-classes/<c>.md`)}   # if exists
=== END VULN CLASS REF ===

=== PHASE TASK ===
${perPhaseTaskPrompt}
=== END PHASE TASK ===
```

3. Repeat for `mini-audit-tracer` (loads only `vuln-classes/`) and `mini-audit-advocate` (loads only `vuln-classes/`).

**Pre-flights (load at the start of every mini-audit session)**:

```
You are starting a mini-audit session on <cwd>. Before any phase:

=== RED-TEAM MINDSET ===
${readFileSync("methodology/redteam-mindset.md")}
=== END ===

=== EVIDENCE HYGIENE ===
${readFileSync("methodology/evidence-hygiene.md")}
=== END ===

=== PERMISSION-DELTA JUDGING (cross-class meta-rule for VALID/INVALID verdicts) ===
${readFileSync("methodology/permission-delta-judging.md")}
=== END ===

=== BUG-BOUNTY (only if scope is bounty) ===
${readFileSync("methodology/bug-bounty.md")}
=== END ===
```

**Wordlist usage** (Bash cat, not prompt template):

```bash
# L5 / P8 probe-strategist directory/file enumeration
cat ~/.minimax/skills/mini-audit/references/wordlists/raft-medium-directories.txt | head -100

# L4 / P1.5 env-provisioner parameter fuzzing
cat ~/.minimax/skills/mini-audit/references/wordlists/burp-parameter-names.txt | head -50

# devils-advocate Layer 4 (Application) defense-bypass search
cat ~/.minimax/skills/mini-audit/references/wordlists/bypass-headers.txt
```

### Inline agent templates (28 files at `references/<name>.md`)

The remaining 28 Piolium specialist agents are NOT first-class mavis roles. They live as cleaned markdown templates under `references/`, and the orchestrator inlines them into `Task` prompts when a phase needs them. Index at `references/README.md`.

| File | Piolium agent | Used in phase(s) |
|------|---------------|------------------|
| `references/advisory-hunter.md` | advisory-hunter | L3 / P1 / KB1 — CVE mining |
| `references/authz-auditor.md` | authz-auditor | L6 / P8 / V5 — authorization review chamber |
| `references/backward-reasoner.md` | backward-reasoner | L6 / P8 — backward-reasoning round |
| `references/commit-archaeologist.md` | commit-archaeologist | L1 / P1 — commit archaeology |
| `references/confirm-reporter.md` | confirm-reporter | V1-V7 / V6 — confirm pass reporting |
| `references/contradiction-reasoner.md` | contradiction-reasoner | L6 / P8 — contradiction round |
| `references/cross-service-auditor.md` | cross-service-auditor | L5 / P8 — cross-service audit |
| `references/env-detective.md` | env-detective | L4 / P1.5 — env introspection |
| `references/env-provisioner.md` | env-provisioner | L4 / P1.5 — env provisioning |
| `references/evidence-harvester.md` | evidence-harvester | L6 / P8 / V5 — evidence collection |
| `references/finding-reporter.md` | finding-reporter | L7 / P15 — final finding report |
| `references/finding-triager.md` | finding-triager | L6b / P10 — draft triage |
| `references/intent-cartographer.md` | intent-cartographer | L1 / P2 / R0 — intent corpus |
| `references/knowledge-base-builder.md` | knowledge-base-builder | K1 / K2 — attack-surface KB build |
| `references/knowledge-base-loader.md` | knowledge-base-loader | K0 — external doc intake |
| `references/longshot-aggregator.md` | longshot-aggregator | X3 — longshot aggregation |
| `references/longshot-hunter.md` | longshot-hunter | X2 — longshot per-file hunt |
| `references/patch-bypass-checker.md` | patch-bypass-checker | P16 — deep patch-bypass check |
| `references/poc-builder.md` | poc-builder | Q3 / L6c / P13 / V3 — PoC construction |
| `references/poc-executor.md` | poc-executor | L7 / P13 — PoC execution |
| `references/probe-strategist.md` | probe-strategist | L5 / P8 — deep probe strategy |
| `references/report-assembler.md` | report-assembler | L7 / P14 — per-finding report |
| `references/spec-gap-analyst.md` | spec-gap-analyst | L6 / P9 — spec gap analysis |
| `references/state-concurrency-auditor.md` | state-concurrency-auditor | L6 / P8 — state-concurrency chamber |
| `references/test-mapper.md` | test-mapper | L6 / P8 — test coverage mapping |
| `references/variant-hunter.md` | variant-hunter | P12 / L6 — variant hunt / cross-check |
| `references/variant-scout.md` | variant-scout | X1 — longshot enumeration |
| `references/wave-verifier.md` | wave-verifier | I2 — cross-agent reinvest wave verification |

**Dispatch pattern** (when a phase needs an inline role):

1. Read `references/<name>.md` (the orchestrator has filesystem access).
2. Construct the `Task` tool prompt:

```
You are the <name> role. Follow the role specification below.

=== ROLE SPEC ===
<contents of references/<name>.md, the full body after the auto-generated header>
=== END ROLE SPEC ===

=== PHASE TASK ===
<per-phase task prompt: cwd, mode, input artifacts, output expectations, hard limits>
=== END PHASE TASK ===
```

3. Use `subagent_type: "general"` for inline roles — they do not have a first-class agent. The role spec + phase task together shape the sub-agent's behavior.
4. After the sub-agent returns, verify the gate artifact on disk before marking the phase `complete`.

**Hard limits carried over from Piolium** (apply to inline role dispatches):

- `poc-builder` — 3 min wall-clock cap per finding (lite) / 5 min (balanced)
- `static-analyzer` (first-class) — 5 min wall-clock (lite) / 15 min (balanced)
- Review Chamber hard limits (already enforced by `mini-audit-synthesizer`): max 7 hypotheses/batch, max 3 rounds/hypothesis, max 6 rounds/chamber

**No Piolium upstream tracking** (architectural decision): the 28 inline agent templates and 7 first-class agent prompts are a **one-time import**. We do NOT maintain bidirectional sync with Piolium. If a Piolium update lands new patterns of interest, the user re-imports manually. The 108 substitution renames (rounds 1-3) are also a one-time cost — the user has accepted that this fork will drift from Piolium over time.

## State machine (on-disk canonical, runtime-owned; Hardening v1.1)

Each phase has status: `pending` → `in_progress` → `complete` | `failed` | `skipped`.

As of Runtime Hardening v1 (see [§ Runtime Hardening](#runtime-hardening-v1-deterministic-layer)), the **canonical state lives on disk at `<cwd>/mini-audit/audit-state.json`**, owned by the deterministic runtime. Agent memory may still hold a snapshot for fast cache reads, but it is **not** the resume authority. All writes to `audit-state.json` go through the `mini-audit-runtime` CLI; the SKILL never edits the JSON directly.

Phase entry shape (mirrored by `runtime.state.PhaseState`):

```yaml
audit_id: <iso-ts>
mode: <mode>
status: <in_progress|complete|incomplete|blocked>
source:
  repository: <git remote or null>
  root: <abs path>
  commit: <sha>
  branch: <name>
  dirty: <bool>
  tree_hash: <sha>
runtime:
  version: "1.0.0"
  agent_sdk: mavis
  model: <name>
phases:
  L1:
    name: L1
    status: complete
    attempt: 1
    max_attempts: 2
    started_at: <iso>
    completed_at: <iso>
    heartbeat_at: <iso>
    artifacts:
      - { path: mini-audit/attack-surface/intent-corpus.json, sha256: ... }
    last_error: null
```

**Forbid**:

* `pending → complete` (must go through `in_progress`)
* `failed → complete` (must re-enter `in_progress`)
* `complete → complete` (no-op)

**Allowed recovery**:

* `failed → in_progress → complete`

The orchestrator does NOT hand-edit state. It shells out to:

```bash
mini-audit-runtime state init --repo-root <path> --audit-root mini-audit
mini-audit-runtime phase start L5
mini-audit-runtime phase complete L5
mini-audit-runtime phase fail L5 --error "..."
mini-audit-runtime phase skip L5
mini-audit-runtime gate L5
mini-audit-runtime state show
```

### Resume protocol

Before resuming (`--action=resume`), the runtime captures a fresh `SourceIdentity` and compares against the stored one:

```bash
mini-audit-runtime source diff --repo-root <path> --audit-root mini-audit
```

| `commit` / `worktree_hash` change | Behavior |
|------------------------------|----------|
| both unchanged | reuse complete phases; resume from first non-terminal |
| either changed | `SOURCE_CHANGED`; refuse to silently reuse; require `--accept-source-change` to acknowledge; artifact-only phases may be re-validated, source-derived phases must rerun |

`worktree_hash` covers the tracked diff **and** untracked (non-ignored) files, so an uncommitted working-tree edit — not just a new commit — trips `SOURCE_CHANGED` and blocks a silent resume. `tree_hash` (committed tree) alone could not see that.

### Why both memory and disk?

* Disk (`audit-state.json`) is the **durable truth** — survives process death, cross-host portability, gates, fingerprinting, coverage ledger all read from it.
* Memory is a **read cache** for the orchestrator so it can render status without re-parsing JSON on every tool call. Writes always go to disk via the CLI.

See [§ Runtime Hardening](#runtime-hardening-v1-deterministic-layer) for the full architecture.

## Artifact gate (deterministic, not the agent's word)

After every phase, the orchestrator must check the gate artifact on disk before marking the phase `complete`. **The agent's "I'm done" is not sufficient.** Phase X is `complete` only when its required artifact exists.

### Lite mode gates

| Phase | Required artifact(s) |
|-------|----------------------|
| Q0 | `mini-audit/attack-surface/recon-report.md`, `mini-audit/attack-surface/candidates-summary.md`, `mini-audit/attack-surface/candidates.jsonl` |
| Q1 | `mini-audit/attack-surface/lite-q1-summary.md` |
| Q2 | `mini-audit/attack-surface/lite-q2-summary.md`, `mini-audit/attack-surface/unauthenticated-surface.md` |
| Q3 | `mini-audit/attack-surface/lite-consolidation-manifest.json` (one `poc.*` or `poc.theoretical.md` per promoted finding) |
| Q4 | `mini-audit/attack-surface/lite-verification-summary.md` |

### Balanced mode gates

| Phase | Required artifact |
|-------|-------------------|
| L1 | `mini-audit/attack-surface/intent-corpus.json` |
| L2 | `mini-audit/attack-surface/knowledge-base-report.md`, `mini-audit/attack-surface/sbom.json` |
| L3 | (advisories written to KB) |
| L4 | (env provisioning log in KB) |
| L5 | `mini-audit/probe-workspace/*/probe-summary.md` (one per high-risk slice) |
| L6 | `mini-audit/chamber-workspace/*/debate.md` (CLOSED), `mini-audit/findings-draft/p10-*.md` (one per VALID) |
| L6b | `mini-audit/findings/<id>-<slug>/draft.md` (one per promoted) |
| L6c | one `poc.{py,sh,js,rb,go}` or `poc.theoretical.md` per finding |
| L7 | `mini-audit/findings/<id>-<slug>/cold-verify-verdict.md` (CRIT/HIGH only), `mini-audit/findings/<id>-<slug>/report.md` (all), `mini-audit/final-audit-report.md` |

### Deep mode gates (P1–P17)

- P1 advisories: `mini-audit/attack-surface/advisories.md`
- P1.5 env: `mini-audit/attack-surface/env-provisioning.md`
- P2 intent: `mini-audit/attack-surface/intent-corpus.json` (deep variant)
- P3 attack surface: `mini-audit/attack-surface/knowledge-base-report.md` (full DFD/CFD)
- P4 SAST: `## Static Analysis Summary`, `## CodeQL Structural Analysis`, `## SAST Enrichment` sections of `knowledge-base-report.md`
- P5/P6/P7: probe results
- P8 deep-probe: `mini-audit/probe-workspace/*/probe-summary.md`
- P9 spec gap: `mini-audit/attack-surface/spec-gap.md`
- P10 chamber: as in L6
- P11 cold verify: as in L7
- P12 variant hunt: `mini-audit/attack-surface/variant-candidates.md`
- P13 PoC: `mini-audit/findings/<id>-<slug>/poc.{py,sh,js,rb,go}`
- P14 report: `mini-audit/findings/<id>-<slug>/report.md`
- P15 final: `mini-audit/final-audit-report.md`
- P16 patch-bypass: `mini-audit/findings/<id>-<slug>/patch-bypass.md` (per finding with a known fix)
- P17 cleanup: `mini-audit/attack-surface/cleanup-manifest.json` (transient paths removed)

### Gate coverage

**Gate coverage: 38 phases declare a deterministic gate** — the ungated
remainder is listed below rather than assumed away.

| Mode | Gated | Ungated (no dedicated artifact) |
|------|-------|----------------------------------|
| lite | Q0, Q1, Q2, Q3, Q4 | — |
| balanced | L1, L2, L3, L4, L5, L6, L6b, L6c, L7 | — |
| deep | P1, P1.5, P2, P3, P8, P9, P10, P12, P13, P14, P15, P16, P17 | P4, P5, P6, P7, P11 |
| confirm | V1, V7 | V1.5, V2, V3, V4, V5, V6 |
| revisit | R0 | R5, R7, R8, R9, R10, R10k, R11, R11b, R11c |
| merge | — | M1, M2, M3, M4, M5, M6, M7 |
| longshot | X1, X2, X3 | — |
| reinvest | I2 | I1, I3 |
| knowledge-base | K1, K2 | KB0 |
| judge | J1, J2 | — |

A phase is gated when it writes a **dedicated artifact file** the runtime can
`stat`, parse and schema-check on disk. The ungated set is deliberate:

- **P4–P7, P11** write *sections* into a shared document
  (`knowledge-base-report.md`, `probe-workspace/*/probe-summary.md`,
  `findings/*/cold-verify-verdict.md`) that other phases also write, so a
  per-phase existence gate would be satisfied by a sibling phase's output.
- **V1.5, V2–V6** are per-finding and optional (V1.5 is skipped when no intent
  corpus exists; V2–V5 only run for findings with a runnable PoC).
- **R5–R11c, M1–M7, I1, I3, KB0** re-run agents over an existing finding set
  or are optional intake steps with no documented artifact path.

Gating those would block legitimate completion, which is worse than an honest
gap. `runtime/gates.py` owns the canonical sets (`gated_phases(mode)` /
`ungated_phases(mode)`), `scripts/doc_counts.py` verifies the count quoted here,
and `tests/unit/test_gate_coverage.py` fails if a phase is silently moved from
one set to the other.

## Hard filter at the gate (mandatory, no finding escapes these three)

Before any finding is promoted to `findings-draft/` (or any report), the
chamber-synthesizer (and later the judge) must pass **all three** of:

1. **Privilege Delta != None** — the boundary sentence can be filled
   with two distinct capabilities. If "before" and "after" describe the
   same capability, or the attacker could already do the "after"
   through normal features, Delta is None.
2. **Boundary Sentence complete** — the 21st-section template
   (filling-the-blanks: "an attacker who could only X can now Y, but
   the product's permission model did not allow Y") is filled in
   concretely. No "TBD", no "see report", no abstract phrases.
3. **Six FP gate all answered** — DEFAULT / AUTHORITY / DEPENDENCIES /
   DERIVATION / SPEC / DELTA each have a concrete answer. Any
   "unknown" → the gate fails.

**Demotion (when any of the three fails)**:

| Failed condition | Demote to |
|---|---|
| Privilege Delta None (counterfactual passed = same effect via normal features) | `NO_NEW_SECURITY_CAPABILITY` |
| Privilege Delta None because admin can already do this | `PREREQUISITE_DOMINATES_IMPACT` |
| Six FP — DEFAULT shows effective value is safe | `INTENDED_BEHAVIOR` |
| Six FP — AUTHORITY shows admin opt-in required | `ADMIN_MISCONFIGURATION` |
| Six FP — SPEC shows only SHOULD/BCP violation, no boundary crossing | `SPEC_COMPLIANT_WEAK_DEFAULT` / `LEGACY_SECURITY_DEFAULT` / `HARDENING_OPPORTUNITY` |
| Six FP — DEPENDENCIES shows depth >= 2 | downgraded confidence; usually `HARDENING_OPPORTUNITY` |
| Six FP — DERIVATION shows constrained source | typically `HARDENING_OPPORTUNITY` (the constrained value reaches the sink safely) |
| 14-item report gate fails on multiple boxes | `INSUFFICIENT_EVIDENCE` / `FALSE_POSITIVE` |

**The chamber-synthesizer's `Pre-Finding Quality Gate` (in its agent
prompt) implements this as step 4, between the existing 5 checks and
the severity calibration. The convergence table maps every outcome to
a 12-category label, not the old VALID / FALSE POSITIVE dichotomy.**

A finding that fails the hard filter is **not** written to
`findings-draft/`. It is logged in `chamber-workspace/<id>/debate.md`
with its 12-category label, and the audit-state records it as
"demoted" rather than "promoted". The user still sees all demoted items
in the final report, but they go to the misconfiguration / hardening /
false-positive appendix, not the vulnerability list.

This is a **hard gate**, not a soft warning. It is what stops
over-confirmation from contaminating the report.

## Concurrency cap (Swarm Burst Cap)

Default 3 concurrent sub-agents, overridable via `--max-agents=N` or env `MINI_AUDIT_MAX_AGENTS`. Piolium's `Scheduler` (FIFO with `maxConcurrent` + per-task `AbortSignal` + timeout) maps to mavis's `Task` tool with the appropriate batching. For batch dispatches, cap the in-flight count.

## Review Chamber debate protocol (L6 / L10 / V5)

For each threat cluster:
1. Dispatch `Task(subagent_type="mini-audit-ideator", prompt=...)` — 8-mode hypothesis generation, max 7/batch
2. Dispatch `Task(subagent_type="mini-audit-tracer", prompt=...)` — trace H-01..H-NN, mark REACHABLE/PARTIAL/UNREACHABLE
3. Dispatch `Task(subagent_type="mini-audit-advocate", prompt=...)` — 5-layer protection search, FP-pattern check
4. Dispatch `Task(subagent_type="mini-audit-synthesizer", prompt=...)` — verdict + finding draft (only role that writes drafts)

**Hard limits**: max 7 hypotheses/batch, max 3 rounds/hypothesis (1 initial + 2 follow-ups), max 6 total rounds/chamber.

**Permission-delta gate (synthesizer-only, but all 4 roles should know it)**:

Every `VALID` verdict must pass **both** the **one-sentence test** and the
**counterfactual test** from `methodology/permission-delta-judging.md`:

- *One-sentence*: "An attacker who could only **X**, through this finding, can now **Y**, which the product's permission / isolation model did not allow." Both blanks must be filled concretely. If the two blanks describe the same capability, the finding is `INVALID`.
- *Counterfactual*: After the proposed fix, with the attacker's pre-existing privileges unchanged, can they still reach the same effect through normal features? If yes, the finding is hardening, not a boundary crossing.

The 4 roles' interaction with the framework:

- **ideator** — gate every generated hypothesis against the one-sentence test before dispatch; drop candidates that fail.
- **tracer** — when marking REACHABLE, also state the attacker's pre-existing authority and the specific boundary that would be crossed.
- **advocate** — work the anti-patterns list as your checklist; if a candidate finding matches any of the 10 anti-patterns, your job is to break it before the synthesizer promotes it.
- **synthesizer** — apply the one-sentence and counterfactual tests as gate conditions for `VALID`. A draft that cannot pass both is `INVALID — <category: by-design / equivalent-capability / post-compromise / hardening / invented-permission / etc.>`.

## Cold verifier isolation rule (L7 / P11 / V6)

When dispatching `mini-audit-cold-verifier`, the prompt must hard-constrain input:

```
You will receive ONLY a single finding draft file path. You MUST NOT:
- read mini-audit/chamber-workspace/
- read mini-audit/probe-workspace/
- read any other mini-audit/ file
- read prior wave verdicts before forming your own view
Read the draft, restate the claim, trace from source independently, search 5 protection layers, write cold-verify-verdict.md.
```

**Note on what cold-verifier DOES load (intentional)**: the class-agnostic
judging meta-rule `methodology/permission-delta-judging.md` is loaded by
cold-verifier on purpose. The isolation property is preserved by what
cold-verifier does **not** read (chamber / probe workspaces, prior verdicts,
class-specific hunting references) — not by skipping the meta-rule. The
permission-delta framework is the standard the chamber and the cold-verifier
both apply, but cold-verifier applies it independently without seeing how the
chamber applied it. This keeps the standards aligned (so the cold-verifier
does not reject valid findings on bad grounds) while preserving the
zero-debate-bias property.

## Resume protocol (`--action=resume`)

1. Query memory for the latest non-complete audit under `mini-audit-state-*` topic prefix
2. Identify the last `in_progress` or `failed` phase
3. Verify its gate artifact does NOT exist (otherwise mark `complete` and skip)
4. Resume from that phase, retaining all `complete` phases
5. If `--fresh` is set, ignore memory and start over

## Default task prompt template (lite Q2 example)

When dispatching a sub-agent for phase Q2 (lite SAST), the prompt is:

```
You are running the Q2 phase of a /mini-audit-lite scan on <cwd>.

This is a TIGHTLY SCOPED lite-mode SAST pass — not a full audit. Constraints:
  - Hard time budget: 5 minutes wall-clock.
  - Do NOT build CodeQL/Semgrep databases. If those tools aren't already installed, fall back to grep + read.
  - Focus on cheap, high-signal patterns: command injection, path traversal, SSRF, hardcoded crypto, broken authn/z.
  - Read mini-audit/attack-surface/lite-recon.md, candidates-summary.md, candidates.jsonl, lite-q1-summary.md if present.
  - For each candidate issue, write a draft finding to mini-audit/findings-draft/q2-NNN-<slug>.md.
  - Write a phase summary to mini-audit/attack-surface/lite-q2-summary.md even when nothing is found.
  - Always write mini-audit/attack-surface/unauthenticated-surface.md: best-effort model-level enumeration of pre-auth reachability, classify each entry as by-design / missing-guard / middleware-gap.
  - Pre-auth = highest severity. When a finding is reachable from a pre-auth entry point, elevate severity one band and note 'pre-auth' in the draft.
  - Stop after at most 8 candidate findings — quality over quantity.

Each finding draft frontmatter:
  ---
  id: q2-NNN
  phase: Q2
  slug: <kebab-case>
  severity: high|medium|low
  ---

Begin now.
```

Similar templates exist for every other phase; the orchestrator builds the per-phase prompt from the per-phase constraints in this skill.

## Mode-specific orchestrators (delegation patterns)

### `lite` (5 phases, ~5 min wall-clock)
Q0 (deterministic recon + candidate scan) → [Q1 (trufflehog/gitleaks, deterministic) ‖ Q2 (`mini-audit-static-analyzer`, lite prompt)] → Q3 (consolidate drafts → per-finding `poc-builder` fan-out, max 3 concurrent) → Q4 (verify + cleanup transient).

### `balanced` (9 phases, ~30-60 min)
L1 (`intent-cartographer` inline) → L2 (`knowledge-base-builder` inline) → [L3 (`advisory-hunter` inline) ‖ L4 (`env-provisioner` inline)] → L5 (`probe-strategist` inline, fan-out per slice) → L6 (Review Chamber per threat cluster) → L6b (promote drafts to findings/) → L6c (per-finding `poc-builder` fan-out) → L7 (`mini-audit-cold-verifier` for CRIT/HIGH + `report-assembler` for all + cleanup).

### `deep` (17 phases, hours)
P1..P17, mostly the balanced sequence plus P9 spec-gap, P12 variant hunt, P13 PoC per-finding, P14 report, P15 final, P16 patch-bypass, P17 cleanup.

### `confirm` (V1-V7, validates a pre-existing finding set)
V1 boot, V1.5 intent cross-check, V2..V5 incremental cold verification, V6 final review chamber, V7 redaction + cleanup.

### `revisit` (R0-R11c, anti-anchoring)
R0 intent corpus rebuild, R5/R7/R8/R9/R10/R10k iterative chambers, R11/R11b/R11c final.

### `merge` (M1-M7, deterministic)
M1 deterministic copy, M2..M7 agent-driven dedup, renumber, report. Records an audit run.

### `longshot` (X1-X3, hail-mary)
X1 enumerate → X2 hunt fan-out (`variant-scout` per file) → X3 aggregate.

### `reinvest` (I1-I3, cross-agent)
I1 enumerate CRIT/HIGH → I2 `wave-verifier` fan-out (cap 3) → I3 consensus summary.

### `knowledge-base` (KB0-K2, context-only)
KB0 external-doc intake (optional) → K1 advisory + SBOM → K2 project model + unauth surface. Stops before SAST/findings.

### `judge` (J1-J2, **NEW** — permission-delta meta-audit re-judgment)

Meta-audit mode that re-evaluates **already-confirmed** findings against
`methodology/permission-delta-judging.md`. Run after `balanced` / `deep` /
`confirm` / `revisit` to catch over-confirmation that the chamber and
cold-verifier missed. Does NOT run a new attack; does NOT debate; does NOT
re-trace code from scratch. Reads each finding's report + cited paths, writes
an independent verdict.

- **J1** — Per-finding re-judgment. Dispatch `Task(subagent_type="mini-audit-judge", prompt=...)`
  once per `<id>-<slug>/`. Each dispatch is independent (no cross-finding bias).
  Writes `<id>-<slug>/judge-verdict.md`. Default scope: all `mini-audit/findings/<id>-<slug>/`
  directories; `--finding=<id>` limits to a single finding for spot-check.
- **J2** — Aggregate. The orchestrator (not a sub-agent) walks all
  `judge-verdict.md` files, partitions findings into the re-classification
  categories, writes `mini-audit/judge-report.md` with the **full table** and
  the proposed re-classifications. **J2 produces ONE aggregated re-classification
  table covering all findings, NOT per-finding prompts.** The user reviews the
  full table once at the end and either accepts all proposed re-classifications,
  accepts with edits, or rejects and keeps the original chamber verdict. J2 is
  the ONLY place in mini-audit that pauses for user input.

**Isolation properties** (parallel to cold-verifier, but distinct purpose):

- The judge loads only `methodology/permission-delta-judging.md` — no
  class-specific hunting, no class-specific vuln reference, no chamber debate,
  no probe workspace, no other findings' verdicts.
- The judge may read the cited source files to verify the claim, but does
  not re-trace from scratch.
- The judge's verdict is independent of the chamber's and cold-verifier's
  verdicts. If all three agree, the finding is strongly VALID. If the judge
  disagrees, the user is shown the disagreement and asked to accept the
  re-classification.

**Re-classification outputs** (one of, per non-VALID finding):

- `→ drop` — remove from `findings/`, do not export
- `→ hardening` — move to `mini-audit/hardening.md` (separate non-vuln list)
- `→ re-dispatch` — kick back to chamber with the missing piece named
- `→ keep-as-valid` — re-affirm (the framework passes despite chamber framing)
- `→ keep-with-adjusted-severity` — VALID but the original severity was inflated

**Default scope**: all `mini-audit/findings/<id>-<slug>/`. The `--finding=<id>`
flag limits J1 to a single finding for spot-checking.

## CLI flag → env mapping (preserved from Piolium)

| Flag | Env | Default | Purpose |
|------|-----|---------|---------|
| `--dir=PATH` | `MINI_AUDIT_DIR` | cwd | Target repo |
| `--fresh` | `MINI_AUDIT_FRESH` | off | Restart from scratch |
| `--max-agents=N` | `MINI_AUDIT_MAX_AGENTS` | 3 | Swarm Burst Cap |
| `--phase-retries=N` | `MINI_AUDIT_PHASE_MAX_RETRIES` | 5 | Per-phase retry count |
| `--phase-backoff=ms` | `MINI_AUDIT_PHASE_BACKOFF_BASE_MS` | 5000 | Per-phase retry base backoff |
| `--phase-backoff-max=ms` | `MINI_AUDIT_PHASE_BACKOFF_MAX_MS` | 120000 | Per-phase retry max backoff |
| `--longshot-limit=N` | `MINI_AUDIT_LONGSHOT_LIMIT` | 1000 | Longshot max files |
| `--longshot-timeout=ms` | `MINI_AUDIT_LONGSHOT_TIMEOUT_MS` | 21600000 | Longshot per-file kill timer (6h) |
| `--longshot-langs=py,go` | `MINI_AUDIT_LONGSHOT_LANGS` | auto | Longshot language allowlist |
| `--longshot-include-tests` | `MINI_AUDIT_LONGSHOT_INCLUDE_TESTS` | off | Include test files |
| `--knowledge-base=PATH` | `MINI_AUDIT_KNOWLEDGE_BASE` | unset | Markdown file or docs dir as untrusted KB input |
| `--knowledge-base-raw=STRING` | `MINI_AUDIT_KNOWLEDGE_BASE_RAW` | unset | Inline markdown KB input |
| `--since=SHA` | `MINI_AUDIT_SINCE` | unset | Diff base commit |
| `--repo=URL` | `MINI_AUDIT_REPO` | unset | Confirm pass repo URL override |
| `--finding=<id>` | `MINI_AUDIT_FINDING_ID` | unset | `--mode=judge` only: limit J1 to a single finding (spot-check) |

The `MINI_AUDIT_*` env prefix replaces Piolium's `PIOLIUM_*` prefix. Migration scripts can `PIOLIUM_*` → `MINI_AUDIT_*` with sed.

## Run lifecycle (orchestrator checklist)

When invoked with `--action=run --mode=<mode> [--fresh] [--dir=PATH]`:

1. Resolve target dir (default = cwd, fallback = `--dir`)
2. Initialize or resume audit state in memory (skip if `--fresh`)
3. Print the phase strip (TUI equivalent: render a status table to chat):
   ```
   ● Q0 quick recon       (in progress, attempt 1/6)
   · Q1 secrets           (queued)
   · Q2 fast SAST         (queued)
   · Q3 promote+PoC       (queued)
   · Q4 verify+cleanup    (queued)
   ```
4. For each phase in canonical order:
   a. If status=complete and gate artifact exists → skip
   b. Mark status=in_progress, attempt=N in memory
   c. Dispatch the agent with the per-phase task prompt
   d. Wait for completion (foreground, since results are blocking)
   e. Verify gate artifact exists
   f. If gate passes → mark complete, write memory snapshot
   g. If gate fails and attempts < max → retry with exponential backoff
   h. If gate fails and attempts == max → mark failed, surface error
5. After all phases, write final summary to chat:
   ```
   mini-audit (balanced) complete — 3 findings (1 CRIT, 1 HIGH, 1 MEDIUM)
   Audit state: ~/.minimax/agents/mavis/memory/mini-audit-state-2026-09-09T16:25:30Z
   Final report: <cwd>/mini-audit/final-audit-report.md
   ```

## Sub-agent dispatch (mavis `Task` tool)

```typescript
Task(
  subagent_type: "mini-audit-static-analyzer",   // the role
  description: "Q2 fast SAST",                    // human-readable
  prompt: buildQ2TaskPrompt(cwd, target),         // per-phase template
  isolation: "worktree",                          // optional
)
```

When the role is not first-class (e.g. `poc-builder`, `report-assembler`), use the generic `general` agent and inline the Piolium `agents/<name>.md` body into the prompt — set the prompt prefix to: `You are the <name> role. Follow the role specification below.\n\n<agents/<name>.md body>\n\n<phase-specific task>`.

## Sub-tasks this skill dispatches to itself (for complex per-phase work)

- `Task(subagent_type="explore")` — read-only mapping of target repo's attack surface, before SAST phase
- `Task(subagent_type="verifier")` — independent verification of synthesizer verdict when its confidence is low
- `Task(subagent_type="general")` — inline-role dispatch for non-first-class specialists

## Reuse of bundled skills

The following Piolium skills should be loaded via the local skill loader when their phase is active:
- `codeql` — Phase P4 CodeQL runs
- `semgrep` — Phase P4 Semgrep runs (Pro when available)
- `sarif-parsing` — Phase P4 SARIF merging
- `audit` — general audit methodology
- `vuln-report` — final report assembly
- `security-threat-model` — Phase P9 spec gap
- `agentic-actions-auditor` — when `.github/workflows/` exists
- `zeroize-audit` — when crypto/secret classes are present
- `sharp-edges` / `insecure-defaults` / `supply-chain-risk-auditor` / `variant-analysis` / `spec-to-code-compliance` / `differential-review` / `fp-check` — on-demand via the orchestrator

## Output conventions

- All findings live under `<cwd>/mini-audit/findings/<id>-<slug>/{draft.md, poc.*, evidence/, report.md}`
- Final report at `<cwd>/mini-audit/final-audit-report.md`
- KB at `<cwd>/mini-audit/attack-surface/`
- Transcripts: mavis session messages (per session, queryable via `mavis session messages <id>`)
- No `tmp/mini-audit/runs/<runId>/` directory — replaced by mavis's native session storage

## Quick start (chat form)

```
> /skill:mini-audit --action=help
> /skill:mini-audit --action=status --dir=~/Desktop/target-repo
> /skill:mini-audit --action=run --mode=lite --fresh --dir=~/Desktop/target-repo
> /skill:mini-audit --action=run --mode=balanced --fresh --dir=~/Desktop/target-repo
> /skill:mini-audit --action=run --mode=deep --fresh --dir=~/Desktop/target-repo
> /skill:mini-audit --action=resume
> /skill:mini-audit --action=export --format=md-dir --out=~/Desktop/export --min-severity=high
> /skill:mini-audit --action=learn --apply
```

## Migration note (Piolium → mini-audit)

- All Piolium `PIOLIUM_*` env vars → `MINI_AUDIT_*`
- All Piolium `piolium/` artifact dir → `mini-audit/` (no interop requirement; mini-audit is a standalone mavis skill)
- Phase IDs unchanged: Q0..Q4, L1..L7, P1..P17, V1..V7, R0..R11c, M1..M7, X1..X3, I1..I3, KB0..K2
- Audit state is canonical on disk at `mini-audit/audit-state.json` (runtime-owned); `mavis memory` is only a read cache for the orchestrator
- 35 specialist agents → 7 first-class roles + 28 inline-dispatched roles
- Pi extension runtime → mavis skill + `Task` tool
