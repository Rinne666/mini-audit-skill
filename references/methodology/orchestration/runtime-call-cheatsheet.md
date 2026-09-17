# Runtime call cheatsheet (scanner / sandbox / export / coverage / state)

This is the quick reference for what the orchestrator calls into the runtime
for, and what each call writes back. SKILL.md keeps the thin overview; this
file owns the per-call mechanics.

## Scanner integration (Spec §26–28)

Scanners do **not** write findings. They write **candidates**. The pipeline
is:

```text
scanner (codeql / semgrep / sarif) → SARIF
   ↓
mini-audit-runtime sarif normalize <sarif> --source <name>
   ↓
mini-audit/candidates/<source>-candidates.json
   ↓
review-chamber turns candidates into draft findings
```

Rule: **candidates go through the chamber.** A scanner's output is never
promoted directly to a finding, even if it carries a CVE id. The chamber is
what makes a finding a *judgement*, not a *signal*.

The orchestrator decides **which** scanner to run per phase:

- `idle / Q0` — `mini-audit-runtime detect-tools` once
- `Q2` (lite) — built-in grep + read; no external scanner
- `L5 / P8` (deep probe) — `scripts/run-codeql.sh` or `scripts/run-semgrep.sh`
  via `mini-audit-runtime sandbox-run --kind source-scan`

**Hard rule**: every scanner invocation goes through `mini-audit-runtime
sandbox-run --kind source-scan`. The sandbox probe must pass; otherwise the
runtime refuses to execute the scanner.

## Sandbox policy (Spec §25)

The sandbox policy is **deterministic and probe-enforced**. Three primitives:

- `mini-audit-runtime sandbox probe --kind <K>` — runs the differential canary
  on the chosen isolation backend and writes
  `mini-audit/sandbox/probe-<K>.json` with `passes: true/false`.
- `mini-audit-runtime sandbox check --kind <K>` — reads the probe document
  and reports `passes: true/false` without re-running it. (Use this in CI; do
  not re-probe every audit.)
- `mini-audit-runtime sandbox run --kind <K> -- <cmd>` — executes a command
  under the sandbox policy iff the probe for `K` is passing. Policy-denied
  exits with code 4 and writes a machine-readable reason.

`K` is one of `target-build`, `source-scan`, `poc`. The probe for `K=poc` is
the strictest (full differential canary). For lite mode, `K=source-scan` is
sufficient.

**No host fallback.** A policy-denied execution is a hard failure, not a
warning. The orchestrator surfaces it as `SandboxPolicyDenied` and continues.

## Export (Spec §34)

The export is **deterministic** and emit-once-only. Three formats:

- `mini-audit-runtime export --format json` — full `findings.json` re-emitted
  in a stable JSON shape. Used for downstream tools and SARIF ingest.
- `mini-audit-runtime export --format md` — Markdown report. The default
  shape the orchestrator prints to chat.
- `mini-audit-runtime export --format sarif` — SARIF 2.1.0, suitable for
  GitHub code-scanning ingest.

Filters:

- `--verdict` (confirmed / needs_validation / rejected / invalid)
- `--min-severity` (critical / high / medium / low / info)
- `--class` (single vuln class)
- `--since` (ISO 8601 timestamp)

**No state mutation.** Export is a pure read against canonical findings.

## Coverage accounting (Spec §20)

`coverage-ledger.json` lives next to the other canonical artifacts. It
records:

- `planning_status` — `complete` | `in_progress` | `pending`
- `units[]` — one entry per attack-class × boundary × subsystem triple, with
  status `planned` / `in_progress` / `covered` / `deferred` / `rejected`

`mini-audit-runtime coverage init <plan>` seeds the ledger from a plan
JSON. `mini-audit-runtime coverage validate` runs the same schema + semantic
checks the L7 closure gate does, separately from the gate.

The orchestrator reads `coverage-ledger.json` via the snapshot
(`mini-audit-runtime snapshot`) — the snapshot exposes `coverage_debt` (a
mechanical summary the model can reason over, not a decision the runtime
makes).

## Reference provenance (Spec §35, §36; Hardening v1.1 §13)

Every artifact referenced by a finding draft carries a `references/<name>.md`
provenance — the role that cited the file, the line range, the citation time.
The fingerprint of a finding includes the reference SHA-256, so a finding
becomes stale the moment a referenced file changes.

`mini-audit-runtime reference provenance <finding-id>` emits the provenance
list for one finding. The orchestrator uses this to detect findings that
became stale after a code change and re-dispatches them through the chamber.

## Stable fingerprint (Spec §12)

A finding's fingerprint is `sha256(class | attacker.type | before_capability
| after_capability | security_invariant | boundary.kind)`. Two findings
sharing a fingerprint are duplicates — the second is rejected at promotion.
A finding without a fingerprint is rejected at promotion with reason
`missing_fingerprint`.

The fingerprint is computed by `mini-audit-runtime finding validate
<file>` and stored on the canonical `findings.json` entry. The orchestrator
never mints a fingerprint manually.

## Default Security Invariant (Spec §18)

Every finding MUST cite a security invariant — a *user* statement about the
system, not the auditor's opinion. The orchestrator pulls the invariant
from the audit-objective's `security_invariants` list (one of the four
required keys in `objective-proposal.json`). If no invariant covers the
finding, the chamber downgrades to NEEDS_MORE_INFO; the orchestrator adds
the missing invariant to the objective revision and re-runs.

## Verdict model (Spec §10.2)

The verifier emits one of four verdicts per finding:

| Verdict | Meaning | Promotion? |
|---|---|---|
| `VALID` | The finding survives the three hard filters. | yes |
| `INVALID` | The finding fails at least one hard filter. | no — write to `hardening.md` if user wants |
| `NEEDS_MORE_INFO` | A filter needs an additional piece of evidence. | no — re-dispatch |
| `CONFIRMED` | A VALID finding has been re-validated by cold-verifier and survives the additional check. | yes — locked, exportable |

The orchestrator promotes only `VALID` or `CONFIRMED`. Everything else is a
phase input for re-dispatch.

## Scanner integration cheatsheet

| Phase | Scanner call | Sandbox kind | Output |
|---|---|---|---|
| Q0 | `detect-tools.sh` | n/a | `mini-audit/scanner/capabilities.json` |
| Q2 (lite) | grep + read | n/a | inline finding drafts |
| L5 / P8 | `run-codeql.sh` / `run-semgrep.sh` | `source-scan` | SARIF |
| L6c / P13 / V3 | `poc-builder` + `poc-executor` | `poc` | evidence under `findings/<id>-<slug>/evidence/` |
| V4 / V5 | (re-run selected scans) | `source-scan` | SARIF |
| P12 | `run-semgrep.sh --config <custom>` | `source-scan` | SARIF |

## Sandbox CLI commands (skill-side)

- `scripts/detect-tools.sh` — list available scanners + isolation backends,
  write `mini-audit/scanner/capabilities.json`. Run once per audit start.
- `scripts/sandbox-check.sh` — differential canary for the chosen isolation
  backend; writes `mini-audit/sandbox/probe-<K>.json`. Run once per kind.
- `scripts/sandbox-run.sh` — execute a command under sandbox policy; exits 4
  on policy denial.
- `scripts/run-codeql.sh` / `scripts/run-semgrep.sh` — wrap the scanners in
  the sandbox envelope; output SARIF.

The scripts are loaded via `scripts/mini-audit-runtime` and only through the
sandbox envelope — direct invocation from an agent prompt is rejected by the
runtime as a policy bypass.