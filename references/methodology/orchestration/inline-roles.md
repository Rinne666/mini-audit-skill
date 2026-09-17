# Inline agent templates (28 files at `references/<name>.md`)

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

# Dispatch pattern (when a phase needs an inline role)

1. Read `references/<name>.md` (the orchestrator has filesystem access).
2. Construct the `Task` tool prompt:

```text
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

# Hard limits carried over from Piolium (apply to inline role dispatches)

- `poc-builder` — 3 min wall-clock cap per finding (lite) / 5 min (balanced)
- `static-analyzer` (first-class) — 5 min wall-clock (lite) / 15 min (balanced)
- Review Chamber hard limits (already enforced by `mini-audit-synthesizer`): max 7 hypotheses/batch, max 3 rounds/hypothesis, max 6 rounds/chamber

# No Piolium upstream tracking (architectural decision)

The 28 inline agent templates and 7 first-class agent prompts are a **one-time import**. We do NOT maintain bidirectional sync with Piolium. If a Piolium update lands new patterns of interest, the user re-imports manually. The 108 substitution renames (rounds 1-3) are also a one-time cost — the user has accepted that this fork will drift from Piolium over time.