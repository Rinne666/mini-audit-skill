# Mode-specific orchestrators (delegation patterns)

Each mode maps to a different **delegation pattern** the orchestrator runs. The
patterns below say *what* dispatches happen and *in what order*; they do not
say how to phrase the prompt — that is `default-task-prompt.md` and the
per-phase methodology.

## `lite` (5 phases, ~5 min wall-clock)

Q0 (deterministic recon + candidate scan) → [Q1 (trufflehog/gitleaks,
deterministic) ‖ Q2 (`mini-audit-static-analyzer`, lite prompt)] → Q3
(consolidate drafts → per-finding `poc-builder` fan-out, max 3 concurrent) → Q4
(verify + cleanup transient).

## `balanced` (9 phases, ~30-60 min)

L1 (`intent-cartographer` inline) → L2 (`knowledge-base-builder` inline) →
[L3 (`advisory-hunter` inline) ‖ L4 (`env-provisioner` inline)] → L5
(`probe-strategist` inline, fan-out per slice) → L6 (Review Chamber per threat
cluster) → L6b (promote drafts to findings/) → L6c (per-finding `poc-builder`
fan-out) → L7 (`mini-audit-cold-verifier` for CRIT/HIGH + `report-assembler`
for all + cleanup).

## `deep` (17 phases, hours)

P1..P17, mostly the balanced sequence plus P9 spec-gap, P12 variant hunt, P13
PoC per-finding, P14 report, P15 final, P16 patch-bypass, P17 cleanup.

## `confirm` (V1-V7, validates a pre-existing finding set)

V1 boot, V1.5 intent cross-check, V2..V5 incremental cold verification, V6
final review chamber, V7 redaction + cleanup.

## `revisit` (R0-R11c, anti-anchoring)

R0 intent corpus rebuild, R5/R7/R8/R9/R10/R10k iterative chambers, R11/R11b/R11c
final.

## `merge` (M1-M7, deterministic)

M1 deterministic copy, M2..M7 agent-driven dedup, renumber, report. Records an
audit run.

## `longshot` (X1-X3, hail-mary)

X1 enumerate → X2 hunt fan-out (`variant-scout` per file) → X3 aggregate.

## `diff` (D0–D6, incremental audit against a change-set)

The diff mode does not own a planner. Its job is to derive the change-set,
widen it in three tiers, then re-enter the normal Search Governance round.
Every selector resolves to `{scope_type, selector, baseline, target, merge_base}`
via `runtime/diff_scope.py::resolve_diff_range`; the runtime refuses hand-rolled
ranges so a future resume can trust `diff-scope.json`.

```text
D0  selector resolution          runtime   diff scope / diff stage
D1  changed-file enumeration     runtime   line_ranges, added/modified/deleted/renamed
D2  risk ranking                 runtime   risk_ranked: security-sensitive paths first
D3  history / fix-commit signal  runtime   diff-d3.json (commits, subjects, suspicious vocabulary)
D4  blast radius of named symbol runtime   diff-d4.json (caller/callee classification)
D5  test-gap map                 runtime   diff-d5.json (changed paths without coverage)
D6  adversarial plan             runtime   diff-d6.json (probes + scope edges)
─────────────────────────────────────────────────────────────────────
then: the normal Search Governance round, with `diff-scope.json` as an extra input
```

The phase catalog is fixed — `diff: [D0, D1, D2, D3, D4, D5, D6]`. Each stage
writes a canonical JSON the next stage can consume (`diff-scope.json`,
`diff-d3.json`, …). After D6 the audit is **not** complete; it returns to the
ordinary round loop with the diff artifacts as additional inputs 2/3 of
`methodology/search-governance.md` §1. The orchestrator recipe:

1. `mini-audit-runtime diff scope --repo-root <path> --commit <sha>` (or
   `--since=<ref>`, or `--base=<x> --head=<y>`) — D0 + D1 + D2 in one shot,
   writes `mini-audit/diff-scope.json`.
2. `mini-audit-runtime diff stage --repo-root <path> --stage D3 --stage D4
   --stage D5 --stage D6` (or one at a time) — writes the per-stage artifacts.
   D4 accepts `--symbol X` to scope the blast-radius trace.
3. Reconciliation (Skill responsibility): read the existing objective, ledger,
   graph and findings, then apply §3.1 of `methodology/search-governance.md` —
   the diff-mode triggers table — to decide the next intent set. The most
   valuable thing the round can do is **reopen a blocked path** the old audit
   left `blocked`, not re-read the diff.
4. Propose the intents via the normal `research apply` transaction; agents
   still only ever write into their own scratch directory.

A diff audit may spawn scanners (`sarif normalize` against the changed files,
or the blast-radius files from D4). The constraint is unchanged: scanner
output → candidate, never finding. The diff narrows *where* a scanner looks; it
does not change what its output is worth.

## `reinvest` (I1-I3, cross-agent)

I1 enumerate CRIT/HIGH → I2 `wave-verifier` fan-out (cap 3) → I3 consensus
summary.

## `knowledge-base` (KB0-K2, context-only)

KB0 external-doc intake (optional) → K1 advisory + SBOM → K2 project model +
unauth surface. Stops before SAST/findings.

## `judge` (J1-J2, **NEW** — permission-delta meta-audit re-judgment)

Meta-audit mode that re-evaluates **already-confirmed** findings against
`methodology/permission-delta-judging.md`. Run after `balanced` / `deep` /
`confirm` / `revisit` to catch over-confirmation that the chamber and
cold-verifier missed. Does NOT run a new attack; does NOT debate; does NOT
re-trace code from scratch. Reads each finding's report + cited paths, writes
an independent verdict.

- **J1** — Per-finding re-judgment. Dispatch
  `Task(subagent_type="mini-audit-judge", prompt=...)` once per `<id>-<slug>/`.
  Each dispatch is independent (no cross-finding bias). Writes
  `<id>-<slug>/judge-verdict.md`. Default scope: all
  `mini-audit/findings/<id>-<slug>/` directories; `--finding=<id>` limits to a
  single finding for spot-check.
- **J2** — Aggregate. The orchestrator (not a sub-agent) walks all
  `judge-verdict.md` files, partitions findings into the re-classification
  categories, writes `mini-audit/judge-report.md` with the **full table** and
  the proposed re-classifications. **J2 produces ONE aggregated
  re-classification table covering all findings, NOT per-finding prompts.**
  The user reviews the full table once at the end and either accepts all
  proposed re-classifications, accepts with edits, or rejects and keeps the
  original chamber verdict. J2 is the ONLY place in mini-audit that pauses for
  user input.

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

**Default scope**: all `mini-audit/findings/<id>-<slug>/`. The
`--finding=<id>` flag limits J1 to a single finding for spot-checking.