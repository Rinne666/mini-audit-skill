# Default task prompt template (lite Q2 example)

When dispatching a sub-agent for phase Q2 (lite SAST), the prompt is:

```text
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

Similar templates exist for every other phase; the orchestrator builds the per-phase prompt from the per-phase constraints in `references/methodology/orchestration/` and the per-mode orchestrator recipe (see `mode-orchestrators.md`).