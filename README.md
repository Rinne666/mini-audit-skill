# mini-audit-skill

A prompt-led security audit Skill. The model reasons about a
target codebase; the Harness provides shell, files, sub-agents,
and any required isolation. A small stdlib runtime validates
audit-note structure and skill freshness; it is not a full audit
state machine and cannot prove semantic completeness.

## What you get

- `SKILL.md` — the skill itself. How the model runs an audit.
- `references/` — methodology (Discovery, Verification,
  Permission Delta, Search Strategy) and eight vuln-class
  references (authz, injection, deserialization, path traversal,
  ssrf, crypto, race condition, cross-service trust).
- `templates/audit-notes.md` — the single Markdown file the
  model maintains during the audit.
- `templates/finding.md` — the one-finding-per-file report
  template.
- `schemas/pairing-table.schema.json` and `runtime/validate_notes.py` —
  structural checks for baseline roll-ups, coverage-unit IDs and closure,
  independent review records, candidate dispositions, run status, budget,
  guard evaluations, and evidence references.
- `runtime/coverage_id.py` — deterministic IDs from surface, trust boundary,
  subsystem, attack class, and optional lifecycle.
- `runtime/evidence_log.py` — bounded, read-only source search/read capture
  that writes evidence artifacts and a hash-bearing JSONL ledger.

## How to use it

1. Load `SKILL.md`.
2. Copy `templates/audit-notes.md` into the audit workspace and
   rename it for the target.
3. Run the five-stage loop (Scope → Discover → Verify → Synthesize →
   Report). Set a hard budget, map baseline and target-specific surfaces into
   stable coverage units, and work one unit at a time. After each wave, use a
   separate cold-start critic to find missing entry points and paths; record
   newly found gaps as later-wave units. Capture source searches/reads with
   `runtime/evidence_log.py`, and edit the notes file every round. If there is
   no independent reviewer or a candidate remains unresolved, report the run
   as incomplete.
4. For each Verified Fact, write a `templates/finding.md`.

## What this Skill is not

- It does not provide a sandbox or a full audit state machine.
  The logger captures only its own read/search operations; the validator
  can check those records but cannot prevent other tool use or prove that a
  search was exhaustive.
- It keeps coverage units, reviews, pairings, candidate dispositions, budget,
  and run status in the audit notes. Captured source output lives in a
  supporting JSONL ledger and artifact directory, which the validator checks
  by ID and hash.
- It does not implement a full state machine. Scope, Discover,
  Verify, and Synthesize can interleave; Report has a structural
  precondition check, while the reviewer judges semantic completeness.

## Isolation

This Skill does not provide an isolated execution environment.
For PoC execution that touches the network, runs untrusted code,
or modifies system state, only use isolation the Harness already
provides. If the Harness provides none, do static verification
or minimal non-destructive experiments instead.
