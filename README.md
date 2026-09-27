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
  structural checks for baseline coverage, pairing rows, guard evaluations,
  evidence references, and work-queue closure.
- `runtime/evidence_log.py` — bounded, read-only source search/read capture
  that writes evidence artifacts and a hash-bearing JSONL ledger.

## How to use it

1. Load `SKILL.md`.
2. Copy `templates/audit-notes.md` into the audit workspace and
   rename it for the target.
3. Run the five-stage loop (Scope → Discover → Verify → Synthesize →
   Report). Scope records baseline authz, identity-trust, callback-to-sink,
   and cross-endpoint-state lenses even when the initial hypothesis names
   another class. Keep one active item in the machine-readable work queue,
   capture source searches/reads with `runtime/evidence_log.py`, and edit the
   notes file every round.
4. For each Verified Fact, write a `templates/finding.md`.

## What this Skill is not

- It does not provide a sandbox or a full audit state machine.
  The logger captures only its own read/search operations; the validator
  can check those records but cannot prevent other tool use or prove that a
  search was exhaustive.
- It keeps coverage, pairing, and work-queue state in the audit notes.
  Captured source output lives in a supporting JSONL ledger and artifact
  directory, which the validator checks by ID and hash.
- It does not implement a full state machine. Scope, Discover,
  Verify, and Synthesize can interleave; Report has a structural
  precondition check, while the reviewer judges semantic completeness.

## Isolation

This Skill does not provide an isolated execution environment.
For PoC execution that touches the network, runs untrusted code,
or modifies system state, only use isolation the Harness already
provides. If the Harness provides none, do static verification
or minimal non-destructive experiments instead.
