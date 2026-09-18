# mini-audit-skill

A pure-Prompt security audit Skill. The model reasons about a
target codebase; the Harness provides shell, files, sub-agents,
and any required isolation. There is no Runtime, no schema, no
state machine, no CLI.

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

## How to use it

1. Load `SKILL.md`.
2. Copy `templates/audit-notes.md` into the audit workspace and
   rename it for the target.
3. Run the four-stage loop (Scope → Discover → Verify → Report).
   Edit the notes file every round.
4. For each Verified Fact, write a `templates/finding.md`.

## What this Skill is not

- It is not a runtime. It does not provide a sandbox, a CLI, a
  schema, or a state machine.
- It does not own a Search Ledger or a coverage ledger. There is
  no canonical-state artifact beyond the audit notes file.
- It does not define phases as gates. The four stages are
  cognitive stages the model moves between. The notes file
  does not enforce transitions; the reviewer does.

## Isolation

This Skill does not provide an isolated execution environment.
For PoC execution that touches the network, runs untrusted code,
or modifies system state, only use isolation the Harness already
provides. If the Harness provides none, do static verification
or minimal non-destructive experiments instead.