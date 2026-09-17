# Orchestrator cookbook (run lifecycle, dispatch, output, quick start)

This file collects the procedural reference the orchestrator keeps in working
memory. Detail-heavy prose lives here so SKILL.md can stay a thin kernel.

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
   Audit complete: <N findings> | N critical / N high / N medium / N low
   ```

## Resume protocol

`/mini-audit-resume` (or `--action=resume`) reads
`<cwd>/mini-audit/audit-state.json` from disk, replays the recorded state into
orchestrator working memory, and continues from the first phase whose status is
not `complete`. **Disk is the resume authority** — the orchestrator's in-memory
state is a cache, never the source of truth.

```yaml
- Audit interrupted mid-phase Q3 (promote + PoC).
- /mini-audit-resume reads audit-state.json:
    Q0: complete (gate artifact exists)
    Q1: complete (gate artifact exists)
    Q2: complete (gate artifact exists)
    Q3: in_progress (no gate artifact on disk — needs retry)
    Q4: pending
- Resume begins at Q3, attempt counter reset to max(attempts so far)
```

The resume protocol is the reason the canonical state lives on disk and the
runtime is the single writer. An agent in the middle of a phase that crashes
loses only its in-progress scratch; the audit continues from the next pending
phase.

## Sub-agent dispatch (mavis `Task` tool)

Every dispatch is one of two shapes:

**First-class role** (e.g. `mini-audit-static-analyzer`, `mini-audit-ideator`,
`mini-audit-cold-verifier`, `mini-audit-judge`, `mini-audit-tracer`,
`mini-audit-advocate`, `mini-audit-synthesizer`):

```typescript
Task(
  subagent_type: "<first-class-role>",
  description: "<short role hint>",
  prompt: build<Phase>TaskPrompt(cwd, target, attempt),
  isolation: "worktree",
)
```

**Inline role** (anything not in the first-class list — see
`inline-roles.md`):

```typescript
Task(
  subagent_type: "general",
  description: "<short role hint>",
  prompt: readFileSync("references/<name>.md") + build<Phase>TaskPrompt(cwd, target, attempt),
  isolation: "worktree",
)
```

The `build<Phase>TaskPrompt` function returns the per-phase prompt from
`default-task-prompt.md` and the per-mode orchestrator recipe. Inline-role
prompts always include the full body of `references/<name>.md` so the sub-agent
has the methodology in-context.

## Sub-tasks this skill dispatches to itself (for complex per-phase work)

Some phases split naturally into independent sub-tasks (e.g. L5 probe fan-out
across slices). The orchestrator dispatches the sub-tasks as separate `Task`
calls and reconciles their outputs at phase close. Sub-task dispatch follows the
same `Task(...)` shape — only the prompt and description change. Sub-tasks are
not sub-sub-agents; they are independent `Task` dispatches at the same layer.

## Reuse of bundled skills

This skill does NOT spawn additional specialist skills (`worktree-management`,
`mavis-foundation`, etc.) as separate processes. Where a sub-task would benefit
from a bundled skill, the orchestrator inlines the **methodology section** of
that skill into the relevant `Task` prompt. Spawning a separate skill process
adds round-trip latency and makes the orchestrator lose visibility into the
sub-task's working state. Inline-and-watch beats spawn-and-poll.

## Output conventions

Every phase writes one or more **canonical artifacts** the next phase can
consume. Conventions:

- Paths are relative to `<cwd>` (the audit root), absolute paths only when the
  runner resolves them.
- Markdown files use frontmatter (`id`, `phase`, `slug`, `severity`,
  `verdict`) where the next phase needs the keys; pure prose elsewhere.
- JSON files are `mini-prettie`-formatted (2-space indent, ISO-8601 timestamps,
  trailing newline). `mini-audit-runtime export --format json` is the
  deterministic emitter.
- `mini-audit-runtime export --format md` emits Markdown with the same shape
  the orchestrator prints to chat.

## Quick start (chat form)

```text
User:  /mini-audit-balanced
Skill: target = <cwd>, mode = balanced
       audit-state.json initialized, source identity captured
       ● L1 intent-cartographer    (in progress, attempt 1/6)
       ● L2 knowledge-base-builder (queued)
       ● L3 advisory-hunter        (queued)
       ● L4 env-provisioner        (queued)
       ● L5 probe-strategist       (queued)
       ● L6 review-chamber         (queued)
       ● L6b promote-drafts        (queued)
       ● L6c poc-builder           (queued)
       ● L7 cold-verifier+report   (queued)

User:  /mini-audit-status
Skill: ● L1 .. L7 complete. 4 findings. Resume from scratch with /mini-audit-resume --fresh.

User:  /mini-audit-export --format md --out report.md
Skill: written to <cwd>/report.md
```

## Migration note (Piolium → mini-audit)

| Piolium term | mini-audit term |
|---|---|
| `PIOLIUM_*` env | `MINI_AUDIT_*` env |
| `piolium-*` slash command | `mini-audit-*` slash command |
| `piolium-runtime` CLI | `mini-audit-runtime` CLI |
| `piolium-<role>` agent | inline `references/<name>.md` role |
| `findings/<id>-<slug>/` | unchanged |
| `audit-state.json` | unchanged |
| `audit-objective.json` | unchanged |
| `attack-graph.json` | unchanged |
| `search-ledger.json` | unchanged |

Migration scripts can `PIOLIUM_*` → `MINI_AUDIT_*` with `sed`. There is **no
data migration** — the JSON artifacts on disk have the same shape, and the
runtime rejects only what the new schema rejects (e.g. unknown top-level keys).

The 28 inline agent templates and 7 first-class agent prompts are a **one-time
import** from Piolium. They are not auto-updated. If you want a new Piolium
pattern, copy the file manually and rename the substitution targets.