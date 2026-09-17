# Context budget discipline (orchestrator methodology)

The 103 reference files total ~1.7MB on disk. None of that enters context unless the orchestrator explicitly reads a file. Per sub-agent call, inline at most **1 hunting + 1 vuln-classes + 1 inline agent** file = 10-30KB ≈ 3-8K tokens. Opus 200K context is enough headroom for 17 phases.

## NEVER (will blow up the context window)

- `Read references/` or `Read references/hunting/` or `Read references/vuln-classes/` as a **directory read** — would load 1.2MB ≈ 250K+ tokens in one go
- `Read` more than **1 hunting/*.md** file per Task dispatch (only inline the one matching the current hypothesis class)
- `Read` more than **1 vuln-classes/*.md** file per Task dispatch
- Re-`Read` `references/_hunt-class-map.md` more than **once per session** — read it at session start, then refer to it from working memory
- Re-`Read` `references/README.md` more than **once per session**
- Inline `methodology/redteam-mindset.md` or `methodology/evidence-hygiene.md` or `methodology/permission-delta-judging.md` mid-session — they are pre-flights only

## ALWAYS

- At session start, `Read` `references/_hunt-class-map.md` **once** (10.6KB) to learn the class→file mapping
- At session start, `Read` `references/README.md` **once** (8.8KB) to learn the layout
- For each Task dispatch, determine the hypothesis class first, then read at most 1 hunting + 1 vuln-classes file by exact path
- Use `Glob` or `Bash ls` to verify file existence, never `cat` a whole directory
- Pre-flight load `methodology/redteam-mindset.md` and `methodology/evidence-hygiene.md` and `methodology/permission-delta-judging.md` **once** at the start of the first sub-agent dispatch
- Use `Bash cat <single-wordlist-file>` (not `Read`) for wordlists — they're runtime resources, not prompt templates

## Cost model (per phase)

| Component | Typical size | Tokens | When read |
|-----------|--------------|--------|-----------|
| orchestrator's own system prompt | 5-10KB | 1.5-3K | always (registered in mavis) |
| sub-agent system prompt (e.g. attack-ideator) | 5-15KB | 1.5-4K | per dispatch (mavis passes) |
| phase task prompt | 1-3KB | 0.5-1K | per dispatch |
| inline role spec (1 file) | 5-30KB | 1.5-8K | per dispatch |
| inline class reference (hunt + vuln) | 10-30KB | 3-8K | per dispatch |
| **Total per dispatch** | **~30-90KB** | **~8-25K** | — |

Opus 200K context: even with 20 dispatched sub-agents in a long audit, the orchestrator's accumulated context stays under 80-100K tokens if it doesn't re-read map/README. Each sub-agent's own context is independent (mavis session) and resets after the dispatch returns.

## When you feel tempted to bulk-read

Stop. Use the 1 hunting + 1 vuln-classes pattern. The cost of reading more is not just tokens — it dilutes the sub-agent's attention on the specific class being debated. Class-aware loading is also a quality control mechanism.

# Context pruning between phases (CRITICAL — apply after every sub-agent return)

Class-aware loading controls what enters context **at dispatch time**. Pruning controls what **stays** in the orchestrator's working memory after a sub-agent returns. Both are required.

## After every Task return, the orchestrator compresses the result

| Field | Keep | Discard |
|---|---|---|
| Status | `complete` / `failed` / `skipped` (one word) | — |
| Summary | one-line, ≤ 200 chars | long-form prose |
| Artifacts | rel paths of files created | file contents (re-read on demand) |
| IDs | hypothesis / finding / cluster ID and verdict | raw tool calls and intermediate reasoning |
| Failure hint | if failed, ≤ 100 char re-dispatch hint | full stack trace (re-derive from logs on demand) |

## Per-phase compression rules

- After a chamber cluster closes: keep only the verdict table, not the full `debate.md`. The next phase reads `debate.md` from disk on demand.
- After probe workspace closes: keep only the `probe-summary.md` path, not the full evidence tree.
- After cold-verifier returns: keep only the verdict line + `cold-verify-verdict.md` path, not the full report.
- After static-analyzer returns: keep only the JSON summary, not raw SARIF.
- After KB-builder returns: keep only the section headers present in `knowledge-base-report.md`, not the full body.
- After judge-verdict (J1) returns: keep only `[<finding-id>, <verdict>, <one-line>]` tuples, not the full `judge-verdict.md`.

## Concretely

Replace the verbose return in working memory with a 4-tuple:

```text
[<id>, <status>, <one-line summary>, <artifact-paths>]
```

before issuing the next dispatch. The verbose content lives on disk; the orchestrator only needs the index.

## Discipline rules

- **NEVER**: re-`Read` a file the orchestrator already saw, just because it remembers the path is "important". The `Read` itself re-loads into context. Use the path; the next sub-agent can `Read` if it needs the body.
- **NEVER**: copy a sub-agent's full output into the prompt for the next sub-agent. Reference the artifact path; the next sub-agent reads on demand.
- **NEVER**: keep long markdown bodies (debate.md, judge-verdict.md, full report.md) in the orchestrator's context. The orchestrator is the **router**, not the **reader**. It dispatches; it does not re-summarize.
- **ALWAYS**: at the end of a phase, drop everything from prior phases except the artifact index, the verdict table, and the next-phase task prompt.

## Why this matters

A balanced audit with 5-10 threat clusters produces ~30-60 sub-agent dispatches (chamber × 4 roles × 2-3 rounds × clusters, plus KB builders, probe fan-out, cold-verifier, judge). Without pruning, the orchestrator's working memory grows by ~10K tokens per dispatch return. At 30 dispatches that's 300K tokens — already past Opus 200K capacity. Pruning caps the orchestrator's active working set at **~30-50K tokens** for the lifetime of a long audit.

## Dispatch pattern (class-aware chamber)

When `mini-audit-ideator` generates a hypothesis with class `c`:

1. Read `references/_hunt-class-map.md` to find `hunting/hunt-<c>.md` (if exists) and `references/vuln-classes/<c>.md` (if exists).
2. Construct the role dispatch:

```text
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

## Pre-flights (load at the start of every mini-audit session)

```text
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

## Wordlist usage (Bash cat, not prompt template)

```bash
# L5 / P8 probe-strategist directory/file enumeration
cat ~/.minimax/skills/mini-audit/references/wordlists/raft-medium-directories.txt | head -100

# L4 / P1.5 env-provisioner parameter fuzzing
cat ~/.minimax/skills/mini-audit/references/wordlists/burp-parameter-names.txt | head -50

# devils-advocate Layer 4 (Application) defense-bypass search
cat ~/.minimax/skills/mini-audit/references/wordlists/bypass-headers.txt
```