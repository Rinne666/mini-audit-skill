# Review Chamber debate protocol (L6 / L10 / V5)

For every threat cluster the orchestrator opens, four specialists exchange structured
arguments on disk at `<cluster>/debate.md`:

1. **ideator** — proposes the hypothesis, what class it belongs to, what evidence
   it would take to settle the question.
2. **tracer** — actually reads the code paths, collects the line-grounded evidence
   (file:line refs), and either confirms or refutes the hypothesis.
3. **advocate** — argues the strongest case for "this is a real boundary crossing",
   stresses the attacker's perspective.
4. **devils-advocate** — argues the strongest case for "this is not a real
   boundary crossing", stresses the defender's perspective and pre-existing
   controls.

The synthesizer (a fifth sub-agent, **not** in the chamber) reads `debate.md` and
the source files it cites, applies `permission-delta-judging.md`, and emits a
**verdict**: VALID / INVALID / NEEDS_MORE_INFO. The verdict is what
`findings/<id>-<slug>/report.md` is built from.

Chamber rules:

- **7 hypothesis / batch** — the orchestrator partitions a cluster into at most
  7 hypotheses and dispatches them in one batch.
- **3 rounds / hypothesis** — if a hypothesis has not converged after 3 rounds of
  evidence collection, the orchestrator either downgrades it to NEEDS_MORE_INFO
  or splits it.
- **6 rounds / chamber** — if the whole chamber has not converged after 6 rounds,
  the orchestrator flags the cluster for human review and continues.
- **Debate lives on disk** — `debate.md` is a markdown file with one section per
  round per hypothesis. Sub-agents only ever write to their own scratch
  directory; the synthesizer reads, never writes, debate.md.

The chamber **never** advances phase state on its own. The synthesizer's verdict
is a draft finding; the orchestrator is the only entity that promotes it via
`research apply`.

# Cold verifier isolation rule (L7 / P11 / V6)

`mini-audit-cold-verifier` is the only sub-agent allowed to disagree with the
chamber's verdict. Its job is to re-trace the cited source files **without any
prior context from the chamber** — it loads only:

- `references/methodology/permission-delta-judging.md` (the meta-rule)
- `references/methodology/evidence-hygiene.md` (the evidence bar)
- the cited file:line chain from the chamber's draft finding
- the **opposite** hypothesis's argument in `debate.md` (so it cannot be primed)

What it MUST NOT load:

- any class-specific hunting or vuln reference (no `hunting/`, no
  `vuln-classes/`)
- the chamber's `attack-ideator` or `attack-advocate` arguments in full
- any other finding's verdict
- any KB loader output
- any other sub-agent's scratch

It writes `<id>-<slug>/cold-verify-verdict.md` containing exactly one line:
`verdict: VALID|INVALID|NEEDS_MORE_INFO` plus the file:line chain it actually
re-read. **No long prose.** The orchestrator reconciles the cold-verifier's
verdict with the chamber's verdict, and the rule is:

- chamber VALID + cold-verifier VALID → promote to findings
- chamber VALID + cold-verifier INVALID → re-dispatch to chamber with the
  counter-evidence named
- chamber VALID + cold-verifier NEEDS_MORE_INFO → add the missing piece,
  re-dispatch
- chamber NEEDS_MORE_INFO + cold-verifier INVALID → drop or hardening

The cold-verifier may NOT cast a vote on severity; that is the chamber's
responsibility.

# Hard filter at the gate (mandatory, no finding escapes these three)

A finding draft survives promotion only if it passes **all three** filters. Any
filter failing blocks promotion and surfaces the rejection reason.

**1. Stable fingerprint** (Spec §12)

A finding's fingerprint is the hash of (class, attacker_model, before_capability,
after_capability, security_invariant, boundary.kind). Two drafts with the same
fingerprint are the same finding; the second is rejected with reason
`duplicate_finding`. Promoting without a fingerprint is rejected with reason
`missing_fingerprint`.

**2. Permission delta** (Spec §15)

A finding is INVALID if:

- the "before" capability is not actually achievable by the attacker model, or
- the "after" capability is not actually privileged relative to the security
  invariant, or
- the security invariant is misquoted (the "invariant" is a *user* statement,
  not the auditor's — `permission-delta-judging.md` decides), or
- a control in the codebase actually denies the delta and the advocate cannot
  refute it.

**3. Evidence ground** (Spec §13)

A finding's evidence must be:

- concrete (file:line, not "near the auth handler"), and
- reproducible (the next auditor can re-read the cited lines and reach the same
  conclusion), and
- truthful (no invented file paths, no over-claimed lines, no hyperbole).

A finding with `evidence: "we believe this might be vulnerable"` is rejected.

# Concurrency cap (Swarm Burst Cap)

The Swarm Burst Cap is set by `--max-agents=N` / `MINI_AUDIT_MAX_AGENTS=N`
(default 3). The orchestrator MUST NOT exceed N concurrent sub-agent dispatches
in any phase. Exceeding the cap is the most common cause of Opus context
overflow; the cap is also the quality-control lever — fewer parallel dispatches
means each one gets more attention.

The cap is **per-phase**, not global. A balanced audit with chamber fan-out may
legitimately have 4 hypotheses × 4 chamber roles = 16 dispatches over the
course of a single cluster, but never 16 simultaneously.

Cap-related aborts are surface as `SwarmBurstExceeded` and the orchestrator
queues the excess dispatches for the next round.