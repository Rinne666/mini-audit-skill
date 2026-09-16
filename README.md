# mini-audit-skill

A multi-phase security audit pipeline packaged as a Mavis / MiniMax Code skill.

Originally developed for internal use by the [lannister](https://github.com/Rinne666/lannister) vulnerability-mining agent and forked from upstream [Piolium/autoaudit](https://github.com/Piolium/autoaudit) with selective, hardened implementation.

## What this is

`mini-audit` runs a source-grounded security audit of an arbitrary target repository through a composable phase pipeline (L1–L7 balanced, with L6 split into L6b/L6c):

| Phase | Mode(s) | Purpose |
| --- | --- | --- |
| L1 | Q0-Q4 lite, L1-L7 balanced | Reconnaissance & intent corpus |
| L2 | L1-L7 balanced | Knowledge base + attack-surface enumeration |
| L3 | L1-L7 balanced | Public advisory correlation & SBOM |
| L4 | L1-L7 balanced | Live-environment setup (e.g. dev-mode Keycloak) |
| L5 | L1-L7 balanced | Hypothesis generation per attack surface slice |
| L6 | L1-L7 balanced | Multi-agent chamber validation (permission-delta judging) |
| L6b / L6c | L1-L7 balanced | Draft promotion + PoC capture |
| L7 | L1-L7 balanced | Cold-verifier wave + report assembly |

Plus confirm (`V1-V7`), revisit (`R0-R11c`), merge (`M1-M7`), longshot (`X1-X3`) and incident (`I1-I3`) extensions.

Across those modes, **38 phases declare a deterministic gate**: a phase only
reaches `complete` when its required artifact exists on disk, parses, passes
schema validation and satisfies its semantic checks. The phases that are *not*
gated are listed explicitly in SKILL.md § Gate coverage — they either write
into a shared document or have no artifact contract, so gating them would block
legitimate completion rather than enforce anything real.

## Search Governance

A phase pipeline answers "is this finding real?". It does not answer "what should
we search next, and which half-finished lead should we keep?". Search Governance
adds a research plane beside the verdict plane:

```text
Audit Objective   (mini-audit/audit-objective.json)   what this audit must prove
Search Ledger     (mini-audit/search-ledger.json)     known / suspected / blocked / intended
Attack Graph      (mini-audit/attack-graph.json)      capability nodes and their conversions
SearchGovernanceLock (.search-governance.lock)        one lock over the whole transaction
```

The invariants that make it safe to run long:

* **The objective cannot be moved by the thing being measured.** An L1 agent only
  writes a *proposal* under `agents/<id>/scratch/`; `objective init --from-proposal`
  promotes it. Afterwards the objective is immutable — `objective replace` needs
  `--force` **and** `--reason`, increments `revision`, appends a supersedes entry
  carrying the previous content hash, and records a system fact in the ledger.
* **A delta is idempotent and all-or-nothing.** Objects are addressed by a stable
  semantic key; the runtime allocates the canonical id. Re-submitting a delta is a
  no-op. Two objects sharing a key must agree on their identity fields, otherwise
  the *entire* delta is refused — a partially applied delta would leave the agent
  unable to tell which of its claims took effect.
* **"Not exploitable yet" is not "disproved".** A locally real bug missing a
  prerequisite becomes a *blocked path* carrying its blocker, evidence, reopen
  conditions and priority. Disproving the assumption it depends on reopens it;
  supporting that assumption closes it with `close_reason = blocker_supported`.
  Neither direction rewrites the candidate's verdict.
* **No node type the runtime cannot check.** v1 allows `principal`, `capability`
  and `goal` only; `state` was dropped rather than shipped unverified.

```bash
mini-audit-runtime objective init --from-proposal <path>
mini-audit-runtime objective replace --from <file> --force --reason "..."
mini-audit-runtime objective show
mini-audit-runtime research apply <delta.json>
mini-audit-runtime research status
```

Search Governance is currently at **Phase A–D of its own plan**: research state,
attack graph, objective bootstrap, the lock, and the L1/L6 gate integration are
implemented and tested. The search governor, saturation reporting and the
long-horizon replay evaluator are the remaining phases. See SKILL.md § Search
Governance for the full contract.

## Repository layout

```
SKILL.md                              # entrypoint — top-level orchestration contract
_meta.json                            # Mavis skill metadata
README.md                             # this file
runtime/                              # deterministic layer (Python 3.9+, stdlib-only)
  state.py gates.py schema.py coverage.py findings.py scheduler.py
  sandbox.py sandbox_backend.py source_identity.py diff_scope.py sarif.py export.py
  fingerprint.py atomic_io.py cli.py
  objective.py research_state.py attack_graph.py search_lock.py   # Search Governance v1
schemas/                              # JSON Schema for audit-state / finding / coverage / candidate / phase-result
                                      # + audit-objective / search-ledger / research-delta / attack-graph
.github/workflows/ci.yml              # the checks below, run on every push / PR
scripts/
  mini-audit-runtime                  # CLI launcher
  manifest.py                         # generate references/MANIFEST.json (with provenance)
  check-manifest.py                   # verify manifest ↔ disk (+ provenance, counts)
  doc_counts.py                       # derive + verify the counts quoted in the docs
  detect-tools.sh run-semgrep.sh run-codeql.sh sandbox-check.sh sandbox-run.sh
evals/                                # regression corpus (positive / negative / ambiguous) + run.py + score.py
tests/unit/                           # runtime unit + hardening tests
references/
  README.md                           # reference index + provenance table
  MANIFEST.json                       # 130 items: sha256 + source repo/commit/path + license
  PROVENANCE.json                     # source declarations, path→source rules, commit map
  *.md                                # 28 inline Piolium agent templates
  hunting/                            # 58 per-class hunting methodologies
  vuln-classes/                       # 29 per-vuln-class playbooks
  methodology/                        # 8 operator methodologies (incl. permission-delta judging)
  wordlists/                          # 5 recon wordlists (api-endpoints, raft-medium, …)
```

## Permissions / safety

This skill is **offensive-by-design** — it is meant to be run against targets the
operator owns or has written authorization to test. It is **not** an exploitation
framework and **does not** ship working exploits; it produces advisory-grade
findings and reproducible PoCs against authorized targets.

## Provenance

Forked from `Piolium/autoaudit`. The mini-audit fork accepts drift from upstream
over time; the current 8 full + 5 partial + 4 stub command surface is intentional.

Per-file provenance for the reference corpus — source repo, upstream commit,
source path, license, modified flag and import date — is recorded in
`references/MANIFEST.json`, driven by `references/PROVENANCE.json`. Regenerate with
`python scripts/manifest.py`; verify with `python scripts/check-manifest.py --strict`.
Sources that are not vendored (`Claude-BugHunter`, `strix`) currently carry an
`UNKNOWN` license and are flagged as warnings until confirmed.

## Counts

<!-- BEGIN auto-counts — generated, do not edit by hand
| Metric | Value |
|--------|-------|
| reference files (4 sub-directories) | 100 |
| manifest items (incl. inline agents) | 130 |
| inline agent templates | 28 |
| per-class hunting methodologies | 58 |
| per-class vulnerability references | 29 |
| operator methodologies | 8 |
| runtime wordlists | 5 |
| eval fixtures | 30 |
| first-class roles | 7 |
| phase gates declared | 38 |
| runtime version | 1.2.0 |
| commands: full / partial / stub | 8 / 5 / 4 |
<!-- END auto-counts -->

Refresh with `python scripts/doc_counts.py --write`; CI runs
`python scripts/doc_counts.py --check`.

## Continuous integration

`.github/workflows/ci.yml` runs the repo's own verification commands on every
push to `main` and every pull request:

- `python -m pytest tests/unit -q` on Python 3.9 and 3.13 (the advertised
  support range)
- `python scripts/check-manifest.py --strict` (manifest ↔ disk + provenance)
- `python scripts/doc_counts.py --check` (counts quoted in the docs)
- `python evals/run.py --self-check` (eval corpus structure)
- `bash -n` over `scripts/*.sh` and `compileall` over the Python sources

A second job (`sandbox-containment`) stages `alpine:3.20` and runs the live
Docker containment tests, because the isolation claim is only worth what a
running canary proves — a unit test asserting the argv is shaped correctly does
not show that a write is actually blocked. Those tests need no egress: the
network canary stands up its own listener on the host's routable address, so
"the sandbox blocked the network" is measured rather than assumed from a public
endpoint being reachable.

## License

This is a **public** repository. The mini-audit code itself ships no license file.
Bundled reference material retains the license of its upstream source (see the
`license` field on each item in `references/MANIFEST.json`; Piolium-derived files
are MIT).