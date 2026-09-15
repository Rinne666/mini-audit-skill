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

## Repository layout

```
SKILL.md                              # entrypoint — top-level orchestration contract
_meta.json                            # Mavis skill metadata
README.md                             # this file
runtime/                              # deterministic layer (Python 3.9+, stdlib-only)
  state.py gates.py schema.py coverage.py findings.py scheduler.py
  sandbox.py source_identity.py diff_scope.py sarif.py export.py fingerprint.py cli.py
schemas/                              # JSON Schema for audit-state / finding / coverage / candidate / phase-result
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
| runtime version | 1.1.0 |
| commands: full / partial / stub | 8 / 5 / 4 |
<!-- END auto-counts -->

Refresh with `python scripts/doc_counts.py --write`; CI runs
`python scripts/doc_counts.py --check`.

## License

This is a **private** repository. The mini-audit code itself ships no license file.
Bundled reference material retains the license of its upstream source (see the
`license` field on each item in `references/MANIFEST.json`; Piolium-derived files
are MIT).