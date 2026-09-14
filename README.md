# mini-audit-skill

A multi-phase security audit pipeline packaged as a Mavis / MiniMax Code skill.

Originally developed for internal use by the [lannister](https://github.com/Rinne666/lannister) vulnerability-mining agent and forked from upstream [Piolium/autoaudit](https://github.com/Piolium/autoaudit) with selective, hardened implementation.

## What this is

`mini-audit` runs a source-grounded security audit of an arbitrary target repository through eight composable phases:

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
references/
  intent-cartographer.md              # L1
  env-detective.md                    # L1
  probe-strategist.md                 # L5
  cross-service-auditor.md            # L5
  state-concurrency-auditor.md        # L5
  finding-triager.md                  # L6 (input classifier)
  finding-reporter.md                 # L6b (draft author)
  poc-executor.md                     # L6c (PoC capture)
  confirm-reporter.md                 # V-series
  longshot-hunter.md                  # X-series
  test-mapper.md                      # L2/L5 cross-cuts
  vuln-classes/                       # 30 per-vuln-class playbooks
  methodology/                        # recon-scope, report-writing, permission-delta judging
  wordlists/                           # recon wordlists (api-endpoints, raft-medium, …)
templates/                            # judge-verdict / report templates (placeholder)
```

## Permissions / safety

This skill is **offensive-by-design** — it is meant to be run against targets the
operator owns or has written authorization to test. It is **not** an exploitation
framework and **does not** ship working exploits; it produces advisory-grade
findings and reproducible PoCs against authorized targets.

## Provenance

Forked from `Piolium/autoaudit`. The mini-audit fork accepts drift from upstream
over time; the 7 working modes + 5 partial + 5 stub implementation is intentional.

## License

This is a **private** repository. No license file is included by default.