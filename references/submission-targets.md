# Submission Targets

> Load this when a claim has held and the question becomes *where it
> can be reported*: which maintainer channel, whether a CVE is reachable
> through a CNA, whether CNVD would take it, whether an SRC or a bounty
> platform is the right intake.
>
> This file encodes each target's **acceptance scope** and **evidence
> norms** as a common core distilled from the platforms' published
> rules. Platform rules change without notice and activity rules
> override the baseline. Before any actual submission, re-read the
> platform's own current rules page — this file decides *fit*, the
> platform decides *intake*.

---

## 0. The target vocabulary

Every reportable claim carries a `submission.targets` list. Each entry
names one of:

| Target | What it is | The authority that decides |
|---|---|---|
| `vendor_advisory` | The maintainer's own private disclosure channel: SECURITY.md flow, GitHub private advisory, PSIRT/security email | The maintainer |
| `cve_cna` | A CVE ID through the CNA whose scope covers the product | The CNA (GitHub, Red Hat, Apache, the vendor itself, …) |
| `cnvd` | 国家信息安全漏洞共享平台 (China National Vulnerability Database) | CNVD's three-stage review |
| `src_platform` | A vendor Security Response Center (腾讯 TSRC, 阿里 ASRC, 字节 ByteSRC, 京东 JSRC, 百度 BSRC, 美团 SRC, …) | That SRC's rules |
| `bounty_platform` | HackerOne, Bugcrowd, or the vendor's own bounty program | The program's triage team |
| `hardening_channel` | A patch / issue for a claim that holds but will not be accepted as a vulnerability report | The maintainer |

Exactly one target is `primary` — the channel that receives the
submission. Everything else is `secondary` (viable, not first) or
`unsuitable` (with the reason recorded). Two primary targets means
duplicate intake, which every platform in this file punishes.

**The universal ordering rule:** for an open-source project, the
maintainer (`vendor_advisory`) is almost always primary. A CVE arrives
*through* the maintainer's advisory (GitHub assigns a CVE when the
maintainer publishes a repo security advisory), CNVD and SRC intake
expect the vendor to be informed first or simultaneously, and a report
that outruns the maintainer burns the disclosure relationship every
later report depends on.

---

## 1. `vendor_advisory` — the maintainer's private channel

**Scope.** Defects in the project's own code, reached without a
deployment the project does not support. The project's SECURITY.md (or
`.well-known/security.txt`, or the security page its docs link) defines
the scope; where none exists, the acceptance model is **derived** and
the report must say so.

**Community ingestion standards** — read these before choosing the
channel, they are the project's own statement of how it wants reports:

- `SECURITY.md` at the repo root, `docs/`, or `.github/`.
- `.well-known/security.txt` (RFC 9116): `Contact:` and `Preferred-Languages:`.
- GitHub's **"Report a vulnerability"** button (repo → Security tab):
  opens a private advisory draft with a private fork. This is the
  structured flow; most projects that have it publish their advisories
  through it.
- The project's published advisory history — which flow its GHSA/CVE
  entries actually came through. History beats stated preference.

**Evidence norms.** A reproduction an maintainer can follow in minutes;
the invariant the code fails to enforce as the subject; affected
version range derived from the introducing commit, never invented;
`file:line` for every claim. See `references/report-writing.md`.

**Rejections that repeat across projects:** the behaviour is documented
as intended; the precondition requires a misconfiguration; the issue is
in an unmaintained plugin; the finding re-reports a published advisory.

---

## 2. `cve_cna` — CVE through a Numbering Authority

**How scope works.** Every CNA publishes a Scope Definition and may
assign IDs only inside it (CNA Operational Rules). Finding the right CNA
is a lookup, not a judgment:

1. **The product's own CNA.** Apache, Red Hat, Mozilla, Python, the
   Linux kernel, most large vendors number their own products.
2. **GitHub**, for open-source projects hosted on GitHub that no other
   CNA covers. GitHub assigns the CVE **when the maintainer publishes a
   repository security advisory** — a reporter cannot pull a CVE from
   GitHub directly; the path is: private draft advisory → maintainer
   collaboration → "Request CVE ID" → publish → GHSA + CVE together.
3. **The relevant Root** (CISA for ICS, the MITRE Top-Level Root
   otherwise) as the escalation point when scope is disputed or no CNA
   covers the product.

**What a CVE record needs** — the minimum every CNA asks for: affected
product and versions (from a traced introducing commit, or "every build
containing this function"), a defect description precise enough to
distinguish it from neighbours, a public reference (published advisory,
fix commit, or issue), and the reporter's credit line. A CVE is a
*catalog entry for a disclosed defect*, not a certificate of severity.

**Common CNA reject shapes:** a functional bug with no security
boundary crossed; the affected code path cannot be reached in a
supported configuration; the "vulnerability" is a misuse or an
unsupported deployment; the issue already has an ID (duplicate); the
reporter wants the ID before telling the maintainer (most CNAs route
through the maintainer for OSS).

**Clock fact.** A CVE record only becomes public when the advisory
publishes. Requesting the ID early is fine; expecting it public early
is not.

---

## 3. `cnvd` — 国家信息安全漏洞共享平台

Two acceptance lanes with different bars; the claim's shape decides the
lane.

**通用型 (product/component vulnerabilities).** A defect in a
*distributed* product or component — CMS, framework, firmware, library
— that exists across installations. Acceptance bar:

- 中危及以上 severity;
- **未公开披露** — not already published as CVE/GHSA/advisory; a
  published defect is at most a 备案, not an original submission;
- **可验证** — a PoC/验证代码, or multiple live internet instances of
  the affected product;
- the vendor's own case or the product's reality to anchor it.

**事件型 (specific-instance vulnerabilities).** A defect in one
concrete deployed site/system. Certificates are limited to 三大运营商
(移动/联通/电信) and 党政机关、事业单位 targets at 中高危; ordinary
enterprise sites score points but do not certificate. A closed-source
web service finding with no product behind it is event-shaped, not
product-shaped — and event-shaped claims about a random company site
are usually an SRC matter, not a CNVD matter.

**Submission content** (the form demands all of it): 漏洞名称, 漏洞
URL/位置, 涉事单位 or affected product + version, 影响对象类型, 危害
描述, 复现过程 (step-by-step with screenshots as attachment), 解决
建议. Review is three-stage (完整性 → 真实性 → 定级), and the
原创漏洞证明 / certificate follows archiving. Note the submission is
per-instance-of-review: incomplete 复现材料 is the most common
first-stage rejection.

**CNVD vs CNNVD.** Separate national databases (CNVD under CNCERT,
CNNVD under 中国信息安全测评中心). A double filing to both is common
practice for certificates but is two submissions by design — record it
as two targets if the submitter plans it; never let it happen by
accident.

---

## 4. `src_platform` — vendor Security Response Centers

Every SRC's published rules reduce to the same core, with per-vendor
weighting. The common core, then the vendors worth naming.

**The common core — assume it everywhere:**

1. **Authorization scope.** Only the assets the SRC lists. Anything
   else is unauthorised testing regardless of how real the bug is.
   Activity windows matter (京东 JSRC suspends intake during 双十一-class
   events; others run event-scoped bonus ranges).
2. **Data minimization.** Prove the boundary crossing with data you
   created; never read, export, or retain real user data. The 网易 SRC
   行业规范 states the norm the industry copied: an injection is proven
   by *reading that reading works*, reading table contents is
   forbidden; write-type injections (UPDATE/DELETE/INSERT) must not be
   tested with automated tools.
3. **No damage, no extortion.** No using the flaw against users,
   business operations, or data; no leverage over the vendor. 字节
   ByteSRC's rules state it verbatim, every SRC enforces it.
4. **Confidentiality.** No third-party disclosure of the vulnerability
   or related intelligence without the vendor's authorization — 腾讯
   TSRC's clause is representative: violation forfeits all rewards.
   Coordinated disclosure is not a preference here; it is a term.
5. **Complete, reproducible report.** Steps a triager can replay,
   request/response evidence, concrete harm statement, affected
   asset named exactly (domain / IP / app name + package name).
   字节 asks injection reports to carry the injection point and payload
   or the full URL; 滴滴 asks the app name and package name for mobile.
6. **One channel.** Duplicate intake across the SRC's own channels or
   between SRC and bounty program reads as spam or double-claiming.

**Per-vendor notes (verify against the current rules page):**

| SRC | Intake shape worth knowing |
|---|---|
| 腾讯 TSRC | Own products/business; high/critical bonuses scale with events; strict confidentiality clause; high-quality single reports separately rewarded |
| 阿里 ASRC / 先知 | Own assets first; **third-party product vulns are capped low (≤中危, contribution-limited, first-submitter only)** — do not route an OSS finding here expecting a CVE-grade reception; 先知's 通用软件计划 scores CVSS 3.1 + 影响面 + 利用可能性 for listed vendors |
| 字节 ByteSRC | 处置规则 V6.0; an explicit **AI-generated report standard** — an agent-assisted report must meet the same completeness bar as a human one; asset/payload naming requirements above |
| 京东 JSRC | 外部威胁处理规则 V9.1; intake windows pause during major sale events |
| 百度 BSRC | Own product lines; a separate 隐私漏洞处理标准 for mobile privacy-compliance findings |
| 美团 SRC | 美团 + 大众点评 products |
| 补天 (Butian) | Crowd platform between white hats and vendor SRCs; 通用型 has its own reward schedule; event-type goes 平台审核 → 厂商复审; site-weight thresholds apply to what counts as a valid target |

**The routing decision for an audit finding:** an SRC takes a finding
in *that vendor's* assets. An open-source library defect used by many
vendors is **通用型** material (CNVD / CVE lane), not SRC material —
unless the auditor's finding is in the vendor's own deployment of it.

---

## 5. `bounty_platform` — HackerOne / Bugcrowd / vendor programs

**Scope.** The program brief, asset by asset. The brief overrides
everything: in-scope assets, out-of-scope weaknesses, safe-harbour
terms, disclosure timeline. A perfect report on an out-of-scope asset
earns nothing but a marked profile.

**Report anatomy every platform asks for** (HackerOne's quality bar,
verbatim in intent):

1. A short, direct title and summary.
2. **Steps to reproduce**, numbered, replayable by the triager without
   asking a question ("create account A → log in → open …").
3. **Impact** — what the attacker achieves, stated as capability, not
   as technique.
4. Supporting evidence: HTTP request/response, screenshots, PoC code,
   affected URL/app and environment.
5. Severity *suggested* by the researcher (CVSS where the program uses
   it), **decided** by triage. Suggesting P1 does not make it P1.

**Bugcrowd VRT P1–P5**, the industry's baseline severity taxonomy:
P1 critical (privilege escalation to admin, RCE, direct financial
theft), P2 severe (sensitive data exposure, stored XSS on key pages),
P3 moderate (reflected XSS, CSRF on state-changing actions), P4 low
(GET-based open redirect, minor info leak), P5 informational (weak
policy without demonstrated impact). Rate against the taxonomy the
program uses, and remember VRT priorities are *baseline* — the brief's
exceptions override.

**Agent-assisted reports.** More platforms now distinguish
AI-generated or AI-assisted submissions explicitly (ByteSRC's standard
is the named example). The bar is the same completeness and
reproducibility as a human report; the submitter signs for it. Record
the AI-assistance disclosure state in the advisory's submitter notes.

---

## 6. Mapping claim shape to target fit

The adjudication's own answers decide the fit, before any platform is
consulted:

| Claim shape | vendor_advisory | cve_cna | cnvd | src_platform | bounty_platform |
|---|---|---|---|---|---|
| OSS defect, holds, maintainer advisory flow exists | **primary** | via the maintainer's advisory | secondary if 通用型 bar met (unpublished + PoC + distribution) | unsuitable (not vendor asset) | only if listed program |
| OSS defect, maintainer declines as hardening | hardening_channel instead | unlikely — no boundary crossed per maintainer | weak — published-classification disputes sink it | unsuitable | unsuitable |
| Vendor web asset defect (their own site/app) | vendor security email | not applicable | event-type at best (no product) | **primary** (their SRC) | **primary** if program exists — pick one |
| Distributed product/library defect, multi-vendor | vendor first | primary after maintainer acknowledges | 通用型 primary for CN credit | each vendor's SRC is secondary per its own use | per program |
| Already published / already has CVE | nothing to submit | duplicate | 备案 at best | duplicate | rejected |
| needs_more_evidence | nothing anywhere | no | no | no | no |

Two mechanical fit rules the validator enforces elsewhere: a
`needs_more_evidence` or `does_not_hold` claim has no submission at
all, and no claim carries two primary targets.

---

## 7. Before any submission

- [ ] Re-read the target platform's **current** rules page — this file
      is the distilled baseline, not the live rule.
- [ ] The maintainer (or primary target) has the complete report; no
      other channel has a copy.
- [ ] The PoC touches only data the reporter created.
- [ ] The affected range comes from a traced commit or says "every
      build that contains this function".
- [ ] Disclosure timeline stated and honoured; CNVD 通用型 requires
      未公开 until archived.
- [ ] The submitter — not this Skill — presses the submit button.
