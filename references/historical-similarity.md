# Historical Similarity and Maintainer Preference

> Load this during the Assess stage, every time Q2 (boundary) is
> answered for an open-source target. The project's own history with
> near-identical issues is the strongest acceptance evidence available —
> a similar shape that was released as *Hardening* rather than *Security
> fix* means the answer to this claim is already written, and a report
> that ignores it walks into a pre-decided closure.

Two questions are answered here, both recorded in
`acceptance.oss_verification`:

1. **Historical similarity** — has this project (or its ecosystem)
   had this *shape* of issue before, and how was it classified?
2. **Maintainer preference** — what does the project demonstrably
   accept, credit, and publish, versus argue down?

---

## 1. Finding the similar issues

Search in decreasing order of authority:

1. **The project's own advisory history** — the Security → Advisories
   tab, `SECURITY.md`'s advisory table, `docs/security/`. Each entry is
   the project classifying an issue *in its own words*.
2. **The fix history of the same sink** — `git log -p -- <path>`
   around the vulnerable code. Past fixes to the same file/sink show
   what the maintainers treated as worth fixing and how they labelled
   the commit (`security:`, `fix:`, `harden:` — conventional commits
   make this a grep).
3. **GitHub Advisory Database / OSV / NVD keyword search** — the
   component name plus the flaw shape ("deserialization", "path
   traversal", "empty response"). Near-identical issues in *sibling*
   projects count as evidence too, weighted lower.
4. **The issue tracker** — closed issues with the maintainer's own
   closure reasons. A closure reason is the maintainer's acceptance
   model stated out loud (see `references/ordering-and-channels.md` §4
   for turning a closure into a rule).

Each similar issue is recorded as a reference (GHSA id, CVE id, commit
sha, issue number) plus its classification. "None found" is a valid
answer and must carry what was searched — `{ref: "none found — GHSA
repo query + NVD keyword + git log -p of the sink", classification:
"unknown"}`.

## 2. The classification labels

| Label | What it predicts for this claim |
|---|---|
| `security_fix` | The same shape was accepted as a vulnerability. Strong accept signal; cite it in the advisory's favour. |
| `hardening` | The same shape was accepted only as an improvement. Expect `decline` on the report, offer the patch. |
| `bug_fix` | The shape was fixed without security framing. The report must argue the boundary crossing explicitly, or expect the same framing. |
| `wontfix` | The maintainer already ruled this shape out of scope. Do not submit the same shape without a new divergence. |
| `unknown` | Nothing similar found (with the searches recorded). The claim rests on its own evidence. |

The fixture's SECURITY.md states the doctrine most projects follow
without writing it down: **a declared invariant that the code violates
on one path is a security fix; a missing control the product never
claimed to have is hardening.** When the project's history shows both
labels in use, this distinction — not severity — decides which one this
claim gets.

## 3. Reading maintainer preference

Preference is a pattern, not a vibe. Cite the instances:

- **Labelling pattern** — how the project's fix commits and advisories
  split between `security_fix` / `hardening` / `bug_fix` (from §1's
  searches). One data point is an anecdote; three is a pattern.
- **Credit behaviour** — do published advisories credit external
  reporters? A project that never credits still accepts reports; a
  project that credits actively is likelier to engage with them.
- **Publication cadence** — regular advisories mean a live disclosure
  process and a working CVE path (through their CNA or GitHub); the
  last advisory years old means the report may sit.
- **Argument style** — from closed issues: does the maintainer argue
  reachability (then lead with the divergence), intent (then lead with
  the declared boundary), or deployment (then the premise must be
  attacker_only or the report is hardening)?

## 4. Developer awareness — did they already know?

A specific, high-value signal inside the source itself. Before
concluding, check the code around the defect for signs the developers
noticed the risk:

- comments naming the risk (`// TODO: validate`, `// FIXME:
  injection`, `// NOTE: unsafe, do not expose`);
- partial guards added then bypassed — a check that covers a sibling
  path but not this one (which is exactly the divergence Q3 wants);
- issue links in comments or commit messages pointing at a known bug.

Record `developer_awareness` per reportable claim:

- `aware` (with the comment/issue cited) — the report must address
  *why the acknowledgement never became a fix*, or it will be closed
  as "known issue / wontfix";
- `false` (searched, nothing) — normal case, say so;
- `unknown` — the history is unavailable, with what was tried.

An `aware` finding is not a reason to stay silent — a TODO is not a
fix, and the invariant is still violated — but it changes the report's
framing from "you have a bug" to "the check you started is missing on
this path", which is the framing that survives.

## 5. Writing it down

`oss_verification.historical_similar` lists the refs and their labels;
`oss_verification.maintainer_preference` states the pattern in one
paragraph with its citations. If the pattern and the three acceptance
answers disagree — the history says hardening, the derivation says
accept — the disagreement belongs in the rationale, resolved before
delivery, not after the submission.
