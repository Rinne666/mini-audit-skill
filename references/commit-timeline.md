# Commit Timeline

> Load this when a claim holds against an open-source target and the
> adjudication must place the defect **in time**: when it was
> introduced, which releases carry it, whether it is already fixed or
> already published. Every one of those facts decides a downstream
> field — the affected range in the advisory, the `already_fixed`
> verdict, the CNVD 通用型 未公开 requirement, and whether the
> maintainer has already classified this exact shape.

The timeline is recorded once per holding claim, in
`acceptance.oss_verification.commit_timeline`, and every field is
either a cited fact or an explicit `untraced — <reason>`. A guessed
timeline is worse than none: the affected range in a published advisory
is what vendors build their patches against.

---

## 1. The four facts, and what each decides

| Fact | What it decides | Where it lands |
|---|---|---|
| **Introducing commit** | The affected range start; whether the defect predates a rewrite or fork | Advisory "Affected versions"; CNVD affected-product versioning |
| **First release containing it** | The advisory's version floor — the earliest version a user can be running | `git tag --contains` |
| **Fix commit / fix state** | Whether the verdict is `already_fixed`; the "Patched version" field | `already_fixed` verdict; advisory patched-version field |
| **Published advisory covering it** | Whether re-reporting would be a duplicate | `already_fixed` verdict even when the code still carries the bug; CNVD 通用型 未公开 bar |

## 2. Tracing the introducing commit

The goal is the commit that first introduced the defect's *behaviour*,
not the commit that last touched the line.

- `git log -S'<the guard or the missing check's token>' --oneline --
  <path>` — pickaxe search for when a decisive token (the guard call,
  the config read, the sink function) entered or left the file.
- `git log -L<start>,<end>:<path>` — the history of exactly the
  vulnerable line range, through renames.
- `git blame -L<start>,<end> <path>` — the fast first pass; follow up
  because a blame shows the last edit, not the introduction.
- `git log --follow -- <path>` before any of the above when the file
  was renamed.

**When the trace fails**, record `untraced — <what you tried>`. The
advisory then states "every build that contains this function" as the
affected range. Never convert an untraced introduction into a guessed
version number — an unverified range invites the maintainer to find a
boundary you did not intend.

## 3. Tracing the releases that carry it

- `git tag --contains <introducing-commit>` — every tagged release
  that contains the defect; the oldest is the version floor.
- `git log <tag>..<introducing-commit>` is empty when the tag contains
  the commit (spell it as `git merge-base --is-ancestor <commit>
  <tag>` for a single check).
- If the project versions by branch (`release/1.x`), repeat per branch.

## 4. Tracing the fix state

- The current source no longer contains the defect → validity is
  `already_fixed`; cite the fixing commit (`git log -S` again, on the
  fix side) and check whether the fix is complete or partial.
- The fix exists on `main` but unreleased → the advisory's patched
  field is "unreleased on `main`, commit `<sha>`", never a guessed
  next version number.
- The bug is still present and a public issue/advisory already covers
  it → the claim is still `already_fixed` in spirit: **check before
  writing**, because re-reporting a published advisory is the fastest
  way to lose credibility, and it is trivially avoidable.

## 5. Checking whether it is already published

Search, in this order, and record what was searched:

1. The project's own advisory list — GitHub **Security → Advisories**
   tab, `SECURITY.md` history table, `docs/security/`, changelogs.
2. **GitHub Advisory Database** — `github.com/advisories?query=`
   with the repo slug (`owner/repo`) and again with the component
   name and flaw keyword.
3. **OSV.dev** — package-scoped, catches GHSA and many vendor feeds.
4. **NVD / CVE keyword search** — product name + the sink or
   capability words; CPE-flavoured queries for packaged products.
5. The repo itself: `git log --grep='CVE' --grep='security' -i` — the
   commit history of past security fixes shows both prior
   classifications and whether this defect was among them.

A defect that is already published is not submittable anywhere as an
original: CNVD 通用型 requires 未公开, every CNA treats it as a
duplicate, and every bounty program closes it.

## 6. The timeline table

One row per holding claim, kept in the notes file under OSS
Verification:

```text
| Claim | Introduced | First release with it | Fix state | Published as | Confidence |
|---|---|---|---|---|---|
| C1 | `a1b2c3d` 2024-03-02 (log -S on the guard token) | v2.1.0 (tag --contains) | none on main | none found (GHSA repo query + NVD keyword, 2026-10) | cited |
| C2 | untraced — file predates repo split, tried log -S and -L | unknown | none | none found | untraced |
```

Confidence is `cited` (sha in the row) or `untraced` (reason in the
row). A timeline row with neither is empty, and an empty row fails the
validator's non-empty-string requirement — deliberately.
