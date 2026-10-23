# Refutation — {slug}

> The artifact for a claim whose validity is **`does_not_hold`**, or
> whose validity is `needs_more_evidence`.
>
> This is not a report and must not be sent to the maintainer as one.
> It is the written answer to "we looked, and here is what we found".
> Its value is that it records *why*, so the next person does not redo
> the work — and so nobody re-reports the same non-issue.

## Claim as received

> {the claim, in the words it was made}

**Source of the claim**: `{scanner / colleague / advisory / bounty
report / our own reading}`.

## Verdict

**`{does_not_hold | needs_more_evidence | already_fixed}`**

One sentence: {what the evidence shows}.

## What refutes it

| Assertion | Verdict | Evidence | What it shows |
|---|---|---|---|
| | `refuted / confirmed / unresolved / fixed` | `file:line` | |

## The refutation, in detail

The specific thing that makes the claim false. Quote the guarding
line, the unreachable condition, or the earlier check that already
enforces the invariant.

> `{the code that decides it}`

Explain in two or three sentences why this defeats the claim — not
that the code looks safe, but that the claim's own path runs through
this check and the check holds.

## Refutation attempts that did not refute

Attempts that looked promising but did not hold up. Recording these
matters: without them, a reader cannot tell the difference between a
claim that was carefully killed and one that was never really tested.

| Attempt | Result |
|---|---|
| | |

## If `needs_more_evidence`: what is missing

The exact fact that could not be obtained from source, and a safe way
to observe it. Name it precisely enough that someone else can go get
it.

| Missing fact | How to observe it safely | Who can observe it |
|---|---|---|

**Do not report this claim while this is outstanding.** The verdict
stays `needs_more_evidence` until the fact is in hand.

## If `already_fixed`: where the fix is

- The fixing commit or the guarding line: `file:line` or a SHA.
- Whether the fix is **complete** — does it cover every path that
  reached the defect, or only the one that was reported?
- Whether the fix shipped in a release, and in which.

A partial fix is not the same as a fixed issue, and a partial fix may
be a new claim with a narrower subject.

## What would change this verdict

The specific new evidence that would flip the verdict to `holds`.
Without this, a refutation is a dead end; with it, the next reader
knows exactly where to push.

## Note for the submitter

- This claim is **not** being reported to the maintainer.
- If the maintainer is already aware of the issue, a note may still be
  worth sending — but it is a note, not a report, and it is a separate
  decision from the submitter.
