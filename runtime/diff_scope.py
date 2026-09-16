"""Diff scope analyzer (Spec §31, Hardening v1.1 §11).

Phase ``D0..D6`` of the diff-mode pipeline:

    D0 baseline resolution
    D1 changed-file enumeration
    D2 risk scoring
    D3 history/regression analysis
    D4 caller/blast-radius analysis
    D5 test-gap analysis
    D6 adversarial review + verification

Scope is not limited to changed lines. We trace:

    changed symbol
        ↓
    callers
        ↓
    security boundary
        ↓
    affected invariant

This module is intentionally language-agnostic: it consumes git diff data
between two SHAs and emits a structured diff scope record.

Hardening v1.1 §11 completes the stage set. v1 implemented D0–D2 plus a
partial D4 (raw ``grep`` caller search). Added here:

* **D3** — per-path commit history and regression signals (revert/rollback
  messages, fix-on-fix churn, repeated edits of the same path).
* **D4** — *structured* blast radius: callers classified by locality
  (same file / same module / cross module) and flagged when they look like
  entrypoints or touch security-sensitive code.
* **D5** — test-gap analysis: which changed paths have no test, and which
  changed paths changed without their tests changing.
* **D6** — an adversarial verification plan: deterministic task specs an
  LLM verifier can execute. The runtime does not pretend to do the
  adversarial reasoning itself; it produces the checklist and the evidence
  requirements.

Caller search remains text-based by default. :func:`find_symbol_references`
is the seam where an AST / SCIP / language-server backend plugs in, and the
structured D4 output already carries the fields such a backend would fill.

D0 turns one of three selectors into the ``(baseline, target)`` pair the rest of
the stages consume — ``--commit`` (``sha^..sha``), ``--since`` (``ref..HEAD``)
and ``--base``/``--head`` (``merge-base(base, head)..head``). It lives in code
rather than in the caller because the PR case is easy to get wrong in a way that
still produces a plausible-looking diff; see :func:`resolve_diff_range`.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Mapping, Optional

# ---------------------------------------------------------------------------
# D0 — selector resolution
# ---------------------------------------------------------------------------

#: What the caller *meant*, recorded in ``diff-scope.json`` so a later reader
#: (or a resumed audit) can tell which question was asked without re-deriving it
#: from two bare SHAs.
SCOPE_TYPE_COMMIT = "commit"
SCOPE_TYPE_SINCE = "since"
SCOPE_TYPE_BASE_HEAD = "base-head"
SCOPE_TYPE_EXPLICIT = "explicit"


class DiffRangeError(RuntimeError):
    """A selector is unresolvable, ambiguous, or internally inconsistent."""


@dataclass(frozen=True)
class DiffRange:
    """A resolved change-set: two commits plus how they were chosen."""

    baseline: str
    target: str
    scope_type: str
    selector: dict[str, str] = field(default_factory=dict)
    merge_base: str = ""

    def to_dict(self) -> dict[str, Any]:
        document: dict[str, Any] = {
            "scope_type": self.scope_type,
            "baseline": self.baseline,
            "target": self.target,
        }
        if self.selector:
            document["selector"] = dict(self.selector)
        if self.merge_base:
            document["merge_base"] = self.merge_base
        return document


def _resolve_commit(repo_root: os.PathLike[str] | str, ref: str) -> Optional[str]:
    """Full 40-char commit SHA for *ref*, or ``None`` if it names no commit.

    ``^{commit}`` peels annotated tags to the commit they point at, so a tag
    range works without the caller knowing whether the tag is annotated.
    """
    proc = subprocess.run(
        ["git", "-C", str(repo_root), "rev-parse", "--verify", "--quiet", f"{ref}^{{commit}}"],
        capture_output=True, text=True, check=False, timeout=60,
    )
    if proc.returncode != 0:
        return None
    return proc.stdout.strip() or None


def _empty_tree(repo_root: os.PathLike[str] | str) -> str:
    """The empty tree object, so a parentless commit still has a baseline.

    ``<sha>^`` does not resolve for a root commit. Diffing against the empty
    tree is what ``git diff --root`` does internally, and it answers the same
    question ("everything this commit introduced") for the first commit of a
    repository.
    """
    proc = subprocess.run(
        ["git", "-C", str(repo_root), "hash-object", "-t", "tree", "--stdin"],
        input="", capture_output=True, text=True, check=False, timeout=60,
    )
    tree = proc.stdout.strip()
    if proc.returncode != 0 or not tree:
        raise DiffRangeError(
            f"could not compute the empty tree in {repo_root}: {proc.stderr.strip()}"
        )
    return tree


def _merge_base(repo_root: os.PathLike[str] | str, left: str, right: str) -> str:
    proc = subprocess.run(
        ["git", "-C", str(repo_root), "merge-base", left, right],
        capture_output=True, text=True, check=False, timeout=60,
    )
    base = proc.stdout.strip()
    if proc.returncode != 0 or not base:
        raise DiffRangeError(
            f"no merge base between {left!r} and {right!r}: "
            f"{proc.stderr.strip() or 'unrelated histories? '}"
            "an incremental audit needs a common ancestor to diff from"
        )
    return base


def resolve_diff_range(
    repo_root: os.PathLike[str] | str,
    *,
    commit: Optional[str] = None,
    since: Optional[str] = None,
    base: Optional[str] = None,
    head: Optional[str] = None,
    baseline: Optional[str] = None,
    target: Optional[str] = None,
) -> DiffRange:
    """Turn one of three selectors into a ``(baseline, target)`` pair.

    Exactly one of these is accepted:

    ``--commit <sha>``
        ``baseline = <sha>^``, ``target = <sha>`` — "audit the security change
        this commit introduced". A root commit diffs against the empty tree.

    ``--since <sha|tag>``
        ``baseline = <ref>``, ``target = HEAD`` — "audit everything since a
        baseline I recorded earlier".

    ``--base <x> --head <y>``
        ``baseline = git merge-base x y``, ``target = y``. This is the PR case,
        and the merge base is the whole point: ``x..y`` describes the difference
        between two *tips*, so it reports everything the base branch did since
        the fork as if the head branch had undone it. Diffs against a merge base
        report only what the branch itself introduced.

    ``--baseline`` / ``--target`` stay available and are passed through
    verbatim, because they are the escape hatch for a revision expression the
    three selectors do not express. They may not be combined with a selector.
    """
    named = [(name, value) for name, value in (("commit", commit), ("since", since))
             if value]
    if base or head:
        if not (base and head):
            raise DiffRangeError("--base and --head must be given together")
        named.append(("base-head", f"{base}..{head}"))

    if baseline or target:
        if not (baseline and target):
            raise DiffRangeError("--baseline and --target must be given together")
        if named:
            raise DiffRangeError(
                "give either a selector (--commit / --since / --base+--head) or an "
                f"explicit --baseline/--target, not both (got {' and '.join(n for n, _ in named)})"
            )
        return DiffRange(baseline=str(baseline), target=str(target),
                         scope_type=SCOPE_TYPE_EXPLICIT,
                         selector={"baseline": str(baseline), "target": str(target)})

    if not named:
        raise DiffRangeError(
            "no change-set given: use --commit <sha>, --since <sha|tag>, "
            "--base <x> --head <y>, or an explicit --baseline <a> --target <b>"
        )
    if len(named) > 1:
        raise DiffRangeError(
            f"ambiguous selector: {' and '.join(n for n, _ in named)}; give exactly one"
        )

    name, value = named[0]

    if name == "commit":
        resolved = _resolve_commit(repo_root, value)
        if resolved is None:
            raise DiffRangeError(f"--commit {value!r} does not resolve to a commit")
        parent = _resolve_commit(repo_root, f"{value}^")
        return DiffRange(baseline=parent or _empty_tree(repo_root), target=resolved,
                         scope_type=SCOPE_TYPE_COMMIT, selector={"commit": value})

    if name == "since":
        resolved = _resolve_commit(repo_root, value)
        if resolved is None:
            raise DiffRangeError(f"--since {value!r} does not resolve to a commit")
        head_sha = _resolve_commit(repo_root, "HEAD")
        if head_sha is None:
            raise DiffRangeError("HEAD does not resolve to a commit")
        return DiffRange(baseline=resolved, target=head_sha,
                         scope_type=SCOPE_TYPE_SINCE, selector={"since": value})

    base_sha = _resolve_commit(repo_root, str(base))
    if base_sha is None:
        raise DiffRangeError(f"--base {base!r} does not resolve to a commit")
    head_sha = _resolve_commit(repo_root, str(head))
    if head_sha is None:
        raise DiffRangeError(f"--head {head!r} does not resolve to a commit")
    fork_point = _merge_base(repo_root, base_sha, head_sha)
    return DiffRange(baseline=fork_point, target=head_sha,
                     scope_type=SCOPE_TYPE_BASE_HEAD,
                     selector={"base": str(base), "head": str(head)},
                     merge_base=fork_point)


# ---------------------------------------------------------------------------
# D1 — changed-file enumeration
# ---------------------------------------------------------------------------


def resolve_changed_files(repo_root: os.PathLike[str] | str, *, baseline: str, target: str,
                          include_untracked: bool = True) -> list[dict[str, Any]]:
    """Run `git diff --name-status <baseline>..<target>` and parse output.

    Each entry: { path, status, old_path? }
    status ∈ { A: added, M: modified, D: deleted, R: renamed, C: copied }
    """
    root = Path(repo_root)
    cmd = ["git", "-C", str(root), "diff", "--name-status", "--diff-filter=ADMRC", f"{baseline}..{target}"]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60, check=False)
    if proc.returncode != 0:
        raise RuntimeError(f"git diff failed: {proc.stderr.strip()}")

    entries: list[dict[str, Any]] = []
    for line in proc.stdout.splitlines():
        if not line.strip():
            continue
        parts = line.split("\t")
        if len(parts) < 2:
            continue
        status = parts[0]
        if status.startswith("R") and len(parts) >= 3:
            entries.append({"status": "renamed", "old_path": parts[1], "path": parts[2]})
        else:
            entries.append({"status": {"A": "added", "M": "modified", "D": "deleted"}.get(status[0], "modified"),
                            "path": parts[1]})

    if include_untracked:
        # Pick up files added since target as untracked-only-relative-to-baseline.
        # We can't easily know that without `git diff <baseline>..<target> --diff-filter=A`,
        # which is already covered by 'A' status above. We do not chase working
        # tree untracked files because the diff baseline defines scope.
        pass

    return entries


def changed_line_ranges(repo_root: os.PathLike[str] | str, *, baseline: str, target: str,
                        paths: Iterable[str]) -> dict[str, list[tuple[int, int]]]:
    """Return ``{path: [(start_line, end_line), ...]}`` of changed regions.

    Uses `git diff -U0` and parses ``@@ -old_start,old_count +new_start,new_count @@``
    hunk headers.
    """
    root = Path(repo_root)
    paths_list = list(paths)
    if not paths_list:
        return {}
    cmd = ["git", "-C", str(root), "diff", "-U0", f"{baseline}..{target}", "--", *paths_list]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60, check=False)
    if proc.returncode != 0:
        raise RuntimeError(f"git diff line ranges failed: {proc.stderr.strip()}")
    out: dict[str, list[tuple[int, int]]] = {}
    current_path: Optional[str] = None
    for line in proc.stdout.splitlines():
        if line.startswith("+++ b/"):
            current_path = line[len("+++ b/"):]
            out.setdefault(current_path, [])
        elif line.startswith("+++ /dev/null"):
            # A deletion has no lines on the new side. Without this branch the
            # path stays on whatever file was parsed last, so a deleted file's
            # `@@ -1,2 +0,0 @@` header is attributed to an unrelated file as the
            # range (0, 0) — and line 0 is not somewhere a reviewer can be sent.
            current_path = None
        elif line.startswith("@@"):
            m = re.match(r"@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@", line)
            if not m or not current_path:
                continue
            count = int(m.group(2)) if m.group(2) is not None else 1
            if count == 0:
                continue  # pure deletion: nothing added to point at
            start = int(m.group(1))
            out[current_path].append((start, start + count - 1))
    return out


# ---------------------------------------------------------------------------
# D2 — risk scoring
# ---------------------------------------------------------------------------


RISKY_PATH_HINTS = (
    "/auth", "/login", "/oauth", "/session", "/permission", "/authorize",
    "/admin", "/user", "/account", "/billing", "/payment", "/checkout",
    "/upload", "/file", "/import", "/export", "/deserialize", "/exec",
    "/api/v", "/api/admin", "/internal", "/debug", "/console",
)

RISKY_FILE_HINTS = (
    "auth.", "session.", "permission.", "policy.", "security.", "crypto.",
    "jwt.", "oauth.", "saml.", "ldap.", "user_controller", "account_controller",
    "admin_controller", "billing_controller", "payment_controller",
    "upload_controller", "import_controller", "exec.", "command.",
)


def score_path(path: str, *, status: str) -> int:
    """Heuristic risk score 0..10 for a changed path.

    Score breakdown (max 10):

        path hits a security-sensitive route     +4
        filename hits a security-sensitive name +3
        status is 'added' (no audit history)    +2
        status is 'deleted' (no callers left)   -1
        default                                +1
    """
    lowered = path.lower()
    score = 1  # baseline — at least one path changed
    for hint in RISKY_PATH_HINTS:
        if hint in lowered:
            score += 4
            break
    for hint in RISKY_FILE_HINTS:
        if hint in lowered:
            score += 3
            break
    if status == "added":
        score += 2
    elif status == "deleted":
        score -= 1
    return max(0, min(score, 10))


def prioritize_paths(entries: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Return changed-file entries with risk_score attached, sorted desc."""
    out = []
    for e in entries:
        e = dict(e)
        e["risk_score"] = score_path(e["path"], status=e["status"])
        out.append(e)
    out.sort(key=lambda x: (-x["risk_score"], x["path"]))
    return out


# ---------------------------------------------------------------------------
# D4 — caller/blast-radius analysis (lightweight, language-agnostic)
# ---------------------------------------------------------------------------


def find_text_callers(repo_root: os.PathLike[str] | str, *, symbol: str,
                      file_glob: str = "*") -> list[dict[str, Any]]:
    """Naive text search for callers of *symbol*.

    This is the language-agnostic fallback. Real callers analysis should
    use tree-sitter / SCIP / language servers; this exists so the diff
    pipeline has *something* deterministic and testable.
    """
    root = Path(repo_root)
    pattern = re.compile(r"\b" + re.escape(symbol) + r"\b")
    out: list[dict[str, Any]] = []
    cmd = ["grep", "-rn", "--include", file_glob, "-F", symbol, str(root)]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120, check=False)
    for line in proc.stdout.splitlines():
        if not line.strip():
            continue
        parts = line.split(":", 2)
        if len(parts) < 3:
            continue
        path, lineno, content = parts[0], parts[1], parts[2]
        try:
            lineno_int = int(lineno)
        except ValueError:
            continue
        if not pattern.search(content):
            continue
        out.append({"file": os.path.relpath(path, root), "line": lineno_int, "match": content.strip()})
    return out


@dataclass
class DiffScope:
    baseline: str
    target: str
    changed: list[dict[str, Any]] = field(default_factory=list)
    risk_ranked: list[dict[str, Any]] = field(default_factory=list)
    line_ranges: dict[str, list[tuple[int, int]]] = field(default_factory=dict)
    callers: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    #: How the two SHAs above were chosen (see :func:`resolve_diff_range`).
    #: Recorded because "which question was this audit answering" is not
    #: recoverable from the SHAs, and a resumed or incremental audit needs it.
    scope_type: str = SCOPE_TYPE_EXPLICIT
    selector: dict[str, str] = field(default_factory=dict)
    merge_base: str = ""

    def to_dict(self) -> dict[str, Any]:
        document: dict[str, Any] = {
            "scope_type": self.scope_type,
            "baseline": self.baseline,
            "target": self.target,
            "changed": list(self.changed),
            "risk_ranked": list(self.risk_ranked),
            "line_ranges": {k: list(v) for k, v in self.line_ranges.items()},
            "callers": {k: list(v) for k, v in self.callers.items()},
        }
        if self.selector:
            document["selector"] = dict(self.selector)
        if self.merge_base:
            document["merge_base"] = self.merge_base
        return document


def build_diff_scope(repo_root: os.PathLike[str] | str, *, baseline: str, target: str,
                     risky_symbols: Iterable[str] = (),
                     resolved_range: Optional[DiffRange] = None) -> DiffScope:
    changed = resolve_changed_files(repo_root, baseline=baseline, target=target)
    ranked = prioritize_paths(changed)
    # Pathspec must name BOTH sides of a rename. Restricted to the new path
    # alone, git cannot pair the two, so a rename is reported as "new file" and
    # the whole file comes back as changed lines — for a file that was only
    # moved. Naming both sides restores the pure-rename form, which has no
    # hunks and therefore no changed lines to its name.
    pathspec: list[str] = []
    for entry in changed:
        for key in ("path", "old_path"):
            value = entry.get(key)
            if value and value not in pathspec:
                pathspec.append(str(value))
    ranges = changed_line_ranges(repo_root, baseline=baseline, target=target, paths=pathspec)
    callers: dict[str, list[dict[str, Any]]] = {}
    for sym in risky_symbols:
        callers[sym] = find_text_callers(repo_root, symbol=sym)
    return DiffScope(
        baseline=baseline,
        target=target,
        changed=changed,
        risk_ranked=ranked,
        line_ranges=ranges,
        callers=callers,
        scope_type=resolved_range.scope_type if resolved_range else SCOPE_TYPE_EXPLICIT,
        selector=dict(resolved_range.selector) if resolved_range else {"baseline": str(baseline),
                                                                      "target": str(target)},
        merge_base=resolved_range.merge_base if resolved_range else "",
    )


# ---------------------------------------------------------------------------
# D3 — history / regression analysis
# ---------------------------------------------------------------------------


REGRESSION_PATTERN = re.compile(
    r"\b(revert|rollback|re-?apply|regression|hotfix|workaround|"
    r"fix\s+typo|again|2nd|second\s+attempt)\b",
    re.IGNORECASE,
)

SECURITY_FIX_PATTERN = re.compile(
    r"\b(cve-\d{4}-\d+|security|vuln|exploit|xss|sqli|csrf|ssrf|rce|"
    r"auth[zn]?|permission|privilege|injection|traversal|overflow|"
    r"sanitiz|escap|bypass)\b",
    re.IGNORECASE,
)


def _git_lines(repo_root: os.PathLike[str] | str, *args: str) -> list[str]:
    proc = subprocess.run(
        ["git", "-C", str(repo_root), *args],
        capture_output=True, text=True, timeout=120, check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"git {args} failed: {proc.stderr.strip()}")
    return [line for line in proc.stdout.splitlines() if line.strip()]


@dataclass
class PathHistory:
    path: str
    commits: int = 0
    authors: list[str] = field(default_factory=list)
    subjects: list[str] = field(default_factory=list)
    insertions: int = 0
    deletions: int = 0
    regression_signals: list[str] = field(default_factory=list)
    security_fix_signals: list[str] = field(default_factory=list)

    @property
    def churn(self) -> int:
        return self.insertions + self.deletions

    @property
    def regression_risk(self) -> int:
        """0..10 heuristic: reverted/re-fixed/security-fixed paths score high."""
        score = 0
        score += min(4, 2 * len(self.regression_signals))
        score += min(4, 2 * len(self.security_fix_signals))
        if self.commits >= 5:
            score += 2
        elif self.commits >= 3:
            score += 1
        return min(score, 10)

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "commits": self.commits,
            "authors": list(self.authors),
            "subjects": list(self.subjects),
            "insertions": self.insertions,
            "deletions": self.deletions,
            "churn": self.churn,
            "regression_signals": list(self.regression_signals),
            "security_fix_signals": list(self.security_fix_signals),
            "regression_risk": self.regression_risk,
        }


def analyze_path_history(repo_root: os.PathLike[str] | str, *,
                         baseline: str, target: str,
                         paths: Iterable[str]) -> dict[str, PathHistory]:
    """D3: per-path commit history + regression signals across baseline..target."""
    out: dict[str, PathHistory] = {}
    for path in paths:
        history = PathHistory(path=path)
        try:
            log = _git_lines(
                repo_root, "log", "--no-merges", "--format=%an\t%s",
                f"{baseline}..{target}", "--", path,
            )
        except RuntimeError:
            log = []
        for line in log:
            author, _, subject = line.partition("\t")
            history.commits += 1
            if author and author not in history.authors:
                history.authors.append(author)
            if subject:
                history.subjects.append(subject)
                if REGRESSION_PATTERN.search(subject):
                    history.regression_signals.append(subject)
                if SECURITY_FIX_PATTERN.search(subject):
                    history.security_fix_signals.append(subject)
        try:
            numstat = _git_lines(repo_root, "diff", "--numstat",
                                 f"{baseline}..{target}", "--", path)
        except RuntimeError:
            numstat = []
        for line in numstat:
            parts = line.split("\t")
            if len(parts) >= 2:
                history.insertions += int(parts[0]) if parts[0].isdigit() else 0
                history.deletions += int(parts[1]) if parts[1].isdigit() else 0
        out[path] = history
    return out


# ---------------------------------------------------------------------------
# D4 — structured blast radius
# ---------------------------------------------------------------------------


ENTRYPOINT_HINT = re.compile(
    r"\b(handler|controller|view|endpoint|route|router|resource|api|"
    r"resolver|mutation|action|servlet|listener|consumer|worker)\b",
    re.IGNORECASE,
)


def _classify_caller(caller_path: str, changed_path: str) -> str:
    if caller_path == changed_path:
        return "same_file"
    if os.path.dirname(caller_path).split(os.sep)[:1] == os.path.dirname(changed_path).split(os.sep)[:1]:
        return "same_module"
    return "cross_module"


def _is_security_sensitive_path(path: str) -> bool:
    lowered = path.lower()
    return any(h in lowered for h in RISKY_PATH_HINTS) or any(
        h in lowered for h in RISKY_FILE_HINTS
    )


def find_symbol_references(repo_root: os.PathLike[str] | str, *, symbol: str,
                           file_glob: str = "*") -> list[dict[str, Any]]:
    """Return references to *symbol*.

    Text search is the default backend; this is the seam for an AST / SCIP /
    language-server implementation (which would return the same record shape
    with ``backend`` set to its own name).
    """
    refs = find_text_callers(repo_root, symbol=symbol, file_glob=file_glob)
    for ref in refs:
        ref.setdefault("backend", "text-grep")
    return refs


def structured_blast_radius(repo_root: os.PathLike[str] | str, *,
                            changed_paths: Iterable[str],
                            symbols: Iterable[str] = ()) -> dict[str, Any]:
    """D4: callers per symbol, classified by locality and security relevance."""
    changed_list = list(changed_paths)
    per_symbol: dict[str, dict[str, Any]] = {}
    for symbol in symbols:
        refs = find_symbol_references(repo_root, symbol=symbol)
        enriched: list[dict[str, Any]] = []
        for ref in refs:
            caller_path = ref.get("file", "")
            locality = "unknown"
            for changed in changed_list:
                if caller_path == changed or caller_path.endswith(os.sep + changed):
                    locality = _classify_caller(caller_path, changed)
                    break
            match_text = ref.get("match", "")
            enriched.append({
                **ref,
                "locality": locality,
                "security_sensitive": _is_security_sensitive_path(caller_path),
                "looks_like_entrypoint": bool(ENTRYPOINT_HINT.search(caller_path.split("/")[-1])
                                              or ENTRYPOINT_HINT.search(match_text)),
            })
        entrypoints = [r for r in enriched if r["looks_like_entrypoint"]]
        sensitive = [r for r in enriched if r["security_sensitive"]]
        cross_module = [r for r in enriched if r["locality"] == "cross_module"]
        per_symbol[symbol] = {
            "references": enriched,
            "count": len(enriched),
            "entrypoint_like": len(entrypoints),
            "security_sensitive": len(sensitive),
            "cross_module": len(cross_module),
            # A symbol reached from another module, from an entrypoint, or from
            # security-sensitive code is where a boundary change matters most.
            "blast_radius": (
                "wide" if (cross_module or len(sensitive) >= 2)
                else "moderate" if enriched
                else "none"
            ),
        }
    return {"per_symbol": per_symbol, "symbols": list(symbols)}


# ---------------------------------------------------------------------------
# D5 — test-gap analysis
# ---------------------------------------------------------------------------


TEST_PATH_HINTS = ("/test/", "/tests/", "/testing/", "/spec/", "/specs/",
                   "/__tests__/", "/testdata/", "/fixtures/")
TEST_NAME_HINTS = ("test_", "_test.", ".test.", ".spec.", "spec_", "_spec.")


def is_test_path(path: str) -> bool:
    lowered = "/" + path.lower().replace(os.sep, "/") + "/"
    if any(h in lowered for h in TEST_PATH_HINTS):
        return True
    name = os.path.basename(path).lower()
    return any(h in name for h in TEST_NAME_HINTS)


def candidate_test_paths(path: str) -> list[str]:
    """Heuristic map from a source path to plausible test paths."""
    path = path.replace(os.sep, "/")
    directory, _, filename = path.rpartition("/")
    stem, dot, ext = filename.rpartition(".")
    if not dot:
        stem, ext = filename, ""
    ext = ext or "py"
    names = [
        f"test_{stem}.{ext}",
        f"{stem}_test.{ext}",
        f"{stem}.test.{ext}",
        f"{stem}.spec.{ext}",
    ]
    bases = [directory, "tests", "test", "spec", "tests/unit",
             directory.replace("src", "tests") if "src" in directory else "tests"]
    out: list[str] = []
    for base in bases:
        for name in names:
            candidate = f"{base}/{name}" if base else name
            if candidate not in out:
                out.append(candidate)
    return out


def analyze_test_gaps(repo_root: os.PathLike[str] | str, *,
                      changed_paths: Iterable[str],
                      changed_line_ranges: Optional[Mapping[str, Any]] = None) -> dict[str, Any]:
    """D5: which changed source paths are untested, and which changed without tests.

    Two distinct risks:

    * ``untested_paths`` — a changed source file with no test file anywhere.
    * ``test_stale_paths`` — the source changed but its test did not change in
      the same range (behaviour moved without the test moving).
    """
    root = Path(repo_root)
    changed_list = [p for p in changed_paths]
    changed_set = set(changed_list)
    untested: list[dict[str, Any]] = []
    stale: list[dict[str, Any]] = []
    tested: list[dict[str, Any]] = []

    for path in changed_list:
        if is_test_path(path):
            continue
        existing = [c for c in candidate_test_paths(path) if (root / c).exists()]
        if not existing:
            untested.append({"path": path, "candidate_tests": candidate_test_paths(path)[:6]})
            continue
        changed_tests = [t for t in existing if t in changed_set]
        record = {"path": path, "tests": existing, "tests_changed": changed_tests}
        if not changed_tests:
            stale.append(record)
        else:
            tested.append(record)

    changed_tests_touched = sorted(p for p in changed_list if is_test_path(p))
    total_sources = len([p for p in changed_list if not is_test_path(p)])
    covered = len(tested)
    return {
        "total_changed_sources": total_sources,
        "tested_paths": tested,
        "untested_paths": untested,
        "test_stale_paths": stale,
        "changed_test_files": changed_tests_touched,
        "test_coverage_ratio": (covered / total_sources) if total_sources else 1.0,
        "gap_risk": (
            "high" if untested and len(untested) >= max(1, total_sources // 2)
            else "medium" if (untested or stale)
            else "low"
        ),
    }


# ---------------------------------------------------------------------------
# D6 — adversarial verification plan
# ---------------------------------------------------------------------------


CLASS_HINTS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("rce", ("exec", "eval", "subprocess", "popen", "system(", "shell", "deserialize",
             "pickle", "yaml.load", "spawn", "child_process")),
    ("sql_injection", ("query", "cursor", "execute(", "raw", "select ", "insert ", "where ")),
    ("ssrf", ("request", "fetch", "urlopen", "http", "webhook", "proxy", "redirect")),
    ("path_traversal", ("open(", "readfile", "read_file", "sendfile", "join(", "path")),
    ("idor", ("findbyid", "get_by_id", "owner", "tenant", "account_id", "user_id")),
    ("broken_authentication", ("login", "session", "token", "jwt", "password", "credential")),
    ("broken_authorization", ("authorize", "permission", "role", "admin", "guard", "policy")),
    ("csrf", ("csrf", "state_change", "post", "form")),
    ("race_condition", ("thread", "lock", "mutex", "transaction", "concurrent", "atomic")),
    ("insecure_default", ("default", "config", "secret", "env", "password")),
)

ANTI_PATTERNS = (
    "declared_value_is_not_effective_value",
    "sanitizer_present_but_not_on_this_path",
    "framework_already_enforces_the_invariant",
    "attacker_could_already_do_this_via_normal_features",
    "requires_admin_action",
    "test_or_dev_only_default",
    "dead_code_or_unreachable",
    "duplicate_of_existing_finding",
)


def _read_changed_text(repo_root: os.PathLike[str] | str, path: str,
                       ranges: Optional[list[tuple[int, int]]], *, limit: int = 200) -> str:
    """Best-effort read of changed lines (falls back to the whole file head)."""
    full = Path(repo_root) / path
    try:
        lines = full.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return ""
    if not ranges:
        return "\n".join(lines[:limit])
    out: list[str] = []
    for start, end in ranges:
        out.extend(lines[max(0, start - 1):end])
    return "\n".join(out[:limit])


def hypothesize_classes(path: str, text: str) -> list[str]:
    """Deterministic class hints from the path and the changed text."""
    blob = f"{path}\n{text}".lower()
    classes: list[str] = []
    for cls, hints in CLASS_HINTS:
        if any(h in blob for h in hints):
            classes.append(cls)
    return classes or ["unclassified"]


def build_adversarial_plan(repo_root: os.PathLike[str] | str, *,
                           risk_ranked: Iterable[Mapping[str, Any]],
                           line_ranges: Optional[Mapping[str, list[tuple[int, int]]]] = None,
                           min_risk: int = 6) -> dict[str, Any]:
    """D6: deterministic task specs for adversarial verification.

    For every changed path above *min_risk* we emit the questions a verifier
    must answer, the evidence it must produce, and the anti-patterns to rule
    out. This is the checklist half of D6 — the reasoning half stays with the
    LLM verifier.
    """
    line_ranges = line_ranges or {}
    tasks: list[dict[str, Any]] = []
    for entry in risk_ranked:
        path = entry.get("path", "")
        score = int(entry.get("risk_score", 0))
        if score < min_risk:
            continue
        ranges = list(line_ranges.get(path, []))
        text = _read_changed_text(repo_root, path, ranges)
        classes = hypothesize_classes(path, text)
        tasks.append({
            "path": path,
            "risk_score": score,
            "status": entry.get("status"),
            "changed_line_ranges": ranges,
            "hypothesis_classes": classes,
            "adversarial_questions": [
                "What is the trust boundary this change touches, and who is on each side?",
                "Can an actor who previously could only X now do Y? (fill both blanks concretely)",
                "Is the value reaching the sink actually the attacker-controlled one, after every transform?",
                "Which existing control (sanitizer / framework / authorization) would have to be absent for this to be exploitable?",
                "What evidence would falsify the claim?",
            ],
            "required_evidence": [
                "entrypoint: file:line of the attacker-reachable entry",
                "propagation: each hop from entrypoint to sink",
                "sink: file:line of the dangerous operation",
                "control: the specific guard that is missing or bypassed",
                "either a reproduction or an explicit statement of what blocked it",
            ],
            "anti_patterns_to_rule_out": list(ANTI_PATTERNS),
        })
    return {
        "min_risk": min_risk,
        "task_count": len(tasks),
        "tasks": tasks,
    }


def build_diff_scope_extended(repo_root: os.PathLike[str] | str, *,
                              baseline: str, target: str,
                              risky_symbols: Iterable[str] = (),
                              min_risk: int = 6) -> dict[str, Any]:
    """Run D0–D6 and return one serializable record."""
    scope = build_diff_scope(repo_root, baseline=baseline, target=target,
                             risky_symbols=risky_symbols)
    changed_paths = [c["path"] for c in scope.changed]
    history = analyze_path_history(repo_root, baseline=baseline, target=target,
                                   paths=changed_paths)
    blast = structured_blast_radius(repo_root, changed_paths=changed_paths,
                                    symbols=risky_symbols)
    gaps = analyze_test_gaps(repo_root, changed_paths=changed_paths,
                             changed_line_ranges=scope.line_ranges)
    plan = build_adversarial_plan(repo_root, risk_ranked=scope.risk_ranked,
                                  line_ranges=scope.line_ranges, min_risk=min_risk)

    # Re-rank: D2 risk adjusted by D3 regression risk.
    reranked: list[dict[str, Any]] = []
    for entry in scope.risk_ranked:
        item = dict(entry)
        hist = history.get(entry["path"])
        reg = hist.regression_risk if hist else 0
        item["regression_risk"] = reg
        item["combined_risk"] = min(10, int(entry.get("risk_score", 0)) + (2 if reg >= 6 else 1 if reg >= 3 else 0))
        reranked.append(item)
    reranked.sort(key=lambda x: (-x["combined_risk"], x["path"]))

    return {
        "baseline": scope.baseline,
        "target": scope.target,
        "changed": scope.changed,
        "risk_ranked": reranked,
        "line_ranges": {k: list(v) for k, v in scope.line_ranges.items()},
        "callers": {k: list(v) for k, v in scope.callers.items()},
        "D3_history": {k: v.to_dict() for k, v in history.items()},
        "D4_blast_radius": blast,
        "D5_test_gaps": gaps,
        "D6_adversarial_plan": plan,
    }
