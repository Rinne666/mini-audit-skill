"""Diff scope analyzer (Spec §31).

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

This module is intentionally language-agnostic: it consumes a
`changed_files.json` artifact (produced by `git diff` between two
SHAs) and emits a structured diff scope record.
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
# D0 / D1 — baseline resolution + changed-file enumeration
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
        elif line.startswith("@@"):
            m = re.match(r"@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@", line)
            if not m or not current_path:
                continue
            start = int(m.group(1))
            count = int(m.group(2) or 1)
            out[current_path].append((start, start + max(count, 1) - 1))
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

    def to_dict(self) -> dict[str, Any]:
        return {
            "baseline": self.baseline,
            "target": self.target,
            "changed": list(self.changed),
            "risk_ranked": list(self.risk_ranked),
            "line_ranges": {k: list(v) for k, v in self.line_ranges.items()},
            "callers": {k: list(v) for k, v in self.callers.items()},
        }


def build_diff_scope(repo_root: os.PathLike[str] | str, *, baseline: str, target: str,
                     risky_symbols: Iterable[str] = ()) -> DiffScope:
    changed = resolve_changed_files(repo_root, baseline=baseline, target=target)
    ranked = prioritize_paths(changed)
    ranges = changed_line_ranges(repo_root, baseline=baseline, target=target, paths=[c["path"] for c in changed])
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
    )