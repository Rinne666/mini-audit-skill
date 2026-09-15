#!/usr/bin/env python3
"""Single source of truth for the counts quoted across the docs (Spec §14).

Documentation drift (``99 reference files``, ``6 first-class roles``,
``export = stub``) is a recurring class of bug. Instead of hand-maintaining
numbers in prose, this script:

* derives every count from the artefacts themselves (manifest, test
  collection, eval corpus, SKILL.md tables),
* renders a generated counts block that docs embed between
  ``<!-- BEGIN auto-counts -->`` / ``<!-- END auto-counts -->`` markers,
* and — with ``--check`` — fails when a doc block or a known prose claim
  disagrees with the derived truth.

Usage:
    doc_counts.py                 # print the metrics as JSON
    doc_counts.py --check         # verify docs, exit 1 on drift
    doc_counts.py --write         # refresh the generated blocks in docs
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path


SKILL_ROOT = Path(__file__).resolve().parent.parent
DOCS = ("SKILL.md", "README.md")
BEGIN = "<!-- BEGIN auto-counts"
END = "<!-- END auto-counts -->"
SUBDIR_KINDS = ("hunting", "vuln-class", "methodology", "wordlist")
HUNTING = "hunting"
VULN_CLASS = "vuln-class"
METHODOLOGY = "methodology"
WORDLIST = "wordlist"
STATUS_FULL, STATUS_PARTIAL, STATUS_STUB = "✓ full", "◐ partial", "✗ stub"


# ---------------------------------------------------------------------------
# metric derivation
# ---------------------------------------------------------------------------


def _manifest(root: Path) -> dict:
    return json.loads((root / "references" / "MANIFEST.json").read_text(encoding="utf-8"))


def reference_metrics(root: Path) -> dict:
    m = _manifest(root)
    items = m.get("items", [])
    by_kind: dict[str, int] = {}
    for i in items:
        by_kind[i["kind"]] = by_kind.get(i["kind"], 0) + 1
    return {
        "reference_subdir_files": sum(by_kind.get(k, 0) for k in SUBDIR_KINDS),
        "reference_items": len(items),
        "inline_agents": by_kind.get("agent-inline", 0),
        "hunting_files": by_kind.get(HUNTING, 0),
        "vuln_class_files": by_kind.get(VULN_CLASS, 0),
        "methodology_files": by_kind.get(METHODOLOGY, 0),
        "wordlist_files": by_kind.get(WORDLIST, 0),
    }


def unit_test_count(root: Path) -> int:
    """Collect tests/unit via pytest; fall back to counting test functions."""
    tests = root / "tests" / "unit"
    try:
        proc = subprocess.run(
            [sys.executable, "-m", "pytest", str(tests), "--collect-only", "-q"],
            capture_output=True, text=True, check=False, cwd=str(root),
        )
        for line in proc.stdout.splitlines():
            m = re.search(r"(\d+) tests? collected", line)
            if m:
                return int(m.group(1))
    except OSError:
        pass
    return sum(
        len(re.findall(r"^\s*def test_", p.read_text(encoding="utf-8"), re.M))
        for p in sorted(tests.glob("*.py"))
    )


def eval_metrics(root: Path) -> dict:
    expected = json.loads((root / "evals" / "expected.json").read_text(encoding="utf-8"))
    fixtures = expected.get("fixtures", [])
    return {"eval_fixtures": len(fixtures)}


def runtime_version(root: Path) -> str:
    text = (root / "runtime" / "__init__.py").read_text(encoding="utf-8")
    m = re.search(r'__version__\s*=\s*"([^"]+)"', text)
    return m.group(1) if m else "UNKNOWN"


def gate_metrics(root: Path) -> dict:
    """Derive gate coverage from the runtime, never from prose (v1.1.1 §19).

    The v1.1 review flagged "every phase is gated" as an unverifiable claim.
    Importing the gate table makes the claim checkable in the same pass as
    every other count.
    """
    entry = str(root)
    if entry not in sys.path:
        sys.path.insert(0, entry)
    try:
        from runtime import gates  # noqa: PLC0415  (late import; needs root on path)
        return {"phase_gates": len(gates.DEFAULT_PHASE_GATES)}
    finally:
        if entry in sys.path:
            sys.path.remove(entry)


def _table_rows_after(text: str, heading: str) -> list[str]:
    """Return markdown table rows appearing after `heading` until a blank line."""
    idx = text.find(heading)
    if idx < 0:
        return []
    rows: list[str] = []
    started = False
    for line in text[idx + len(heading):].splitlines():
        if line.startswith("|"):
            started = True
            rows.append(line)
        elif started:
            break
    return rows


def role_metrics(root: Path) -> dict:
    text = (root / "SKILL.md").read_text(encoding="utf-8")
    rows = _table_rows_after(text, "### Default first-class roles")
    roles = [r for r in rows if re.match(r"\|\s*`mini-audit-", r)]
    return {"first_class_roles": len(roles)}


def command_metrics(root: Path) -> dict:
    text = (root / "SKILL.md").read_text(encoding="utf-8")
    rows = [
        l for l in text.splitlines()
        if l.startswith("| `/") and any(s in l for s in (STATUS_FULL, STATUS_PARTIAL, STATUS_STUB))
    ]
    full = sum(STATUS_FULL in r for r in rows)
    partial = sum(STATUS_PARTIAL in r for r in rows)
    stub = sum(STATUS_STUB in r for r in rows)
    return {
        "commands_total": len(rows),
        "commands_full": full,
        "commands_partial": partial,
        "commands_stub": stub,
    }


def collect_metrics(root: Path) -> dict:
    metrics: dict = {}
    metrics.update(reference_metrics(root))
    metrics.update(eval_metrics(root))
    metrics.update(role_metrics(root))
    metrics.update(command_metrics(root))
    metrics.update(gate_metrics(root))
    metrics["unit_tests"] = unit_test_count(root)
    metrics["runtime_version"] = runtime_version(root)
    return metrics


# ---------------------------------------------------------------------------
# generated block
# ---------------------------------------------------------------------------

BLOCK_ROWS = (
    ("reference files (4 sub-directories)", "reference_subdir_files"),
    ("manifest items (incl. inline agents)", "reference_items"),
    ("inline agent templates", "inline_agents"),
    ("per-class hunting methodologies", "hunting_files"),
    ("per-class vulnerability references", "vuln_class_files"),
    ("operator methodologies", "methodology_files"),
    ("runtime wordlists", "wordlist_files"),
    ("eval fixtures", "eval_fixtures"),
    ("first-class roles", "first_class_roles"),
    ("phase gates declared", "phase_gates"),
    ("runtime version", "runtime_version"),
)
# NOTE: the unit-test count is deliberately NOT emitted into docs — it changes
# every time a test is added, which would make the generated block perpetually
# stale. It stays available via `doc_counts.py` (JSON output) instead.


def render_block(metrics: dict) -> str:
    lines = [
        f"{BEGIN} — generated, do not edit by hand",
        "| Metric | Value |",
        "|--------|-------|",
    ]
    for label, key in BLOCK_ROWS:
        lines.append(f"| {label} | {metrics.get(key, 'n/a')} |")
    lines.append(
        "| commands: full / partial / stub | "
        f"{metrics.get('commands_full', '?')} / {metrics.get('commands_partial', '?')} / "
        f"{metrics.get('commands_stub', '?')} |"
    )
    lines.append(END)
    return "\n".join(lines)


def replace_block(text: str, block: str) -> str | None:
    start = text.find(BEGIN)
    end = text.find(END)
    if start < 0 or end < 0 or end < start:
        return None
    end += len(END)
    return text[:start] + block + text[end:]


# ---------------------------------------------------------------------------
# prose claim checks
# ---------------------------------------------------------------------------


def prose_claims(root: Path, metrics: dict) -> list[tuple[str, str, int, int]]:
    """Return (doc, description, claimed, actual) mismatches."""
    problems: list[tuple[str, str, int, int]] = []

    def check(doc: str, text: str, pattern: str, key: str, label: str,
              group: int = 1) -> None:
        m = re.search(pattern, text)
        if not m:
            return
        claimed = int(m.group(group))
        actual = metrics[key]
        if claimed != actual:
            problems.append((doc, label, claimed, actual))

    skill = (root / "SKILL.md").read_text(encoding="utf-8")
    readme = (root / "README.md").read_text(encoding="utf-8")
    refs_readme = (root / "references" / "README.md").read_text(encoding="utf-8")

    check("SKILL.md", skill, r"(\d+)\s+unit tests? for runtime", "unit_tests",
          "unit test count")
    check("SKILL.md", skill,
          r"contains\s+(\d+)\s+reference files in 4 sub-directories",
          "reference_subdir_files", "reference file count")
    check("SKILL.md", skill, r"The\s+(\d+)\s+reference files total",
          "reference_subdir_files", "reference file count (context budget)")
    check("SKILL.md", skill, r"\((\d+)\s+reference files in 4 sub-directories\)",
          "reference_subdir_files", "reference file count (heading)")
    check("SKILL.md", skill,
          r"surfaced as\s+(\d+)\s+first-class mini-audit roles",
          "first_class_roles", "first-class role count")
    check("SKILL.md", skill,
          r"the\s+(\d+)\s+inline agent templates and\s+(\d+)\s+first-class agent prompts",
          "inline_agents", "inline agent template count")
    check("SKILL.md", skill,
          r"the\s+(\d+)\s+inline agent templates and\s+(\d+)\s+first-class agent prompts",
          "first_class_roles", "first-class agent prompt count", group=2)
    check("SKILL.md", skill, r"Of the\s+(\d+)\s+commands", "commands_total",
          "command count")
    check("SKILL.md", skill, r"(\d+)\s+are full \(", "commands_full",
          "full command count")
    check("SKILL.md", skill, r"(\d+)\s+are partial \(", "commands_partial",
          "partial command count")
    check("SKILL.md", skill, r"(\d+)\s+are stub \(", "commands_stub",
          "stub command count")
    check("SKILL.md", skill,
          r"35 specialist agents → (\d+) first-class roles", "first_class_roles",
          "agent mapping first-class count")
    check("SKILL.md", skill,
          r"first-class roles \+ (\d+) inline-dispatched roles", "inline_agents",
          "agent mapping inline count")
    check("SKILL.md", skill,
          r"Gate coverage:\s*(\d+)\s+phases declare a deterministic gate",
          "phase_gates", "phase gate count")

    check("README.md", readme, r"vuln-classes/\s*#\s*(\d+)\s+per-vuln-class",
          "vuln_class_files", "vuln-class playbook count")
    check("README.md", readme,
          r"(\d+)\s+phases declare a deterministic gate",
          "phase_gates", "phase gate count")

    check("references/README.md", refs_readme, r"(\d+) first-class mavis agents",
          "first_class_roles", "first-class agent count")
    check("references/README.md", refs_readme, r"(\d+) inline Piolium role specs",
          "inline_agents", "inline role-spec count")
    check("references/README.md", refs_readme,
          r"(\d+) per-class hunting methodologies", "hunting_files",
          "hunting methodology count")
    check("references/README.md", refs_readme,
          r"(\d+) per-class vulnerability references", "vuln_class_files",
          "vulnerability reference count")
    check("references/README.md", refs_readme,
          r"(\d+) operator methodology references", "methodology_files",
          "methodology reference count")
    check("references/README.md", refs_readme, r"(\d+) runtime wordlists",
          "wordlist_files", "wordlist count")
    return problems


# ---------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="docs count truth + drift check")
    ap.add_argument("--root", default=str(SKILL_ROOT))
    ap.add_argument("--check", action="store_true")
    ap.add_argument("--write", action="store_true")
    args = ap.parse_args(argv)

    root = Path(args.root).resolve()
    metrics = collect_metrics(root)

    if args.write:
        block = render_block(metrics)
        for doc in DOCS:
            path = root / doc
            text = path.read_text(encoding="utf-8")
            updated = replace_block(text, block)
            if updated is None:
                print(f"{doc}: no auto-counts markers — skipped", file=sys.stderr)
                continue
            if updated != text:
                path.write_text(updated, encoding="utf-8")
                print(f"{doc}: counts block refreshed")
            else:
                print(f"{doc}: counts block already current")
        return 0

    if args.check:
        errors: list[str] = []
        for doc in DOCS:
            path = root / doc
            text = path.read_text(encoding="utf-8")
            expected = render_block(metrics)
            updated = replace_block(text, expected)
            if updated is None:
                continue
            if updated != text:
                errors.append(f"{doc}: generated counts block is stale "
                              f"(run scripts/doc_counts.py --write)")
        for doc, label, claimed, actual in prose_claims(root, metrics):
            errors.append(f"{doc}: {label} claims {claimed}, actual {actual}")
        if errors:
            print("doc count drift:", file=sys.stderr)
            for e in errors:
                print(f"  {e}", file=sys.stderr)
            return 1
        print("doc counts consistent")
        return 0

    print(json.dumps(metrics, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
