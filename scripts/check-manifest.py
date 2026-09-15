#!/usr/bin/env python3
"""Validate `references/MANIFEST.json` against the filesystem.

Usage:
    check-manifest.py [--root PATH] [--strict]

With `--strict`, any missing or unmanifested file is a hard failure.
Without `--strict`, only structure errors fail.

Checks:
  - all reference files are manifested
  - all manifested files exist on disk
  - SHA-256 of every manifested file matches
  - hunt-class map points to existing files
  - README counts match the manifest
  - every item carries provenance (Spec §13): source_repo, source_commit,
    source_path, license, modified, imported_at
  - source_repo resolves to a declared source and license agrees with it
  - unresolved (UNKNOWN) licenses are reported as warnings
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from pathlib import Path


REQUIRED_PROVENANCE = (
    "source_repo",
    "source_commit",
    "source_path",
    "license",
    "modified",
    "imported_at",
)
MIN_MANIFEST_SCHEMA_VERSION = 2
UNKNOWN = "UNKNOWN"


def sha256_of(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def categorize(rel: str) -> str:
    if rel.endswith("_hunt-class-map.md"):
        return "cross-reference"
    if rel == "README.md":
        return "index"
    if "/hunting/" in "/" + rel:
        return "hunting"
    if "/vuln-classes/" in "/" + rel:
        return "vuln-class"
    if "/methodology/" in "/" + rel:
        return "methodology"
    if "/wordlists/" in "/" + rel:
        return "wordlist"
    if rel.endswith(".md"):
        return "agent-inline"
    return "other"


def claim_int(text: str, pattern: str) -> int | None:
    m = re.search(pattern, text)
    return int(m.group(1)) if m else None


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", default="references")
    ap.add_argument("--strict", action="store_true")
    args = ap.parse_args()

    root = Path(args.root).resolve()
    manifest_path = root / "MANIFEST.json"
    if not manifest_path.exists():
        print(f"missing manifest: {manifest_path}", file=sys.stderr)
        return 1
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    items = {item["path"]: item for item in manifest.get("items", [])}
    sources = manifest.get("sources", {})

    errors: list[str] = []
    warnings: list[str] = []

    # --- manifest structure -------------------------------------------------
    schema_version = manifest.get("schema_version", 1)
    if schema_version < MIN_MANIFEST_SCHEMA_VERSION:
        errors.append(
            f"manifest schema_version {schema_version} < "
            f"{MIN_MANIFEST_SCHEMA_VERSION} (run scripts/manifest.py)"
        )
    if "sources" not in manifest:
        errors.append("manifest has no `sources` block (run scripts/manifest.py)")

    # --- walk disk ----------------------------------------------------------
    on_disk: dict[str, set[str]] = {}
    for r, _, files in os.walk(root):
        for name in sorted(files):
            if name.startswith("."):
                continue
            if name in ("MANIFEST.json", "PROVENANCE.json"):
                continue
            full = Path(r) / name
            rel = str(full.relative_to(root))
            on_disk.setdefault(categorize(rel), set()).add(rel)

    on_disk_all: set[str] = set()
    for paths in on_disk.values():
        on_disk_all.update(paths)

    # --- presence -----------------------------------------------------------
    unmanifested = sorted(on_disk_all - items.keys())
    if unmanifested:
        msg = f"unmanifested files: {len(unmanifested)}"
        target = errors if args.strict else warnings
        target.append(msg)
        target.extend(f"  - {p}" for p in unmanifested)

    missing = sorted(set(items) - on_disk_all)
    if missing:
        errors.append(f"missing files (in manifest, not on disk): {len(missing)}")
        errors.extend(f"  - {p}" for p in missing)

    # --- sha256 -------------------------------------------------------------
    for rel, item in items.items():
        full = root / rel
        if not full.exists():
            continue
        if sha256_of(full) != item.get("sha256"):
            errors.append(f"sha256 mismatch for {rel}")

    # --- provenance (Spec §13) ---------------------------------------------
    unresolved_licenses: set[str] = set()
    for rel, item in items.items():
        absent = [k for k in REQUIRED_PROVENANCE if k not in item]
        if absent:
            errors.append(f"provenance missing {absent} for {rel}")
            continue
        repo = item["source_repo"]
        if repo not in sources:
            errors.append(f"{rel}: source_repo '{repo}' not declared in sources")
            continue
        declared_license = sources.get(repo, {}).get("license", UNKNOWN)
        if item["license"] != declared_license:
            errors.append(
                f"{rel}: license '{item['license']}' != source "
                f"'{repo}' license '{declared_license}'"
            )
        if not str(item["source_commit"]).strip():
            errors.append(f"{rel}: empty source_commit")
        if not str(item["source_path"]).strip():
            errors.append(f"{rel}: empty source_path")
        if item["license"] == UNKNOWN:
            unresolved_licenses.add(repo)
    if unresolved_licenses:
        warnings.append(
            "unresolved license(s) for source(s): "
            + ", ".join(sorted(unresolved_licenses))
            + " — confirm before redistribution"
        )

    # --- hunt-class map cross-references ------------------------------------
    hunt_map = root / "_hunt-class-map.md"
    if hunt_map.exists():
        text = hunt_map.read_text(encoding="utf-8")
        referenced = set(re.findall(r"hunting/[a-z0-9\-]+\.md", text))
        unresolved = sorted(r for r in referenced if not (root / r).exists())
        if unresolved:
            errors.append(f"hunt-class map references {len(unresolved)} missing file(s)")
            errors.extend(f"  - {p}" for p in unresolved)

        hunting_n = len(on_disk.get("hunting", set()))
        vuln_n = len(on_disk.get("vuln-class", set()))
        claims = (
            (r"\*\*(\d+) hunting methodologies\*\*", hunting_n, "hunting methodologies"),
            (r"\*\*(\d+) vulnerability class references\*\*", vuln_n,
             "vulnerability class references"),
        )
        for pattern, actual, label in claims:
            claimed = claim_int(text, pattern)
            if claimed is not None and claimed != actual:
                msg = f"hunt-class map {label} ({claimed}) != on-disk ({actual})"
                (errors if args.strict else warnings).append(msg)

        paired = re.search(r"\*\*(\d+)/(\d+) hunts\*\*", text)
        if paired:
            if int(paired.group(1)) > hunting_n or int(paired.group(2)) != hunting_n:
                msg = (
                    f"hunt-class map paired hunts ({paired.group(1)}/"
                    f"{paired.group(2)}) inconsistent with on-disk hunting "
                    f"count ({hunting_n})"
                )
                (errors if args.strict else warnings).append(msg)

    # --- README counts must match manifest ----------------------------------
    readme = root / "README.md"
    if readme.exists():
        text = readme.read_text(encoding="utf-8")
        dir_labels = {
            "hunting": "hunting",
            "vuln-classes": "vuln-class",
            "methodology": "methodology",
            "wordlists": "wordlist",
        }
        for dirname, category in dir_labels.items():
            claimed = claim_int(text, rf"{re.escape(dirname)}/[^\n]*?(\d+)\s*files")
            if claimed is None:
                continue
            actual = len(on_disk.get(category, set()))
            if claimed != actual:
                msg = f"README count for {dirname} ({claimed}) != on-disk ({actual})"
                (errors if args.strict else warnings).append(msg)

        # aggregate totals (README counts sub-directory files, not inline agents)
        subdir_total = sum(
            len(on_disk.get(c, set()))
            for c in ("hunting", "vuln-class", "methodology", "wordlist")
        )
        for pattern in (r"total \*\*(\d+) reference files", r"Total: (\d+) reference files"):
            claimed = claim_int(text, pattern)
            if claimed is not None and claimed != subdir_total:
                msg = (
                    f"README total reference count ({claimed}) != "
                    f"on-disk sub-directory files ({subdir_total})"
                )
                (errors if args.strict else warnings).append(msg)

        inline = len(on_disk.get("agent-inline", set()))
        claimed_inline = claim_int(text, r"the (\d+) inline Piolium agents")
        if claimed_inline is None:
            claimed_inline = claim_int(text, r"\((\d+) files\)[^\n]*inline Piolium")
        if claimed_inline is not None and claimed_inline != inline:
            msg = f"README inline-agent count ({claimed_inline}) != on-disk ({inline})"
            (errors if args.strict else warnings).append(msg)

        subdir_count = sum(
            1 for c in ("hunting", "vuln-class", "methodology", "wordlist")
            if on_disk.get(c)
        )
        claimed_subdirs = claim_int(text, r"(\d+) sub-directories")
        if claimed_subdirs is not None and claimed_subdirs != subdir_count:
            msg = (
                f"README sub-directory count ({claimed_subdirs}) != "
                f"on-disk ({subdir_count})"
            )
            (errors if args.strict else warnings).append(msg)

        claimed_new = claim_int(text, r"the (\d+) new files")
        if claimed_new is not None and claimed_new != subdir_total:
            msg = f"README new-file count ({claimed_new}) != on-disk ({subdir_total})"
            (errors if args.strict else warnings).append(msg)

    summary = {
        "manifest_schema_version": schema_version,
        "manifest_items": len(items),
        "on_disk_files": len(on_disk_all),
        "errors": len(errors),
        "warnings": len(warnings),
    }
    print(json.dumps(summary, indent=2))
    if warnings:
        print("\nWARNINGS:", file=sys.stderr)
        for w in warnings:
            print(f"  {w}", file=sys.stderr)
    if errors:
        print("\nERRORS:", file=sys.stderr)
        for e in errors:
            print(f"  {e}", file=sys.stderr)
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
