#!/usr/bin/env python3
"""Validate `references/MANIFEST.json` against the filesystem.

Usage:
    check-manifest.py [--root PATH] [--strict]

With `--strict`, any missing or unmanifested file is a hard failure.
Without `--strict`, only structure errors fail.

Checks (Spec §35):
  - all reference files are manifested
  - all manifested files exist on disk
  - hunt-class map points to existing files
  - README counts match manifest
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from pathlib import Path


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

    errors: list[str] = []
    warnings: list[str] = []

    # Walk disk
    on_disk: dict[str, set[str]] = {}
    for r, _, files in os.walk(root):
        for name in sorted(files):
            if name.startswith("."):
                continue
            if name == "MANIFEST.json":
                continue
            full = Path(r) / name
            rel = str(full.relative_to(root))
            on_disk.setdefault(categorize(rel), set()).add(rel)

    # Files on disk that are not manifested
    on_disk_all: set[str] = set()
    for paths in on_disk.values():
        on_disk_all.update(paths)
    unmanifested = sorted(on_disk_all - items.keys())
    if unmanifested:
        msg = f"unmanifested files: {len(unmanifested)}"
        if args.strict:
            errors.append(msg)
            errors.extend(f"  - {p}" for p in unmanifested)
        else:
            warnings.append(msg)
            warnings.extend(f"  - {p}" for p in unmanifested)

    # Manifested files that are missing on disk
    missing = sorted(set(items) - on_disk_all)
    if missing:
        msg = f"missing files (in manifest, not on disk): {len(missing)}"
        errors.append(msg)
        errors.extend(f"  - {p}" for p in missing)

    # SHA256 check
    for rel, item in items.items():
        full = root / rel
        if not full.exists():
            continue
        actual = sha256_of(full)
        if actual != item.get("sha256"):
            errors.append(f"sha256 mismatch for {rel}")

    # Hunt-class map cross-references
    hunt_map = root / "_hunt-class-map.md"
    if hunt_map.exists():
        text = hunt_map.read_text(encoding="utf-8")
        referenced = set(re.findall(r"hunting/[a-z0-9\-]+\.md", text))
        unresolved = sorted(r for r in referenced if not (root / r).exists())
        if unresolved:
            errors.append(f"hunt-class map references {len(unresolved)} missing file(s)")
            errors.extend(f"  - {p}" for p in unresolved)

    # README counts must match manifest
    readme = root / "README.md"
    if readme.exists():
        text = readme.read_text(encoding="utf-8")
        counts_in_readme = {
            "hunting": re.search(r"hunting/[^|]+—\s*(\d+)\s*files", text),
            "vuln-classes": re.search(r"vuln-classes/[^|]+—\s*(\d+)\s*files", text),
            "methodology": re.search(r"methodology/[^|]+—\s*(\d+)\s*files", text),
            "wordlists": re.search(r"wordlists/[^|]+—\s*(\d+)\s*files", text),
        }
        for label, m in counts_in_readme.items():
            if not m:
                continue
            claimed = int(m.group(1))
            actual = len(on_disk.get(label, set()))
            if claimed != actual:
                msg = f"README count for {label} ({claimed}) != on-disk ({actual})"
                if args.strict:
                    errors.append(msg)
                else:
                    warnings.append(msg)

    summary = {
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