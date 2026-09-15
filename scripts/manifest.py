#!/usr/bin/env python3
"""Generate `references/MANIFEST.json` with provenance metadata.

Spec §13 (Reference Provenance). The manifest records, per file:

    path, kind, size_bytes, sha256          (integrity — v1)
    source_repo, source_commit, source_path (provenance — v1.1)
    license, modified, imported_at          (license / lineage — v1.1)

Usage:
    manifest.py [--root PATH]                 # write MANIFEST.json
    manifest.py --check                       # verify, no write (exit 1 on drift)
    manifest.py --resolve-commits             # refresh per-file commits from
                                              # a local checkout, then write
    manifest.py --print                       # dump to stdout, no write

Provenance is declared in `PROVENANCE.json` (sources + rules + overrides +
commit_map). Commit resolution is *offline by default*: it reads the frozen
`commit_map` so CI reproduces byte-identical output. `--resolve-commits`
re-queries a local git checkout (e.g. `/Users/rinne/Desktop/piolium`) and
freezes the result back into `commit_map`.
"""
from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path


MANIFEST_SCHEMA_VERSION = 2
PROVENANCE_FILENAME = "PROVENANCE.json"
MANIFEST_FILENAME = "MANIFEST.json"
# Metadata files are not themselves reference content.
META_FILES = {MANIFEST_FILENAME, PROVENANCE_FILENAME}


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


def _match(pattern: str, rel: str) -> bool:
    """Component-wise glob: ``*`` never crosses ``/``.

    This makes ``*.md`` match only top-level files, unlike ``fnmatch`` where
    ``*`` would also swallow ``hunting/x.md``.
    """
    p = pattern.split("/")
    c = rel.split("/")
    if len(p) != len(c):
        return False
    return all(fnmatch.fnmatchcase(part, pat) for part, pat in zip(c, p))


def resolve_provenance(rel: str, prov: dict) -> dict:
    """Return {source, source_path, modified, note?} for one relative path."""
    overrides = prov.get("overrides", {})
    if rel in overrides:
        rule = dict(overrides[rel])
    else:
        rule = None
        for candidate in prov.get("rules", []):
            if _match(candidate["match"], rel):
                rule = candidate
                break
        if rule is None:
            rule = {"source": "local", "source_path": rel}

    name = os.path.basename(rel)
    stem = name[: -len(Path(name).suffix)] if Path(name).suffix else name
    source_path = (
        rule.get("source_path", rel)
        .replace("{stem}", stem)
        .replace("{name}", name)
        .replace("{rel}", rel)
    )

    source = rule.get("source", "local")
    modified = rule.get("modified")
    if modified is None:
        modified = prov.get("modified_by_source", {}).get(source, False)

    out = {
        "source_repo": source,
        "source_path": source_path,
        "modified": bool(modified),
    }
    if "note" in rule:
        out["note"] = rule["note"]
    return out


def resolve_commit(rel: str, source: str, prov: dict) -> str:
    commit_map = prov.get("commit_map", {})
    if rel in commit_map:
        return commit_map[rel]
    return prov.get("sources", {}).get(source, {}).get("commit", "UNKNOWN")


def build_manifest(root: Path) -> dict:
    prov_path = root / PROVENANCE_FILENAME
    if not prov_path.exists():
        raise SystemExit(f"missing provenance file: {prov_path}")
    prov = json.loads(prov_path.read_text(encoding="utf-8"))
    sources = prov.get("sources", {})
    imported_at = prov.get("imported_at", "UNKNOWN")

    items = []
    for r, _, files in os.walk(root):
        for name in sorted(files):
            if name.startswith(".") or name in META_FILES:
                continue
            full = Path(r) / name
            rel = str(full.relative_to(root))
            source_info = resolve_provenance(rel, prov)
            source = source_info["source_repo"]
            item = {
                "path": rel,
                "kind": categorize(rel),
                "size_bytes": full.stat().st_size,
                "sha256": sha256_of(full),
                "source_repo": source,
                "source_commit": resolve_commit(rel, source, prov),
                "source_path": source_info["source_path"],
                "license": sources.get(source, {}).get("license", "UNKNOWN"),
                "modified": source_info["modified"],
                "imported_at": imported_at,
            }
            if "note" in source_info:
                item["note"] = source_info["note"]
            items.append(item)

    items.sort(key=lambda i: i["path"])
    return {
        "schema_version": MANIFEST_SCHEMA_VERSION,
        "kind": "reference-manifest",
        "generated_by": "scripts/manifest.py",
        "imported_at": imported_at,
        "sources": sources,
        "item_count": len(items),
        "items": items,
    }


def resolve_commits(root: Path, prov_path: Path) -> int:
    """Refresh `commit_map` for sources that have a local git checkout."""
    prov = json.loads(prov_path.read_text(encoding="utf-8"))
    sources = prov.get("sources", {})
    commit_map: dict[str, str] = dict(prov.get("commit_map", {}))
    resolved = 0
    for r, _, files in os.walk(root):
        for name in sorted(files):
            if name.startswith(".") or name in META_FILES:
                continue
            rel = str((Path(r) / name).relative_to(root))
            info = resolve_provenance(rel, prov)
            source = info["source_repo"]
            local_path = sources.get(source, {}).get("local_path")
            if not local_path:
                continue
            repo = Path(local_path)
            if not (repo / ".git").exists():
                continue
            try:
                out = subprocess.run(
                    ["git", "-C", str(repo), "log", "-1", "--format=%H", "--",
                     info["source_path"]],
                    capture_output=True, text=True, check=False,
                )
            except OSError:
                continue
            sha = out.stdout.strip()
            if sha:
                commit_map[rel] = sha
                resolved += 1
    prov["commit_map"] = commit_map
    prov_path.write_text(
        json.dumps(prov, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    return resolved


def _stable(obj: dict) -> str:
    """Canonical dump ignoring volatile ordering only — full compare."""
    return json.dumps(obj, indent=2, ensure_ascii=False, sort_keys=False)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="generate references/MANIFEST.json")
    ap.add_argument("--root", default="references")
    ap.add_argument("--check", action="store_true",
                    help="verify MANIFEST matches the tree; do not write")
    ap.add_argument("--print", dest="dump", action="store_true",
                    help="write computed manifest to stdout only")
    ap.add_argument("--resolve-commits", action="store_true",
                    help="refresh per-file commits from local checkouts first")
    args = ap.parse_args(argv)

    root = Path(args.root).resolve()
    if not root.exists():
        print(f"root not found: {root}", file=sys.stderr)
        return 2

    if args.resolve_commits:
        n = resolve_commits(root, root / PROVENANCE_FILENAME)
        print(f"resolved {n} commit(s) from local checkouts", file=sys.stderr)

    computed = build_manifest(root)
    manifest_path = root / MANIFEST_FILENAME

    if args.dump:
        print(_stable(computed))
        return 0

    if args.check:
        if not manifest_path.exists():
            print(f"missing manifest: {manifest_path}", file=sys.stderr)
            return 1
        current = json.loads(manifest_path.read_text(encoding="utf-8"))
        if _stable(current) != _stable(computed):
            cur_by = {i["path"]: i for i in current.get("items", [])}
            new_by = {i["path"]: i for i in computed["items"]}
            for p in sorted(set(cur_by) | set(new_by)):
                if cur_by.get(p) != new_by.get(p):
                    print(f"drift: {p}", file=sys.stderr)
            print("manifest out of date — run scripts/manifest.py", file=sys.stderr)
            return 1
        print(f"manifest up to date ({computed['item_count']} items)")
        return 0

    manifest_path.write_text(_stable(computed) + "\n", encoding="utf-8")
    print(f"wrote {manifest_path.relative_to(Path.cwd()) if manifest_path.is_relative_to(Path.cwd()) else manifest_path} "
          f"({computed['item_count']} items)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
