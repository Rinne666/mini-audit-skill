#!/usr/bin/env python3
"""Generate stable coverage-unit IDs from source-derived dimensions."""

from __future__ import annotations

import argparse
import hashlib
import json
import unicodedata

DIMENSION_KEYS = ("surface", "boundary", "subsystem", "attack_class", "lifecycle")


def _normalise(value: str | None) -> str | None:
    if value is None:
        return None
    cleaned = " ".join(unicodedata.normalize("NFC", value).split())
    if not cleaned:
        raise ValueError("coverage dimensions must not be blank")
    return cleaned


def canonical_dimensions(dimensions: dict) -> dict:
    """Return canonical values; identity excludes line numbers, status, and owner."""
    missing = [key for key in DIMENSION_KEYS[:-1] if key not in dimensions]
    if missing:
        raise ValueError("missing coverage dimensions: " + ", ".join(missing))
    result = {key: _normalise(dimensions.get(key)) for key in DIMENSION_KEYS}
    if result["lifecycle"] is None and "lifecycle" in dimensions:
        result["lifecycle"] = None
    return result


def coverage_id_for(dimensions: dict) -> str:
    canonical = canonical_dimensions(dimensions)
    encoded = json.dumps(canonical, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return "CU-" + hashlib.sha256(encoded).hexdigest()[:24]


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate a stable mini-audit coverage-unit ID.")
    parser.add_argument("--surface", required=True, help="Source-derived ingress or externally reachable surface")
    parser.add_argument("--boundary", required=True, help="Trust boundary crossed by this unit")
    parser.add_argument("--subsystem", required=True, help="Relevant subsystem or security decision point")
    parser.add_argument("--attack-class", required=True, help="Baseline lens or target-specific class")
    parser.add_argument("--lifecycle", help="Optional lifecycle phase")
    args = parser.parse_args()
    dimensions = {
        "surface": args.surface,
        "boundary": args.boundary,
        "subsystem": args.subsystem,
        "attack_class": args.attack_class,
        "lifecycle": args.lifecycle,
    }
    print(coverage_id_for(dimensions))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
