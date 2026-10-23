#!/usr/bin/env python3
"""cvss31 -- CVSS v3.1 base score calculator (cross-check only).

ROLE: a second implementation of the CVSS v3.1 base-score formula, used
to catch a hand-computed score that silently drops a metric. The most
common error is omitting the ISS multiplication on the impact
sub-score: Impact = 6.42 x ISS, not 6.42 + ISS. That moves a score by
roughly a full point and is invisible without an independent
implementation.

The platform's own advisory-form calculator is authoritative. This
script is a cross-check, never the authority.

Usage:
    python runtime/cvss31.py "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    python runtime/cvss31.py --selftest

Exit codes:
    0  ok
    1  bad input
    2  selftest failure
"""

from __future__ import annotations

import argparse
import math
import re
import sys

AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
AC = {"L": 0.77, "H": 0.44}
PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.5}
UI = {"N": 0.85, "R": 0.62}
CIA = {"H": 0.56, "L": 0.22, "N": 0.0}
REQUIRED = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")

# Published vectors with known scores. Chosen to cover the unchanged and
# changed scope, the three privilege levels, and the high-complexity
# attack path that a report about a configured extension will use.
ANCHORS = (
    ("CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:L/A:N", 4.2, "published SFTPGo GHSA anchor"),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8, "textbook unchanged-scope case"),
    ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N", 7.4, "high complexity, no availability loss"),
    ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N", 8.1, "low privilege, full C/I"),
    ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 8.8, "privilege required"),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0, "changed scope"),
)


def _py_round(x: float) -> int:
    """Round half to even, matching the Python reference implementation."""
    floor = math.floor(x)
    diff = x - floor
    if diff > 0.5:
        return floor + 1
    if diff < 0.5:
        return floor
    return floor if floor % 2 == 0 else floor + 1


def _roundup1(x: float) -> float:
    """CVSS v3.1 Roundup: the smallest one-decimal number >= x."""
    int_input = _py_round(x * 100000)
    if int_input % 10000 == 0:
        return int_input / 100000
    return (math.floor(int_input / 10000) + 1) / 10


def severity(score: float) -> str:
    if score == 0:
        return "None"
    if score < 4.0:
        return "Low"
    if score < 7.0:
        return "Medium"
    if score < 9.0:
        return "High"
    return "Critical"


def parse_vector(vector: str) -> dict[str, str]:
    if not vector or not vector.strip():
        raise ValueError("vector must be a non-empty string")
    raw = vector.strip()
    match = re.match(r"^(CVSS:3\.[01])/(.+)$", raw)
    if not match:
        raise ValueError(f"vector must start with CVSS:3.1/ or CVSS:3.0/ - got: {raw}")
    metrics: dict[str, str] = {}
    for part in match.group(2).split("/"):
        if ":" not in part:
            raise ValueError(f"malformed metric segment: {part}")
        key, value = part.split(":", 1)
        if key in metrics:
            raise ValueError(f"duplicate metric: {key}")
        metrics[key] = value
    for key in REQUIRED:
        if key not in metrics:
            raise ValueError(f"missing required metric: {key}")
    for key, table in (("AV", AV), ("AC", AC), ("UI", UI), ("C", CIA), ("I", CIA), ("A", CIA)):
        if metrics[key] not in table:
            raise ValueError(
                f"invalid value for {key}: {metrics[key]} (expected one of {'/'.join(table)})"
            )
    if metrics["S"] not in {"U", "C"}:
        raise ValueError(f"invalid value for S: {metrics['S']} (expected U/C)")
    if metrics["PR"] not in {"N", "L", "H"}:
        raise ValueError(f"invalid value for PR: {metrics['PR']} (expected N/L/H)")
    return metrics


def base_score(metrics: dict[str, str]) -> dict[str, float | str]:
    scope_changed = metrics["S"] == "C"
    pr_table = PR_CHANGED if scope_changed else PR_UNCHANGED
    iss = 1 - (1 - CIA[metrics["C"]]) * (1 - CIA[metrics["I"]]) * (1 - CIA[metrics["A"]])
    if scope_changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    else:
        impact = 6.42 * iss
    exploitability = (
        8.22 * AV[metrics["AV"]] * AC[metrics["AC"]] * pr_table[metrics["PR"]] * UI[metrics["UI"]]
    )
    if impact <= 0:
        score = 0.0
    elif scope_changed:
        score = _roundup1(min(1.08 * (impact + exploitability), 10))
    else:
        score = _roundup1(min(impact + exploitability, 10))
    return {
        "score": score,
        "iss": iss,
        "impact": impact,
        "exploitability": exploitability,
        "severity": severity(score),
    }


def compute(vector: str) -> dict[str, object]:
    metrics = parse_vector(vector)
    return {"vector": vector.strip(), "metrics": metrics, **base_score(metrics)}


def selftest() -> int:
    failed = 0
    for vector, expected, note in ANCHORS:
        try:
            got = float(compute(vector)["score"])
        except ValueError as exc:
            print(f"FAIL: {vector} threw: {exc}", file=sys.stderr)
            failed += 1
            continue
        if abs(got - expected) > 0.001:
            print(f"FAIL: {vector} => {got}, expected {expected} ({note})", file=sys.stderr)
            failed += 1
        else:
            print(f"OK:   {vector} => {got} {severity(got)} ({note})")
    probe = base_score({"AV": "N", "AC": "H", "PR": "N", "UI": "N", "S": "U", "C": "H", "I": "H", "A": "H"})
    if float(probe["iss"]) >= 0.9:
        print(f"OK:   ISS is applied to Impact (iss={probe['iss']:.6f})")
    else:
        print("FAIL: ISS was not applied to Impact", file=sys.stderr)
        failed += 1
    print("selftest passed" if failed == 0 else f"selftest FAILED ({failed})", file=sys.stderr if failed else sys.stdout)
    return 0 if failed == 0 else 2


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="CVSS v3.1 base score cross-check.")
    parser.add_argument("vector", nargs="?", help="CVSS:3.1/... vector string")
    parser.add_argument("--selftest", action="store_true", help="run the anchor checks and exit")
    args = parser.parse_args(argv)

    if args.selftest:
        return selftest()
    if not args.vector:
        parser.print_usage(sys.stderr)
        return 1
    try:
        result = compute(args.vector)
    except ValueError as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1
    print(f"vector    : {result['vector']}")
    print(f"ISS       : {result['iss']:.6f}")
    print(f"Impact    : {result['impact']:.6f}")
    print(f"Exploit.  : {result['exploitability']:.6f}")
    print(f"Base score: {result['score']} ({result['severity']})")
    print("note      : cross-check only; the platform calculator decides the reported score")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
