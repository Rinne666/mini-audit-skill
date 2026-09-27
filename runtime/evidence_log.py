#!/usr/bin/env python3
"""Run read-only source searches/reads and save auditable evidence records.

This helper does not execute arbitrary shell commands. It supports only
`rg` searches and bounded source-file reads, saving their output as an
artifact and appending a JSONL record with the command, exit code, and
SHA-256. The audit notes should cite these evidence IDs. This records
tool use through this helper; it cannot detect searches performed through
other tools or prevent a user from editing the log. Source paths are stored
relative to the working directory and that directory is stored relative to
the ledger, avoiding absolute home-directory paths in committed fixtures.

Usage:

    python runtime/evidence_log.py search \
      --ledger audit/evidence.jsonl --artifact-dir audit/evidence \
      --pattern 'trusted|proxy|verify' src/

    python runtime/evidence_log.py read \
      --ledger audit/evidence.jsonl --artifact-dir audit/evidence \
      --path src/auth.py --start 10 --end 40
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path

MAX_ARTIFACT_BYTES = 1_000_000
MAX_READ_LINES = 500
MAX_SEARCH_RESULTS_PER_FILE = 500
EVIDENCE_ID = re.compile(r"^E([0-9]{6})$")


def _next_id(ledger: Path) -> str:
    if not ledger.exists():
        return "E000001"
    highest = 0
    for line_number, line in enumerate(ledger.read_text(encoding="utf-8").splitlines(), 1):
        try:
            record = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"malformed evidence ledger line {line_number}: {exc}") from exc
        if not isinstance(record, dict):
            raise ValueError(f"evidence ledger line {line_number} must be an object")
        match = EVIDENCE_ID.fullmatch(str(record.get("id", "")))
        if not match:
            raise ValueError(f"invalid evidence ID on ledger line {line_number}")
        highest = max(highest, int(match.group(1)))
    return f"E{highest + 1:06d}"


def _prepare_paths(ledger_arg: str, artifact_dir_arg: str) -> tuple[Path, Path]:
    ledger = Path(ledger_arg).resolve()
    artifact_dir = Path(artifact_dir_arg).resolve()
    ledger.parent.mkdir(parents=True, exist_ok=True)
    try:
        artifact_dir.relative_to(ledger.parent)
    except ValueError as exc:
        raise ValueError("artifact directory must be inside the evidence ledger directory") from exc
    artifact_dir.mkdir(parents=True, exist_ok=True)
    return ledger, artifact_dir


def _relative_path(path: str, base: Path) -> str:
    """Return a path relative to base, including for absolute input paths."""
    if path == "-":
        return path
    return os.path.relpath(Path(path).resolve(), base.resolve())


def _write_record(ledger: Path, artifact_dir: Path, record: dict, output: bytes) -> int:
    evidence_id = record["id"]
    truncated = len(output) > MAX_ARTIFACT_BYTES
    saved = output[:MAX_ARTIFACT_BYTES]
    artifact = artifact_dir / f"{evidence_id}.txt"
    artifact.write_bytes(saved)
    relative_artifact = os.path.relpath(artifact, ledger.parent)
    record.update(
        {
            "artifact": relative_artifact,
            "artifact_bytes": len(saved),
            "artifact_sha256": hashlib.sha256(saved).hexdigest(),
            "truncated": truncated,
        }
    )
    with ledger.open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(record, sort_keys=True) + "\n")
    sys.stdout.buffer.write(saved)
    if truncated:
        print(f"\n[output truncated at {MAX_ARTIFACT_BYTES} bytes]", file=sys.stderr)
    print(f"\nEvidence {evidence_id}: {relative_artifact} (sha256 {record['artifact_sha256']})", file=sys.stderr)
    return 0


def _run_search(args: argparse.Namespace) -> int:
    ledger, artifact_dir = _prepare_paths(args.ledger, args.artifact_dir)
    evidence_id = _next_id(ledger)
    command = ["rg", "--line-number", "--with-filename", "--no-heading", "--color", "never", "--max-count", str(MAX_SEARCH_RESULTS_PER_FILE)]
    for glob in args.glob:
        command.extend(["--glob", glob])
    command.extend(["--", args.pattern, *args.paths])
    logged_paths = [_relative_path(path, Path.cwd()) for path in args.paths]
    logged_command = [*command[:-len(args.paths)], *logged_paths]
    try:
        result = subprocess.run(command, capture_output=True, timeout=args.timeout, check=False)
        output = result.stdout
        if result.stderr:
            output += b"\n[stderr]\n" + result.stderr
        result_code = result.returncode
        timed_out = False
    except FileNotFoundError:
        output = b"rg executable not found\n"
        result_code = 127
        timed_out = False
    except subprocess.TimeoutExpired as exc:
        output = exc.stdout or b""
        if isinstance(output, str):
            output = output.encode("utf-8", errors="replace")
        output += b"\n[search timed out]\n"
        result_code = 124
        timed_out = True
    summary = "no matches" if result_code == 1 else ("matches found" if result_code == 0 else "search incomplete or failed")
    write_status = _write_record(
        ledger,
        artifact_dir,
        {
            "id": evidence_id,
            "kind": "search",
            "cwd": os.path.relpath(Path.cwd(), ledger.parent),
            "query": args.pattern,
            "paths": logged_paths,
            "globs": args.glob,
            "command": logged_command,
            "exit_code": result_code,
            "result_summary": summary,
            "timed_out": timed_out,
        },
        output,
    )
    if write_status != 0:
        return write_status
    return 124 if timed_out else (0 if result_code in {0, 1} else result_code)


def _run_read(args: argparse.Namespace) -> int:
    if args.start < 1 or args.end < args.start or args.end - args.start + 1 > MAX_READ_LINES:
        print(f"read line range must be 1-{MAX_READ_LINES} lines, inclusive", file=sys.stderr)
        return 2
    ledger, artifact_dir = _prepare_paths(args.ledger, args.artifact_dir)
    evidence_id = _next_id(ledger)
    path = Path(args.path).resolve()
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError as exc:
        print(f"cannot read {path}: {exc}", file=sys.stderr)
        return 2
    selected = lines[args.start - 1 : args.end]
    output = "".join(
        f"{index}: {line}\n" if line else f"{index}:\n"
        for index, line in enumerate(selected, args.start)
    ).encode("utf-8")
    return _write_record(
        ledger,
        artifact_dir,
        {
            "id": evidence_id,
            "kind": "read",
            "cwd": os.path.relpath(Path.cwd(), ledger.parent),
            "path": os.path.relpath(path, Path.cwd()),
            "start_line": args.start,
            "end_line": min(args.end, len(lines)),
            "result_summary": f"read {len(selected)} line(s)",
            "exit_code": 0,
            "timed_out": False,
        },
        output,
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Capture read-only source searches and reads as evidence artifacts.")
    subparsers = parser.add_subparsers(dest="operation", required=True)
    search = subparsers.add_parser("search", help="Run a read-only ripgrep search and capture its result.")
    search.add_argument("--ledger", required=True, help="JSONL evidence ledger path")
    search.add_argument("--artifact-dir", required=True, help="Evidence artifact directory inside the ledger directory")
    search.add_argument("--pattern", required=True, help="ripgrep pattern")
    search.add_argument("--glob", action="append", default=[], help="optional ripgrep glob; may be repeated")
    search.add_argument("--timeout", type=int, default=60, help="search timeout in seconds")
    search.add_argument("paths", nargs="+", help="file or directory paths to search")
    search.set_defaults(run=_run_search)

    read = subparsers.add_parser("read", help="Capture a bounded source-file line range.")
    read.add_argument("--ledger", required=True, help="JSONL evidence ledger path")
    read.add_argument("--artifact-dir", required=True, help="Evidence artifact directory inside the ledger directory")
    read.add_argument("--path", required=True, help="source file to read")
    read.add_argument("--start", required=True, type=int, help="first line, one-based")
    read.add_argument("--end", required=True, type=int, help="last line, inclusive")
    read.set_defaults(run=_run_read)

    args = parser.parse_args(argv)
    try:
        return args.run(args)
    except (OSError, ValueError) as exc:
        print(f"evidence logging failed: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
