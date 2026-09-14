"""Tests for runtime/atomic_io.py — atomic writes + corruption recovery."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from runtime.atomic_io import (
    AtomicIOError,
    read_json_or_corrupt,
    safe_rename,
    sha256_file,
    sha256_text,
    write_json_atomic,
    write_text_atomic,
)


def test_write_text_atomic_roundtrip(tmp_path: Path) -> None:
    target = tmp_path / "state.json"
    write_text_atomic(target, "hello\n")
    assert target.read_text(encoding="utf-8") == "hello\n"


def test_write_json_atomic_pretty(tmp_path: Path) -> None:
    target = tmp_path / "data.json"
    write_json_atomic(target, {"a": 1, "b": [1, 2, 3]})
    raw = target.read_text(encoding="utf-8")
    # Ensure trailing newline + indent
    assert raw.endswith("\n")
    assert json.loads(raw) == {"a": 1, "b": [1, 2, 3]}


def test_write_atomic_overwrites_existing(tmp_path: Path) -> None:
    target = tmp_path / "state.json"
    write_text_atomic(target, "v1")
    write_text_atomic(target, "v2")
    assert target.read_text(encoding="utf-8") == "v2"


def test_read_json_or_corrupt_raises_and_quarantines(tmp_path: Path) -> None:
    target = tmp_path / "state.json"
    target.write_text("{not valid json", encoding="utf-8")
    with pytest.raises(AtomicIOError) as excinfo:
        read_json_or_corrupt(target)
    assert "corrupt state" in str(excinfo.value)
    # Original moved aside
    assert not target.exists()
    corrupt_files = list(tmp_path.glob("state.json.corrupt-*"))
    assert len(corrupt_files) == 1
    assert "not valid json" in corrupt_files[0].read_text(encoding="utf-8")


def test_read_json_or_corrupt_missing_raises_filenotfound(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        read_json_or_corrupt(tmp_path / "nope.json")


def test_sha256_file_matches_text(tmp_path: Path) -> None:
    target = tmp_path / "x.txt"
    target.write_text("abc", encoding="utf-8")
    assert sha256_file(target) == sha256_text("abc")


def test_safe_rename_refuses_overwrite(tmp_path: Path) -> None:
    src = tmp_path / "src"
    dst = tmp_path / "dst"
    src.write_text("x", encoding="utf-8")
    dst.write_text("y", encoding="utf-8")
    with pytest.raises(AtomicIOError):
        safe_rename(src, dst)
    # dst untouched
    assert dst.read_text(encoding="utf-8") == "y"


def test_safe_rename_happy(tmp_path: Path) -> None:
    src = tmp_path / "src"
    dst = tmp_path / "dst"
    src.write_text("payload", encoding="utf-8")
    safe_rename(src, dst)
    assert not src.exists()
    assert dst.read_text(encoding="utf-8") == "payload"


def test_write_atomic_no_tempfile_leak_on_failure(tmp_path: Path) -> None:
    """If write fails midway, no leftover .tmp file is left behind."""
    target = tmp_path / "state.json"
    target.write_text("seed", encoding="utf-8")
    # Force a failure by passing a non-serializable object
    with pytest.raises((TypeError, ValueError)):
        write_json_atomic(target, {"bad": set()})  # set() not JSON-serializable
    # Original seed still present; no .tmp lingering
    leftovers = list(tmp_path.glob(".state.json.*"))
    assert target.read_text(encoding="utf-8") == "seed"
    assert leftovers == []