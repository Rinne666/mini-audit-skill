"""Hardening v1.1 §7 §8 — scanner scripts and sandbox policy.

These tests actually execute the shell scripts. v1.0's `detect-tools.sh`
reported every tool as unavailable because it called a bash function from a
Python heredoc; that class of bug is only caught by running the script.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

SKILL_ROOT = Path(__file__).resolve().parent.parent.parent
SCRIPTS = SKILL_ROOT / "scripts"
LAUNCHER = SCRIPTS / "mini-audit-runtime"


def _run(*args: str, cwd: Path, env: dict | None = None) -> subprocess.CompletedProcess:
    full_env = dict(os.environ)
    if env:
        full_env.update(env)
    return subprocess.run(
        list(args), capture_output=True, text=True, cwd=str(cwd), env=full_env, check=False
    )


def _bash(script: Path, *args: str, cwd: Path, env: dict | None = None) -> subprocess.CompletedProcess:
    return _run("bash", str(script), *args, cwd=cwd, env=env)


def _fake_semgrep(
    bin_dir: Path,
    record: Path,
    *,
    exit_code: int = 0,
    write_output: bool = True,
    payload: dict | None = None,
) -> Path:
    """Install a fake `semgrep` that records argv and optional SARIF output.

    It parses `--output` and writes a minimal SARIF document, because a real
    scan always produces an artifact and the wrapper now verifies that it did.
    """
    bin_dir.mkdir(parents=True, exist_ok=True)
    fake = bin_dir / "semgrep"
    doc = payload or {
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "semgrep"}}, "results": []}],
    }
    fake.write_text(
        "#!/usr/bin/env bash\n"
        f"printf '%s\\n' \"$@\" > {record}\n"
        "out=\"\"\n"
        "prev=\"\"\n"
        "for a in \"$@\"; do\n"
        "  if [ \"$prev\" = \"--output\" ]; then out=\"$a\"; fi\n"
        "  prev=\"$a\"\n"
        "done\n"
        + (
            f"if [ -n \"$out\" ]; then cat > \"$out\" <<'SARIF'\n{json.dumps(doc)}\nSARIF\nfi\n"
            if write_output
            else ""
        )
        + f"exit {exit_code}\n",
        encoding="utf-8",
    )
    fake.chmod(0o755)
    return fake


def _fake_env(fake_bin: Path) -> dict:
    return {"PATH": f"{fake_bin}{os.pathsep}{os.environ.get('PATH','')}"}


def _fake_codeql(
    bin_dir: Path,
    record: Path,
    *,
    analyze_exit: int = 0,
    write_output: bool = True,
) -> Path:
    """Install a fake `codeql` that records argv and emulates analyze output.

    `codeql database analyze` receives `--output=<path>` as a single argument,
    and the wrapper now verifies that the SARIF actually appeared.
    """
    bin_dir.mkdir(parents=True, exist_ok=True)
    fake = bin_dir / "codeql"
    doc = {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "codeql"}}, "results": []}]}
    fake.write_text(
        "#!/usr/bin/env bash\n"
        f"printf '%s\\n' \"$@\" >> {record}\n"
        'if [ "${1:-}" = "database" ] && [ "${2:-}" = "analyze" ]; then\n'
        "  out=\"\"\n"
        '  for a in "$@"; do\n'
        '    case "$a" in --output=*) out="${a#--output=}";; esac\n'
        "  done\n"
        + (
            f"  if [ -n \"$out\" ]; then mkdir -p \"$(dirname \"$out\")\"; cat > \"$out\" <<'SARIF'\n{json.dumps(doc)}\nSARIF\n  fi\n"
            if write_output
            else ""
        )
        + f"  exit {analyze_exit}\n"
        "fi\n"
        "exit 0\n",
        encoding="utf-8",
    )
    fake.chmod(0o755)
    return fake


# ---------------------------------------------------------------------------
# detect-tools.sh
# ---------------------------------------------------------------------------


def test_detect_tools_probes_real_binaries(tmp_path: Path) -> None:
    """git is certainly installed; it must be reported available.

    v1.0 always reported every tool unavailable.
    """
    out_path = tmp_path / "caps.json"
    result = _bash(SCRIPTS / "detect-tools.sh", "--output", str(out_path), cwd=tmp_path)
    assert result.returncode == 0, result.stderr

    caps = json.loads(out_path.read_text(encoding="utf-8"))
    assert caps["schema_version"] == 1
    assert "tools" in caps and "sandbox" in caps

    git = caps["tools"]["git"]
    assert git["available"] is True, "git must be detected"
    assert shutil.which("git") == git["path"]
    assert git["version"], "version string must be captured"

    # The Python interpreter itself is present, so at least one probe must
    # succeed — the key regression guard for the cross-language bug.
    assert any(t.get("available") for t in caps["tools"].values())


def test_detect_tools_default_output_path(tmp_path: Path) -> None:
    result = _bash(SCRIPTS / "detect-tools.sh", "--audit-root", "mini-audit",
                   cwd=tmp_path)
    assert result.returncode == 0, result.stderr
    assert (tmp_path / "mini-audit" / "scanner" / "capabilities.json").exists()


def test_detect_tools_rejects_unknown_arg(tmp_path: Path) -> None:
    result = _bash(SCRIPTS / "detect-tools.sh", "--nope", cwd=tmp_path)
    assert result.returncode == 2


def test_detect_tools_help(tmp_path: Path) -> None:
    result = _bash(SCRIPTS / "detect-tools.sh", "--help", cwd=tmp_path)
    assert result.returncode == 0
    assert "Usage" in result.stdout


def test_detect_tools_missing_tool_is_not_fatal(tmp_path: Path) -> None:
    caps_path = tmp_path / "caps.json"
    _bash(SCRIPTS / "detect-tools.sh", "--output", str(caps_path), cwd=tmp_path)
    caps = json.loads(caps_path.read_text(encoding="utf-8"))
    # semgrep is very likely absent in CI; it must be recorded as unavailable,
    # not crash the script.
    assert set(caps["tools"]) >= {"semgrep", "codeql", "gitleaks", "git"}


# ---------------------------------------------------------------------------
# sandbox-check.sh
# ---------------------------------------------------------------------------


def test_sandbox_check_writes_probe_and_exits(tmp_path: Path) -> None:
    """v1.0 crashed with NameError: sys on the exit-code path."""
    result = _bash(SCRIPTS / "sandbox-check.sh", "--audit-root", "mini-audit", cwd=tmp_path)
    assert "NameError" not in (result.stderr + result.stdout)
    assert "NameError" not in result.stderr

    probe_path = tmp_path / "mini-audit" / "sandbox" / "probe.json"
    assert probe_path.exists()
    probe = json.loads(probe_path.read_text(encoding="utf-8"))
    assert probe["schema_version"] == 1
    assert probe["verdict"] in ("ok", "blocked")
    for key in ("sandbox_available", "external_network_disabled",
                "safe_writable_scratch", "timeout_available",
                "resource_limit_available", "environment_sanitized"):
        assert key in probe["checks"]

    # Exit code agrees with the verdict.
    if probe["missing_critical"]:
        assert result.returncode == 1
    else:
        assert result.returncode == 0


def test_sandbox_check_reports_sandbox_available_when_env_set(tmp_path: Path) -> None:
    result = _bash(SCRIPTS / "sandbox-check.sh", "--audit-root", "mini-audit",
                   cwd=tmp_path, env={"MINI_AUDIT_SANDBOX": "1"})
    probe = json.loads((tmp_path / "mini-audit" / "sandbox" / "probe.json").read_text(encoding="utf-8"))
    assert probe["checks"]["sandbox_available"] is True


def test_sandbox_check_strict_fails_on_warnings(tmp_path: Path) -> None:
    # With no sandbox env vars at all, there will be warnings.
    result = _bash(SCRIPTS / "sandbox-check.sh", "--strict", "--audit-root", "mini-audit",
                   cwd=tmp_path, env={"MINI_AUDIT_SANDBOX": "1", "MINI_AUDIT_NO_NET": "1",
                                      "MINI_AUDIT_SANITIZED": "1"})
    # Either it is ok (all warnings gone) or it failed because of warnings.
    probe = json.loads((tmp_path / "mini-audit" / "sandbox" / "probe.json").read_text(encoding="utf-8"))
    if probe["warnings"]:
        assert result.returncode == 1
    else:
        assert result.returncode == 0


def test_sandbox_check_help(tmp_path: Path) -> None:
    assert _bash(SCRIPTS / "sandbox-check.sh", "--help", cwd=tmp_path).returncode == 0


# ---------------------------------------------------------------------------
# run-semgrep.sh / run-codeql.sh
# ---------------------------------------------------------------------------


def _write_permissive_probe(audit_root: Path) -> None:
    """Grant every capability so policy gating does not mask the assertion."""
    (audit_root / "sandbox").mkdir(parents=True, exist_ok=True)
    (audit_root / "sandbox" / "probe.json").write_text(json.dumps({
        "schema_version": 1,
        "checks": {
            "sandbox_available": True,
            "external_network_disabled": True,
            "safe_writable_scratch": True,
            "timeout_available": True,
            "resource_limit_available": True,
            "environment_sanitized": True,
        },
    }), encoding="utf-8")


def test_run_semgrep_passes_each_config_separately(tmp_path: Path) -> None:
    """--config must be repeated, not passed as one space-joined string."""
    fake_bin = tmp_path / "bin"
    record = tmp_path / "argv.txt"
    _fake_semgrep(fake_bin, record)

    audit_root = tmp_path / "mini-audit"
    # Hardening v1.1 §8: scanning is gated by the sandbox policy, so the probe
    # must exist (and pass) before any scanner runs.
    _write_permissive_probe(audit_root)

    env = _fake_env(fake_bin)
    result = _bash(
        SCRIPTS / "run-semgrep.sh",
        "--repo-root", str(tmp_path / "repo"),
        "--output", str(tmp_path / "out.sarif"),
        "--audit-root", str(audit_root),
        cwd=tmp_path, env=env,
    )
    assert result.returncode == 0, result.stderr + result.stdout

    argv = record.read_text(encoding="utf-8").splitlines()
    config_indices = [i for i, a in enumerate(argv) if a == "--config"]
    assert len(config_indices) == 2, f"expected two --config flags, got {argv}"
    configs = [argv[i + 1] for i in config_indices]
    assert configs == ["p/security-audit", "p/owasp-top-ten"]
    assert not any(" " in c for c in configs), "a config must never contain a space"


def test_run_semgrep_does_not_pass_error_flag(tmp_path: Path) -> None:
    """Regression: `--error` made a *productive* scan look like a failure.

    Semgrep's `--error` exits non-zero as soon as it finds anything. Because the
    wrapper runs under `set -e`, the one run that actually mattered — the one
    that found bugs — aborted before confirming its SARIF, and the caller saw a
    non-zero exit. Findings are the SARIF's job; the exit code reports scan
    health. Guard the cause, not just the symptom.
    """
    fake_bin = tmp_path / "bin"
    record = tmp_path / "argv.txt"
    _fake_semgrep(fake_bin, record)
    audit_root = tmp_path / "mini-audit"
    _write_permissive_probe(audit_root)

    result = _bash(
        SCRIPTS / "run-semgrep.sh",
        "--repo-root", str(tmp_path / "repo"),
        "--audit-root", str(audit_root),
        cwd=tmp_path, env=_fake_env(fake_bin),
    )
    assert result.returncode == 0, result.stderr + result.stdout
    argv = record.read_text(encoding="utf-8").splitlines()
    assert "--error" not in argv, "`--error` turns findings into a non-zero exit"


def test_run_semgrep_default_output_respects_audit_root(tmp_path: Path) -> None:
    """Regression: the default output path ignored --audit-root.

    run-semgrep.sh hardcoded `mini-audit/scanner/semgrep.sarif` while
    detect-tools.sh and run-codeql.sh both derived theirs from $AUDIT_ROOT. With
    a custom audit root the SARIF landed in a stray directory (or worse, inside
    the target repo) and the gate that expects <AUDIT_ROOT>/scanner/... failed.
    """
    fake_bin = tmp_path / "bin"
    record = tmp_path / "argv.txt"
    _fake_semgrep(fake_bin, record)
    audit_root = tmp_path / "custom-audit"
    _write_permissive_probe(audit_root)

    result = _bash(
        SCRIPTS / "run-semgrep.sh",
        "--repo-root", str(tmp_path / "repo"),
        "--audit-root", str(audit_root),
        cwd=tmp_path, env=_fake_env(fake_bin),
    )
    assert result.returncode == 0, result.stderr + result.stdout

    expected = audit_root / "scanner" / "semgrep.sarif"
    assert expected.exists(), f"SARIF must be written under the audit root; tree={list(tmp_path.rglob('*.sarif'))}"
    assert str(expected) in result.stderr, "the script must report the real output path"
    assert not (tmp_path / "mini-audit").exists(), "no stray hardcoded audit dir"


def test_run_semgrep_fails_when_no_sarif_is_written(tmp_path: Path) -> None:
    """Exit 0 from the scanner is not enough — the artifact must exist."""
    fake_bin = tmp_path / "bin"
    record = tmp_path / "argv.txt"
    _fake_semgrep(fake_bin, record, write_output=False)
    audit_root = tmp_path / "mini-audit"
    _write_permissive_probe(audit_root)

    result = _bash(
        SCRIPTS / "run-semgrep.sh",
        "--repo-root", str(tmp_path / "repo"),
        "--audit-root", str(audit_root),
        cwd=tmp_path, env=_fake_env(fake_bin),
    )
    assert result.returncode == 1, result.stdout + result.stderr
    assert "no SARIF" in result.stderr


def test_run_semgrep_reports_scanner_error(tmp_path: Path) -> None:
    """A genuinely broken scanner exits 1, and the real code stays retrievable."""
    fake_bin = tmp_path / "bin"
    record = tmp_path / "argv.txt"
    _fake_semgrep(fake_bin, record, exit_code=7)
    audit_root = tmp_path / "mini-audit"
    _write_permissive_probe(audit_root)

    result = _bash(
        SCRIPTS / "run-semgrep.sh",
        "--repo-root", str(tmp_path / "repo"),
        "--audit-root", str(audit_root),
        cwd=tmp_path, env=_fake_env(fake_bin),
    )
    assert result.returncode == 1, result.stdout + result.stderr
    assert "usable SARIF" in result.stderr

    # sandbox-run.sh flattens any run failure to 1, so the scanner's own exit
    # code must survive in the machine-readable report rather than be lost.
    report = json.loads(result.stdout)
    assert report["sandbox"]["execution_status"] == "allowed"
    assert report["outcome"]["returncode"] == 7


def test_run_semgrep_consumes_findings_from_sarif(tmp_path: Path) -> None:
    """A scan with findings is a *success*, and the runtime can read the SARIF."""
    fake_bin = tmp_path / "bin"
    record = tmp_path / "argv.txt"
    sarif_doc = {
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "semgrep"}},
            "results": [{
                "ruleId": "python.lang.security.audit.subprocess-shell-true",
                "message": {"text": "shell=True"},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": "app.py"},
                        "region": {"startLine": 5},
                    }
                }],
            }],
        }],
    }
    _fake_semgrep(fake_bin, record, payload=sarif_doc)
    audit_root = tmp_path / "mini-audit"
    _write_permissive_probe(audit_root)

    result = _bash(
        SCRIPTS / "run-semgrep.sh",
        "--repo-root", str(tmp_path / "repo"),
        "--audit-root", str(audit_root),
        cwd=tmp_path, env=_fake_env(fake_bin),
    )
    assert result.returncode == 0, result.stderr + result.stdout

    sys.path.insert(0, str(SKILL_ROOT))
    from runtime import sarif as sarif_mod

    cands = sarif_mod.normalize_sarif_file(audit_root / "scanner" / "semgrep.sarif")
    assert len(cands) == 1, "the productive path must still yield a candidate"
    assert cands[0]["rule_id"] == "python.lang.security.audit.subprocess-shell-true"


def test_run_semgrep_is_blocked_without_a_probe(tmp_path: Path) -> None:
    """Fail-closed: no probe means we do not know the capabilities, so no run."""
    fake_bin = tmp_path / "bin"
    record = tmp_path / "argv.txt"
    _fake_semgrep(fake_bin, record)
    env = _fake_env(fake_bin)
    result = _bash(
        SCRIPTS / "run-semgrep.sh",
        "--repo-root", str(tmp_path / "repo"),
        "--audit-root", str(tmp_path / "mini-audit"),
        cwd=tmp_path, env=env,
    )
    assert result.returncode == 4, result.stdout + result.stderr
    assert not record.exists(), "semgrep must not have been invoked"


def test_run_semgrep_custom_configs(tmp_path: Path) -> None:
    fake_bin = tmp_path / "bin"
    record = tmp_path / "argv.txt"
    _fake_semgrep(fake_bin, record)
    audit_root = tmp_path / "mini-audit"
    _write_permissive_probe(audit_root)
    env = _fake_env(fake_bin)
    _bash(SCRIPTS / "run-semgrep.sh", "--repo-root", str(tmp_path), "--config", "p/ci",
          "--config", "p/secrets", "--config", "p/trailofbits",
          "--audit-root", str(audit_root), cwd=tmp_path, env=env)
    argv = record.read_text(encoding="utf-8").splitlines()
    configs = [argv[i + 1] for i, a in enumerate(argv) if a == "--config"]
    assert configs == ["p/ci", "p/secrets", "p/trailofbits"]


def test_run_semgrep_rerun_after_sandbox_check(tmp_path: Path) -> None:
    """The documented workflow: sandbox-check first, then the scanner runs."""
    fake_bin = tmp_path / "bin"
    record = tmp_path / "argv.txt"
    _fake_semgrep(fake_bin, record)
    audit_root = tmp_path / "mini-audit"

    _bash(SCRIPTS / "sandbox-check.sh", "--audit-root", str(audit_root), cwd=tmp_path)
    env = _fake_env(fake_bin)
    result = _bash(SCRIPTS / "run-semgrep.sh", "--repo-root", str(tmp_path),
                   "--audit-root", str(audit_root), cwd=tmp_path, env=env)
    assert result.returncode == 0, result.stdout + result.stderr
    assert record.exists()
    assert (audit_root / "scanner" / "semgrep.sarif").exists()


def test_run_semgrep_requires_repo_root(tmp_path: Path) -> None:
    result = _bash(SCRIPTS / "run-semgrep.sh", cwd=tmp_path)
    assert result.returncode == 2
    assert "--repo-root is required" in result.stderr


def test_run_codeql_blocks_when_sandbox_unavailable(tmp_path: Path) -> None:
    """No sandbox capability → CodeQL must not run, and must not fall back."""
    env = {
        "PATH": "/usr/bin:/bin",   # keep codeql off PATH entirely
        "MINI_AUDIT_SANDBOX": "",
        "MINI_AUDIT_NO_NET": "",
        "MINI_AUDIT_SANITIZED": "",
    }
    result = _bash(
        SCRIPTS / "run-codeql.sh",
        "--repo-root", str(tmp_path / "repo"),
        "--language", "python",
        "--audit-root", str(tmp_path / "mini-audit"),
        cwd=tmp_path, env=env,
    )
    assert result.returncode == 4, result.stdout + result.stderr
    marker = tmp_path / "mini-audit" / "scanner" / "codeql-blocked.json"
    assert marker.exists()
    payload = json.loads(marker.read_text(encoding="utf-8"))
    assert payload["execution_status"] == "blocked"
    assert payload["verdict"] == "needs_validation"
    assert payload["host_fallback"] is False


def test_run_codeql_requires_repo_root_and_language(tmp_path: Path) -> None:
    assert _bash(SCRIPTS / "run-codeql.sh", "--repo-root", str(tmp_path), cwd=tmp_path).returncode == 2


def test_run_codeql_writes_sarif_and_confirms_it(tmp_path: Path) -> None:
    """The SARIF must land under the audit root and be confirmed present."""
    fake_bin = tmp_path / "bin"
    record = tmp_path / "argv.txt"
    _fake_codeql(fake_bin, record)
    audit_root = tmp_path / "custom-audit"
    _write_permissive_probe(audit_root)

    result = _bash(
        SCRIPTS / "run-codeql.sh",
        "--repo-root", str(tmp_path / "repo"),
        "--language", "python",
        "--audit-root", str(audit_root),
        cwd=tmp_path, env=_fake_env(fake_bin),
    )
    assert result.returncode == 0, result.stdout + result.stderr

    expected = audit_root / "scanner" / "codeql.sarif"
    assert expected.exists(), f"no SARIF at {expected}"
    assert str(expected) in result.stderr

    # stdout must be exactly ONE JSON document. It used to be three
    # concatenated reports, which makes `json.load(stdout)` raise "Extra data".
    _dec = json.JSONDecoder()
    doc, end = _dec.raw_decode(result.stdout.lstrip())
    assert not result.stdout.lstrip()[end:].strip(), "stdout must hold a single JSON document"
    assert doc["scanner"] == "codeql"
    assert doc["execution_status"] == "allowed"
    assert doc["host_fallback"] is False
    assert [s.get("command") for s in doc["steps"]] == ["sandbox.check", "sandbox.run", "sandbox.run"]


def test_run_codeql_reports_failure_instead_of_dying_mute(tmp_path: Path) -> None:
    """Regression: under `set -e` a failed analyze died with no explanation."""
    fake_bin = tmp_path / "bin"
    record = tmp_path / "argv.txt"
    _fake_codeql(fake_bin, record, analyze_exit=9)
    audit_root = tmp_path / "mini-audit"
    _write_permissive_probe(audit_root)

    result = _bash(
        SCRIPTS / "run-codeql.sh",
        "--repo-root", str(tmp_path / "repo"),
        "--language", "python",
        "--audit-root", str(audit_root),
        cwd=tmp_path, env=_fake_env(fake_bin),
    )
    assert result.returncode == 1, result.stdout + result.stderr
    assert "usable SARIF" in result.stderr, "the failure must be explained, not mute"


def test_run_codeql_fails_when_sarif_missing(tmp_path: Path) -> None:
    """Exit 0 from the scanner is not enough — the artifact must exist."""
    fake_bin = tmp_path / "bin"
    record = tmp_path / "argv.txt"
    _fake_codeql(fake_bin, record, write_output=False)
    audit_root = tmp_path / "mini-audit"
    _write_permissive_probe(audit_root)

    result = _bash(
        SCRIPTS / "run-codeql.sh",
        "--repo-root", str(tmp_path / "repo"),
        "--language", "python",
        "--audit-root", str(audit_root),
        cwd=tmp_path, env=_fake_env(fake_bin),
    )
    assert result.returncode == 1, result.stdout + result.stderr
    assert "no SARIF" in result.stderr


def test_run_codeql_help(tmp_path: Path) -> None:
    assert _bash(SCRIPTS / "run-codeql.sh", "--help", cwd=tmp_path).returncode == 0


# ---------------------------------------------------------------------------
# sandbox-run.sh
# ---------------------------------------------------------------------------


def test_sandbox_run_describe(tmp_path: Path) -> None:
    result = _bash(SCRIPTS / "sandbox-run.sh", "--kind", "source-scan",
                   "--audit-root", str(tmp_path / "mini-audit"), "--describe", cwd=tmp_path)
    # With no probe present the decision is "blocked"; either way it is JSON.
    payload = json.loads(result.stdout)
    assert payload["kind"] == "source-scan"
    assert payload["host_fallback"] is False


def test_sandbox_run_uses_runtime_decision(tmp_path: Path) -> None:
    """With no probe.json, nothing executes and the exit code is 4."""
    sentinel = tmp_path / "ran.txt"
    result = _bash(SCRIPTS / "sandbox-run.sh", "--kind", "poc",
                   "--audit-root", str(tmp_path / "mini-audit"),
                   "--", "bash", "-c", f"echo ran > {sentinel}",
                   cwd=tmp_path)
    assert result.returncode == 4, result.stdout + result.stderr
    assert not sentinel.exists(), "blocked command must not have run"


def test_sandbox_run_executes_when_policy_allows(tmp_path: Path) -> None:
    import runtime.sandbox as rt_sandbox  # noqa: F401  (path sanity)

    audit_root = tmp_path / "mini-audit"
    (audit_root / "sandbox").mkdir(parents=True)
    (audit_root / "sandbox" / "probe.json").write_text(json.dumps({
        "schema_version": 1,
        "checks": {
            "sandbox_available": True,
            "external_network_disabled": True,
            "safe_writable_scratch": True,
            "timeout_available": False,
            "resource_limit_available": True,
            "environment_sanitized": True,
        },
    }), encoding="utf-8")
    sentinel = tmp_path / "ran.txt"
    result = _bash(SCRIPTS / "sandbox-run.sh", "--kind", "poc",
                   "--audit-root", str(audit_root), "--timeout", "20",
                   "--", "bash", "-c", f"echo ran > {sentinel}",
                   cwd=tmp_path)
    assert result.returncode == 0, result.stdout + result.stderr
    assert sentinel.exists()


def test_sandbox_run_without_command_is_usage_error(tmp_path: Path) -> None:
    result = _bash(SCRIPTS / "sandbox-run.sh", "--kind", "poc",
                   "--audit-root", str(tmp_path / "mini-audit"), cwd=tmp_path)
    assert result.returncode == 2
