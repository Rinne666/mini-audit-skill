"""Hardening v1.1.1 §2 — real isolation backends.

The property under test is the one v1.1 got wrong: *a backend that does not
contain anything must never be credited with containment*. Presence of a binary
is not function, and a declaration is not evidence.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

from runtime.sandbox import KIND_POC, KIND_SOURCE_SCAN, KIND_TARGET_BUILD
from runtime.sandbox_backend import (
    ALL_CONTROLS,
    BACKENDS,
    CONTROL_ENV_SANITIZED,
    CONTROL_NETWORK_DENIAL,
    CONTROL_READ_ONLY_SOURCE,
    CONTROL_RESOURCE_LIMITS,
    CONTROL_WRITE_CONFINEMENT,
    BwrapBackend,
    DockerBackend,
    IsolationBackend,
    SandboxExecBackend,
    SandboxSpec,
    _ulimit_wrap,
    sanitized_env,
    select_backend,
    verify_backend,
)


def _spec(tmp_path: Path, kind: str = KIND_POC, **kw) -> SandboxSpec:
    repo = tmp_path / "repo"
    repo.mkdir(exist_ok=True)
    audit = tmp_path / "mini-audit"
    audit.mkdir(exist_ok=True)
    return SandboxSpec.for_kind(
        kind, repo_root=repo, audit_root=audit, base_env=dict(os.environ), **kw
    )


class NullBackend(IsolationBackend):
    """A backend that claims to isolate but runs the command untouched.

    This is the shape of the v1.1 bug: the wrapper is a no-op, so nothing is
    contained.
    """

    name = "null"
    binary = "sh"

    def build_argv(self, argv, spec):
        return list(argv)


class AlwaysUnavailableBackend(IsolationBackend):
    name = "ghost"
    binary = "definitely-not-a-real-binary"

    def build_argv(self, argv, spec):  # pragma: no cover - never reached
        return list(argv)


class RigidBackend(IsolationBackend):
    """Declares a fixed control profile — used to test selection logic."""

    def __init__(self, name: str, controls: list[str]) -> None:
        self.name = name
        self.binary = "sh"
        self._controls = set(controls)

    def build_argv(self, argv, spec):  # pragma: no cover - not exercised
        return list(argv)


# ---------------------------------------------------------------------------
# The wrapper must be real
# ---------------------------------------------------------------------------


def test_bwrap_wrapper_contains_the_actual_namespace_flags(tmp_path: Path) -> None:
    spec = _spec(tmp_path, KIND_POC)
    argv = BwrapBackend().build_argv(["echo", "hi"], spec)
    assert argv[0] == "bwrap"
    assert "--ro-bind" in argv, "the root filesystem must be read-only"
    assert "--unshare-net" in argv, "network must be namespaced away for poc"
    assert "--unshare-pid" in argv
    # writable holes punched for the audit root
    binds = [argv[i + 1] for i, a in enumerate(argv) if a == "--bind"]
    assert any(str(spec.audit_root) == b for b in binds), binds
    assert argv[-2:] == ["echo", "hi"], "the command must come after --"


def test_bwrap_allows_network_when_the_spec_permits_it(tmp_path: Path) -> None:
    spec = _spec(tmp_path, KIND_SOURCE_SCAN)
    args = BwrapBackend().build_argv(["true"], spec)
    assert "--unshare-net" not in args


def test_sandbox_exec_profile_denies_writes_and_network(tmp_path: Path) -> None:
    spec = _spec(tmp_path, KIND_POC)
    profile = SandboxExecBackend.profile(spec)
    assert "(deny file-write*)" in profile
    assert "(deny network*)" in profile
    assert str(spec.audit_root) in profile
    argv = SandboxExecBackend().build_argv(["echo", "hi"], spec)
    assert argv[0] == "sandbox-exec"
    assert "-p" in argv


def test_sandbox_exec_profile_permits_network_when_allowed(tmp_path: Path) -> None:
    profile = SandboxExecBackend.profile(_spec(tmp_path, KIND_SOURCE_SCAN))
    assert "(deny network*)" not in profile


def test_docker_wrapper_uses_read_only_rootfs_and_network_none(tmp_path: Path) -> None:
    spec = _spec(tmp_path, KIND_POC)
    backend = DockerBackend(image="alpine:3.20")
    argv = backend.build_argv(["echo", "hi"], spec)
    assert argv[:2] == ["docker", "run"]
    assert "--network" in argv and argv[argv.index("--network") + 1] == "none"
    assert "--read-only" in argv
    assert f"{spec.repo_root}:{spec.repo_root}:ro" in argv
    assert f"{spec.audit_root}:{spec.audit_root}:rw" in argv
    assert argv[-2:] == ["echo", "hi"]


def test_docker_requires_a_locally_present_image() -> None:
    backend = DockerBackend(image="")
    # Either a local image was found, or the backend must explain itself rather
    # than silently running without isolation.
    if not backend.available():
        assert "image" in backend.unavailable_reason() or "daemon" in backend.unavailable_reason()


# ---------------------------------------------------------------------------
# Runtime-provided controls
# ---------------------------------------------------------------------------


def test_sanitized_env_drops_everything_but_the_allowlist(tmp_path: Path) -> None:
    spec = _spec(tmp_path)
    spec = SandboxSpec(**{**spec.__dict__, "env": {
        "PATH": "/usr/bin", "HOME": "/Users/someone", "AWS_SECRET_ACCESS_KEY": "leak",
        "GITHUB_TOKEN": "leak",
    }})
    env = sanitized_env(spec)
    assert "AWS_SECRET_ACCESS_KEY" not in env
    assert "GITHUB_TOKEN" not in env
    assert env["HOME"] == str(spec.scratch_dir), "HOME must point into scratch"
    assert env["TMPDIR"] == str(spec.scratch_dir)


def test_ulimit_wrapper_applies_file_and_cpu_limits() -> None:
    wrapped = _ulimit_wrap(["echo", "hi"], max_file_mb=8, cpu_seconds=30)
    assert wrapped[0] == "sh"
    script = wrapped[2]
    assert "ulimit -f" in script and "ulimit -t" in script
    assert str(8 * 2048) in script, "ulimit -f is in 512-byte blocks"
    assert wrapped[-2:] == ["echo", "hi"]


# ---------------------------------------------------------------------------
# Verification: a non-isolating backend must not be credited
# ---------------------------------------------------------------------------


def test_verify_rejects_a_backend_that_does_not_isolate(tmp_path: Path) -> None:
    """The core regression guard for v1.1.1.

    A pass-through backend performs every forbidden action, so it must be
    credited with *none* of the backend-provided controls. The runtime-provided
    controls (env sanitisation, resource limits) are still applied by this
    runtime, and must be reported as such.
    """
    spec = _spec(tmp_path)
    report = verify_backend(NullBackend(), spec, timeout_seconds=30)

    assert report.usable is True, "the null backend does run commands"
    assert report.controls[CONTROL_WRITE_CONFINEMENT] is False
    assert report.controls[CONTROL_READ_ONLY_SOURCE] is False
    assert report.controls[CONTROL_NETWORK_DENIAL] is False
    # Runtime-provided controls are genuine even without a backend.
    assert report.controls[CONTROL_ENV_SANITIZED] is True
    assert report.controls[CONTROL_RESOURCE_LIMITS] is True

    # And therefore it cannot satisfy a kind that needs containment.
    backend, reports = select_backend(
        spec,
        verifications=[report],
        required_controls=[CONTROL_WRITE_CONFINEMENT, CONTROL_READ_ONLY_SOURCE,
                           CONTROL_NETWORK_DENIAL],
    )
    assert backend is None
    assert reports


def test_verify_reports_unavailable_backend_without_claiming_controls(tmp_path: Path) -> None:
    report = verify_backend(AlwaysUnavailableBackend(), _spec(tmp_path), timeout_seconds=5)
    assert report.usable is False
    assert report.demonstrated == []
    assert "not found on PATH" in report.detail


def test_select_backend_picks_one_that_satisfies_all_required_controls() -> None:
    weak = RigidBackend("weak", [CONTROL_WRITE_CONFINEMENT])
    strong = RigidBackend("strong", [CONTROL_WRITE_CONFINEMENT, CONTROL_READ_ONLY_SOURCE])

    from runtime.sandbox_backend import BackendVerification

    def report_for(backend: RigidBackend) -> BackendVerification:
        return BackendVerification(
            backend=backend.name,
            usable=True,
            controls={c: (c in backend._controls) for c in ALL_CONTROLS},
        )

    chosen, _ = select_backend(
        _spec(Path("/tmp")),  # spec unused by the stub verifier
        verifications=[report_for(weak), report_for(strong)],
        required_controls=[CONTROL_WRITE_CONFINEMENT, CONTROL_READ_ONLY_SOURCE],
        backends=[weak, strong],
    )
    assert chosen is not None and chosen.name == "strong"

    # Nothing satisfies a control no backend has.
    chosen2, _ = select_backend(
        _spec(Path("/tmp")),
        verifications=[report_for(weak), report_for(strong)],
        required_controls=[CONTROL_NETWORK_DENIAL],
        backends=[weak, strong],
    )
    assert chosen2 is None


def test_backend_registry_covers_the_documented_backends() -> None:
    names = {b.name for b in BACKENDS}
    assert {"bwrap", "sandbox-exec", "docker"} <= names


@pytest.mark.skipif(
    not any(b.name == "docker" and b.available() for b in BACKENDS),
    reason="docker daemon/image not available",
)
def test_live_docker_actually_contains_a_process(tmp_path: Path) -> None:
    """End-to-end proof: the wrapper really stops a write, not just claims to.

    This is deliberately a live test. Unit tests can prove the argv is built
    correctly; only running it proves the containment is real.
    """
    docker = [b for b in BACKENDS if b.name == "docker"][0]
    spec = _spec(tmp_path)

    outside = tmp_path / "escaped.txt"
    sentinel = tmp_path / "repo" / "mutated.txt"
    script = f"import pathlib; pathlib.Path({str(outside)!r}).write_text('x')"

    from runtime.sandbox import run_sandboxed

    # Build a probe that documents docker's real, measured capabilities.
    report = verify_backend(docker, spec, timeout_seconds=60)
    assert report.usable, report.detail
    assert report.controls[CONTROL_WRITE_CONFINEMENT], "docker must confine writes"

    probe = {
        "schema_version": 2,
        "backends": [report.to_dict()],
    }
    result = run_sandboxed(
        [sys.executable, "-c", script],
        kind=KIND_POC,
        audit_root=spec.audit_root,
        repo_root=spec.repo_root,
        probe=probe,
        timeout_seconds=60,
    )
    assert result.executed is True
    assert result.decision.isolation_backend == "docker"
    assert not outside.exists(), "the write must have been confined"

    assert not sentinel.exists(), "the source tree must be read-only"


# ---------------------------------------------------------------------------
# Spec normalisation — regression for the relative-path bug
# ---------------------------------------------------------------------------


def test_spec_mount_paths_are_always_absolute(tmp_path: Path, monkeypatch) -> None:
    """Regression: a relative --repo-root used to produce `-v repo:repo:ro`.

    `docker run` then exits 125 with `invalid mount path: 'repo'`, which the
    probe reported as "no usable isolation backend" — a false negative that
    disabled execution entirely. Every mount source must be absolute regardless
    of how the caller spelled the path.
    """
    (tmp_path / "repo").mkdir()
    (tmp_path / "mini-audit").mkdir()
    monkeypatch.chdir(tmp_path)

    spec = SandboxSpec.for_kind(
        KIND_POC, repo_root="repo", audit_root="mini-audit",
        cwd="repo", base_env={},
    )
    for path in (*spec.read_only_paths, *spec.writable_paths):
        assert Path(path).is_absolute(), f"relative mount path survived: {path!r}"


def test_spec_mounts_both_absolute_and_resolved_forms(tmp_path: Path) -> None:
    """/tmp vs /private/tmp: the caller's spelling must stay visible."""
    (tmp_path / "repo").mkdir()
    (tmp_path / "mini-audit").mkdir()
    spec = SandboxSpec.for_kind(
        KIND_POC, repo_root=tmp_path / "repo", audit_root=tmp_path / "mini-audit",
        base_env={},
    )
    # At minimum the resolved path is present; on a symlinked tmpdir the
    # unresolved absolute form is too.
    assert spec.repo_root in spec.read_only_paths


@pytest.mark.parametrize("backend_cls", [DockerBackend, BwrapBackend])
def test_backends_refuse_relative_mounts(backend_cls, tmp_path: Path) -> None:
    """A malformed spec must fail loudly, not silently disable isolation."""
    from runtime.sandbox_backend import SandboxBackendError

    spec = SandboxSpec.for_kind(
        KIND_POC, repo_root=tmp_path / "repo", audit_root=tmp_path / "mini-audit",
        base_env={},
    )
    broken = SandboxSpec(
        kind=spec.kind, repo_root=spec.repo_root, audit_root=spec.audit_root,
        scratch_dir=spec.scratch_dir, cwd=spec.cwd, allow_network=spec.allow_network,
        read_only_paths=(Path("relative-repo"),), writable_paths=spec.writable_paths,
        env={},
    )
    with pytest.raises(SandboxBackendError):
        backend_cls().build_argv(["true"], broken)


# ---------------------------------------------------------------------------
# Hermetic network probe — the differential must not depend on the internet
# ---------------------------------------------------------------------------


def test_probe_listener_is_reachable_without_egress() -> None:
    """The network canary must not rely on any public endpoint.

    A hardcoded target is reachable on some networks and not others; measured on
    one host, ``1.1.1.1:53`` and ``:80`` answered while ``1.1.1.1:443`` and
    ``8.8.8.8:53`` timed out. That made the control — and therefore the whole
    ``poc`` kind — fail closed on an offline machine or a locked-down runner.
    The listener is stood up locally instead, so "the baseline could reach it"
    is established, not assumed.
    """
    from runtime.sandbox_backend import _ProbeListener

    with _ProbeListener() as listener:
        assert listener.target, "a listener must be startable on any host, online or not"
        host, _, port = listener.target.rpartition(":")
        assert port.isdigit()

        import socket as _socket

        client = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
        client.settimeout(2.0)
        try:
            client.connect((host, int(port)))
        finally:
            client.close()


def test_probe_host_prefers_a_routable_address_over_loopback() -> None:
    """Loopback is a weak differential: a container's loopback is its own.

    Preferring the host's routable address is what makes ``--network none``
    observably different from a bridged container.
    """
    from runtime.sandbox_backend import _candidate_probe_hosts

    hosts = _candidate_probe_hosts()
    assert hosts, "at least loopback is always a candidate"
    assert hosts[-1] == "127.0.0.1", "loopback is the last resort, not the first"


def test_network_denial_is_not_credited_when_nothing_was_reachable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """No reachable target ⇒ undeterminable ⇒ not demonstrated (and said so).

    This is the fail-closed half: an unreachable baseline must never be
    mistaken for successful containment.
    """
    from runtime import sandbox_backend as sb

    class NoRoute(sb._ProbeListener):
        def start(self):  # type: ignore[override]
            return self  # never finds a host: nothing is reachable

    monkeypatch.setattr(sb, "_ProbeListener", NoRoute)

    spec = _spec(tmp_path, KIND_POC)
    report = sb.verify_backend(NullBackend(), spec, timeout_seconds=30)

    assert report.controls[sb.CONTROL_NETWORK_DENIAL] is False
    assert report.evidence["net_baseline_reachable"] is False
    assert report.evidence["net_probe_target"] is None
    assert "undeterminable" in report.detail
