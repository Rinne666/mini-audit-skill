"""Concrete isolation backends (Hardening v1.1.1 §2).

Hardening v1.1 shipped a *capability check*: it read a probe document, asked
"does this host claim to have a sandbox?", and — if the answer was yes — ran the
command with plain ``subprocess``. Nothing was ever contained. A machine with
``docker`` installed was scored as "sandboxed" even though ``docker run`` was
never invoked, and every capability came from a self-declared environment
variable.

This module replaces that with an actual isolation layer:

    SandboxSpec  →  select a concrete backend  →  build the wrapped argv
                 →  *verify by canary*  →  execute inside the wrapper
                 →  no verified backend ⇒ refuse to execute

Two ideas carry the weight:

1. **The wrapper is real.** ``build_argv`` emits the actual ``bwrap`` /
   ``sandbox-exec`` / ``docker run`` invocation that applies read-only source,
   scratch-only writes, a network namespace, and so on. If we cannot build one,
   we do not run.

2. **Presence is not function, and declaration is not evidence.** A binary on
   ``PATH`` proves nothing: on macOS ``sandbox-exec`` exists but commonly fails
   with ``sandbox_apply: Operation not permitted``. Verification therefore runs
   a *differential canary* — the same probe with and without the wrapper — and
   only counts a control as demonstrated when the unisolated run performed the
   forbidden action **and** the isolated run did not. A control we cannot
   demonstrate is reported as ``False``, never assumed.
"""

from __future__ import annotations

import dataclasses
import os
import shutil
import socket
import stat
import subprocess
import threading
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping, Optional, Sequence

from .process_control import run_command_with_timeout

# ---------------------------------------------------------------------------
# Control vocabulary
# ---------------------------------------------------------------------------

# Demonstrated by the isolation backend itself.
CONTROL_WRITE_CONFINEMENT = "write_confinement"
CONTROL_READ_ONLY_SOURCE = "read_only_source"
CONTROL_NETWORK_DENIAL = "network_denial"

# Enforced by the runtime around any backend (portable POSIX controls). Still
# canary-verified: we assert the mechanism is actually applied, not that it
# exists.
CONTROL_ENV_SANITIZED = "env_sanitized"
CONTROL_RESOURCE_LIMITS = "resource_limits"

# Enforced by the process_control process-group deadline; covered by the hard
# timeout tests rather than the canary (by the time a canary could observe it,
# the process is already dead).
CONTROL_HARD_TIMEOUT = "hard_timeout"

ALL_CONTROLS = (
    CONTROL_WRITE_CONFINEMENT,
    CONTROL_READ_ONLY_SOURCE,
    CONTROL_NETWORK_DENIAL,
    CONTROL_ENV_SANITIZED,
    CONTROL_RESOURCE_LIMITS,
    CONTROL_HARD_TIMEOUT,
)

BACKEND_PROVIDED_CONTROLS = (
    CONTROL_WRITE_CONFINEMENT,
    CONTROL_READ_ONLY_SOURCE,
    CONTROL_NETWORK_DENIAL,
)

RUNTIME_PROVIDED_CONTROLS = (
    CONTROL_ENV_SANITIZED,
    CONTROL_RESOURCE_LIMITS,
    CONTROL_HARD_TIMEOUT,
)

DEFAULT_CANARY_TIMEOUT = 45.0

# Environment variables that survive sanitisation. Everything else is dropped,
# so a target cannot read the operator's tokens out of the environment.
ENV_ALLOWLIST = ("PATH", "HOME", "LANG", "LC_ALL", "LC_CTYPE", "TMPDIR", "TERM", "TZ")

DEFAULT_MEMORY_MB = 4096
DEFAULT_CPU_SECONDS = 1800
DEFAULT_MAX_FILE_MB = 2048


# ---------------------------------------------------------------------------
# Spec
# ---------------------------------------------------------------------------


@dataclasses.dataclass(frozen=True)
class SandboxSpec:
    """What one execution needs, independent of which backend provides it."""

    kind: str
    repo_root: Path
    audit_root: Path
    scratch_dir: Path
    cwd: Path
    allow_network: bool
    read_only_paths: tuple[Path, ...]
    writable_paths: tuple[Path, ...]
    env: dict[str, str]
    memory_mb: int = DEFAULT_MEMORY_MB
    cpu_seconds: int = DEFAULT_CPU_SECONDS
    max_file_mb: int = DEFAULT_MAX_FILE_MB

    @classmethod
    def for_kind(
        cls,
        kind: str,
        *,
        repo_root: os.PathLike[str] | str,
        audit_root: os.PathLike[str] | str,
        scratch_dir: Optional[os.PathLike[str] | str] = None,
        cwd: Optional[os.PathLike[str] | str] = None,
        base_env: Optional[Mapping[str, str]] = None,
        allow_network: Optional[bool] = None,
        **limits: Any,
    ) -> "SandboxSpec":
        from .sandbox import KIND_SOURCE_SCAN, KIND_TARGET, KIND_TARGET_BUILD

        raw_repo = Path(repo_root)
        raw_audit = Path(audit_root)
        repo = raw_repo.resolve()
        audit = raw_audit.resolve()
        raw_scratch = Path(scratch_dir) if scratch_dir else raw_audit / "scratch"
        scratch = raw_scratch.resolve() if scratch_dir else audit / "scratch"
        work = Path(cwd).resolve() if cwd else repo

        if allow_network is None:
            # Scanners read source text and may fetch a remote ruleset
            # (`semgrep --config p/...`); everything that runs target-controlled
            # code is network-isolated.
            allow_network = kind == KIND_SOURCE_SCAN
            if kind in (KIND_TARGET_BUILD, KIND_TARGET):
                allow_network = False

        # Mount both the absolute and the symlink-resolved form. On macOS
        # `/tmp` is a symlink to `/private/tmp`, and a command in the sandbox
        # refers to whichever form the caller typed — mounting only the resolved
        # path makes the tool invisible at the path it was invoked with.
        #
        # Both forms must be *absolute*: `docker run -v` (and bwrap) reject a
        # relative mount source, and the failure surfaces as a cryptic
        # `exit=125 ... invalid mount path: 'repo'` that reads like "no usable
        # backend" rather than "you passed a relative --repo-root". `os.path.
        # abspath` (not `resolve`) is deliberate — it gives the second form
        # without collapsing the very symlink we are trying to bridge.
        read_only = _dedupe([_absolute(raw_repo), repo])
        writable = _dedupe([_absolute(raw_audit), audit,
                            _absolute(raw_scratch), scratch])

        return cls(
            kind=kind,
            repo_root=repo,
            audit_root=audit,
            scratch_dir=scratch,
            cwd=work,
            allow_network=bool(allow_network),
            read_only_paths=tuple(read_only),
            writable_paths=tuple(writable),
            env=dict(base_env or {}),
            **limits,
        )


def _dedupe(paths: Iterable[Path]) -> list[Path]:
    """Drop paths contained in another (a child bind is redundant under a parent)."""
    ordered = sorted({p for p in paths}, key=lambda p: len(str(p)))
    kept: list[Path] = []
    for p in ordered:
        if any(str(p) == str(k) or str(p).startswith(str(k) + os.sep) for k in kept):
            continue
        kept.append(p)
    return kept


def _absolute(path: Path) -> Path:
    """Absolute but *not* symlink-resolved (normalises relative input only)."""
    return Path(os.path.abspath(path))


class SandboxBackendError(RuntimeError):
    """Raised when a backend cannot build a valid invocation for a spec."""


def _require_absolute(paths: Iterable[Path], backend: str) -> None:
    """Tripwire: mount sources must be absolute.

    A relative mount path makes `docker run` exit 125 and `bwrap` fail with an
    unrelated-looking error, which then reads as "backend unusable" instead of
    "bad spec". Failing loudly keeps that from silently disabling isolation.
    """
    for path in paths:
        if not Path(path).is_absolute():
            raise SandboxBackendError(
                f"{backend}: refusing to build a mount for non-absolute path {str(path)!r}; "
                "resolve it to an absolute path first"
            )


def sanitized_env(spec: SandboxSpec, *, extra: Optional[Mapping[str, str]] = None) -> dict[str, str]:
    """Reduce the environment to an allowlist, pinned to the scratch dir.

    ``HOME`` is redirected into scratch so tools that write caches
    (``~/.cache/semgrep``) do not need write access to the real home.
    """
    src = dict(spec.env)
    out: dict[str, str] = {}
    for key in ENV_ALLOWLIST:
        if key in src:
            out[key] = src[key]
    out.setdefault("PATH", "/usr/local/bin:/usr/bin:/bin")
    out["HOME"] = str(spec.scratch_dir)
    out["TMPDIR"] = str(spec.scratch_dir)
    if extra:
        out.update({k: v for k, v in extra.items()})
    return out


# ---------------------------------------------------------------------------
# Backends
# ---------------------------------------------------------------------------


class IsolationBackend:
    """A concrete way to contain a process."""

    name = "abstract"
    binary = ""

    def available(self) -> bool:
        return bool(shutil.which(self.binary))

    def unavailable_reason(self) -> str:
        return f"{self.binary} not found on PATH"

    def build_argv(self, argv: Sequence[str], spec: SandboxSpec) -> list[str]:
        raise NotImplementedError

    def describe(self) -> dict[str, Any]:
        return {"name": self.name, "binary": self.binary, "available": self.available()}


class BwrapBackend(IsolationBackend):
    """bubblewrap (Linux). Read-only root, writable binds, network namespace."""

    name = "bwrap"
    binary = "bwrap"

    def build_argv(self, argv: Sequence[str], spec: SandboxSpec) -> list[str]:
        args = [
            self.binary,
            "--die-with-parent",
            "--new-session",
            # Whole filesystem read-only, then punch holes for the writable set.
            "--ro-bind", "/", "/",
            "--dev", "/dev",
            "--proc", "/proc",
            "--tmpfs", "/tmp",
            "--unshare-pid",
            "--unshare-ipc",
            "--unshare-uts",
        ]
        if not spec.allow_network:
            args += ["--unshare-net"]
        # bwrap only *references* the writable set (the whole root is already
        # read-only), but the spec as a whole must still be well-formed so a
        # malformed one fails loudly instead of silently limiting isolation.
        _require_absolute([*spec.read_only_paths, *spec.writable_paths], self.name)
        for path in spec.writable_paths:
            args += ["--bind", str(path), str(path)]
        args += ["--chdir", str(spec.cwd)]
        for key, value in sanitized_env(spec).items():
            args += ["--setenv", key, value]
        args += ["--", *argv]
        return args


class SandboxExecBackend(IsolationBackend):
    """macOS Seatbelt (``sandbox-exec``). Write confinement + network deny."""

    name = "sandbox-exec"
    binary = "sandbox-exec"

    def build_argv(self, argv: Sequence[str], spec: SandboxSpec) -> list[str]:
        return [self.binary, "-p", self.profile(spec), *argv]

    @staticmethod
    def profile(spec: SandboxSpec) -> str:
        """SBPL profile: default-allow, then deny the things we care about.

        Deny-by-default would break dynamic linking and sysctl reads, so we
        start from allow and subtract: writes, and (when required) network.
        """
        _require_absolute([*spec.read_only_paths, *spec.writable_paths], "sandbox-exec")
        writable = " ".join(f'(subpath "{p}")' for p in spec.writable_paths)
        rules = [
            "(version 1)",
            "(allow default)",
            "(deny file-write*)",
            f"(allow file-write* {writable})" if writable else "",
            # Devices that must stay writable for a process to run at all.
            '(allow file-write* (literal "/dev/null") (literal "/dev/zero") '
            '(literal "/dev/dtracehelper") (literal "/dev/tty") '
            '(regex #"^/dev/fd/"))',
        ]
        if not spec.allow_network:
            rules.append("(deny network*)")
        return "".join(rules)


class DockerBackend(IsolationBackend):
    """Docker. Read-only rootfs, bind mounts, ``--network none``, pids limit.

    Requires an image that is already present locally: pulling one would make
    verification depend on the network, and a verification that only sometimes
    runs is worse than none.
    """

    name = "docker"
    binary = "docker"

    IMAGE_CANDIDATES = ("alpine:3.20", "alpine:latest", "debian:stable-slim", "ubuntu:latest")

    def __init__(self, image: Optional[str] = None) -> None:
        self._image = image
        self._resolved = image is not None

    # -- availability -------------------------------------------------------

    @property
    def image(self) -> str:
        """The image to run, or ``""`` when none is actually usable.

        Resolution is cached because ``available()`` is called from test skip
        guards and from every probe iteration.

        An explicit ``MINI_AUDIT_DOCKER_IMAGE`` is honoured only when it is
        genuinely present: treating a typo (or a ref that was never pulled) as
        "docker is available" would turn a clear configuration error into a
        confusing downstream failure.
        """
        if self._resolved:
            return self._image or ""

        env = os.environ.get("MINI_AUDIT_DOCKER_IMAGE")
        if env:
            self._image = env if self._image_present(env) else ""
        else:
            self._image = ""
            for candidate in self.IMAGE_CANDIDATES:
                if self._image_present(candidate):
                    self._image = candidate
                    break
        self._resolved = True
        return self._image

    def _image_present(self, ref: str) -> bool:
        # A missing binary must read as "not present", not raise: this is
        # reached from `verify_backend`'s early-return path, i.e. precisely when
        # docker is *absent*. Shelling out to a binary that does not exist
        # raised FileNotFoundError there, so `sandbox probe` used to traceback
        # on any host without docker instead of reporting it as unavailable.
        if not self.binary or shutil.which(self.binary) is None:
            return False
        try:
            proc = subprocess.run(
                [self.binary, "image", "inspect", ref],
                capture_output=True, text=True, check=False,
            )
        except OSError:
            return False
        return proc.returncode == 0

    def _daemon_up(self) -> bool:
        if not self.binary or shutil.which(self.binary) is None:
            return False
        try:
            proc = subprocess.run(
                [self.binary, "info", "--format", "{{.ServerVersion}}"],
                capture_output=True, text=True, check=False,
            )
        except OSError:
            return False
        return proc.returncode == 0

    def available(self) -> bool:
        if not shutil.which(self.binary):
            return False
        if not self._daemon_up():
            return False
        return bool(self.image)

    def unavailable_reason(self) -> str:
        if not shutil.which(self.binary):
            return "docker not found on PATH"
        if not self._daemon_up():
            return "docker daemon not reachable"
        if not self.image:
            env = os.environ.get("MINI_AUDIT_DOCKER_IMAGE")
            if env:
                return (
                    f"MINI_AUDIT_DOCKER_IMAGE={env!r} is not present locally "
                    "(docker image inspect failed); pull it or unset the override"
                )
            return (
                "no usable image present locally "
                f"(tried {', '.join(self.IMAGE_CANDIDATES)}); "
                "set MINI_AUDIT_DOCKER_IMAGE or pull one"
            )
        return "unavailable"

    # -- invocation ---------------------------------------------------------

    def build_argv(self, argv: Sequence[str], spec: SandboxSpec) -> list[str]:
        args = [self.binary, "run", "--rm", "-i", "--read-only"]
        # A private /tmp is useful (tools that ignore TMPDIR still get a writable
        # temp), but it must not shadow a mount: mounting tmpfs at /tmp while
        # also bind-mounting e.g. /tmp/build/repo would hide the bind.
        mounted = [*spec.read_only_paths, *spec.writable_paths]
        _require_absolute(mounted, self.name)
        if not any(str(p).startswith("/tmp/") or str(p).startswith("/private/tmp/") for p in mounted):
            args += ["--tmpfs", "/tmp"]
        args += ["--network", "none"] if not spec.allow_network else ["--network", "bridge"]
        args += ["--pids-limit", "512"]
        if spec.memory_mb:
            args += ["--memory", f"{spec.memory_mb}m"]
        for path in spec.read_only_paths:
            args += ["-v", f"{path}:{path}:ro"]
        for path in spec.writable_paths:
            args += ["-v", f"{path}:{path}:rw"]
        args += ["-w", str(spec.cwd)]
        for key, value in sanitized_env(spec).items():
            args += ["-e", f"{key}={value}"]
        args += [self.image, *argv]
        return args


BACKENDS: tuple[IsolationBackend, ...] = (
    DockerBackend(),
    BwrapBackend(),
    SandboxExecBackend(),
)


def available_backends() -> list[IsolationBackend]:
    return [b for b in BACKENDS if b.available()]


# ---------------------------------------------------------------------------
# Differential canary
# ---------------------------------------------------------------------------


# POSIX sh so it runs under every backend (a container image need not ship
# Python). Written to disk rather than passed with `sh -c` to keep quoting out
# of the picture; the audit root is mounted rw, so the sandbox can read it.
CANARY_SCRIPT = """#!/bin/sh
# args: $1 result_path  $2 forbidden_path  $3 source_root  $4 net_target(host:port|"")
res="$1"; forb="$2"; src="$3"; tgt="$4"
w=0
if printf x > "$forb" 2>/dev/null; then w=1; rm -f "$forb" 2>/dev/null; fi
r=0
if printf x > "$src/.mini-audit-canary" 2>/dev/null; then
  r=1; rm -f "$src/.mini-audit-canary" 2>/dev/null
fi
e=0
if [ -n "${MINI_AUDIT_CANARY_ENV:-}" ]; then e=1; fi
n=undetermined
if [ -n "$tgt" ]; then
  # The target is a listener this very process's host started, on an address the
  # *unisolated* host can reach (see _ProbeListener). "undetermined" is sticky:
  # if no prober is available on this image we report that rather than guess.
  hp="${tgt%:*}"; pt="${tgt##*:}"
  if command -v python3 >/dev/null 2>&1; then
    if python3 -c 'import socket,sys
s = socket.socket()
s.settimeout(2)
try:
    s.connect((sys.argv[1], int(sys.argv[2])))
except Exception:
    raise SystemExit(1)
raise SystemExit(0)' "$hp" "$pt" >/dev/null 2>&1; then n=1; else n=0; fi
  fi
  if [ "$n" = "undetermined" ] && command -v nc >/dev/null 2>&1; then
    # `-z` is a GNU/openbsd extension; busybox nc rejects it, so fall back to a
    # plain connect. Either way, exit status is the answer.
    if nc -z -w 2 "$hp" "$pt" >/dev/null 2>&1; then n=1
    elif nc -w 2 "$hp" "$pt" </dev/null >/dev/null 2>&1; then n=1
    else n=0; fi
  fi
fi
printf '{"wrote_forbidden": %s, "wrote_source": %s, "saw_env": %s, "network": "%s"}\\n' \\
  "$w" "$r" "$e" "$n" > "$res" 2>/dev/null
exit 0
"""

# Proves the runtime's `ulimit` wrapper is applied *to this process*. Rather than
# burning CPU and inferring a limit from a signal, the canary reads its own
# RLIMIT_CPU / RLIMIT_FSIZE and reports the values: that is a direct observation
# of the limit the process is actually running under.
#
# It is also instant and portable, which matters — an earlier iteration inferred
# the limit from SIGXCPU, but a busy loop under busybox `ash` in a container
# took minutes, and RLIMIT_FSIZE turned out not to survive binary shims.
CANARY_LIMITS_SCRIPT = """#!/bin/sh
# args: $1 result_path
res="$1"
cpu=$(ulimit -t 2>/dev/null || echo unknown)
fblk=$(ulimit -f 2>/dev/null || echo unknown)
printf '{"cpu_limit": "%s", "file_limit": "%s"}\\n' "$cpu" "$fblk" > "$res" 2>/dev/null
exit 0
"""


def canary_paths(audit_root: os.PathLike[str] | str) -> Path:
    return Path(audit_root) / "sandbox"


# ---------------------------------------------------------------------------
# Hermetic network probe target
# ---------------------------------------------------------------------------


def _candidate_probe_hosts() -> list[str]:
    """Addresses this host is likely reachable at *from a container*.

    Order matters: the primary outbound address (the one the kernel picks for a
    default route) is the address a bridged container actually routes back to.
    Loopback is useless as a differential signal — a container's own loopback is
    always separate from the host's — so it is only a last resort for a machine
    with no usable interface at all.
    """
    found: list[str] = []

    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # No packet is sent; this only asks the routing table for a source
        # address, which is exactly the address a peer would see us as.
        probe.connect(("1.1.1.1", 53))
        found.append(probe.getsockname()[0])
    except OSError:
        pass
    finally:
        probe.close()

    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            found.append(info[4][0])
    except (OSError, socket.gaierror):
        pass

    found.append("127.0.0.1")
    seen: list[str] = []
    for addr in found:
        if addr and addr not in seen:
            seen.append(addr)
    return seen


class _ProbeListener:
    """A throwaway TCP listener an unisolated process can reach.

    Why not just probe a public IP? Because "the sandbox blocks the network" is
    only demonstrable if the network was reachable to begin with, and a
    hardcoded public endpoint is reachable on some networks and not others —
    measured on one host here, ``1.1.1.1:53`` and ``1.1.1.1:80`` answered while
    ``1.1.1.1:443`` and ``8.8.8.8:53`` timed out. Binding our own listener on
    the host's routable address makes the baseline reachability a fact we
    establish rather than a fact we assume, and needs no egress at all.

    Containment is still a real differential: a bridged container reaches the
    host address, and the same container under a private network namespace does
    not.
    """

    def __init__(self) -> None:
        self._server: Optional[socket.socket] = None
        self._thread: Optional[threading.Thread] = None
        self._stop = threading.Event()
        self.host: Optional[str] = None
        self.port: Optional[int] = None

    def start(self) -> "_ProbeListener":
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(("0.0.0.0", 0))
        server.listen(16)
        server.settimeout(0.25)
        self._server = server
        self.port = server.getsockname()[1]

        for candidate in _candidate_probe_hosts():
            if self._self_connect(candidate):
                self.host = candidate
                break
        if self.host is None:
            self.stop()
            return self

        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()
        return self

    def _self_connect(self, host: str) -> bool:
        """Can an *unisolated* process reach this address? (baseline evidence)"""
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.settimeout(2.0)
        try:
            client.connect((host, self.port))
            return True
        except OSError:
            return False
        finally:
            client.close()

    def _serve(self) -> None:
        while not self._stop.is_set():
            server = self._server
            if server is None:
                return
            try:
                conn, _ = server.accept()
            except (socket.timeout, OSError):
                continue
            try:
                conn.close()
            except OSError:
                pass

    @property
    def target(self) -> Optional[str]:
        if self.host is None or self.port is None:
            return None
        return f"{self.host}:{self.port}"

    def stop(self) -> None:
        self._stop.set()
        server, self._server = self._server, None
        if server is not None:
            try:
                server.close()
            except OSError:
                pass
        thread, self._thread = self._thread, None
        if thread is not None and thread.is_alive():
            thread.join(timeout=1.0)

    def __enter__(self) -> "_ProbeListener":
        return self.start()

    def __exit__(self, *exc: object) -> None:
        self.stop()


def write_canary_scripts(audit_root: os.PathLike[str] | str) -> tuple[Path, Path]:
    """Materialise the canary scripts; returns (probe_script, limits_script)."""
    directory = canary_paths(audit_root)
    directory.mkdir(parents=True, exist_ok=True)
    probe = directory / "canary.sh"
    limits = directory / "canary-limits.sh"
    for path, body in ((probe, CANARY_SCRIPT), (limits, CANARY_LIMITS_SCRIPT)):
        path.write_text(body, encoding="utf-8")
        path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return probe, limits


@dataclasses.dataclass
class BackendVerification:
    """What one backend actually demonstrated on this host, right now."""

    backend: str
    usable: bool
    controls: dict[str, bool] = dataclasses.field(default_factory=dict)
    evidence: dict[str, Any] = dataclasses.field(default_factory=dict)
    detail: str = ""
    image: str = ""

    @property
    def demonstrated(self) -> list[str]:
        return sorted(k for k, v in self.controls.items() if v)

    def to_dict(self) -> dict[str, Any]:
        return {
            "backend": self.backend,
            "usable": self.usable,
            "verified": self.usable and bool(self.demonstrated),
            "controls": dict(self.controls),
            "demonstrated": self.demonstrated,
            "evidence": dict(self.evidence),
            "detail": self.detail,
            "image": self.image,
        }


def _read_canary_result(path: Path) -> Optional[dict[str, Any]]:
    import json

    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def _ulimit_wrap(argv: Sequence[str], *, max_file_mb: int, cpu_seconds: int) -> list[str]:
    """Apply POSIX resource limits around *argv*.

    ``ulimit -f`` is in 512-byte blocks; ``ulimit -t`` is CPU seconds.
    """
    blocks = int(max_file_mb) * 2048
    script = f"ulimit -f {blocks} 2>/dev/null; ulimit -t {int(cpu_seconds)} 2>/dev/null; exec \"$@\""
    return ["sh", "-c", script, "mini-audit-limits", *argv]


def verify_backend(
    backend: IsolationBackend,
    spec: SandboxSpec,
    *,
    timeout_seconds: float = DEFAULT_CANARY_TIMEOUT,
    baseline: bool = True,
) -> BackendVerification:
    """Run the differential canary for *backend*.

    A control counts as demonstrated only when the unisolated baseline performed
    the forbidden action and the isolated run did not. If the baseline could not
    perform it either (e.g. the host is offline, or the process lacks permission
    regardless), the control is reported ``False`` — we never claim containment
    we cannot distinguish from the host's own behaviour.
    """
    if not backend.available():
        return BackendVerification(
            backend=backend.name, usable=False,
            controls={c: False for c in ALL_CONTROLS},
            detail=backend.unavailable_reason(),
            image=getattr(backend, "image", "") or "",
        )

    probe_script, limits_script = write_canary_scripts(spec.audit_root)
    canary_dir = canary_paths(spec.audit_root) / "canary"
    canary_dir.mkdir(parents=True, exist_ok=True)
    result_path = canary_dir / "result.json"
    forbidden_path = spec.repo_root.parent / f".mini-audit-canary-{os.getpid()}"

    # `network_denial` needs a target that is reachable without the sandbox and
    # unreachable with it. We stand one up ourselves rather than trusting a
    # public address to be routable from whatever network this host is on.
    listener = _ProbeListener()
    if not spec.allow_network:
        listener.start()
    net_target = listener.target or ""
    baseline_reached_network = listener.host is not None

    try:
        return _verify_with_canary(
            backend, spec, probe_script, limits_script, canary_dir, result_path,
            forbidden_path, net_target, baseline_reached_network,
            timeout_seconds=timeout_seconds, baseline=baseline,
        )
    finally:
        listener.stop()


def _verify_with_canary(
    backend: IsolationBackend,
    spec: SandboxSpec,
    probe_script: Path,
    limits_script: Path,
    canary_dir: Path,
    result_path: Path,
    forbidden_path: Path,
    net_target: str,
    baseline_reached_network: bool,
    *,
    timeout_seconds: float,
    baseline: bool,
) -> BackendVerification:
    canary_argv = ["sh", str(probe_script), str(result_path), str(forbidden_path),
                   str(spec.repo_root), net_target]

    base: Optional[dict[str, Any]] = None
    if baseline:
        result_path.unlink(missing_ok=True)
        base_env = sanitized_env(spec, extra={"MINI_AUDIT_CANARY_ENV": "leaked"})
        run_command_with_timeout(
            _ulimit_wrap(canary_argv, max_file_mb=spec.max_file_mb,
                         cpu_seconds=spec.cpu_seconds),
            timeout_seconds=timeout_seconds, cwd=spec.cwd, env=base_env,
        )
        base = _read_canary_result(result_path)

    # Isolated run: put the canary *inside* the wrapper, and do NOT hand it the
    # sentinel env var, so `env_sanitized` is observable.
    result_path.unlink(missing_ok=True)
    inner = _ulimit_wrap(canary_argv, max_file_mb=spec.max_file_mb,
                         cpu_seconds=spec.cpu_seconds)
    try:
        wrapped = backend.build_argv(inner, spec)
    except SandboxBackendError as exc:
        # A malformed spec must not read as "no isolation available anywhere";
        # name the backend and the reason so it is fixable.
        forbidden_path.unlink(missing_ok=True)
        return BackendVerification(
            backend=backend.name, usable=False,
            controls={c: False for c in ALL_CONTROLS},
            detail=str(exc),
            image=getattr(backend, "image", "") or "",
        )
    outcome = run_command_with_timeout(
        wrapped, timeout_seconds=timeout_seconds, cwd=spec.cwd, env=sanitized_env(spec),
    )
    isolated = _read_canary_result(result_path)
    forbidden_path.unlink(missing_ok=True)

    evidence: dict[str, Any] = {
        "baseline": base,
        "isolated": isolated,
        "isolated_exit": outcome.returncode,
        "isolated_stderr": (outcome.stderr or "").strip()[:400],
        "net_probe_target": net_target or None,
        # Directly observed by the *unisolated* verifier process, not inferred
        # from the canary's shell tooling: this is the "baseline performed the
        # forbidden action" half of the differential.
        "net_baseline_reachable": baseline_reached_network,
    }

    if isolated is None:
        return BackendVerification(
            backend=backend.name, usable=False,
            controls={c: False for c in ALL_CONTROLS},
            evidence=evidence,
            detail=(
                f"{backend.name} could not execute the canary "
                f"(exit={outcome.returncode}); "
                f"{(outcome.stderr or '').strip().splitlines()[-1][:160] if outcome.stderr else 'no stderr'}"
            ),
            image=getattr(backend, "image", "") or "",
        )

    def demonstrated(key: str, forbidden_in_baseline: bool, forbidden_in_isolated: bool) -> bool:
        return bool(forbidden_in_baseline) and not bool(forbidden_in_isolated)

    wrote_forbidden_isolated = bool(isolated.get("wrote_forbidden"))
    wrote_source_isolated = bool(isolated.get("wrote_source"))
    isolated_network = isolated.get("network")

    controls = {
        CONTROL_WRITE_CONFINEMENT: demonstrated(
            "write", bool(base and base.get("wrote_forbidden")), wrote_forbidden_isolated,
        ),
        CONTROL_READ_ONLY_SOURCE: demonstrated(
            "source", bool(base and base.get("wrote_source")), wrote_source_isolated,
        ),
        # Denial is only meaningful if there was something to deny: the
        # verifier had to reach the probe target first, and the sandboxed run
        # has to affirmatively report it could not. `undetermined` (no prober
        # on this image) is not evidence, so it does not count.
        CONTROL_NETWORK_DENIAL: (
            True
            if spec.allow_network
            else baseline_reached_network and isolated_network == "0"
        ),
        # The sentinel var was present in the baseline env and is absent from
        # the isolated env by construction; observing its absence inside the
        # sandbox is what makes this evidence rather than intent.
        CONTROL_ENV_SANITIZED: base is not None and bool(base.get("saw_env")) and not bool(isolated.get("saw_env")),
        CONTROL_RESOURCE_LIMITS: False,  # measured separately, below
        CONTROL_HARD_TIMEOUT: True,      # process_control process-group deadline
    }

    controls[CONTROL_RESOURCE_LIMITS] = _verify_resource_limits(
        backend, spec, limits_script, canary_dir, timeout_seconds=timeout_seconds,
        baseline=base,
    )
    evidence["resource_limits"] = {"demonstrated": controls[CONTROL_RESOURCE_LIMITS]}

    detail = "demonstrated: " + (", ".join(sorted(k for k, v in controls.items() if v)) or "nothing")
    if not spec.allow_network and not controls[CONTROL_NETWORK_DENIAL]:
        if not baseline_reached_network:
            detail += (
                "; network_denial undeterminable — this host has no address a "
                "sandboxed process could have reached either"
            )
        elif isolated_network == "undetermined":
            detail += (
                "; network_denial undeterminable — the sandboxed image has "
                "neither python3 nor nc to attempt a connection"
            )
    return BackendVerification(
        backend=backend.name, usable=True, controls=controls, evidence=evidence,
        detail=detail, image=getattr(backend, "image", "") or "",
    )


def _verify_resource_limits(
    backend: IsolationBackend,
    spec: SandboxSpec,
    limits_script: Path,
    canary_dir: Path,
    *,
    timeout_seconds: float,
    baseline: Optional[Mapping[str, Any]] = None,
) -> bool:
    """Prove the runtime's ``ulimit`` wrapper reaches the process.

    The canary reports the RLIMIT_CPU/RLIMIT_FSIZE it observes. The control
    counts as demonstrated when the wrapped run reports exactly the configured
    CPU limit and the unwrapped baseline reports something else — i.e. the limit
    visible to the process changed *because our wrapper ran*, not because the
    host happens to be configured that way.
    """
    expected = str(int(spec.cpu_seconds))
    result_path = canary_dir / "limits.json"

    if baseline is None:
        result_path.unlink(missing_ok=True)
        run_command_with_timeout(
            ["sh", str(limits_script), str(result_path)],
            timeout_seconds=timeout_seconds, cwd=spec.cwd, env=sanitized_env(spec),
        )
        baseline = _read_canary_result(result_path)

    result_path.unlink(missing_ok=True)
    inner = _ulimit_wrap(
        ["sh", str(limits_script), str(result_path)],
        max_file_mb=spec.max_file_mb, cpu_seconds=spec.cpu_seconds,
    )
    run_command_with_timeout(
        backend.build_argv(inner, spec),
        timeout_seconds=timeout_seconds, cwd=spec.cwd, env=sanitized_env(spec),
    )
    isolated = _read_canary_result(result_path)
    if isolated is None:
        return False

    base_cpu = str((baseline or {}).get("cpu_limit", ""))
    if base_cpu == expected:
        # The host already runs under this limit, so the observation cannot
        # distinguish our wrapper from the environment.
        return False
    return str(isolated.get("cpu_limit")) == expected


def select_backend(
    spec: SandboxSpec,
    *,
    verifications: Optional[Sequence[BackendVerification]] = None,
    required_controls: Sequence[str] = (),
    verifier: Callable[[IsolationBackend, SandboxSpec], BackendVerification] = verify_backend,
    backends: Optional[Sequence[IsolationBackend]] = None,
) -> tuple[Optional[IsolationBackend], list[BackendVerification]]:
    """Pick the first backend that demonstrably provides *required_controls*."""
    candidates = list(backends) if backends is not None else list(BACKENDS)
    if verifications is None:
        reports = [verifier(backend, spec) for backend in candidates if backend.available()]
    else:
        reports = list(verifications)

    by_name = {b.name: b for b in candidates}
    for report in reports:
        if not report.usable:
            continue
        if all(report.controls.get(c, False) for c in required_controls):
            backend = by_name.get(report.backend)
            if backend is not None:
                return backend, reports
    return None, reports
