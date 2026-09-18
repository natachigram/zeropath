"""Safe, deterministic subprocess backends for the ZeroPath harness.

The harness owns orchestration and evidence; Foundry, Echidna, Medusa, and
Halmos remain replaceable execution engines.  Only named binaries and fixed
argument shapes are accepted here.  There is intentionally no generic shell
or user-supplied command escape hatch.
"""

from __future__ import annotations

import re
import shutil
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol
from uuid import uuid4

from zeropath.core.utils import utc_now
from zeropath.harness.digests import ScopeError, ensure_relative_path
from zeropath.harness.models import BackendRun


class BackendError(RuntimeError):
    """Raised for invalid local backend configuration."""


@dataclass(frozen=True)
class BackendContext:
    campaign_id: str
    root_path: Path
    target_path: str | Path | None
    seed: int
    timeout_seconds: int
    verbosity: int = 0
    replay_of: str | None = None


class Backend(Protocol):
    name: str
    executable: str

    def available(self) -> bool: ...

    def command(self, context: BackendContext) -> list[str]: ...


def _target_relative(root_path: Path, target_path: str | Path | None) -> str | None:
    if target_path is None:
        return None
    try:
        return ensure_relative_path(root_path, target_path)
    except ScopeError as exc:
        raise BackendError(str(exc)) from exc


@dataclass(frozen=True)
class FoundryBackend:
    name: str = "foundry"
    executable: str = "forge"

    def available(self) -> bool:
        return shutil.which(self.executable) is not None

    def command(self, context: BackendContext) -> list[str]:
        command = [self.executable, "test", "--offline", "--fuzz-seed", str(context.seed)]
        target = _target_relative(context.root_path, context.target_path)
        if target:
            command.extend(["--match-path", target])
        if context.verbosity > 0:
            command.append("-" + ("v" * min(max(context.verbosity, 1), 5)))
        return command


@dataclass(frozen=True)
class EchidnaBackend:
    name: str = "echidna"
    executable: str = "echidna"

    def available(self) -> bool:
        return shutil.which(self.executable) is not None

    def command(self, context: BackendContext) -> list[str]:
        target = _target_relative(context.root_path, context.target_path)
        if not target:
            raise BackendError("echidna requires a scoped Solidity harness path")
        return [self.executable, target, "--format", "json", "--seed", str(context.seed)]


@dataclass(frozen=True)
class MedusaBackend:
    name: str = "medusa"
    executable: str = "medusa"

    def available(self) -> bool:
        return shutil.which(self.executable) is not None

    def command(self, context: BackendContext) -> list[str]:
        # Medusa resolves the Foundry project from cwd.  The target path is
        # recorded for evidence but is not interpolated into an untrusted CLI
        # command because Medusa's project-level config controls selection.
        return [self.executable, "fuzz", "--seed", str(context.seed)]


@dataclass(frozen=True)
class HalmosBackend:
    name: str = "halmos"
    executable: str = "halmos"

    def available(self) -> bool:
        return shutil.which(self.executable) is not None

    def command(self, context: BackendContext) -> list[str]:
        return [self.executable, "--seed", str(context.seed)]


_BACKENDS: dict[str, Backend] = {
    "foundry": FoundryBackend(),
    "echidna": EchidnaBackend(),
    "medusa": MedusaBackend(),
    "halmos": HalmosBackend(),
}


def supported_backends() -> tuple[str, ...]:
    return tuple(_BACKENDS)


def get_backend(name: str) -> Backend:
    key = name.strip().lower()
    try:
        return _BACKENDS[key]
    except KeyError as exc:
        choices = ", ".join(supported_backends())
        raise BackendError(f"unsupported backend {name!r}; choose one of: {choices}") from exc


def backend_availability() -> dict[str, bool]:
    return {name: backend.available() for name, backend in _BACKENDS.items()}


def run_named_backend(
    name: str,
    context: BackendContext,
    *,
    source_digest_before: str = "",
    max_stdout: int = 64_000,
    max_stderr: int = 32_000,
) -> BackendRun:
    """Execute a backend without a shell and capture a bounded result."""

    normalized_name = name.strip().lower()
    started = time.monotonic()
    started_at = utc_now()
    try:
        backend = get_backend(normalized_name)
    except BackendError as exc:
        return BackendRun(
            run_id=_run_id(normalized_name or "unknown"),
            campaign_id=context.campaign_id,
            backend=normalized_name or name,
            status="blocked",
            target_path=str(context.target_path) if context.target_path is not None else None,
            seed=context.seed,
            verbosity=context.verbosity,
            timeout_seconds=max(1, context.timeout_seconds),
            started_at=started_at,
            finished_at=utc_now(),
            duration_seconds=0.0,
            source_digest_before=source_digest_before,
            error=str(exc),
        )
    try:
        command = backend.command(context)
    except BackendError as exc:
        return BackendRun(
            run_id=_run_id(normalized_name),
            campaign_id=context.campaign_id,
            backend=normalized_name,
            status="blocked",
            target_path=str(context.target_path) if context.target_path is not None else None,
            seed=context.seed,
            verbosity=context.verbosity,
            timeout_seconds=max(1, context.timeout_seconds),
            started_at=started_at,
            finished_at=utc_now(),
            duration_seconds=0.0,
            source_digest_before=source_digest_before,
            error=str(exc),
        )

    target_relative = _target_relative(context.root_path, context.target_path)
    common = dict(
        run_id=_run_id(normalized_name),
        campaign_id=context.campaign_id,
        backend=normalized_name,
        command=command,
        cwd=str(context.root_path),
        target_path=target_relative,
        seed=context.seed,
        verbosity=context.verbosity,
        timeout_seconds=max(1, context.timeout_seconds),
        started_at=started_at,
        replay_of=context.replay_of,
        source_digest_before=source_digest_before,
    )
    if not backend.available():
        return BackendRun(
            **common,
            status="unavailable",
            finished_at=started_at,
            duration_seconds=0.0,
            error=f"{backend.executable} is not installed or not on PATH",
        )

    try:
        process = subprocess.run(
            command,
            cwd=str(context.root_path),
            capture_output=True,
            text=True,
            timeout=max(1, context.timeout_seconds),
            check=False,
            shell=False,
        )
    except subprocess.TimeoutExpired as exc:
        finished_at = utc_now()
        return BackendRun(
            **common,
            status="timeout",
            finished_at=finished_at,
            duration_seconds=round(time.monotonic() - started, 3),
            stdout=_truncate(_as_text(exc.stdout), max_stdout),
            stderr=_truncate(_as_text(exc.stderr), max_stderr),
            error=f"backend timed out after {context.timeout_seconds}s",
        )
    except OSError as exc:
        finished_at = utc_now()
        return BackendRun(
            **common,
            status="unknown",
            finished_at=finished_at,
            duration_seconds=round(time.monotonic() - started, 3),
            error=str(exc),
        )

    stdout = _truncate(process.stdout or "", max_stdout)
    stderr = _truncate(process.stderr or "", max_stderr)
    combined = f"{stdout}\n{stderr}"
    if "No tests found" in combined:
        status = "no_tests"
    else:
        status = "passed" if process.returncode == 0 else "failed"
    finished_at = utc_now()
    return BackendRun(
        **common,
        status=status,
        finished_at=finished_at,
        duration_seconds=round(time.monotonic() - started, 3),
        returncode=process.returncode,
        stdout=stdout,
        stderr=stderr,
    )


def _run_id(backend: str) -> str:
    safe_backend = re.sub(r"[^A-Za-z0-9_.-]", "_", backend) or "unknown"
    return f"BR-{int(time.time() * 1000)}-{safe_backend}-{uuid4().hex[:8]}"


def _truncate(value: str, limit: int) -> str:
    if len(value) <= limit:
        return value
    return value[-limit:]


def _as_text(value: str | bytes | None) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value


__all__ = [
    "BackendContext",
    "BackendError",
    "EchidnaBackend",
    "FoundryBackend",
    "HalmosBackend",
    "MedusaBackend",
    "backend_availability",
    "get_backend",
    "run_named_backend",
    "supported_backends",
]
