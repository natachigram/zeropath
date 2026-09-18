"""Deterministic identity and scope helpers for harness campaigns."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Iterable


class ScopeError(ValueError):
    """Raised when a requested path escapes the local target root."""


def canonical_json(value: Any) -> str:
    """Return the canonical JSON representation used by artifact digests."""

    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def json_digest(value: Any) -> str:
    return sha256_bytes(canonical_json(value).encode("utf-8"))


def _safe_relative(root: Path, path: str | Path) -> tuple[str, Path]:
    root = root.resolve()
    candidate = Path(path)
    resolved = (root / candidate).resolve() if not candidate.is_absolute() else candidate.resolve()
    if resolved != root and root not in resolved.parents:
        raise ScopeError(f"path escapes target root: {path}")
    return str(resolved.relative_to(root)), resolved


def expand_scoped_paths(root: str | Path, paths: Iterable[str | Path]) -> tuple[list[str], list[str]]:
    """Expand a list of files/directories into sorted relative file paths.

    Missing paths are returned separately and are intentionally not silently
    ignored: a changed source boundary must be visible in the run manifest.
    Symlinks are resolved before the containment check, so a link cannot pull
    an unscoped file into a campaign.
    """

    root_path = Path(root).resolve()
    files: set[str] = set()
    missing: list[str] = []
    for requested in paths:
        relative, resolved = _safe_relative(root_path, requested)
        if not resolved.exists():
            missing.append(relative)
            continue
        if resolved.is_file():
            files.add(relative)
            continue
        for child in resolved.rglob("*"):
            if child.is_symlink():
                try:
                    _, child_resolved = _safe_relative(root_path, child)
                except ScopeError:
                    continue
                child = child_resolved
            if child.is_file():
                child_relative, _ = _safe_relative(root_path, child)
                files.add(child_relative)
    return sorted(files), sorted(set(missing))


def scoped_source_digest(root: str | Path, paths: Iterable[str | Path]) -> tuple[str, list[str], list[str]]:
    """Hash relative paths and bytes for an exact, reproducible source scope.

    The path names are part of the digest.  A rename therefore changes source
    identity even when file contents remain identical.  Missing requested paths
    are included as explicit markers and returned to the caller for reporting.
    """

    root_path = Path(root).resolve()
    files, missing = expand_scoped_paths(root_path, paths)
    hasher = hashlib.sha256()
    for relative in files:
        data = (root_path / relative).read_bytes()
        encoded_name = relative.encode("utf-8")
        hasher.update(b"file\0")
        hasher.update(str(len(encoded_name)).encode("ascii"))
        hasher.update(b"\0")
        hasher.update(encoded_name)
        hasher.update(b"\0")
        hasher.update(str(len(data)).encode("ascii"))
        hasher.update(b"\0")
        hasher.update(data)
    for relative in missing:
        hasher.update(b"missing\0")
        hasher.update(relative.encode("utf-8"))
        hasher.update(b"\0")
    return hasher.hexdigest(), files, missing


def ensure_relative_path(root: str | Path, path: str | Path) -> str:
    """Validate and return a normalized path relative to *root*."""

    relative, _ = _safe_relative(Path(root).resolve(), path)
    return relative


__all__ = [
    "ScopeError",
    "canonical_json",
    "ensure_relative_path",
    "expand_scoped_paths",
    "json_digest",
    "scoped_source_digest",
    "sha256_bytes",
]
