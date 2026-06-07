"""Small shared helpers for the evidence-first core."""

from __future__ import annotations

import hashlib
import subprocess
from datetime import datetime, timezone
from pathlib import Path


def utc_now() -> datetime:
    """Return an aware UTC timestamp."""

    return datetime.now(timezone.utc)


def repo_commit(root_path: str | Path) -> str | None:
    """Return the current git commit for a repo, if available."""

    root = Path(root_path)
    try:
        result = subprocess.run(
            ["git", "-C", str(root), "rev-parse", "HEAD"],
            check=True,
            capture_output=True,
            text=True,
            timeout=5,
        )
    except Exception:
        return None
    commit = result.stdout.strip()
    return commit or None


def sha256_file(path: str | Path) -> str:
    """Hash a file without loading it all into memory."""

    h = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def safe_relpath(path: str | Path, root_path: str | Path) -> str:
    """Return a display-safe relative path when possible."""

    p = Path(path)
    root = Path(root_path)
    try:
        return str(p.resolve().relative_to(root.resolve()))
    except Exception:
        return str(p)


def slugify(value: str) -> str:
    """Create a conservative identifier slug."""

    out = []
    for ch in value.lower():
        if ch.isalnum():
            out.append(ch)
        elif out and out[-1] != "-":
            out.append("-")
    return "".join(out).strip("-") or "project"
