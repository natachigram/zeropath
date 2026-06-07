"""Foundry execution helpers."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path
from typing import Any


def forge_available() -> bool:
    return shutil.which("forge") is not None


def run_forge_test(root_path: str | Path, match_path: str | Path | None = None) -> dict[str, Any]:
    if not forge_available():
        return {"ok": False, "status": "unavailable", "message": "forge is not installed or not on PATH"}
    cmd = ["forge", "test"]
    if match_path:
        cmd.extend(["--match-path", str(match_path)])
    try:
        result = subprocess.run(
            cmd,
            cwd=str(root_path),
            text=True,
            capture_output=True,
            timeout=120,
        )
    except subprocess.TimeoutExpired as exc:
        return {"ok": False, "status": "timeout", "stdout": exc.stdout, "stderr": exc.stderr}
    return {
        "ok": result.returncode == 0,
        "status": "passed" if result.returncode == 0 else "failed",
        "returncode": result.returncode,
        "stdout": result.stdout[-12000:],
        "stderr": result.stderr[-12000:],
    }
