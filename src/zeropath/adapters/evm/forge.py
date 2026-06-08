"""Foundry execution helpers."""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Any

from zeropath.core.schemas import CandidateFinding
from zeropath.core.storage import Storage


def forge_available() -> bool:
    return shutil.which("forge") is not None


def run_forge_test(root_path: str | Path, match_path: str | Path | None = None) -> dict[str, Any]:
    if not forge_available():
        return {"ok": False, "status": "unavailable", "message": "forge is not installed or not on PATH"}
    root = Path(root_path).resolve()
    normalized_match_path = _normalize_match_path(root, match_path) if match_path else None
    cmd = ["forge", "test"]
    if normalized_match_path:
        cmd.extend(["--match-path", normalized_match_path])
    try:
        result = subprocess.run(
            cmd,
            cwd=str(root),
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
        "command": cmd,
        "match_path": normalized_match_path,
        "stdout": result.stdout[-12000:],
        "stderr": result.stderr[-12000:],
    }


def save_forge_trace(storage: Storage, candidate: CandidateFinding, result: dict[str, Any]) -> Path:
    payload = {
        "candidate_id": candidate.id,
        "backend": "foundry",
        "status": result.get("status"),
        "ok": result.get("ok"),
        "returncode": result.get("returncode"),
        "command": result.get("command"),
        "match_path": result.get("match_path"),
        "message": result.get("message"),
        "stdout": result.get("stdout"),
        "stderr": result.get("stderr"),
    }
    return storage.append_artifact(
        Path("traces") / f"{candidate.id.replace('-', '_')}_forge_result.json",
        json.dumps(payload, indent=2, sort_keys=True),
        overwrite=True,
    )


def _normalize_match_path(root_path: Path, match_path: str | Path) -> str:
    path = Path(match_path)
    if not path.is_absolute():
        return str(path)
    try:
        return str(path.resolve().relative_to(root_path))
    except ValueError:
        return str(path)
