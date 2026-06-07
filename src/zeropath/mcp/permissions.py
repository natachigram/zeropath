"""MCP security helpers."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any


SECRET_PATTERNS = (
    re.compile(r"(?i)(api[_-]?key|token|secret|password)\s*[:=]\s*['\"]?[^'\"\s,}]+"),
    re.compile(r"0x[a-fA-F0-9]{64}"),
)


def redact(value: Any) -> Any:
    text = json.dumps(value, default=str) if not isinstance(value, str) else value
    for pattern in SECRET_PATTERNS:
        text = pattern.sub(lambda m: m.group(0).split("=")[0] + "=<redacted>" if "=" in m.group(0) else "<redacted>", text)
    if isinstance(value, str):
        return text
    try:
        return json.loads(text)
    except Exception:
        return text


def workspace_path(path: str | Path, workspace_root: str | Path) -> Path:
    root = Path(workspace_root).resolve()
    resolved = Path(path).resolve()
    if resolved != root and root not in resolved.parents:
        raise PermissionError(f"path is outside workspace allowlist: {resolved}")
    return resolved


def require_write(args: dict[str, Any]) -> bool:
    return bool(args.get("write_mode") or args.get("writeMode"))


def log_tool_call(root_path: str | Path, name: str, args: dict[str, Any]) -> None:
    zp_dir = Path(root_path).resolve() / ".zeropath"
    log_dir = zp_dir / "logs"
    if not log_dir.exists():
        return
    log_dir.mkdir(parents=True, exist_ok=True)
    payload = json.dumps({"tool": name, "args": redact(args)}, sort_keys=True, default=str)
    with (log_dir / "mcp.log").open("a", encoding="utf-8") as handle:
        handle.write(payload + "\n")
