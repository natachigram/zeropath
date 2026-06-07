"""MCP security helpers."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any


SECRET_KEY_RE = re.compile(r"(?i)(api[_-]?key|token|secret|password|private[_-]?key)")
SECRET_ASSIGNMENT_RE = re.compile(
    r"(?i)\b(api[_-]?key|token|secret|password|private[_-]?key)\b\s*[:=]\s*['\"]?[^'\"\s,}]+"
)
HEX_SECRET_RE = re.compile(r"0x[a-fA-F0-9]{64}")


def redact(value: Any) -> Any:
    if isinstance(value, str):
        text = SECRET_ASSIGNMENT_RE.sub(lambda m: f"{m.group(1)}=<redacted>", value)
        return HEX_SECRET_RE.sub("<redacted>", text)
    if isinstance(value, dict):
        redacted: dict[Any, Any] = {}
        for key, item in value.items():
            if SECRET_KEY_RE.search(str(key)):
                redacted[key] = "<redacted>"
            else:
                redacted[key] = redact(item)
        return redacted
    if isinstance(value, list):
        return [redact(item) for item in value]
    if isinstance(value, tuple):
        return tuple(redact(item) for item in value)
    text = json.dumps(value, default=str)
    if HEX_SECRET_RE.search(text):
        return HEX_SECRET_RE.sub("<redacted>", text)
    return value


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
