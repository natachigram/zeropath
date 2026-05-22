"""
IDE auto-installer for the ZeroPath MCP server.

Writes / merges the right config file for each supported IDE so the user
goes from ``pip install zeropath`` to "ZeroPath tools available in my
agent" in one command.

Supported targets (mid-2026):

  * ``claude-desktop``  — Anthropic's desktop app (macOS / Windows / Linux)
  * ``claude-code``     — Claude Code CLI (settings.json mcpServers block)
  * ``cursor``          — Cursor IDE (.cursor/mcp.json)
  * ``cline``           — Cline VS Code extension (cline_mcp_settings.json)
  * ``continue``        — Continue.dev VS Code / JetBrains extension

All writes are *additive* — existing ``mcpServers`` entries are preserved,
and our entry is keyed on ``"zeropath"`` so re-running ``install`` is
idempotent.
"""

from __future__ import annotations

import json
import logging
import os
import platform
import shutil
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


# Name of our MCP server entry in IDE configs.
_SERVER_KEY = "zeropath"


# ---------------------------------------------------------------------------
# Per-IDE config paths
# ---------------------------------------------------------------------------


def _home() -> Path:
    return Path.home()


def _config_path_claude_desktop() -> Path:
    system = platform.system()
    if system == "Darwin":
        return _home() / "Library" / "Application Support" / "Claude" / "claude_desktop_config.json"
    if system == "Windows":
        appdata = os.environ.get("APPDATA")
        if appdata:
            return Path(appdata) / "Claude" / "claude_desktop_config.json"
        return _home() / "AppData" / "Roaming" / "Claude" / "claude_desktop_config.json"
    # Linux
    return _home() / ".config" / "Claude" / "claude_desktop_config.json"


def _config_path_claude_code() -> Path:
    # Claude Code reads ~/.claude/settings.json (user-level) and a project-
    # level .claude.json. We write to the user-level file so the server is
    # available across every project.
    return _home() / ".claude" / "settings.json"


def _config_path_cursor() -> Path:
    # Cursor stores MCP configs at ~/.cursor/mcp.json (user-level).
    return _home() / ".cursor" / "mcp.json"


def _config_path_cline() -> Path:
    # Cline (VS Code) — settings live in VS Code globalStorage.
    if platform.system() == "Darwin":
        return (
            _home() / "Library" / "Application Support" / "Code" / "User"
            / "globalStorage" / "saoudrizwan.claude-dev" / "settings"
            / "cline_mcp_settings.json"
        )
    if platform.system() == "Windows":
        appdata = os.environ.get("APPDATA")
        if appdata:
            return (
                Path(appdata) / "Code" / "User" / "globalStorage"
                / "saoudrizwan.claude-dev" / "settings"
                / "cline_mcp_settings.json"
            )
    return (
        _home() / ".config" / "Code" / "User" / "globalStorage"
        / "saoudrizwan.claude-dev" / "settings" / "cline_mcp_settings.json"
    )


def _config_path_continue() -> Path:
    # Continue.dev reads ~/.continue/mcp.json.
    return _home() / ".continue" / "mcp.json"


_INSTALLERS: dict[str, callable] = {
    "claude-desktop": _config_path_claude_desktop,
    "claude-code":    _config_path_claude_code,
    "cursor":         _config_path_cursor,
    "cline":          _config_path_cline,
    "continue":       _config_path_continue,
}


SUPPORTED_CLIENTS = tuple(_INSTALLERS.keys())


# ---------------------------------------------------------------------------
# Result record
# ---------------------------------------------------------------------------


@dataclass
class InstallResult:
    client: str
    config_path: Path
    written: bool
    already_present: bool
    backup_path: Optional[Path] = None
    error: Optional[str] = None


# ---------------------------------------------------------------------------
# Server-spawn command
# ---------------------------------------------------------------------------


def _server_command(*, python: Optional[str] = None, kg_dir: Optional[str] = None) -> dict:
    """
    Build the ``mcpServers["zeropath"]`` entry written into each IDE config.

    Uses the *currently running* Python by default so the agent gets the
    exact same package versions the user just installed. Override with
    ``--python`` when packaging a portable launcher.
    """
    python = python or sys.executable
    args = ["-m", "zeropath.cli", "mcp", "serve"]
    if kg_dir:
        args.extend(["--kg-dir", kg_dir])
    return {
        "command": python,
        "args": args,
        "env": {},
    }


# ---------------------------------------------------------------------------
# Config merge
# ---------------------------------------------------------------------------


def _load_or_init(path: Path) -> dict:
    if not path.exists():
        return {}
    try:
        with path.open("r", encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, dict):
            logger.warning("config at %s is not a JSON object; starting fresh", path)
            return {}
        return data
    except (json.JSONDecodeError, OSError) as exc:
        logger.warning("could not read %s: %s", path, exc)
        return {}


def _backup(path: Path) -> Optional[Path]:
    if not path.exists():
        return None
    backup = path.with_suffix(path.suffix + ".bak")
    try:
        shutil.copy2(path, backup)
        return backup
    except OSError as exc:
        logger.warning("backup failed for %s: %s", path, exc)
        return None


def _merge(config: dict, entry: dict) -> tuple[dict, bool]:
    """
    Add our entry under ``mcpServers``. Returns (merged_config, already_present).
    """
    servers = config.setdefault("mcpServers", {})
    if not isinstance(servers, dict):
        servers = {}
        config["mcpServers"] = servers
    already = servers.get(_SERVER_KEY) == entry
    servers[_SERVER_KEY] = entry
    return config, already


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def install_for_client(
    client: str,
    *,
    python: Optional[str] = None,
    kg_dir: Optional[str] = None,
    dry_run: bool = False,
) -> InstallResult:
    """
    Add a ``zeropath`` MCP server entry to one IDE's config.

    Parameters
    ----------
    client : str
        One of :data:`SUPPORTED_CLIENTS`.
    python : str | None
        Python interpreter the IDE should invoke (defaults to current).
    kg_dir : str | None
        Optional KG directory passed to the server via ``--kg-dir``.
    dry_run : bool
        Render the merged config but don't write to disk.
    """
    if client not in _INSTALLERS:
        return InstallResult(
            client=client, config_path=Path("/dev/null"),
            written=False, already_present=False,
            error=f"unsupported client: {client}",
        )
    path = _INSTALLERS[client]()
    config = _load_or_init(path)
    merged, already = _merge(config, _server_command(python=python, kg_dir=kg_dir))
    if dry_run:
        return InstallResult(
            client=client, config_path=path,
            written=False, already_present=already,
        )
    backup = _backup(path)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8") as f:
            json.dump(merged, f, indent=2)
    except OSError as exc:
        return InstallResult(
            client=client, config_path=path, written=False,
            already_present=already, backup_path=backup,
            error=f"write failed: {exc}",
        )
    return InstallResult(
        client=client, config_path=path, written=True,
        already_present=already, backup_path=backup,
    )


def install_for_all(
    *,
    python: Optional[str] = None,
    kg_dir: Optional[str] = None,
    dry_run: bool = False,
) -> list[InstallResult]:
    """Install into every IDE we have a writer for."""
    return [
        install_for_client(c, python=python, kg_dir=kg_dir, dry_run=dry_run)
        for c in SUPPORTED_CLIENTS
    ]


def uninstall_for_client(client: str) -> InstallResult:
    """Remove the ``zeropath`` entry from one IDE config."""
    if client not in _INSTALLERS:
        return InstallResult(
            client=client, config_path=Path("/dev/null"),
            written=False, already_present=False,
            error=f"unsupported client: {client}",
        )
    path = _INSTALLERS[client]()
    if not path.exists():
        return InstallResult(
            client=client, config_path=path, written=False,
            already_present=False,
        )
    config = _load_or_init(path)
    servers = config.get("mcpServers") or {}
    if _SERVER_KEY not in servers:
        return InstallResult(
            client=client, config_path=path, written=False,
            already_present=False,
        )
    servers.pop(_SERVER_KEY)
    config["mcpServers"] = servers
    backup = _backup(path)
    try:
        with path.open("w", encoding="utf-8") as f:
            json.dump(config, f, indent=2)
    except OSError as exc:
        return InstallResult(
            client=client, config_path=path, written=False,
            already_present=True, backup_path=backup,
            error=f"write failed: {exc}",
        )
    return InstallResult(
        client=client, config_path=path, written=True,
        already_present=True, backup_path=backup,
    )
