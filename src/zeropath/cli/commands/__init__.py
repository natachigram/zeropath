"""Stable import surfaces for evidence-first CLI commands."""

from importlib import import_module
from typing import Any

from zeropath.cli.commands.candidates import candidates
from zeropath.cli.commands.prove import prove

_COMMAND_MODULES = {
    "hunt": "hunt",
    "ingest": "ingest",
    "init": "init",
    "judge": "judge",
    "mcp": "mcp",
    "memory": "memory",
    "report": "report",
    "status": "status",
    "understand": "understand",
}

__all__ = [
    "candidates",
    "hunt",
    "ingest",
    "init",
    "judge",
    "mcp",
    "memory",
    "prove",
    "report",
    "status",
    "understand",
]


def __getattr__(name: str) -> Any:
    if name not in _COMMAND_MODULES:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    module = import_module(f"zeropath.cli.commands.{_COMMAND_MODULES[name]}")
    return getattr(module, name)
