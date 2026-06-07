"""MCP schema snippets for evidence-first tools."""

from __future__ import annotations

EMPTY_INPUT = {"type": "object", "properties": {}, "additionalProperties": False}


def object_schema(properties: dict, required: list[str] | None = None) -> dict:
    return {
        "type": "object",
        "properties": properties,
        "required": required or [],
        "additionalProperties": True,
    }


WRITE_MODE = {
    "write_mode": {
        "type": "boolean",
        "description": "Must be true for tools that write local files or mutate project state.",
        "default": False,
    }
}
