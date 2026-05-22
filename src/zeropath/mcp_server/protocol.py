"""
Model Context Protocol — wire-level JSON-RPC framing.

MCP's stdio transport is newline-delimited JSON-RPC 2.0. One JSON message
per line, both directions. No Content-Length framing (that's only the HTTP
variant of MCP — and we deliberately ship stdio-only to keep things
dependency-free and survive piped invocations from IDEs).

This module is pure stdlib so the MCP server has zero install footprint
beyond what ZeroPath already requires.

Reference: https://spec.modelcontextprotocol.io
"""

from __future__ import annotations

import json
import logging
import sys
import threading
from dataclasses import dataclass, field
from typing import Any, BinaryIO, Iterator, Optional, TextIO

logger = logging.getLogger(__name__)


PROTOCOL_VERSION = "2024-11-05"     # Latest MCP spec version supported

# Standard JSON-RPC error codes
PARSE_ERROR = -32700
INVALID_REQUEST = -32600
METHOD_NOT_FOUND = -32601
INVALID_PARAMS = -32602
INTERNAL_ERROR = -32603

# MCP-specific error codes (negative; outside JSON-RPC reserved range)
RESOURCE_NOT_FOUND = -32001
TOOL_NOT_FOUND = -32002
PROMPT_NOT_FOUND = -32003
TOOL_EXECUTION_ERROR = -32004


# ---------------------------------------------------------------------------
# Message types
# ---------------------------------------------------------------------------


@dataclass
class JsonRpcRequest:
    method: str
    id: int | str | None = None       # None → notification
    params: dict[str, Any] = field(default_factory=dict)

    @property
    def is_notification(self) -> bool:
        return self.id is None

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {"jsonrpc": "2.0", "method": self.method}
        if self.id is not None:
            out["id"] = self.id
        if self.params:
            out["params"] = self.params
        return out


@dataclass
class JsonRpcResponse:
    id: int | str | None
    result: Any = None

    def to_dict(self) -> dict[str, Any]:
        return {"jsonrpc": "2.0", "id": self.id, "result": self.result}


@dataclass
class JsonRpcError:
    id: int | str | None
    code: int
    message: str
    data: Any = None

    def to_dict(self) -> dict[str, Any]:
        err: dict[str, Any] = {"code": self.code, "message": self.message}
        if self.data is not None:
            err["data"] = self.data
        return {"jsonrpc": "2.0", "id": self.id, "error": err}


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------


class ProtocolError(Exception):
    """Malformed JSON-RPC payload."""


def parse_message(line: str) -> JsonRpcRequest:
    """
    Parse one line of newline-delimited JSON into a :class:`JsonRpcRequest`.

    Raises :class:`ProtocolError` for malformed payloads — the caller is
    expected to translate that into a JSON-RPC error response when the
    request had a discoverable ``id``.
    """
    line = line.strip()
    if not line:
        raise ProtocolError("empty message")
    try:
        payload = json.loads(line)
    except json.JSONDecodeError as exc:
        raise ProtocolError(f"invalid JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise ProtocolError("message must be a JSON object")
    if payload.get("jsonrpc") != "2.0":
        raise ProtocolError("missing or invalid jsonrpc version")
    method = payload.get("method")
    if not isinstance(method, str):
        raise ProtocolError("missing method")
    raw_id = payload.get("id")
    if raw_id is not None and not isinstance(raw_id, (int, str)):
        raise ProtocolError("id must be int, str, or absent")
    params = payload.get("params", {})
    if not isinstance(params, dict):
        raise ProtocolError("params must be an object")
    return JsonRpcRequest(method=method, id=raw_id, params=params)


def serialize(message: dict[str, Any]) -> str:
    """One newline-delimited JSON message."""
    return json.dumps(message, separators=(",", ":"), default=str) + "\n"


# ---------------------------------------------------------------------------
# Stdio transport
# ---------------------------------------------------------------------------


class StdioTransport:
    """
    Newline-delimited JSON over stdin/stdout.

    Writes are flushed immediately. Reads are blocking line reads from
    stdin. A lock guards writes so concurrent tool handlers don't
    interleave bytes.
    """

    def __init__(
        self,
        *,
        stdin: Optional[TextIO] = None,
        stdout: Optional[TextIO] = None,
        stderr: Optional[TextIO] = None,
    ) -> None:
        self._in = stdin or sys.stdin
        self._out = stdout or sys.stdout
        self._err = stderr or sys.stderr
        self._write_lock = threading.Lock()

    # ------------------------------------------------------------------
    # Reads
    # ------------------------------------------------------------------

    def iter_messages(self) -> Iterator[JsonRpcRequest]:
        """
        Yield parsed requests until EOF. Malformed lines are turned into
        ProtocolError so the server can choose to send an error response.
        """
        while True:
            line = self._in.readline()
            if not line:
                # EOF — peer closed pipe.
                return
            try:
                yield parse_message(line)
            except ProtocolError as exc:
                # Surface as a fake "parse error" request the server can
                # translate into a JSON-RPC error response with id=None.
                logger.debug("parse error: %s (line=%r)", exc, line[:200])
                yield JsonRpcRequest(method="__parse_error__", id=None,
                                       params={"error": str(exc)})

    # ------------------------------------------------------------------
    # Writes
    # ------------------------------------------------------------------

    def send_response(self, response: JsonRpcResponse) -> None:
        self._send(response.to_dict())

    def send_error(self, err: JsonRpcError) -> None:
        self._send(err.to_dict())

    def send_notification(
        self, method: str, params: Optional[dict[str, Any]] = None,
    ) -> None:
        msg = {"jsonrpc": "2.0", "method": method}
        if params:
            msg["params"] = params
        self._send(msg)

    def _send(self, payload: dict[str, Any]) -> None:
        line = serialize(payload)
        with self._write_lock:
            self._out.write(line)
            self._out.flush()

    # ------------------------------------------------------------------
    # Logging — MUST go to stderr; stdout is reserved for protocol.
    # ------------------------------------------------------------------

    def log(self, message: str) -> None:
        self._err.write(f"[zeropath-mcp] {message}\n")
        self._err.flush()
