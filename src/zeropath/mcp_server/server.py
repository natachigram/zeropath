"""
MCP server — dispatcher + handshake.

Implements the Model Context Protocol over stdio. Routes JSON-RPC requests
to registered tool / resource / prompt handlers.

The server is *single-threaded* — it processes one request at a time off
the stdio pipe. That's fine for the IDE-driven workflow: the agent waits
for each tool result before issuing the next call. If long-running tools
(forge build, parallel audit) become a bottleneck, we can spawn a worker
pool later without changing the protocol surface.
"""

from __future__ import annotations

import logging
import traceback
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

from zeropath.mcp_server.protocol import (
    INTERNAL_ERROR,
    INVALID_PARAMS,
    INVALID_REQUEST,
    METHOD_NOT_FOUND,
    PARSE_ERROR,
    PROMPT_NOT_FOUND,
    PROTOCOL_VERSION,
    RESOURCE_NOT_FOUND,
    TOOL_EXECUTION_ERROR,
    TOOL_NOT_FOUND,
    JsonRpcError,
    JsonRpcRequest,
    JsonRpcResponse,
    ProtocolError,
    StdioTransport,
)

logger = logging.getLogger(__name__)


SERVER_NAME = "zeropath"
SERVER_VERSION = "1.0.0"


# ---------------------------------------------------------------------------
# Tool / Resource / Prompt registries
# ---------------------------------------------------------------------------


@dataclass
class Tool:
    """One callable tool exposed to the IDE agent."""

    name: str
    description: str
    input_schema: dict[str, Any]
    handler: Callable[[dict[str, Any]], Any]


@dataclass
class Resource:
    """One readable resource (file-like data) exposed to the IDE agent."""

    uri: str
    name: str
    description: str
    mime_type: str = "application/json"
    handler: Callable[[str], Any] = lambda uri: None


@dataclass
class ResourceTemplate:
    """A URI template that can resolve dynamic resource URIs."""

    uri_template: str
    name: str
    description: str
    mime_type: str = "application/json"
    handler: Callable[[str, dict[str, str]], Any] = lambda uri, params: None


@dataclass
class Prompt:
    """A pre-built prompt template the IDE agent can invoke."""

    name: str
    description: str
    arguments: list[dict[str, Any]] = field(default_factory=list)
    handler: Callable[[dict[str, Any]], list[dict[str, Any]]] = lambda args: []


# ---------------------------------------------------------------------------
# Server
# ---------------------------------------------------------------------------


class MCPServer:
    """
    Model Context Protocol server speaking stdio JSON-RPC.

    Construction registers nothing by default — use :meth:`add_tool`,
    :meth:`add_resource`, :meth:`add_prompt` to populate the registries.
    The :mod:`zeropath.mcp_server` package provides ``build_default_server``
    that wires every ZeroPath capability up at once.
    """

    def __init__(
        self,
        *,
        name: str = SERVER_NAME,
        version: str = SERVER_VERSION,
        transport: Optional[StdioTransport] = None,
    ) -> None:
        self.name = name
        self.version = version
        self.transport = transport or StdioTransport()
        self._initialized = False
        self._tools: dict[str, Tool] = {}
        self._resources: dict[str, Resource] = {}
        self._resource_templates: list[ResourceTemplate] = []
        self._prompts: dict[str, Prompt] = {}

    # ------------------------------------------------------------------
    # Registration
    # ------------------------------------------------------------------

    def add_tool(self, tool: Tool) -> None:
        self._tools[tool.name] = tool

    def add_resource(self, resource: Resource) -> None:
        self._resources[resource.uri] = resource

    def add_resource_template(self, template: ResourceTemplate) -> None:
        self._resource_templates.append(template)

    def add_prompt(self, prompt: Prompt) -> None:
        self._prompts[prompt.name] = prompt

    # ------------------------------------------------------------------
    # Public diagnostics
    # ------------------------------------------------------------------

    @property
    def tools(self) -> dict[str, Tool]:
        return dict(self._tools)

    @property
    def resources(self) -> dict[str, Resource]:
        return dict(self._resources)

    @property
    def prompts(self) -> dict[str, Prompt]:
        return dict(self._prompts)

    # ------------------------------------------------------------------
    # Main loop
    # ------------------------------------------------------------------

    def serve_forever(self) -> None:
        """Block, reading + dispatching JSON-RPC requests until EOF."""
        self.transport.log(
            f"server starting (tools={len(self._tools)}, "
            f"resources={len(self._resources)}, prompts={len(self._prompts)})"
        )
        for req in self.transport.iter_messages():
            try:
                self._dispatch(req)
            except Exception as exc:
                # Defensive: catch ANY unhandled error so the pipe stays open.
                self.transport.log(
                    f"unhandled error processing {req.method}: {exc}\n"
                    f"{traceback.format_exc()}"
                )
                if not req.is_notification:
                    self.transport.send_error(JsonRpcError(
                        id=req.id, code=INTERNAL_ERROR,
                        message=f"internal error: {exc}",
                    ))
        self.transport.log("server stopped (EOF on stdin)")

    # ------------------------------------------------------------------
    # Dispatch
    # ------------------------------------------------------------------

    def _dispatch(self, req: JsonRpcRequest) -> None:
        if req.method == "__parse_error__":
            self.transport.send_error(JsonRpcError(
                id=None, code=PARSE_ERROR,
                message=req.params.get("error", "parse error"),
            ))
            return

        # Standard MCP methods
        if req.method == "initialize":
            self._handle_initialize(req)
            return
        if req.method == "notifications/initialized":
            self._initialized = True
            return
        if req.method == "ping":
            self._reply(req, {})
            return
        if req.method == "shutdown":
            self._reply(req, {})
            return

        # Tools
        if req.method == "tools/list":
            self._reply(req, {"tools": self._list_tools()})
            return
        if req.method == "tools/call":
            self._handle_tool_call(req)
            return

        # Resources
        if req.method == "resources/list":
            self._reply(req, {"resources": self._list_resources()})
            return
        if req.method == "resources/templates/list":
            self._reply(req, {"resourceTemplates": self._list_templates()})
            return
        if req.method == "resources/read":
            self._handle_resource_read(req)
            return

        # Prompts
        if req.method == "prompts/list":
            self._reply(req, {"prompts": self._list_prompts()})
            return
        if req.method == "prompts/get":
            self._handle_prompt_get(req)
            return

        if req.is_notification:
            # Unknown notifications are silently ignored per spec.
            return

        self.transport.send_error(JsonRpcError(
            id=req.id, code=METHOD_NOT_FOUND,
            message=f"unknown method: {req.method}",
        ))

    # ------------------------------------------------------------------
    # initialize
    # ------------------------------------------------------------------

    def _handle_initialize(self, req: JsonRpcRequest) -> None:
        client = req.params.get("clientInfo") or {}
        protocol = req.params.get("protocolVersion", PROTOCOL_VERSION)
        capabilities: dict[str, Any] = {}
        if self._tools:
            capabilities["tools"] = {"listChanged": False}
        if self._resources or self._resource_templates:
            capabilities["resources"] = {"subscribe": False, "listChanged": False}
        if self._prompts:
            capabilities["prompts"] = {"listChanged": False}
        result = {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": capabilities,
            "serverInfo": {"name": self.name, "version": self.version},
            "instructions": (
                "ZeroPath autonomous-security-research MCP server. "
                "Call tools/list to see every available capability. "
                "Phase 1-10 deterministic pipeline + contest-mode formatter "
                "+ Phase 8 knowledge-graph queries are all exposed as tools."
            ),
        }
        self.transport.log(
            f"initialize from client={client.get('name', '?')} "
            f"proto={protocol}"
        )
        self._reply(req, result)

    # ------------------------------------------------------------------
    # tools/*
    # ------------------------------------------------------------------

    def _list_tools(self) -> list[dict[str, Any]]:
        return [
            {
                "name": t.name,
                "description": t.description,
                "inputSchema": t.input_schema,
            }
            for t in self._tools.values()
        ]

    def _handle_tool_call(self, req: JsonRpcRequest) -> None:
        name = req.params.get("name")
        if not name or not isinstance(name, str):
            self._error(req, INVALID_PARAMS, "tool name is required")
            return
        tool = self._tools.get(name)
        if tool is None:
            self._error(req, TOOL_NOT_FOUND, f"unknown tool: {name}")
            return
        arguments = req.params.get("arguments") or {}
        if not isinstance(arguments, dict):
            self._error(req, INVALID_PARAMS, "arguments must be an object")
            return
        try:
            result = tool.handler(arguments)
        except Exception as exc:
            self.transport.log(
                f"tool {name} failed: {exc}\n{traceback.format_exc()}"
            )
            self._error(req, TOOL_EXECUTION_ERROR, f"tool {name} failed: {exc}")
            return
        # Coerce arbitrary handler outputs into the MCP content shape.
        content = _coerce_tool_content(result)
        self._reply(req, {"content": content, "isError": False})

    # ------------------------------------------------------------------
    # resources/*
    # ------------------------------------------------------------------

    def _list_resources(self) -> list[dict[str, Any]]:
        return [
            {
                "uri": r.uri,
                "name": r.name,
                "description": r.description,
                "mimeType": r.mime_type,
            }
            for r in self._resources.values()
        ]

    def _list_templates(self) -> list[dict[str, Any]]:
        return [
            {
                "uriTemplate": t.uri_template,
                "name": t.name,
                "description": t.description,
                "mimeType": t.mime_type,
            }
            for t in self._resource_templates
        ]

    def _handle_resource_read(self, req: JsonRpcRequest) -> None:
        uri = req.params.get("uri")
        if not uri or not isinstance(uri, str):
            self._error(req, INVALID_PARAMS, "uri is required")
            return

        # Direct match
        resource = self._resources.get(uri)
        if resource is not None:
            try:
                payload = resource.handler(uri)
            except Exception as exc:
                self._error(req, INTERNAL_ERROR, f"resource read failed: {exc}")
                return
            self._reply(req, {"contents": [_coerce_resource_content(uri, resource.mime_type, payload)]})
            return

        # Template match
        for tmpl in self._resource_templates:
            params = _match_template(tmpl.uri_template, uri)
            if params is None:
                continue
            try:
                payload = tmpl.handler(uri, params)
            except Exception as exc:
                self._error(req, INTERNAL_ERROR, f"resource read failed: {exc}")
                return
            self._reply(req, {"contents": [_coerce_resource_content(uri, tmpl.mime_type, payload)]})
            return

        self._error(req, RESOURCE_NOT_FOUND, f"unknown resource: {uri}")

    # ------------------------------------------------------------------
    # prompts/*
    # ------------------------------------------------------------------

    def _list_prompts(self) -> list[dict[str, Any]]:
        return [
            {
                "name": p.name,
                "description": p.description,
                "arguments": p.arguments,
            }
            for p in self._prompts.values()
        ]

    def _handle_prompt_get(self, req: JsonRpcRequest) -> None:
        name = req.params.get("name")
        if not name or not isinstance(name, str):
            self._error(req, INVALID_PARAMS, "prompt name is required")
            return
        prompt = self._prompts.get(name)
        if prompt is None:
            self._error(req, PROMPT_NOT_FOUND, f"unknown prompt: {name}")
            return
        args = req.params.get("arguments") or {}
        try:
            messages = prompt.handler(args) or []
        except Exception as exc:
            self._error(req, INTERNAL_ERROR, f"prompt failed: {exc}")
            return
        self._reply(req, {
            "description": prompt.description,
            "messages": messages,
        })

    # ------------------------------------------------------------------
    # Reply helpers
    # ------------------------------------------------------------------

    def _reply(self, req: JsonRpcRequest, result: Any) -> None:
        if req.is_notification:
            return
        self.transport.send_response(JsonRpcResponse(id=req.id, result=result))

    def _error(self, req: JsonRpcRequest, code: int, message: str) -> None:
        if req.is_notification:
            return
        self.transport.send_error(JsonRpcError(id=req.id, code=code, message=message))


# ---------------------------------------------------------------------------
# Content coercion helpers
# ---------------------------------------------------------------------------


def _coerce_tool_content(value: Any) -> list[dict[str, Any]]:
    """
    Coerce arbitrary handler output into MCP tool ``content`` blocks.

    Strings → text content. Dicts / lists → JSON-formatted text content.
    Bytes → text fallback (we don't ship binary tool outputs).
    """
    import json
    if isinstance(value, str):
        return [{"type": "text", "text": value}]
    if isinstance(value, (dict, list)):
        return [{
            "type": "text",
            "text": json.dumps(value, indent=2, default=str),
        }]
    if isinstance(value, bytes):
        return [{"type": "text", "text": value.decode("utf-8", errors="replace")}]
    return [{"type": "text", "text": str(value)}]


def _coerce_resource_content(
    uri: str, mime_type: str, value: Any,
) -> dict[str, Any]:
    import json
    if isinstance(value, str):
        return {"uri": uri, "mimeType": mime_type, "text": value}
    if isinstance(value, (dict, list)):
        return {
            "uri": uri,
            "mimeType": mime_type,
            "text": json.dumps(value, indent=2, default=str),
        }
    return {"uri": uri, "mimeType": mime_type, "text": str(value)}


# ---------------------------------------------------------------------------
# Template matching
# ---------------------------------------------------------------------------


def _match_template(template: str, uri: str) -> Optional[dict[str, str]]:
    """
    Very-small URI-template matcher.

    Supports ``{var}`` placeholders only. e.g.
        template "zeropath://kg/findings/{id}"
        uri      "zeropath://kg/findings/abc123"
        → {"id": "abc123"}
    """
    import re

    pattern = re.escape(template)
    pattern = pattern.replace(r"\{", "{").replace(r"\}", "}")
    var_names: list[str] = []

    def _sub(m: re.Match) -> str:
        var_names.append(m.group(1))
        return r"(?P<" + m.group(1) + r">[^/]+)"

    regex = re.sub(r"\{(\w+)\}", _sub, pattern)
    regex = "^" + regex + "$"
    match = re.match(regex, uri)
    if match is None:
        return None
    return {name: match.group(name) for name in var_names}
