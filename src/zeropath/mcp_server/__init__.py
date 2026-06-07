"""
ZeroPath MCP server — expose Phase 1-10 + contest mode + KG queries as
Model Context Protocol tools / resources / prompts for any MCP-compatible
IDE (Claude Code, Claude Desktop, Cursor, Cline, Continue, Zed, Windsurf,
ChatGPT Desktop).

Public API::

    from zeropath.mcp_server import build_default_server

    server = build_default_server(kg_dir=Path("./kg"))
    server.serve_forever()

Or via the CLI::

    zeropath mcp install --client claude-code
    zeropath mcp serve              # invoked by the IDE
    zeropath mcp tools              # list every exposed tool
"""

from pathlib import Path
from typing import Optional

from zeropath.mcp_server.install import (
    SUPPORTED_CLIENTS,
    InstallResult,
    install_for_all,
    install_for_client,
    uninstall_for_client,
)
from zeropath.mcp_server.prompts import register_default_prompts
from zeropath.mcp_server.protocol import (
    PROTOCOL_VERSION,
    JsonRpcError,
    JsonRpcRequest,
    JsonRpcResponse,
    ProtocolError,
    StdioTransport,
    parse_message,
    serialize,
)
from zeropath.mcp_server.resources import register_default_resources
from zeropath.mcp_server.server import (
    MCPServer,
    Prompt,
    Resource,
    ResourceTemplate,
    SERVER_NAME,
    SERVER_VERSION,
    Tool,
)
from zeropath.mcp_server.tools import ServerState, register_default_tools


def build_default_server(
    *,
    kg_dir: Optional[Path] = None,
    workspace_root: Optional[Path] = None,
    transport: Optional[StdioTransport] = None,
) -> MCPServer:
    """
    Construct a fully-wired MCP server with every default tool / resource
    / prompt registered.

    Parameters
    ----------
    kg_dir : Path | None
        Directory containing a Phase 8 ``kg.json`` snapshot — enables RAG
        + duplicate-likelihood scoring across sessions.
    workspace_root : Path | None
        Default root used by tools that take a ``repo_path`` argument when
        the agent omits one. Defaults to cwd.
    transport : StdioTransport | None
        Override the I/O transport (used by tests).
    """
    workspace = workspace_root or Path.cwd()
    state = ServerState(
        kg_dir=kg_dir,
        workspace_root=workspace,
    )
    server = MCPServer(transport=transport)
    register_default_tools(server, state)
    from zeropath.mcp.tools import EvidenceMCPState, register_evidence_tools

    register_evidence_tools(
        server,
        EvidenceMCPState(workspace_root=workspace.resolve()),
    )
    register_default_resources(server, state)
    register_default_prompts(server)
    return server


__all__ = [
    # Builder
    "build_default_server",
    # Server primitives
    "MCPServer", "Tool", "Resource", "ResourceTemplate", "Prompt",
    "ServerState",
    "SERVER_NAME", "SERVER_VERSION",
    # Protocol
    "StdioTransport", "JsonRpcRequest", "JsonRpcResponse", "JsonRpcError",
    "ProtocolError", "parse_message", "serialize", "PROTOCOL_VERSION",
    # Installer
    "install_for_client", "install_for_all", "uninstall_for_client",
    "InstallResult", "SUPPORTED_CLIENTS",
    # Default registration helpers (exposed for advanced custom servers)
    "register_default_tools", "register_default_resources",
    "register_default_prompts",
]
