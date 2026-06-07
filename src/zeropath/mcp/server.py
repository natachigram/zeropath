"""Evidence-first MCP server wrapper."""

from __future__ import annotations

from pathlib import Path

from zeropath.mcp.tools import EvidenceMCPState, register_evidence_tools
from zeropath.mcp_server.server import MCPServer


def build_server(workspace_root: str | Path = ".") -> MCPServer:
    """Build an MCP server exposing evidence-first ZeroPath tools."""

    server = MCPServer(name="zeropath-evidence", version="0.1.0")
    state = EvidenceMCPState(workspace_root=Path(workspace_root).resolve())
    register_evidence_tools(server, state)
    return server


def serve_stdio(workspace_root: str | Path = ".") -> None:
    """Run the evidence-first MCP server over stdio."""

    build_server(workspace_root).serve_forever()
