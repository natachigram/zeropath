"""
MCP server test suite.

Coverage:
  - Protocol parsing + serialisation (newline-delimited JSON-RPC 2.0)
  - StdioTransport message I/O via in-memory pipes
  - MCPServer dispatch: initialize handshake, tools/list, tools/call,
    resources/list + read, prompts/list + get, error paths
  - Tool handlers: spec_mine, kg_summary, ingest_threat_intel,
    run_contest_pipeline, format_finding_for_platform,
    estimate_duplicate_likelihood, verify_foundry_poc (forge mocked)
  - Resource templates: zeropath://kg/findings/{id}
  - URI template matcher
  - Installer: writes Claude Code / Cursor / Continue configs (tmp HOME)
  - End-to-end: full client → server lifecycle via piped transport
"""

from __future__ import annotations

import json
import os
from io import StringIO
from pathlib import Path
from typing import Any

import pytest

from zeropath.mcp_server import (
    JsonRpcError,
    JsonRpcRequest,
    JsonRpcResponse,
    MCPServer,
    PROTOCOL_VERSION,
    Prompt,
    ProtocolError,
    Resource,
    ResourceTemplate,
    ServerState,
    SERVER_NAME,
    SERVER_VERSION,
    StdioTransport,
    SUPPORTED_CLIENTS,
    Tool,
    build_default_server,
    install_for_client,
    parse_message,
    register_default_tools,
    serialize,
    uninstall_for_client,
)
from zeropath.mcp_server.server import _match_template, _coerce_tool_content


# ===========================================================================
# Helpers
# ===========================================================================


class _Pipe:
    """In-memory stdio replacement for piped MCP tests."""

    def __init__(self) -> None:
        self.stdin = StringIO()
        self.stdout = StringIO()
        self.stderr = StringIO()

    def write_request(self, payload: dict) -> None:
        self.stdin.write(json.dumps(payload) + "\n")

    def rewind(self) -> None:
        self.stdin.seek(0)

    def read_responses(self) -> list[dict]:
        self.stdout.seek(0)
        return [
            json.loads(line) for line in self.stdout.read().splitlines() if line.strip()
        ]


def _mk_transport(pipe: _Pipe) -> StdioTransport:
    return StdioTransport(stdin=pipe.stdin, stdout=pipe.stdout, stderr=pipe.stderr)


# ===========================================================================
# Protocol layer
# ===========================================================================


class TestProtocolFraming:
    def test_round_trip(self):
        msg = {"jsonrpc": "2.0", "id": 1, "method": "ping", "params": {}}
        line = serialize(msg)
        assert line.endswith("\n")
        parsed = parse_message(line)
        assert parsed.method == "ping"
        assert parsed.id == 1

    def test_notification_has_no_id(self):
        parsed = parse_message(json.dumps({
            "jsonrpc": "2.0", "method": "notifications/initialized",
        }))
        assert parsed.is_notification is True
        assert parsed.id is None

    def test_parse_rejects_invalid_json(self):
        with pytest.raises(ProtocolError):
            parse_message("not json")

    def test_parse_rejects_wrong_version(self):
        with pytest.raises(ProtocolError):
            parse_message(json.dumps({
                "jsonrpc": "1.0", "id": 1, "method": "ping",
            }))

    def test_parse_rejects_missing_method(self):
        with pytest.raises(ProtocolError):
            parse_message(json.dumps({"jsonrpc": "2.0", "id": 1}))

    def test_parse_rejects_non_object(self):
        with pytest.raises(ProtocolError):
            parse_message(json.dumps(["a", "b"]))

    def test_request_to_dict_excludes_empty_params(self):
        req = JsonRpcRequest(method="ping", id=1)
        assert "params" not in req.to_dict()

    def test_error_to_dict_includes_optional_data(self):
        err = JsonRpcError(id=1, code=-32600, message="boom", data={"more": 1})
        d = err.to_dict()
        assert d["error"]["data"] == {"more": 1}


# ===========================================================================
# Transport
# ===========================================================================


class TestStdioTransport:
    def test_iter_messages_handles_empty_input(self):
        pipe = _Pipe()
        pipe.rewind()
        t = _mk_transport(pipe)
        msgs = list(t.iter_messages())
        assert msgs == []

    def test_iter_messages_yields_parse_errors(self):
        pipe = _Pipe()
        pipe.stdin.write("not-json\n")
        pipe.rewind()
        t = _mk_transport(pipe)
        out = list(t.iter_messages())
        assert len(out) == 1
        assert out[0].method == "__parse_error__"

    def test_send_response_writes_one_line(self):
        pipe = _Pipe()
        t = _mk_transport(pipe)
        t.send_response(JsonRpcResponse(id=1, result={"ok": True}))
        responses = pipe.read_responses()
        assert responses == [{"jsonrpc": "2.0", "id": 1, "result": {"ok": True}}]

    def test_log_writes_to_stderr_not_stdout(self):
        pipe = _Pipe()
        t = _mk_transport(pipe)
        t.log("hello")
        pipe.stdout.seek(0); pipe.stderr.seek(0)
        assert pipe.stdout.read() == ""
        assert "hello" in pipe.stderr.read()


# ===========================================================================
# URI template matcher
# ===========================================================================


class TestUriTemplateMatcher:
    def test_simple_match(self):
        params = _match_template(
            "zeropath://kg/findings/{id}",
            "zeropath://kg/findings/abc123",
        )
        assert params == {"id": "abc123"}

    def test_no_match_returns_none(self):
        assert _match_template(
            "zeropath://kg/findings/{id}",
            "zeropath://kg/incidents/abc",
        ) is None

    def test_two_placeholders(self):
        params = _match_template(
            "zeropath://kg/{label}/{id}",
            "zeropath://kg/findings/xyz",
        )
        assert params == {"label": "findings", "id": "xyz"}


# ===========================================================================
# Tool content coercion
# ===========================================================================


class TestToolContentCoercion:
    def test_string_pass_through(self):
        c = _coerce_tool_content("hi")
        assert c == [{"type": "text", "text": "hi"}]

    def test_dict_json_dumped(self):
        c = _coerce_tool_content({"a": 1})
        assert c[0]["type"] == "text"
        assert json.loads(c[0]["text"]) == {"a": 1}

    def test_list_json_dumped(self):
        c = _coerce_tool_content([1, 2, 3])
        assert json.loads(c[0]["text"]) == [1, 2, 3]


# ===========================================================================
# Server dispatch
# ===========================================================================


def _run_one_request(server: MCPServer, pipe: _Pipe, request: dict) -> dict:
    """Write one request, run the server until EOF, return its lone response."""
    pipe.write_request(request)
    pipe.rewind()
    server.serve_forever()
    responses = pipe.read_responses()
    assert len(responses) >= 1, f"no response from server. stderr={pipe.stderr.getvalue()}"
    return responses[-1]


class TestInitialize:
    def test_initialize_handshake(self):
        pipe = _Pipe()
        server = MCPServer(transport=_mk_transport(pipe))
        resp = _run_one_request(server, pipe, {
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {
                "protocolVersion": PROTOCOL_VERSION,
                "clientInfo": {"name": "test-client", "version": "0.0.0"},
                "capabilities": {},
            },
        })
        assert resp["id"] == 1
        result = resp["result"]
        assert result["protocolVersion"] == PROTOCOL_VERSION
        assert result["serverInfo"]["name"] == SERVER_NAME
        assert result["serverInfo"]["version"] == SERVER_VERSION

    def test_capabilities_reflect_registrations(self):
        pipe = _Pipe()
        server = MCPServer(transport=_mk_transport(pipe))
        server.add_tool(Tool(
            name="x", description="d", input_schema={"type": "object"},
            handler=lambda a: {"ok": True},
        ))
        resp = _run_one_request(server, pipe, {
            "jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {},
        })
        assert "tools" in resp["result"]["capabilities"]


class TestPing:
    def test_ping_returns_empty_object(self):
        pipe = _Pipe()
        server = MCPServer(transport=_mk_transport(pipe))
        resp = _run_one_request(server, pipe, {
            "jsonrpc": "2.0", "id": 2, "method": "ping", "params": {},
        })
        assert resp["result"] == {}


class TestUnknownMethod:
    def test_returns_method_not_found(self):
        pipe = _Pipe()
        server = MCPServer(transport=_mk_transport(pipe))
        resp = _run_one_request(server, pipe, {
            "jsonrpc": "2.0", "id": 99, "method": "does/not/exist", "params": {},
        })
        assert "error" in resp
        assert resp["error"]["code"] == -32601

    def test_unknown_notification_ignored_silently(self):
        pipe = _Pipe()
        server = MCPServer(transport=_mk_transport(pipe))
        pipe.write_request({"jsonrpc": "2.0", "method": "weird/notification"})
        pipe.rewind()
        server.serve_forever()
        assert pipe.read_responses() == []


class TestToolsList:
    def test_lists_registered_tools(self):
        pipe = _Pipe()
        server = MCPServer(transport=_mk_transport(pipe))
        server.add_tool(Tool(
            name="echo", description="echo", input_schema={"type": "object"},
            handler=lambda args: args.get("text", ""),
        ))
        resp = _run_one_request(server, pipe, {
            "jsonrpc": "2.0", "id": 3, "method": "tools/list", "params": {},
        })
        tools = resp["result"]["tools"]
        assert any(t["name"] == "echo" for t in tools)


class TestToolsCall:
    def test_calls_tool_and_coerces_output(self):
        pipe = _Pipe()
        server = MCPServer(transport=_mk_transport(pipe))
        server.add_tool(Tool(
            name="echo", description="d", input_schema={"type": "object"},
            handler=lambda args: {"echoed": args.get("text")},
        ))
        resp = _run_one_request(server, pipe, {
            "jsonrpc": "2.0", "id": 4, "method": "tools/call",
            "params": {"name": "echo", "arguments": {"text": "hi"}},
        })
        content = resp["result"]["content"]
        assert json.loads(content[0]["text"]) == {"echoed": "hi"}
        assert resp["result"]["isError"] is False

    def test_returns_tool_not_found(self):
        pipe = _Pipe()
        server = MCPServer(transport=_mk_transport(pipe))
        resp = _run_one_request(server, pipe, {
            "jsonrpc": "2.0", "id": 5, "method": "tools/call",
            "params": {"name": "nonexistent", "arguments": {}},
        })
        assert resp["error"]["code"] == -32002

    def test_tool_exception_returns_error(self):
        pipe = _Pipe()
        server = MCPServer(transport=_mk_transport(pipe))

        def boom(args):
            raise RuntimeError("expected")

        server.add_tool(Tool(name="boom", description="d",
                              input_schema={"type": "object"}, handler=boom))
        resp = _run_one_request(server, pipe, {
            "jsonrpc": "2.0", "id": 6, "method": "tools/call",
            "params": {"name": "boom", "arguments": {}},
        })
        assert "error" in resp
        assert resp["error"]["code"] == -32004
        assert "expected" in resp["error"]["message"]


class TestResources:
    def test_list_and_read(self):
        pipe = _Pipe()
        server = MCPServer(transport=_mk_transport(pipe))
        server.add_resource(Resource(
            uri="x://test", name="t", description="d",
            handler=lambda uri: {"ok": uri},
        ))
        # list
        resp = _run_one_request(server, pipe, {
            "jsonrpc": "2.0", "id": 7, "method": "resources/list", "params": {},
        })
        assert any(r["uri"] == "x://test" for r in resp["result"]["resources"])

    def test_resource_read(self):
        pipe = _Pipe()
        server = MCPServer(transport=_mk_transport(pipe))
        server.add_resource(Resource(
            uri="x://hello", name="t", description="d",
            handler=lambda uri: {"value": 42},
        ))
        resp = _run_one_request(server, pipe, {
            "jsonrpc": "2.0", "id": 8, "method": "resources/read",
            "params": {"uri": "x://hello"},
        })
        c = resp["result"]["contents"][0]
        assert c["uri"] == "x://hello"
        assert json.loads(c["text"]) == {"value": 42}

    def test_resource_template_dispatch(self):
        pipe = _Pipe()
        server = MCPServer(transport=_mk_transport(pipe))
        server.add_resource_template(ResourceTemplate(
            uri_template="x://item/{id}", name="t", description="d",
            handler=lambda uri, params: {"id": params["id"]},
        ))
        resp = _run_one_request(server, pipe, {
            "jsonrpc": "2.0", "id": 9, "method": "resources/read",
            "params": {"uri": "x://item/abc"},
        })
        c = resp["result"]["contents"][0]
        assert json.loads(c["text"])["id"] == "abc"

    def test_resource_not_found(self):
        pipe = _Pipe()
        server = MCPServer(transport=_mk_transport(pipe))
        resp = _run_one_request(server, pipe, {
            "jsonrpc": "2.0", "id": 10, "method": "resources/read",
            "params": {"uri": "x://missing"},
        })
        assert resp["error"]["code"] == -32001


class TestPrompts:
    def test_list_and_get(self):
        pipe = _Pipe()
        server = MCPServer(transport=_mk_transport(pipe))
        server.add_prompt(Prompt(
            name="x", description="d", arguments=[],
            handler=lambda args: [{
                "role": "user", "content": {"type": "text", "text": "hi"},
            }],
        ))
        resp = _run_one_request(server, pipe, {
            "jsonrpc": "2.0", "id": 11, "method": "prompts/get",
            "params": {"name": "x", "arguments": {}},
        })
        msgs = resp["result"]["messages"]
        assert msgs and msgs[0]["role"] == "user"

    def test_prompt_not_found(self):
        pipe = _Pipe()
        server = MCPServer(transport=_mk_transport(pipe))
        resp = _run_one_request(server, pipe, {
            "jsonrpc": "2.0", "id": 12, "method": "prompts/get",
            "params": {"name": "nope", "arguments": {}},
        })
        assert resp["error"]["code"] == -32003


class TestParseErrorHandling:
    def test_garbage_line_yields_parse_error_response(self):
        pipe = _Pipe()
        pipe.stdin.write("garbage\n")
        pipe.rewind()
        server = MCPServer(transport=_mk_transport(pipe))
        server.serve_forever()
        responses = pipe.read_responses()
        assert any(
            r.get("error", {}).get("code") == -32700 for r in responses
        )


# ===========================================================================
# Default server — every tool / resource / prompt wired
# ===========================================================================


class TestBuildDefaultServer:
    def test_includes_expected_tools(self):
        server = build_default_server()
        for tool_name in (
            "analyze_protocol", "infer_invariants", "mine_spec_claims",
            "verify_foundry_poc", "query_kg_similar_exploits",
            "query_kg_historical_grounding", "ingest_threat_intel",
            "ingest_defihacklabs_live", "kg_summary",
            "run_contest_pipeline", "format_finding_for_platform",
            "estimate_duplicate_likelihood",
        ):
            assert tool_name in server.tools, f"missing tool: {tool_name}"

    def test_includes_expected_resources(self):
        server = build_default_server()
        uris = set(server.resources.keys())
        assert "zeropath://kg/summary" in uris
        assert "zeropath://kg/findings" in uris
        assert "zeropath://kg/incidents" in uris
        assert "zeropath://graph/latest" in uris

    def test_includes_expected_prompts(self):
        server = build_default_server()
        assert "contest_audit" in server.prompts
        assert "spec_extract" in server.prompts
        assert "contrarian_review" in server.prompts


# ===========================================================================
# Tool handlers — direct invocation (no protocol overhead)
# ===========================================================================


class TestSpecMineTool:
    def test_mines_repo(self, tmp_path):
        (tmp_path / "Vault.sol").write_text(
            "/// @notice The owner MUST be set on deploy.\n"
            "contract Vault {}"
        )
        server = build_default_server(workspace_root=tmp_path)
        tool = server.tools["mine_spec_claims"]
        result = tool.handler({"repo_path": str(tmp_path)})
        assert result["ok"] is True
        assert result["claimed_invariants"]


class TestIngestThreatIntelTool:
    def test_ingests_into_in_memory_kg(self):
        server = build_default_server()
        tool = server.tools["ingest_threat_intel"]
        result = tool.handler({
            "source": "defihacklabs",
            "entries": [{"protocol": "Euler", "attack": "flash loan", "loss": "$197M"}],
        })
        assert result["ok"] is True
        assert result["ingested"] == 1

    def test_unknown_source_returns_error(self):
        server = build_default_server()
        tool = server.tools["ingest_threat_intel"]
        result = tool.handler({"source": "made_up_source", "entries": [{}]})
        assert result["ok"] is False


class TestKgSummaryTool:
    def test_returns_counts(self):
        server = build_default_server()
        # Ingest something so the summary is non-trivial.
        server.tools["ingest_threat_intel"].handler({
            "source": "defihacklabs",
            "entries": [{"protocol": "X", "attack": "oracle", "loss": "$10M"}],
        })
        result = server.tools["kg_summary"].handler({})
        assert result["ok"] is True
        assert result["incidents"] >= 1


class TestRunContestPipelineTool:
    def test_offline_run(self, tmp_path):
        (tmp_path / "Vault.sol").write_text(
            "/// @notice Withdraw MUST require a 48h delay.\n"
            "contract Vault {}"
        )
        server = build_default_server(workspace_root=tmp_path)
        result = server.tools["run_contest_pipeline"].handler({
            "repo_path": str(tmp_path),
            "platform": "cantina",
            "use_foundry_verifier": False,
        })
        assert result["ok"] is True
        assert "spec_claims_extracted" in result


class TestFormatFindingForPlatform:
    def test_renders_cantina(self):
        server = build_default_server()
        finding = {
            "title": "Reentrancy in withdraw",
            "severity": "high",
            "attack_class": "reentrancy",
            "description": "External call before state update.",
            "impact": "drain",
            "attack_path": ["a", "b"],
            "lines_of_code": ["src/V.sol#L1"],
            "confidence": 0.8,
        }
        result = server.tools["format_finding_for_platform"].handler({
            "platform": "cantina", "finding": finding,
        })
        assert result["ok"] is True
        assert result["rendered"]["title"] == "Reentrancy in withdraw"

    def test_missing_finding(self):
        server = build_default_server()
        result = server.tools["format_finding_for_platform"].handler({
            "platform": "cantina",
        })
        assert result["ok"] is False


class TestEstimateDuplicateLikelihoodTool:
    def test_returns_score(self):
        server = build_default_server()
        result = server.tools["estimate_duplicate_likelihood"].handler({
            "finding": {
                "title": "Reentrancy", "attack_class": "reentrancy",
                "severity": "high", "confidence": 0.8,
            },
        })
        assert result["ok"] is True
        assert 0.0 <= result["duplicate_likelihood"] <= 1.0


class TestVerifyFoundryPocTool:
    def test_missing_forge_returns_error(self, monkeypatch):
        monkeypatch.setattr("shutil.which", lambda b: None)
        server = build_default_server()
        result = server.tools["verify_foundry_poc"].handler({
            "test_code": "contract X {}",
            "test_filename": "X.t.sol",
        })
        assert result["ok"] is False
        assert "forge" in result["error"].lower()


# ===========================================================================
# Resource handlers
# ===========================================================================


class TestResourceHandlers:
    def test_kg_summary_resource(self):
        server = build_default_server()
        # Read via the handler directly.
        res = server.resources["zeropath://kg/summary"]
        payload = res.handler("zeropath://kg/summary")
        assert "exploits_ingested" in payload

    def test_protocol_graph_resource_handles_missing_state(self):
        server = build_default_server()
        res = server.resources["zeropath://graph/latest"]
        payload = res.handler("zeropath://graph/latest")
        assert "error" in payload

    def test_kg_finding_template_returns_error_for_unknown_id(self):
        server = build_default_server()
        tmpl = server._resource_templates[0]  # zeropath://kg/findings/{id}
        out = tmpl.handler("zeropath://kg/findings/nope", {"id": "nope"})
        assert "error" in out


# ===========================================================================
# Installer
# ===========================================================================


class TestInstaller:
    def test_install_claude_code_into_tmp_home(self, tmp_path, monkeypatch):
        monkeypatch.setenv("HOME", str(tmp_path))
        monkeypatch.setattr("zeropath.mcp_server.install._home", lambda: tmp_path)
        result = install_for_client("claude-code", python="/usr/bin/python3")
        assert result.written is True
        config = json.loads(result.config_path.read_text())
        assert "mcpServers" in config
        assert "zeropath" in config["mcpServers"]
        entry = config["mcpServers"]["zeropath"]
        assert entry["command"] == "/usr/bin/python3"
        assert "mcp" in entry["args"]
        assert "serve" in entry["args"]

    def test_install_is_idempotent(self, tmp_path, monkeypatch):
        monkeypatch.setattr("zeropath.mcp_server.install._home", lambda: tmp_path)
        first = install_for_client("cursor", python="/usr/bin/python3")
        second = install_for_client("cursor", python="/usr/bin/python3")
        assert first.written is True
        assert second.already_present is True

    def test_install_preserves_existing_servers(self, tmp_path, monkeypatch):
        monkeypatch.setattr("zeropath.mcp_server.install._home", lambda: tmp_path)
        # Pre-seed with another server entry.
        target = tmp_path / ".cursor" / "mcp.json"
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps({
            "mcpServers": {"other": {"command": "node", "args": ["foo.js"]}},
        }))
        install_for_client("cursor", python="/usr/bin/python3")
        merged = json.loads(target.read_text())
        assert "other" in merged["mcpServers"]
        assert "zeropath" in merged["mcpServers"]

    def test_install_dry_run_does_not_write(self, tmp_path, monkeypatch):
        monkeypatch.setattr("zeropath.mcp_server.install._home", lambda: tmp_path)
        result = install_for_client("cursor", python="/usr/bin/python3", dry_run=True)
        assert result.written is False
        assert not (tmp_path / ".cursor" / "mcp.json").exists()

    def test_uninstall_removes_entry(self, tmp_path, monkeypatch):
        monkeypatch.setattr("zeropath.mcp_server.install._home", lambda: tmp_path)
        install_for_client("cursor")
        result = uninstall_for_client("cursor")
        assert result.written is True
        merged = json.loads((tmp_path / ".cursor" / "mcp.json").read_text())
        assert "zeropath" not in merged.get("mcpServers", {})

    def test_unsupported_client(self):
        result = install_for_client("eclipse")
        assert result.written is False
        assert "unsupported" in (result.error or "")

    def test_supported_client_list_constant(self):
        # Sanity check the public constant matches what install actually supports.
        assert "claude-code" in SUPPORTED_CLIENTS
        assert "cursor" in SUPPORTED_CLIENTS
        assert "claude-desktop" in SUPPORTED_CLIENTS


# ===========================================================================
# Multi-message conversation
# ===========================================================================


class TestEndToEndConversation:
    def test_full_handshake_then_tools_list_then_tool_call(self):
        pipe = _Pipe()
        server = build_default_server(transport=_mk_transport(pipe))
        pipe.write_request({
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {"protocolVersion": PROTOCOL_VERSION,
                       "clientInfo": {"name": "t"}, "capabilities": {}},
        })
        pipe.write_request({
            "jsonrpc": "2.0", "method": "notifications/initialized",
        })
        pipe.write_request({
            "jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {},
        })
        pipe.write_request({
            "jsonrpc": "2.0", "id": 3, "method": "tools/call",
            "params": {"name": "kg_summary", "arguments": {}},
        })
        pipe.rewind()
        server.serve_forever()
        responses = pipe.read_responses()
        # We expect responses for ids 1, 2, 3 (the notification doesn't reply).
        ids = [r.get("id") for r in responses if "id" in r]
        assert 1 in ids and 2 in ids and 3 in ids
        # ID 3 is a kg_summary tool call → should be ok:true.
        kg_resp = next(r for r in responses if r.get("id") == 3)
        assert kg_resp["result"]["isError"] is False
        body = json.loads(kg_resp["result"]["content"][0]["text"])
        assert body["ok"] is True
