"""Evidence-first MCP tool handlers."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from zeropath.mcp.permissions import log_tool_call, require_write, workspace_path
from zeropath.mcp.schemas import EMPTY_INPUT, WRITE_MODE, object_schema
from zeropath.mcp_server.server import Tool


@dataclass
class EvidenceMCPState:
    workspace_root: Path

    def repo(self, args: dict[str, Any] | None = None) -> Path:
        args = args or {}
        path = args.get("repo_path") or args.get("repo") or self.workspace_root
        return workspace_path(path, self.workspace_root)


def register_evidence_tools(server, state: EvidenceMCPState) -> None:
    for tool in build_evidence_tools(state):
        server.add_tool(tool)


def build_evidence_tools(state: EvidenceMCPState) -> list[Tool]:
    return [
        _project_status(state),
        _ingest_repo(state),
        _get_protocol_intent(state),
        _get_critical_invariants(state),
        _get_asset_flow(state),
        _generate_attack_hypotheses(state),
        _get_candidate(state),
        _update_candidate_evidence(state),
        _build_state_plan(state),
        _generate_foundry_poc(state),
        _run_poc(state),
        _judge_candidate(state),
        _export_report(state),
        _memory_search(state),
        _memory_write_proposal(state),
        _memory_mark_stale(state),
    ]


def _ok(**fields: Any) -> dict[str, Any]:
    out = {"ok": True}
    out.update(fields)
    return out


def _err(message: str, **fields: Any) -> dict[str, Any]:
    out = {"ok": False, "error": message}
    out.update(fields)
    return out


def _storage(repo: Path):
    from zeropath.core.storage import Storage

    return Storage(repo)


def _project_status(state: EvidenceMCPState) -> Tool:
    def handler(args: dict[str, Any]) -> dict[str, Any]:
        repo = state.repo(args)
        log_tool_call(repo, "zeropath_project_status", args)
        try:
            return _ok(status=_storage(repo).status_summary())
        except Exception as exc:
            return _err(str(exc))

    return Tool(
        name="zeropath_project_status",
        description="Return current adapter, project status, candidate counts, memory counts, and last judge result.",
        input_schema=object_schema({"repo_path": {"type": "string"}}),
        handler=handler,
    )


def _ingest_repo(state: EvidenceMCPState) -> Tool:
    def handler(args: dict[str, Any]) -> dict[str, Any]:
        if not require_write(args):
            return _err("write_mode=true is required to ingest and mutate .zeropath state")
        repo = state.repo(args)
        log_tool_call(repo, "zeropath_ingest_repo", args)
        try:
            from zeropath.adapters.evm import EVMAdapter
            from zeropath.core.project import create_project_config, detect_adapter

            storage = _storage(repo)
            if not storage.initialized:
                detection = detect_adapter(repo)
                storage.initialize(create_project_config(repo, detection))
            config = storage.load_project_config()
            config.docs_paths = [str(path) for path in args.get("docs_paths", [])]
            config.scope_files = [str(path) for path in args.get("scope_files", [])]
            if config.adapter != "evm":
                return _err(f"no stable ingest adapter for {config.adapter}")
            index = EVMAdapter(repo).ingest_project(config)
            config.source_paths = [item["path"] for item in index.get("files", [])]
            storage.save_project_config(config)
            storage.save_record("ingest", "evm_index", index)
            return _ok(summary={
                "adapter": "evm",
                "files": len(index.get("files", [])),
                "contracts": len(index.get("contracts", [])),
                "functions": len(index.get("functions", [])),
                "protocol_type": index.get("protocol_type", "unknown"),
            })
        except Exception as exc:
            return _err(str(exc))

    return Tool(
        name="zeropath_ingest_repo",
        description="Index a repo through the detected adapter. Produces project evidence only, not findings. Requires write_mode=true.",
        input_schema=object_schema({
            "repo_path": {"type": "string"},
            "docs_paths": {"type": "array", "items": {"type": "string"}},
            "scope_files": {"type": "array", "items": {"type": "string"}},
            **WRITE_MODE,
        }),
        handler=handler,
    )


def _get_protocol_intent(state: EvidenceMCPState) -> Tool:
    def handler(args: dict[str, Any]) -> dict[str, Any]:
        repo = state.repo(args)
        log_tool_call(repo, "zeropath_get_protocol_intent", args)
        try:
            intent = _storage(repo).load_protocol_intent()
            return _ok(protocol_intent=intent.model_dump(mode="json") if intent else None)
        except Exception as exc:
            return _err(str(exc))

    return Tool("zeropath_get_protocol_intent", "Return ProtocolIntent JSON for the current project.", object_schema({"repo_path": {"type": "string"}}), handler)


def _get_critical_invariants(state: EvidenceMCPState) -> Tool:
    def handler(args: dict[str, Any]) -> dict[str, Any]:
        repo = state.repo(args)
        log_tool_call(repo, "zeropath_get_critical_invariants", args)
        try:
            intent = _storage(repo).load_protocol_intent()
            return _ok(invariants=[item.model_dump(mode="json") for item in intent.critical_invariants] if intent else [])
        except Exception as exc:
            return _err(str(exc))

    return Tool("zeropath_get_critical_invariants", "Return critical invariant suggestions from ProtocolIntent.", object_schema({"repo_path": {"type": "string"}}), handler)


def _get_asset_flow(state: EvidenceMCPState) -> Tool:
    def handler(args: dict[str, Any]) -> dict[str, Any]:
        repo = state.repo(args)
        log_tool_call(repo, "zeropath_get_asset_flow", args)
        try:
            index = _storage(repo).load_record("ingest", "evm_index") or {}
            flows = index.get("asset_flows", [])
            contract = args.get("contract")
            function = args.get("function")
            if contract:
                flows = [flow for flow in flows if flow.get("contract") == contract]
            if function:
                flows = [flow for flow in flows if flow.get("function") == function or flow.get("keyword") == function]
            return _ok(asset_flows=flows)
        except Exception as exc:
            return _err(str(exc))

    return Tool("zeropath_get_asset_flow", "Return asset-flow heuristic hits if the adapter supports them.", object_schema({"repo_path": {"type": "string"}, "contract": {"type": "string"}, "function": {"type": "string"}}), handler)


def _generate_attack_hypotheses(state: EvidenceMCPState) -> Tool:
    def handler(args: dict[str, Any]) -> dict[str, Any]:
        if not require_write(args):
            return _err("write_mode=true is required to persist generated candidate hypotheses")
        repo = state.repo(args)
        log_tool_call(repo, "zeropath_generate_attack_hypotheses", args)
        try:
            from zeropath.core.candidates import generate_candidates

            candidates = generate_candidates(
                _storage(repo),
                mode=args.get("mode", "critical"),
                limit=int(args.get("limit", 5)),
                focus=args.get("focus"),
            )
            return _ok(candidates=[candidate.model_dump(mode="json") for candidate in candidates])
        except Exception as exc:
            return _err(str(exc))

    return Tool(
        "zeropath_generate_attack_hypotheses",
        "Produce hypotheses, not final findings. Do not report directly without zeropath_judge_candidate. Requires write_mode=true.",
        object_schema({
            "repo_path": {"type": "string"},
            "mode": {"type": "string", "enum": ["critical", "high-medium", "qa"]},
            "limit": {"type": "integer"},
            "focus": {"type": "string"},
            **WRITE_MODE,
        }),
        handler,
    )


def _get_candidate(state: EvidenceMCPState) -> Tool:
    def handler(args: dict[str, Any]) -> dict[str, Any]:
        repo = state.repo(args)
        log_tool_call(repo, "zeropath_get_candidate", args)
        candidate = _storage(repo).load_candidate(args["candidate_id"])
        return _ok(candidate=candidate.model_dump(mode="json") if candidate else None)

    return Tool("zeropath_get_candidate", "Return one CandidateFinding.", object_schema({"repo_path": {"type": "string"}, "candidate_id": {"type": "string"}}, ["candidate_id"]), handler)


def _update_candidate_evidence(state: EvidenceMCPState) -> Tool:
    def handler(args: dict[str, Any]) -> dict[str, Any]:
        if not require_write(args):
            return _err("write_mode=true is required to update candidate evidence")
        repo = state.repo(args)
        log_tool_call(repo, "zeropath_update_candidate_evidence", args)
        try:
            from zeropath.core.candidates import update_candidate_evidence
            from zeropath.core.evidence import evidence_score, missing_evidence

            candidate = update_candidate_evidence(
                _storage(repo),
                args["candidate_id"],
                root_cause_lines_present=bool(args.get("root_cause_lines_present")),
                attacker_path_present=bool(args.get("attacker_path_present")),
                state_preconditions_present=bool(args.get("state_preconditions_present")),
                known_issues_checked=bool(args.get("known_issues_checked")),
                duplicate_risk_checked=bool(args.get("duplicate_risk_checked")),
                live_config_checked=bool(args.get("live_config_checked")),
                duplicate_risk=args.get("duplicate_risk"),
                known_issue_risk=args.get("known_issue_risk"),
                chain_id=args.get("chain_id"),
                fork_block=args.get("fork_block"),
                poc_path=args.get("poc_path"),
                trace_path=args.get("trace_path"),
                forge_result=args.get("forge_result"),
                invariant_test_result=args.get("invariant_test_result"),
                impact_measured=bool(args.get("impact_measured")),
                profit_measured=bool(args.get("profit_measured")),
                amount=args.get("amount"),
                notes=args.get("notes") or [],
                note=args.get("note"),
            )
            return _ok(
                candidate=candidate.model_dump(mode="json"),
                evidence_score=evidence_score(candidate.evidence),
                missing_evidence=missing_evidence(candidate.evidence),
            )
        except Exception as exc:
            return _err(str(exc))

    return Tool(
        "zeropath_update_candidate_evidence",
        "Record concrete evidence and triage facts for a candidate. Requires write_mode=true.",
        object_schema({
            "repo_path": {"type": "string"},
            "candidate_id": {"type": "string"},
            "root_cause_lines_present": {"type": "boolean"},
            "attacker_path_present": {"type": "boolean"},
            "state_preconditions_present": {"type": "boolean"},
            "known_issues_checked": {"type": "boolean"},
            "duplicate_risk_checked": {"type": "boolean"},
            "live_config_checked": {"type": "boolean"},
            "duplicate_risk": {"type": "string", "enum": ["none", "low", "medium", "high"]},
            "known_issue_risk": {"type": "string", "enum": ["none", "low", "medium", "high"]},
            "chain_id": {"type": "integer"},
            "fork_block": {"type": "integer"},
            "poc_path": {"type": "string"},
            "trace_path": {"type": "string"},
            "forge_result": {"type": "string"},
            "invariant_test_result": {"type": "string"},
            "impact_measured": {"type": "boolean"},
            "profit_measured": {"type": "boolean"},
            "amount": {"type": "string"},
            "note": {"type": "string"},
            "notes": {"type": "array", "items": {"type": "string"}},
            **WRITE_MODE,
        }, ["candidate_id"]),
        handler,
    )


def _build_state_plan(state: EvidenceMCPState) -> Tool:
    def handler(args: dict[str, Any]) -> dict[str, Any]:
        repo = state.repo(args)
        log_tool_call(repo, "zeropath_build_state_plan", args)
        try:
            from zeropath.core.state_plan import build_candidate_state_plan

            plan = build_candidate_state_plan(
                _storage(repo),
                args["candidate_id"],
                persist=require_write(args),
            )
            return _ok(state_plan=plan.model_dump(mode="json"))
        except Exception as exc:
            return _err(str(exc))

    return Tool(
        "zeropath_build_state_plan",
        "Return required state, setup steps, and missing dependencies for a candidate. Persists only with write_mode=true.",
        object_schema({"repo_path": {"type": "string"}, "candidate_id": {"type": "string"}, **WRITE_MODE}, ["candidate_id"]),
        handler,
    )


def _generate_foundry_poc(state: EvidenceMCPState) -> Tool:
    def handler(args: dict[str, Any]) -> dict[str, Any]:
        if not require_write(args):
            return _err("write_mode=true is required to write PoC artifacts")
        repo = state.repo(args)
        log_tool_call(repo, "zeropath_generate_foundry_poc", args)
        try:
            from zeropath.adapters.evm import EVMAdapter
            from zeropath.adapters.evm.foundry import write_candidate_test

            storage = _storage(repo)
            candidate = storage.load_candidate(args["candidate_id"])
            if not candidate:
                return _err("candidate not found")
            poc = EVMAdapter(repo).generate_poc(candidate)
            path = storage.append_artifact(Path("pocs") / f"{candidate.id.replace('-', '_')}.t.sol", poc or "", overwrite=True)
            candidate.evidence.poc_path = str(path)
            candidate.status = "poc_generated"
            poc_write_mode = args.get("write_mode_kind") or args.get("write_mode") or "artifact_only"
            if poc_write_mode == "test_dir":
                test_path = write_candidate_test(repo, candidate, force=bool(args.get("force")))
                candidate.evidence.notes.append(f"Foundry test written to {test_path}")
            storage.save_candidate(candidate)
            return _ok(poc_path=str(path))
        except Exception as exc:
            return _err(str(exc))

    return Tool(
        "zeropath_generate_foundry_poc",
        "Generate a useful Foundry PoC skeleton for a candidate. Requires write_mode=true.",
        object_schema({
            "repo_path": {"type": "string"},
            "candidate_id": {"type": "string"},
            "write_mode": {"type": "string", "enum": ["artifact_only", "test_dir"]},
            "force": {"type": "boolean"},
        }, ["candidate_id"]),
        handler,
    )


def _run_poc(state: EvidenceMCPState) -> Tool:
    def handler(args: dict[str, Any]) -> dict[str, Any]:
        if not require_write(args):
            return _err("write_mode=true is required to update proof evidence")
        repo = state.repo(args)
        log_tool_call(repo, "zeropath_run_poc", args)
        try:
            from zeropath.adapters.evm.forge import run_forge_test

            storage = _storage(repo)
            candidate = storage.load_candidate(args["candidate_id"])
            if not candidate:
                return _err("candidate not found")
            if args.get("backend", "foundry") != "foundry":
                return _err("only foundry backend is currently supported")
            result = run_forge_test(repo)
            candidate.evidence.forge_result = result.get("status")
            candidate.evidence.notes.append(result.get("message") or f"forge test status: {result.get('status')}")
            if result.get("status") == "passed":
                candidate.status = "poc_passed"
            storage.save_candidate(candidate)
            return _ok(result=result, candidate=candidate.model_dump(mode="json"))
        except Exception as exc:
            return _err(str(exc))

    return Tool("zeropath_run_poc", "Run a candidate PoC backend and update evidence. Requires write_mode=true.", object_schema({"repo_path": {"type": "string"}, "candidate_id": {"type": "string"}, "backend": {"type": "string"}, **WRITE_MODE}, ["candidate_id"]), handler)


def _judge_candidate(state: EvidenceMCPState) -> Tool:
    def handler(args: dict[str, Any]) -> dict[str, Any]:
        if not require_write(args):
            return _err("write_mode=true is required to persist judge results")
        repo = state.repo(args)
        log_tool_call(repo, "zeropath_judge_candidate", args)
        try:
            from zeropath.core.judge import judge_candidate

            storage = _storage(repo)
            candidate = storage.load_candidate(args["candidate_id"])
            if not candidate:
                return _err("candidate not found")
            result = judge_candidate(candidate, storage)
            return _ok(judge=result.model_dump(mode="json"))
        except Exception as exc:
            return _err(str(exc))

    return Tool("zeropath_judge_candidate", "Run skeptical judge checks and return JudgeResult. Requires write_mode=true.", object_schema({"repo_path": {"type": "string"}, "candidate_id": {"type": "string"}, **WRITE_MODE}, ["candidate_id"]), handler)


def _export_report(state: EvidenceMCPState) -> Tool:
    def handler(args: dict[str, Any]) -> dict[str, Any]:
        if not require_write(args):
            return _err("write_mode=true is required to export report files")
        repo = state.repo(args)
        log_tool_call(repo, "zeropath_export_report", args)
        try:
            from zeropath.core.reports import export_report

            path = export_report(
                _storage(repo),
                args["candidate_id"],
                report_format=args.get("format", "code4rena"),
                draft=bool(args.get("draft", False)),
            )
            return _ok(report_path=str(path))
        except Exception as exc:
            return _err(str(exc))

    return Tool("zeropath_export_report", "Export a judge-gated report or draft. Requires write_mode=true.", object_schema({"repo_path": {"type": "string"}, "candidate_id": {"type": "string"}, "format": {"type": "string"}, "draft": {"type": "boolean"}, **WRITE_MODE}, ["candidate_id"]), handler)


def _memory_search(state: EvidenceMCPState) -> Tool:
    def handler(args: dict[str, Any]) -> dict[str, Any]:
        repo = state.repo(args)
        log_tool_call(repo, "zeropath_memory_search", args)
        try:
            from zeropath.core.memory import search_memory

            results = search_memory(
                _storage(repo),
                args.get("query", ""),
                scope=args.get("scope"),
                memory_type=args.get("memory_type"),
                tags=args.get("tags"),
            )
            return _ok(memory=[item.model_dump(mode="json") for item in results])
        except Exception as exc:
            return _err(str(exc))

    return Tool("zeropath_memory_search", "Search research memory by keyword, scope, type, and tags.", object_schema({"repo_path": {"type": "string"}, "query": {"type": "string"}, "scope": {"type": "string"}, "memory_type": {"type": "string"}, "tags": {"type": "array", "items": {"type": "string"}}}), handler)


def _memory_write_proposal(state: EvidenceMCPState) -> Tool:
    def handler(args: dict[str, Any]) -> dict[str, Any]:
        if not require_write(args):
            return _err("write_mode=true is required to save memory")
        repo = state.repo(args)
        log_tool_call(repo, "zeropath_memory_write_proposal", args)
        try:
            from zeropath.core.memory import propose_memory

            decision, memory = propose_memory(
                _storage(repo),
                content=args["content"],
                memory_type=args.get("memory_type") or "research_lesson",
                scope=args.get("scope") or "current_project",
                tags=args.get("tags") or [],
                source=args.get("source") or "mcp",
                confidence=args.get("confidence") or "inferred",
                context={"user_approved": bool(args.get("user_approved"))},
            )
            return _ok(decision=decision.model_dump(mode="json"), saved_id=memory.id if memory else None)
        except Exception as exc:
            return _err(str(exc))

    return Tool("zeropath_memory_write_proposal", "Evaluate a memory proposal and save it only if policy allows. Requires write_mode=true.", object_schema({"repo_path": {"type": "string"}, "content": {"type": "string"}, "memory_type": {"type": "string"}, "scope": {"type": "string"}, "tags": {"type": "array", "items": {"type": "string"}}, "source": {"type": "string"}, "confidence": {"type": "string"}, "user_approved": {"type": "boolean"}, **WRITE_MODE}, ["content"]), handler)


def _memory_mark_stale(state: EvidenceMCPState) -> Tool:
    def handler(args: dict[str, Any]) -> dict[str, Any]:
        if not require_write(args):
            return _err("write_mode=true is required to mark memory stale")
        repo = state.repo(args)
        log_tool_call(repo, "zeropath_memory_mark_stale", args)
        try:
            from zeropath.core.memory import mark_memory_stale

            return _ok(success=mark_memory_stale(_storage(repo), args["memory_id"], args["reason"]))
        except Exception as exc:
            return _err(str(exc))

    return Tool("zeropath_memory_mark_stale", "Mark one memory item stale with a reason. Requires write_mode=true.", object_schema({"repo_path": {"type": "string"}, "memory_id": {"type": "string"}, "reason": {"type": "string"}, **WRITE_MODE}, ["memory_id", "reason"]), handler)
