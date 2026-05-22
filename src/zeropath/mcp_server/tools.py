"""
MCP tool definitions wrapping every ZeroPath capability.

Each tool is a thin adapter: validate args → call into ZeroPath → coerce
the structured result back into a JSON-serialisable dict the IDE agent
can read. Heavy lifting (importing slither / spinning Anvil / running
forge) is deferred to call-time so the server starts fast.

Design notes:
  * Tools take *paths*, not source content. The IDE agent already has
    file paths from its own file-system access — we don't need to
    duplicate file contents into MCP request bodies.
  * Tools return plain dicts. The server's :func:`_coerce_tool_content`
    JSON-formats them into the MCP ``content`` shape.
  * Every tool is wrapped in a try/except — failures surface as readable
    error dicts rather than raw stack traces.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from zeropath.mcp_server.server import Tool

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Shared state
# ---------------------------------------------------------------------------


@dataclass
class ServerState:
    """In-memory state the tool handlers can share across calls."""

    kg_dir: Optional[Path] = None
    knowledge: Any = None             # KnowledgeGraphOrchestrator | None
    last_protocol_graph: Any = None
    last_invariant_report: Any = None
    last_contest_report: Any = None
    workspace_root: Path = field(default_factory=lambda: Path.cwd())

    def ensure_knowledge(self):
        """Lazy-load a KG either from disk or in-memory."""
        if self.knowledge is not None:
            return self.knowledge
        from zeropath.knowledge import InMemoryKGStore, KnowledgeGraphOrchestrator
        store = InMemoryKGStore()
        if self.kg_dir:
            snap = self.kg_dir / "kg.json"
            if snap.exists():
                try:
                    store.restore(snap)
                except Exception as exc:
                    logger.warning("KG restore failed: %s", exc)
        self.knowledge = KnowledgeGraphOrchestrator(store)
        return self.knowledge


# ---------------------------------------------------------------------------
# Tool builders — one per logical capability
# ---------------------------------------------------------------------------


def _err(message: str, **extra: Any) -> dict[str, Any]:
    out = {"ok": False, "error": message}
    out.update(extra)
    return out


def _ok(**fields: Any) -> dict[str, Any]:
    out: dict[str, Any] = {"ok": True}
    out.update(fields)
    return out


# ---- Phase 1: protocol graph -------------------------------------------------


def _tool_analyze_protocol(state: ServerState) -> Tool:
    def handler(args: dict[str, Any]) -> dict[str, Any]:
        source = args.get("source")
        if not source:
            return _err("missing 'source' (path or 0x address or owner/repo)")
        store_graph = bool(args.get("store_graph", False))
        try:
            from zeropath.graph_builder import ProtocolGraphBuilder
            from zeropath.parser import SolidityParser

            parser = SolidityParser(solc_version=args.get("solc"))
            graph_builder = ProtocolGraphBuilder(parser=parser)
            graph = graph_builder.build(source)
        except Exception as exc:
            return _err(f"analyze failed: {exc}")
        state.last_protocol_graph = graph
        summary = {
            "ok": True,
            "protocol_name": getattr(graph, "protocol_name", "unknown"),
            "contracts": len(getattr(graph, "contracts", [])),
            "functions": len(getattr(graph, "functions", [])),
            "state_variables": len(getattr(graph, "state_variables", [])),
            "external_dependencies": len(getattr(graph, "external_dependencies", [])),
        }
        if store_graph:
            summary["graph"] = graph.model_dump(mode="json")
        return summary

    return Tool(
        name="analyze_protocol",
        description=(
            "Phase 1: parse Solidity / Vyper source and build the typed "
            "protocol graph (contracts, functions, state vars, call edges, "
            "asset flows, proxy relationships). Source can be a local "
            "directory path, a contract address (with --chain), or a "
            "GitHub repo URL."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "source": {
                    "type": "string",
                    "description": "Local path, 0x-address, or owner/repo URL.",
                },
                "solc": {
                    "type": "string",
                    "description": "Optional solc version pin (e.g. '0.8.20').",
                },
                "store_graph": {
                    "type": "boolean",
                    "description": "Include full graph JSON in the response.",
                    "default": False,
                },
            },
            "required": ["source"],
        },
        handler=handler,
    )


# ---- Phase 2: invariants ----------------------------------------------------


def _tool_infer_invariants(state: ServerState) -> Tool:
    def handler(args: dict[str, Any]) -> dict[str, Any]:
        graph = state.last_protocol_graph
        if graph is None:
            return _err("no protocol graph loaded — call analyze_protocol first")
        try:
            from zeropath.invariants.engine import InvariantInferenceEngine
            engine = InvariantInferenceEngine()
            report = engine.infer(graph, protocol_name=args.get("protocol_name", "unknown"))
        except Exception as exc:
            return _err(f"invariant inference failed: {exc}")
        state.last_invariant_report = report
        min_severity = (args.get("min_severity") or "low").lower()
        order = {"low": 1, "medium": 2, "high": 3, "critical": 4}
        threshold = order.get(min_severity, 1)
        invariants = [
            i.model_dump(mode="json") for i in report.invariants
            if order.get((i.severity.value if hasattr(i.severity, "value") else str(i.severity)), 1) >= threshold
        ]
        return _ok(
            protocol_name=report.protocol_name,
            invariant_count=len(invariants),
            invariants=invariants,
        )

    return Tool(
        name="infer_invariants",
        description=(
            "Phase 2: run 11 invariant detectors over the loaded protocol "
            "graph. Returns each invariant with severity, confidence, "
            "formal_spec, and historical_precedent. Call analyze_protocol "
            "first to populate the graph."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "protocol_name": {"type": "string"},
                "min_severity": {
                    "type": "string",
                    "enum": ["low", "medium", "high", "critical"],
                    "default": "low",
                },
            },
        },
        handler=handler,
    )


# ---- Spec miner --------------------------------------------------------------


def _tool_mine_spec(state: ServerState) -> Tool:
    def handler(args: dict[str, Any]) -> dict[str, Any]:
        repo_path = Path(args.get("repo_path") or state.workspace_root)
        if not repo_path.exists():
            return _err(f"path does not exist: {repo_path}")
        try:
            from zeropath.invariants.spec_miner import SpecMiner
            miner = SpecMiner(repo_path, use_llm=False)
            result = miner.mine()
        except Exception as exc:
            return _err(f"spec miner failed: {exc}")
        return _ok(
            files_processed=len(result.files_processed),
            claimed_invariants=[c.model_dump(mode="json") for c in result.claimed_invariants],
            skipped_files=result.skipped_files,
        )

    return Tool(
        name="mine_spec_claims",
        description=(
            "Extract claimed invariants from NatSpec comments, README.md, "
            "and docs/*.md. Spec/implementation gaps are a high-value bug "
            "class in audit contests — feed these claims back into your "
            "audit prompt as 'things the protocol says must hold'."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "repo_path": {
                    "type": "string",
                    "description": "Repository root. Defaults to server workspace.",
                },
            },
        },
        handler=handler,
    )


# ---- Foundry PoC verifier ----------------------------------------------------


def _tool_verify_foundry_poc(state: ServerState) -> Tool:
    def handler(args: dict[str, Any]) -> dict[str, Any]:
        test_code = args.get("test_code")
        if not test_code:
            return _err("missing 'test_code'")
        test_filename = args.get("test_filename") or "ZeroPathPoC.t.sol"
        project_root = args.get("project_root")
        try:
            from zeropath.simulator.foundry_verifier import (
                FoundryNotAvailable, FoundryPoCVerifier,
            )
            verifier = FoundryPoCVerifier()
        except Exception as exc:
            return _err(f"verifier import failed: {exc}")
        if not verifier.is_available:
            return _err("forge not on PATH — install Foundry to enable PoC verification")
        try:
            result = verifier.run(
                test_code=test_code,
                test_filename=test_filename,
                test_function=args.get("test_function", ""),
                project_root=project_root,
            )
        except FoundryNotAvailable as exc:
            return _err(str(exc))
        except Exception as exc:
            return _err(f"verifier crashed: {exc}")
        return _ok(
            stage=result.stage,
            passed=result.ok,
            elapsed_seconds=result.elapsed_seconds,
            error_summary=result.error_summary,
            stdout_tail=(result.stdout or "")[-2000:],
            stderr_tail=(result.stderr or "")[-1000:],
        )

    return Tool(
        name="verify_foundry_poc",
        description=(
            "Compile + run a generated Foundry test file. Returns whether "
            "the PoC compiles AND its assertions pass. Use to validate "
            "any exploit hypothesis before submission. Failing returns "
            "give you the compile/test error so you can repair and retry."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "test_code": {"type": "string", "description": "Full .t.sol file body."},
                "test_filename": {"type": "string", "default": "ZeroPathPoC.t.sol"},
                "test_function": {
                    "type": "string",
                    "description": "Optional --match-test selector.",
                },
                "project_root": {
                    "type": "string",
                    "description": (
                        "Existing Foundry project to drop the test into. "
                        "Omit to materialise a scratch workspace."
                    ),
                },
            },
            "required": ["test_code"],
        },
        handler=handler,
    )


# ---- KG queries --------------------------------------------------------------


def _tool_query_kg_similar_exploits(state: ServerState) -> Tool:
    def handler(args: dict[str, Any]) -> dict[str, Any]:
        exploit_id = args.get("exploit_id")
        if not exploit_id:
            return _err("missing 'exploit_id'")
        kg = state.ensure_knowledge()
        hits = kg.find_similar_exploits(exploit_id)
        return _ok(hits=[h.model_dump(mode="json") for h in hits])

    return Tool(
        name="query_kg_similar_exploits",
        description=(
            "Phase 8: return exploits structurally similar to the given "
            "exploit_id (by attack class + contracts + functions + state "
            "vars). Use for deduplication or to surface related historical "
            "precedents."
        ),
        input_schema={
            "type": "object",
            "properties": {"exploit_id": {"type": "string"}},
            "required": ["exploit_id"],
        },
        handler=handler,
    )


def _tool_query_kg_historical_grounding(state: ServerState) -> Tool:
    def handler(args: dict[str, Any]) -> dict[str, Any]:
        attack_class = args.get("attack_class")
        contracts = args.get("contracts_involved") or []
        if not attack_class:
            return _err("missing 'attack_class'")
        try:
            from zeropath.adversarial.models import AttackClass, AttackHypothesis
            try:
                cls = AttackClass(attack_class)
            except ValueError:
                cls = AttackClass.UNKNOWN
            stub = AttackHypothesis(
                invariant_id="mcp", invariant_description="mcp query",
                attack_class=cls, title="MCP grounding query",
                proposed_by="mcp", attack_narrative="mcp",
                contracts_involved=list(contracts),
            )
            kg = state.ensure_knowledge()
            boost, matches = kg.lookup_historical_grounding(stub)
        except Exception as exc:
            return _err(f"grounding query failed: {exc}")
        return _ok(
            confidence_boost=boost,
            matched_incidents=[m.model_dump(mode="json") for m in matches],
        )

    return Tool(
        name="query_kg_historical_grounding",
        description=(
            "Look up historical incidents (DeFiHackLabs / Rekt / Immunefi) "
            "matching an attack class + contract names. Returns matched "
            "incidents + a confidence boost the LLM can apply to its "
            "hypothesis."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "attack_class": {
                    "type": "string",
                    "enum": [
                        "oracle_manipulation", "reentrancy", "access_control",
                        "flash_loan", "composability", "governance",
                        "integer_math", "price_manipulation", "unknown",
                    ],
                },
                "contracts_involved": {
                    "type": "array", "items": {"type": "string"},
                },
            },
            "required": ["attack_class"],
        },
        handler=handler,
    )


def _tool_ingest_threat_intel(state: ServerState) -> Tool:
    def handler(args: dict[str, Any]) -> dict[str, Any]:
        source = (args.get("source") or "").lower()
        entries = args.get("entries") or []
        if not source:
            return _err("missing 'source' (defihacklabs / rekt / immunefi)")
        if not isinstance(entries, list) or not entries:
            return _err("missing 'entries' list")
        from zeropath.knowledge import IntelSource
        try:
            intel_source = IntelSource(source)
        except ValueError:
            return _err(f"unknown source: {source}")
        kg = state.ensure_knowledge()
        records = kg.ingest_threat_intel(intel_source, entries)
        return _ok(
            ingested=len(records),
            records=[r.model_dump(mode="json") for r in records[:50]],
        )

    return Tool(
        name="ingest_threat_intel",
        description=(
            "Ingest external threat-intel entries (DeFiHackLabs / Rekt / "
            "Immunefi formats) into the Phase 8 knowledge graph. Each "
            "entry becomes a node linked to a Protocol and an "
            "ExploitPattern."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "source": {
                    "type": "string",
                    "enum": ["defihacklabs", "rekt", "immunefi"],
                },
                "entries": {"type": "array", "items": {"type": "object"}},
            },
            "required": ["source", "entries"],
        },
        handler=handler,
    )


def _tool_ingest_defihacklabs_live(state: ServerState) -> Tool:
    def handler(args: dict[str, Any]) -> dict[str, Any]:
        kg = state.ensure_knowledge()
        try:
            records, stats = kg.intel.ingest_defihacklabs_live(
                timeout=int(args.get("timeout", 15)),
            )
        except Exception as exc:
            return _err(f"live fetch failed: {exc}")
        return _ok(
            ingested=len(records),
            errors=stats.errors,
            sample=[r.model_dump(mode="json") for r in records[:10]],
        )

    return Tool(
        name="ingest_defihacklabs_live",
        description=(
            "Fetch the DeFiHackLabs README directly from GitHub and ingest "
            "every incident into the Phase 8 KG. No API key required."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "timeout": {"type": "integer", "default": 15},
            },
        },
        handler=handler,
    )


def _tool_kg_summary(state: ServerState) -> Tool:
    def handler(args: dict[str, Any]) -> dict[str, Any]:
        kg = state.ensure_knowledge()
        report = kg.report(protocol_name=args.get("protocol_name", "all"))
        return _ok(
            exploits=report.exploits_ingested,
            incidents=report.incidents_ingested,
            inferences=report.inferences_recorded,
            accuracy_metrics=[m.model_dump(mode="json") for m in report.accuracy_metrics],
            metadata=report.analysis_metadata,
        )

    return Tool(
        name="kg_summary",
        description="Top-level Phase 8 KG stats: exploits / incidents / inferences / accuracy.",
        input_schema={
            "type": "object",
            "properties": {"protocol_name": {"type": "string"}},
        },
        handler=handler,
    )


# ---- Contest mode (deterministic — no LLM here, the IDE's agent IS the LLM) ----


def _tool_run_contest_pipeline(state: ServerState) -> Tool:
    def handler(args: dict[str, Any]) -> dict[str, Any]:
        repo_path = args.get("repo_path")
        if not repo_path:
            return _err("missing 'repo_path'")
        platform = (args.get("platform") or "generic").lower()
        try:
            from zeropath.contest import (
                ContestConfig, ContestOrchestrator, ContestPlatform,
            )
            cfg = ContestConfig(
                platform=ContestPlatform(platform),
                contest_name=args.get("contest_name", ""),
                repo_path=str(repo_path),
                scope_files=args.get("scope_files") or [],
                # When invoked via MCP, the IDE's agent IS the LLM —
                # so disable the in-orchestrator LLM call. The agent
                # uses its own model to reason over our deterministic
                # output (spec claims, KG hits, etc.).
                use_llm=False,
                use_spec_miner=bool(args.get("use_spec_miner", True)),
                use_foundry_verifier=bool(args.get("use_foundry_verifier", True)),
                use_contrarian=False,
                submit_confidence_threshold=float(
                    args.get("submit_confidence_threshold", 0.70)
                ),
                submit_severity_floor=args.get("submit_severity_floor", "medium"),
                parallel_workers=int(args.get("parallel_workers", 4)),
            )
            kg = state.knowledge
            report = ContestOrchestrator(cfg, knowledge=kg).run()
        except Exception as exc:
            return _err(f"contest pipeline failed: {exc}")
        state.last_contest_report = report
        return _ok(
            files_scanned=report.files_scanned,
            spec_claims_extracted=report.analysis_metadata.get("spec_claims_extracted", 0),
            actionable_submissions=len(report.ready_to_submit),
            findings_by_severity=report.findings_by_severity,
            elapsed_seconds=report.elapsed_seconds,
            metadata=report.analysis_metadata,
        )

    return Tool(
        name="run_contest_pipeline",
        description=(
            "Run the contest-mode deterministic pipeline (spec mining, "
            "Foundry PoC verification, platform formatting). LLM reasoning "
            "is disabled when invoked from MCP — the IDE agent supplies "
            "that. Returns scan stats + KG-grounded spec mismatches the "
            "agent can audit next."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "repo_path": {"type": "string"},
                "platform": {
                    "type": "string",
                    "enum": ["cantina", "code4rena", "sherlock", "immunefi", "generic"],
                    "default": "generic",
                },
                "contest_name": {"type": "string"},
                "scope_files": {
                    "type": "array", "items": {"type": "string"},
                },
                "submit_confidence_threshold": {
                    "type": "number", "default": 0.70,
                },
                "submit_severity_floor": {
                    "type": "string",
                    "enum": ["critical", "high", "medium", "low", "informational"],
                    "default": "medium",
                },
                "use_spec_miner": {"type": "boolean", "default": True},
                "use_foundry_verifier": {"type": "boolean", "default": True},
                "parallel_workers": {"type": "integer", "default": 4},
            },
            "required": ["repo_path"],
        },
        handler=handler,
    )


def _tool_format_finding_for_platform(state: ServerState) -> Tool:
    def handler(args: dict[str, Any]) -> dict[str, Any]:
        platform = (args.get("platform") or "generic").lower()
        finding_dict = args.get("finding")
        if not isinstance(finding_dict, dict):
            return _err("missing 'finding' object")
        try:
            from zeropath.contest import (
                ContestPlatform, Submission, SubmissionFinding,
                SubmissionDisposition,
            )
            from zeropath.contest.platforms import for_platform
            sf = SubmissionFinding(**finding_dict)
            sub = Submission(
                finding=sf,
                disposition=SubmissionDisposition.SUBMIT_NOW,
                rank=int(args.get("rank", 1)),
                platform=ContestPlatform(platform),
            )
            formatter = for_platform(ContestPlatform(platform))
            rendered = formatter.render(sub)
        except Exception as exc:
            return _err(f"formatter failed: {exc}")
        return _ok(platform=platform, rendered=rendered)

    return Tool(
        name="format_finding_for_platform",
        description=(
            "Render a finding into the exact submission shape for "
            "Cantina / Code4rena / Sherlock / Immunefi. Hand the IDE "
            "agent a structured finding; receive a ready-to-paste payload."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "platform": {
                    "type": "string",
                    "enum": ["cantina", "code4rena", "sherlock", "immunefi", "generic"],
                },
                "finding": {
                    "type": "object",
                    "description": (
                        "SubmissionFinding shape: title, severity, "
                        "attack_class, contracts_involved, "
                        "functions_involved, lines_of_code, description, "
                        "impact, attack_path, preconditions, "
                        "proof_of_concept_code, recommendation, confidence."
                    ),
                },
                "rank": {"type": "integer", "default": 1},
            },
            "required": ["platform", "finding"],
        },
        handler=handler,
    )


def _tool_estimate_duplicate_likelihood(state: ServerState) -> Tool:
    def handler(args: dict[str, Any]) -> dict[str, Any]:
        finding_dict = args.get("finding") or {}
        if not isinstance(finding_dict, dict):
            return _err("missing 'finding' object")
        try:
            from zeropath.contest import (
                SubmissionFinding, estimate_duplicate_likelihood,
            )
            sf = SubmissionFinding(**finding_dict)
        except Exception as exc:
            return _err(f"invalid finding: {exc}")
        kg = state.knowledge
        score = estimate_duplicate_likelihood(sf, knowledge=kg)
        return _ok(duplicate_likelihood=score)

    return Tool(
        name="estimate_duplicate_likelihood",
        description=(
            "Estimate the probability another contest auditor will submit "
            "the same finding. Low score = unique → submit ASAP. Driven "
            "by attack-class base rate + Phase 8 KG distribution + "
            "novelty signals."
        ),
        input_schema={
            "type": "object",
            "properties": {"finding": {"type": "object"}},
            "required": ["finding"],
        },
        handler=handler,
    )


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------


def register_default_tools(server, state: ServerState) -> None:
    """Wire every default tool onto a fresh server."""
    builders = [
        _tool_analyze_protocol,
        _tool_infer_invariants,
        _tool_mine_spec,
        _tool_verify_foundry_poc,
        _tool_query_kg_similar_exploits,
        _tool_query_kg_historical_grounding,
        _tool_ingest_threat_intel,
        _tool_ingest_defihacklabs_live,
        _tool_kg_summary,
        _tool_run_contest_pipeline,
        _tool_format_finding_for_platform,
        _tool_estimate_duplicate_likelihood,
    ]
    for build in builders:
        server.add_tool(build(state))
