"""Initial EVM/Solidity adapter."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from zeropath.adapters.base import LanguageAdapter
from zeropath.adapters.evm.detector import detect_evm_project
from zeropath.adapters.evm.forge import run_forge_test
from zeropath.adapters.evm.foundry import runnable_candidate_test_path
from zeropath.adapters.evm.inflation_poc import (
    InflationProofTargets,
    detect_inflation_targets,
    render_inflation_poc,
)
from zeropath.adapters.evm.invariants import suggest_evm_invariants
from zeropath.adapters.evm.parser import EVMParser
from zeropath.adapters.evm.poc_templates import render_foundry_poc
from zeropath.core.schemas import (
    AdapterDetection,
    CandidateFinding,
    CandidateStatePlan,
    ExternalDependency,
    Invariant,
    ProjectConfig,
    ProtocolIntent,
    Role,
)


class EVMAdapter(LanguageAdapter):
    """Lightweight EVM adapter using source scans and regex indexing."""

    name = "evm"

    def __init__(self, root_path: str | Path | None = None) -> None:
        self.root_path = Path(root_path).resolve() if root_path else None
        self.parser = EVMParser()
        self._index: dict[str, Any] | None = None

    def detect_project(self, root_path: str | Path) -> AdapterDetection:
        return detect_evm_project(root_path)

    def ingest_project(self, project_config: ProjectConfig) -> dict[str, Any]:
        self.root_path = Path(project_config.root_path).resolve()
        index = self.parser.parse_project(self.root_path)
        index["build_system"] = project_config.build_system
        index["adapter_detection"] = project_config.metadata.get("adapter_reasons", [])
        self._index = index
        return index

    def index_contracts(self) -> list[dict[str, Any]]:
        return list((self._index or {}).get("contracts", []))

    def extract_entrypoints(self) -> list[dict[str, Any]]:
        return [
            fn
            for fn in (self._index or {}).get("functions", [])
            if fn.get("visibility") in {"public", "external"}
        ]

    def build_call_graph(self) -> dict[str, Any]:
        external_calls = list((self._index or {}).get("external_calls", []))
        edges = [
            {
                "from": call.get("caller"),
                "to": f"{call.get('target')}.{call.get('callee')}",
                "type": call.get("call_type", "external_member_call"),
                "file": call.get("file"),
                "line": call.get("line"),
                "value_transfer": bool(call.get("value_transfer")),
                "confidence": call.get("confidence", "low"),
                "snippet": call.get("snippet"),
            }
            for call in external_calls
        ]
        return {
            "confidence": "low",
            "nodes": self.extract_entrypoints(),
            "edges": edges,
            "external_calls": external_calls,
            "unknowns": [
                "Regex adapter does not resolve inheritance, dynamic dispatch, or runtime reachability.",
                "External-call edges are heuristic and require proof before reporting.",
            ],
        }

    def build_state_graph(self) -> dict[str, Any]:
        return {
            "confidence": "low",
            "state_variables": list((self._index or {}).get("state_variables", [])),
        }

    def build_asset_flow_graph(self) -> dict[str, Any]:
        return {
            "confidence": "medium",
            "flows": list((self._index or {}).get("asset_flows", [])),
        }

    def extract_roles(self) -> list[Role]:
        return [Role.model_validate(item) for item in (self._index or {}).get("roles", [])]

    def extract_external_dependencies(self) -> list[ExternalDependency]:
        return [
            ExternalDependency.model_validate(item)
            for item in (self._index or {}).get("external_dependencies", [])
        ]

    def infer_protocol_type(self) -> str:
        return str((self._index or {}).get("protocol_type", "unknown"))

    def suggest_invariants(self, protocol_intent: ProtocolIntent) -> list[Invariant]:
        return suggest_evm_invariants(protocol_intent)

    def generate_poc(
        self,
        candidate: CandidateFinding,
        state_plan: CandidateStatePlan | None = None,
        *,
        poc_location: str = ".zeropath/artifacts/pocs",
    ) -> str | None:
        targets = self.detect_inflation_targets(candidate)
        if targets is not None:
            return render_inflation_poc(
                candidate, targets, poc_location=poc_location
            )
        return render_foundry_poc(candidate, state_plan=state_plan)

    def detect_inflation_targets(
        self, candidate: CandidateFinding
    ) -> InflationProofTargets | None:
        """Return inflation PoC targets when the index and candidate fit."""

        return detect_inflation_targets(candidate, self._index, self.root_path)

    def run_proof(self, candidate: CandidateFinding) -> dict[str, Any]:
        if not self.root_path:
            return {"ok": False, "status": "unavailable", "message": "adapter root path is unknown"}
        return run_forge_test(
            self.root_path, runnable_candidate_test_path(self.root_path, candidate)
        )

    def get_supported_backends(self) -> list[str]:
        return ["foundry"]
