"""Base adapter interface.

Core ZeroPath logic must not assume a specific smart contract language or VM.
Adapters own parsing, project detection, proof generation, and execution.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any

from zeropath.core.schemas import (
    AdapterDetection,
    CandidateFinding,
    ExternalDependency,
    Invariant,
    ProjectConfig,
    ProtocolIntent,
    Role,
)


class LanguageAdapter(ABC):
    """Adapter contract for smart contract ecosystems."""

    name = "base"

    @abstractmethod
    def detect_project(self, root_path: str | Path) -> AdapterDetection:
        raise NotImplementedError

    @abstractmethod
    def ingest_project(self, project_config: ProjectConfig) -> dict[str, Any]:
        raise NotImplementedError

    def index_contracts(self) -> list[dict[str, Any]]:
        raise NotImplementedError

    def extract_entrypoints(self) -> list[dict[str, Any]]:
        raise NotImplementedError

    def build_call_graph(self) -> dict[str, Any]:
        raise NotImplementedError

    def build_state_graph(self) -> dict[str, Any]:
        raise NotImplementedError

    def build_asset_flow_graph(self) -> dict[str, Any]:
        raise NotImplementedError

    def extract_roles(self) -> list[Role]:
        raise NotImplementedError

    def extract_external_dependencies(self) -> list[ExternalDependency]:
        raise NotImplementedError

    def infer_protocol_type(self) -> str:
        raise NotImplementedError

    def suggest_invariants(self, protocol_intent: ProtocolIntent) -> list[Invariant]:
        raise NotImplementedError

    def generate_poc(self, candidate: CandidateFinding) -> str | None:
        raise NotImplementedError

    def run_proof(self, candidate: CandidateFinding) -> dict[str, Any]:
        raise NotImplementedError

    def get_supported_backends(self) -> list[str]:
        return []
