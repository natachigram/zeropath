"""Future CosmWasm adapter stub."""

from __future__ import annotations

from pathlib import Path

from zeropath.adapters.base import LanguageAdapter
from zeropath.core.schemas import AdapterDetection, ProjectConfig


class CosmWasmAdapter(LanguageAdapter):
    name = "cosmwasm"

    def detect_project(self, root_path: str | Path) -> AdapterDetection:
        return AdapterDetection(
            adapter="cosmwasm",
            confidence="low",
            reasons=["CosmWasm adapter is planned but not implemented."],
        )

    def ingest_project(self, project_config: ProjectConfig) -> dict:
        raise NotImplementedError("CosmWasm adapter is planned but not implemented.")
