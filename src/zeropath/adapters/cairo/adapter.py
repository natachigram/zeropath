"""Future Cairo/Starknet adapter stub."""

from __future__ import annotations

from pathlib import Path

from zeropath.adapters.base import LanguageAdapter
from zeropath.core.schemas import AdapterDetection, ProjectConfig


class CairoAdapter(LanguageAdapter):
    name = "cairo"

    def detect_project(self, root_path: str | Path) -> AdapterDetection:
        return AdapterDetection(
            adapter="cairo",
            confidence="low",
            reasons=["Cairo adapter is planned but not implemented."],
        )

    def ingest_project(self, project_config: ProjectConfig) -> dict:
        raise NotImplementedError("Cairo adapter is planned but not implemented.")
