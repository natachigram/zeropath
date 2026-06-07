"""Future Move adapter stub."""

from __future__ import annotations

from pathlib import Path

from zeropath.adapters.base import LanguageAdapter
from zeropath.core.schemas import AdapterDetection, ProjectConfig


class MoveAdapter(LanguageAdapter):
    name = "move"

    def detect_project(self, root_path: str | Path) -> AdapterDetection:
        return AdapterDetection(
            adapter="move",
            confidence="low",
            reasons=["Move adapter is planned but not implemented."],
        )

    def ingest_project(self, project_config: ProjectConfig) -> dict:
        raise NotImplementedError("Move adapter is planned but not implemented.")
