"""Future Solana/Rust adapter stub."""

from __future__ import annotations

from pathlib import Path

from zeropath.adapters.base import LanguageAdapter
from zeropath.core.schemas import AdapterDetection, ProjectConfig


class SolanaAdapter(LanguageAdapter):
    name = "solana"

    def detect_project(self, root_path: str | Path) -> AdapterDetection:
        return AdapterDetection(
            adapter="solana",
            confidence="low",
            reasons=["Solana adapter is planned but not implemented."],
        )

    def ingest_project(self, project_config: ProjectConfig) -> dict:
        raise NotImplementedError("Solana adapter is planned but not implemented.")
