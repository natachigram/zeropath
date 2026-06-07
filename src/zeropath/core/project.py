"""Project initialization and adapter detection."""

from __future__ import annotations

from pathlib import Path

from zeropath.core.schemas import AdapterDetection, ProjectConfig
from zeropath.core.storage import Storage
from zeropath.core.utils import repo_commit, slugify


def detect_adapter(root_path: str | Path) -> AdapterDetection:
    """Detect the best available adapter for a project."""

    from zeropath.adapters.evm.detector import detect_evm_project

    evm = detect_evm_project(root_path)
    if evm.adapter == "evm" and evm.confidence in {"medium", "high"}:
        return evm
    return AdapterDetection(
        adapter="unknown",
        confidence="low",
        reasons=["No stable language adapter detected."],
        files_detected=[],
    )


def create_project_config(
    root_path: str | Path,
    detection: AdapterDetection | None = None,
    *,
    docs_paths: list[str] | None = None,
    scope_files: list[str] | None = None,
    source_paths: list[str] | None = None,
) -> ProjectConfig:
    root = Path(root_path).resolve()
    detection = detection or detect_adapter(root)
    return ProjectConfig(
        project_id=slugify(root.name),
        root_path=str(root),
        adapter=detection.adapter,
        repo_commit=repo_commit(root),
        scope_files=scope_files or [],
        docs_paths=docs_paths or [],
        source_paths=source_paths or [],
        build_system=detection.build_system,
        metadata={
            "adapter_confidence": detection.confidence,
            "adapter_reasons": detection.reasons,
            "detected_files": detection.files_detected,
        },
    )


def init_project(root_path: str | Path = ".") -> tuple[Storage, ProjectConfig, AdapterDetection]:
    root = Path(root_path).resolve()
    detection = detect_adapter(root)
    config = create_project_config(root, detection)
    storage = Storage(root)
    storage.initialize(config)
    return storage, config, detection
