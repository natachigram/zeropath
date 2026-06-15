"""Foundry project helpers."""

from __future__ import annotations

from pathlib import Path

from zeropath.adapters.evm.poc_templates import render_foundry_poc
from zeropath.core.schemas import CandidateFinding, CandidateStatePlan


def has_foundry_project(root_path: str | Path) -> bool:
    return (Path(root_path) / "foundry.toml").exists()


def test_dir(root_path: str | Path) -> Path | None:
    root = Path(root_path)
    for rel in ("test", "tests"):
        path = root / rel
        if path.exists() and path.is_dir():
            return path
    return None


def candidate_test_path(root_path: str | Path, candidate: CandidateFinding) -> Path:
    base = test_dir(root_path) or (Path(root_path) / "test")
    return base / "zeropath" / f"{candidate.id.replace('-', '_')}.t.sol"


def runnable_candidate_test_path(root_path: str | Path, candidate: CandidateFinding) -> Path | None:
    path = candidate_test_path(root_path, candidate)
    if path.exists():
        return path
    if candidate.evidence.poc_path:
        artifact = Path(candidate.evidence.poc_path)
        if artifact.exists():
            return artifact
    return None


def write_candidate_test(
    root_path: str | Path,
    candidate: CandidateFinding,
    *,
    state_plan: CandidateStatePlan | None = None,
    force: bool = False,
) -> Path:
    path = candidate_test_path(root_path, candidate)
    if path.exists() and not force:
        raise FileExistsError(f"Refusing to overwrite existing test: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_foundry_poc(candidate, state_plan=state_plan), encoding="utf-8")
    return path


def write_runnable_poc(
    root_path: str | Path,
    candidate: CandidateFinding,
    poc_source: str,
) -> Path:
    """Write an executable PoC into test/zeropath/ for forge discovery.

    Always overwrites - the file is auto-generated and owned by ZeroPath.
    """

    path = candidate_test_path(root_path, candidate)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(poc_source, encoding="utf-8")
    return path
