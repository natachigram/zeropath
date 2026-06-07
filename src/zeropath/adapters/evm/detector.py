"""EVM/Solidity project detection."""

from __future__ import annotations

from pathlib import Path

from zeropath.core.schemas import AdapterDetection
from zeropath.core.utils import safe_relpath


IGNORED_DIRS = {".git", ".zeropath", "node_modules", "out", "cache", "artifacts", "build"}


def detect_evm_project(root_path: str | Path) -> AdapterDetection:
    root = Path(root_path).resolve()
    files: list[str] = []
    reasons: list[str] = []
    build_system: str | None = None

    if (root / "foundry.toml").exists():
        files.append("foundry.toml")
        reasons.append("foundry.toml detected")
        build_system = "foundry"
    for name in ("hardhat.config.ts", "hardhat.config.js", "hardhat.config.cjs", "hardhat.config.mjs"):
        if (root / name).exists():
            files.append(name)
            reasons.append(f"{name} detected")
            build_system = build_system or "hardhat"
    if (root / "remappings.txt").exists():
        files.append("remappings.txt")
        reasons.append("remappings.txt detected")

    sol_files = _solidity_files(root)
    if sol_files:
        files.extend(safe_relpath(path, root) for path in sol_files[:50])
        reasons.append(f"{len(sol_files)} Solidity file(s) detected")

    if sol_files and build_system:
        confidence = "high"
        adapter = "evm"
    elif sol_files:
        confidence = "medium"
        adapter = "evm"
    elif build_system:
        confidence = "low"
        adapter = "evm"
    else:
        confidence = "low"
        adapter = "unknown"
        reasons.append("No Solidity markers detected")

    return AdapterDetection(
        adapter=adapter,
        confidence=confidence,
        reasons=reasons,
        build_system=build_system,
        files_detected=files,
    )


def _solidity_files(root: Path) -> list[Path]:
    candidates: list[Path] = []
    preferred = ["src", "contracts", "test", "script"]
    for rel in preferred:
        base = root / rel
        if base.exists():
            candidates.extend(_walk_solidity(base))
    if not candidates:
        candidates = _walk_solidity(root)
    return sorted(set(candidates))


def _walk_solidity(base: Path) -> list[Path]:
    out: list[Path] = []
    for path in base.rglob("*.sol"):
        if any(part in IGNORED_DIRS for part in path.parts):
            continue
        out.append(path)
    return out
