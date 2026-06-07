"""Lightweight Solidity parser.

This module deliberately uses modest regex/file-scan heuristics. It produces
low/medium-confidence structure for agent guidance, not a complete Solidity AST.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from zeropath.adapters.evm.asset_flow import detect_asset_flows
from zeropath.adapters.evm.detector import _solidity_files
from zeropath.adapters.evm.solidity_models import (
    SolidityContract,
    SolidityFileIndex,
    SolidityFunction,
)
from zeropath.core.utils import safe_relpath


CONTRACT_RE = re.compile(r"\b(contract|interface|library)\s+([A-Za-z_][A-Za-z0-9_]*)")
FUNCTION_RE = re.compile(r"\bfunction\s+([A-Za-z_][A-Za-z0-9_]*)\s*\((.*?)\)\s*([^;{]*)", re.S)
MODIFIER_RE = re.compile(r"\bmodifier\s+([A-Za-z_][A-Za-z0-9_]*)\b")
IMPORT_RE = re.compile(r"^\s*import\s+(.+?);", re.M)
PRAGMA_RE = re.compile(r"^\s*pragma\s+solidity\s+([^;]+);", re.M)
STATE_VAR_RE = re.compile(
    r"^\s*(?P<type>[A-Za-z_][A-Za-z0-9_<>,\[\]\s.]*(?:\([^;]*\))?)\s+"
    r"(?:(?:public|private|internal|external|constant|immutable)\s+)*"
    r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*(?:=|;)",
    re.M,
)

VISIBILITIES = {"public", "external", "internal", "private"}
FUNCTION_QUALIFIERS = {
    "public",
    "external",
    "internal",
    "private",
    "view",
    "pure",
    "payable",
    "virtual",
    "override",
    "returns",
    "memory",
    "calldata",
    "storage",
}
ROLE_TERMS = (
    "owner",
    "onlyOwner",
    "admin",
    "governor",
    "guardian",
    "keeper",
    "operator",
    "manager",
    "pauser",
    "whitelist",
    "accessControl",
    "hasRole",
    "DEFAULT_ADMIN_ROLE",
)
ORACLE_TERMS = ("latestRoundData", "getPrice", "price", "oracle", "twap", "Chainlink", "sequencer", "stale", "heartbeat")


class EVMParser:
    """Regex-based Solidity indexer."""

    def parse_project(self, root_path: str | Path) -> dict[str, Any]:
        root = Path(root_path).resolve()
        files = _solidity_files(root)
        file_indexes = [self.parse_file(path, root) for path in files]
        contracts = [c.model_dump() for file_index in file_indexes for c in file_index.contracts]
        functions = [f.model_dump() for file_index in file_indexes for f in file_index.functions]
        state_variables = [item for file_index in file_indexes for item in file_index.state_variables]
        asset_flows = [item for file_index in file_indexes for item in file_index.asset_flows]
        signals = sorted({signal for file_index in file_indexes for signal in file_index.signals})
        raw_signal_text = [Path(root / file_index.path).read_text(encoding="utf-8", errors="ignore")[:20000] for file_index in file_indexes[:20]]
        protocol_type = infer_protocol_type(functions, state_variables, " ".join(raw_signal_text))
        return {
            "adapter": "evm",
            "confidence": "medium",
            "files": [file_index.model_dump() for file_index in file_indexes],
            "contracts": contracts,
            "functions": functions,
            "state_variables": state_variables,
            "asset_flows": asset_flows,
            "roles": extract_roles(raw_signal_text, functions),
            "external_dependencies": extract_external_dependencies(file_indexes),
            "signals": signals,
            "protocol_type": protocol_type,
            "raw_signal_text": raw_signal_text,
            "unknowns": [
                "Regex parser does not resolve inheritance, modifiers, or runtime reachability.",
                "Findings require proof before reporting.",
            ],
        }

    def parse_file(self, path: Path, root: Path) -> SolidityFileIndex:
        text = path.read_text(encoding="utf-8", errors="ignore")
        rel = safe_relpath(path, root)
        lines = text.splitlines()
        pragma_match = PRAGMA_RE.search(text)
        contracts = self._contracts(text, rel)
        functions = self._functions(text, rel, contracts)
        functions_by_contract: dict[str, list[str]] = {}
        for fn in functions:
            functions_by_contract.setdefault(fn.contract, []).append(fn.name)
        for contract in contracts:
            contract.functions = functions_by_contract.get(contract.name, [])
            contract.modifiers = _modifiers_for_contract(text, contract.name)
        return SolidityFileIndex(
            path=rel,
            pragma=pragma_match.group(1).strip() if pragma_match else None,
            imports=[match.group(1).strip() for match in IMPORT_RE.finditer(text)],
            contracts=contracts,
            functions=functions,
            state_variables=self._state_variables(text, rel),
            asset_flows=detect_asset_flows(lines, file=rel),
            signals=_signals(text),
        )

    def _contracts(self, text: str, rel: str) -> list[SolidityContract]:
        contracts: list[SolidityContract] = []
        for match in CONTRACT_RE.finditer(text):
            contracts.append(
                SolidityContract(
                    name=match.group(2),
                    kind=match.group(1),
                    file=rel,
                    line_start=_line_of(text, match.start()),
                )
            )
        return contracts

    def _functions(self, text: str, rel: str, contracts: list[SolidityContract]) -> list[SolidityFunction]:
        regions = _contract_regions(text, contracts)
        functions: list[SolidityFunction] = []
        for contract, start, end in regions:
            body = text[start:end]
            for match in FUNCTION_RE.finditer(body):
                name = match.group(1)
                suffix = match.group(3) or ""
                words = re.findall(r"[A-Za-z_][A-Za-z0-9_]*", suffix)
                visibility = next((word for word in words if word in VISIBILITIES), "unknown")
                modifiers = [word for word in words if word not in FUNCTION_QUALIFIERS and word != name]
                absolute_start = start + match.start()
                functions.append(
                    SolidityFunction(
                        name=name,
                        contract=contract.name,
                        file=rel,
                        visibility=visibility,
                        modifiers=modifiers,
                        line_start=_line_of(text, absolute_start),
                        line_end=_line_of(text, start + match.end()),
                        raw_signature=" ".join(match.group(0).split()),
                    )
                )
        return functions

    def _state_variables(self, text: str, rel: str) -> list[dict]:
        variables: list[dict] = []
        for match in STATE_VAR_RE.finditer(text):
            line = text[text.rfind("\n", 0, match.start()) + 1 : text.find("\n", match.start())]
            stripped = line.strip()
            if not stripped or stripped.startswith(("function ", "event ", "import ", "pragma ", "return ", "if ", "for ", "while ")):
                continue
            if "(" in stripped and ")" in stripped and "mapping" not in stripped:
                continue
            variables.append(
                {
                    "name": match.group("name"),
                    "type": " ".join(match.group("type").split()),
                    "file": rel,
                    "line": _line_of(text, match.start()),
                    "snippet": stripped[:220],
                }
            )
        return variables


def infer_protocol_type(functions: list[dict], variables: list[dict], text: str) -> str:
    names = " ".join(f.get("name", "") for f in functions).lower()
    var_text = " ".join(f"{v.get('name', '')} {v.get('type', '')}" for v in variables).lower()
    corpus = f"{names} {var_text} {text.lower()}"
    scores = {
        "vault": _score(corpus, ("deposit", "withdraw", "redeem", "totalassets", "totalsupply", "shares")),
        "lending": _score(corpus, ("borrow", "repay", "liquidate", "collateral", "debt", "healthfactor", "ltv")),
        "amm": _score(corpus, ("swap", "reserve", "pool", "liquidity", "tick", "sqrtprice")),
        "bridge": _score(corpus, ("message", "domain", "chainid", "nonce", "replay", "release", "lock", "sendmessage")),
        "staking/rewards": _score(corpus, ("rewardpertoken", "rewarddebt", "accreward", "claim", "stake", "unstake")),
        "governance": _score(corpus, ("proposal", "vote", "quorum", "timelock", "execute")),
        "oracle": _score(corpus, ("latestrounddata", "getprice", "oracle", "twap", "heartbeat")),
        "account abstraction/paymaster": _score(corpus, ("paymaster", "useroperation", "entrypoint", "validatepaymasteruserop")),
    }
    best, score = max(scores.items(), key=lambda item: item[1])
    return best if score > 0 else "unknown"


def extract_roles(texts: list[str], functions: list[dict]) -> list[dict]:
    corpus = "\n".join(texts)
    roles: dict[str, dict] = {}
    for term in ROLE_TERMS:
        if term.lower() in corpus.lower():
            name = term if term.isupper() else term.lower()
            roles[name] = {
                "name": name,
                "capabilities": [f"Observed role/access-control signal `{term}`"],
                "trust_level": "privileged",
                "source": "evm heuristic",
            }
    for fn in functions:
        for mod in fn.get("modifiers", []):
            if mod.lower().startswith("only"):
                roles.setdefault(
                    mod,
                    {
                        "name": mod,
                        "capabilities": [f"Modifier on {fn.get('contract')}.{fn.get('name')}"],
                        "trust_level": "privileged",
                        "source": fn.get("file"),
                    },
                )
    return list(roles.values())


def extract_external_dependencies(files: list[SolidityFileIndex]) -> list[dict]:
    deps: dict[str, dict] = {}
    for file_index in files:
        for imported in file_index.imports:
            deps[imported] = {
                "name": imported,
                "dependency_type": "import",
                "description": "Imported Solidity dependency.",
                "trust_assumption": "Imported dependency behavior matches audited assumptions.",
                "source": file_index.path,
            }
        for contract in file_index.contracts:
            if contract.kind == "interface" or contract.name.startswith("I"):
                deps.setdefault(
                    contract.name,
                    {
                        "name": contract.name,
                        "dependency_type": "interface",
                        "description": "Interface or external dependency detected in source.",
                        "trust_assumption": "External implementation follows the interface safely.",
                        "source": file_index.path,
                    },
                )
    return list(deps.values())


def _signals(text: str) -> list[str]:
    lower = text.lower()
    signals: list[str] = []
    if any(term.lower() in lower for term in ORACLE_TERMS):
        signals.append("oracle")
    if any(term.lower() in lower for term in ROLE_TERMS):
        signals.append("access_control")
    if "initializer" in lower or "upgradeable" in lower or "proxy" in lower or "delegatecall" in lower:
        signals.append("upgradeable")
    if any(term in lower for term in ("transfer(", "safetransfer(", "transferfrom(")):
        signals.append("token_transfer")
    if any(term in lower for term in ("deposit", "withdraw", "redeem", "mint")):
        signals.append("asset_accounting")
    return signals


def _contract_regions(text: str, contracts: list[SolidityContract]) -> list[tuple[SolidityContract, int, int]]:
    matches = list(CONTRACT_RE.finditer(text))
    regions: list[tuple[SolidityContract, int, int]] = []
    for idx, match in enumerate(matches):
        end = matches[idx + 1].start() if idx + 1 < len(matches) else len(text)
        if idx < len(contracts):
            regions.append((contracts[idx], match.start(), end))
    return regions


def _modifiers_for_contract(text: str, contract_name: str) -> list[str]:
    contract_match = re.search(rf"\b(?:contract|interface|library)\s+{re.escape(contract_name)}\b", text)
    if not contract_match:
        return []
    next_match = CONTRACT_RE.search(text, contract_match.end())
    region = text[contract_match.start() : next_match.start() if next_match else len(text)]
    return [match.group(1) for match in MODIFIER_RE.finditer(region)]


def _line_of(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def _score(corpus: str, terms: tuple[str, ...]) -> int:
    return sum(1 for term in terms if term in corpus)
