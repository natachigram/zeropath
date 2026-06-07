"""Foundry PoC skeleton templates."""

from __future__ import annotations

import re

from zeropath.core.schemas import CandidateFinding


def render_foundry_poc(candidate: CandidateFinding) -> str:
    class_name = _class_name(candidate.id)
    required = "\n".join(f"        // TODO: {item}" for item in candidate.required_state) or "        // TODO: define required state"
    sequence = "\n".join(f"        // {idx + 1}. {step}" for idx, step in enumerate(candidate.transaction_sequence)) or "        // TODO: define transaction sequence"
    locations = "\n".join(
        f"// - {loc.file}:{loc.line_start or '?'} {loc.contract or ''}.{loc.function or ''}".rstrip()
        for loc in candidate.root_cause_locations
    ) or "// - TODO: add root cause locations"
    return f"""// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

// ZeroPath generated hypothesis skeleton. This is not proof until the test is
// completed and a backend records a passing result.
//
// Candidate: {candidate.id}
// Title: {candidate.title}
// Affected invariant: {candidate.affected_invariant or "unknown"}
// Attacker model: {candidate.attacker_model or "TODO"}
//
// Root cause signals:
{locations}

import "forge-std/Test.sol";

contract {class_name} is Test {{
    address internal attacker = address(0xA11CE);
    address internal victim = address(0xB0B);

    function setUp() public {{
{required}
    }}

    function test_{candidate.id.replace("-", "_")}_hypothesis() public {{
{sequence}

        // TODO: execute calls against the protocol under test.
        // TODO: assert measurable fund impact or invariant violation.
        // Example:
        // assertGt(attacker.balance, 0, "attacker profit should be measured");
    }}
}}
"""


def _class_name(candidate_id: str) -> str:
    safe = re.sub(r"[^A-Za-z0-9_]", "_", candidate_id)
    return f"ZeroPath_{safe}_PoC"
