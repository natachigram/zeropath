"""Foundry PoC skeleton templates."""

from __future__ import annotations

import re

from zeropath.core.schemas import CandidateFinding, CandidateStatePlan


def render_foundry_poc(
    candidate: CandidateFinding,
    *,
    state_plan: CandidateStatePlan | None = None,
) -> str:
    class_name = _class_name(candidate.id)
    setup = _comment_block(
        state_plan.setup_steps if state_plan else [f"Materialize required state: {item}" for item in candidate.required_state],
        indent="        ",
        empty="TODO: define required state",
    )
    sequence = _comment_block(
        state_plan.transaction_steps if state_plan else [
            f"{idx + 1}. {step}" for idx, step in enumerate(candidate.transaction_sequence)
        ],
        indent="        ",
        empty="TODO: define transaction sequence",
    )
    call_hints = _comment_block(
        _entrypoint_call_hints(candidate.entrypoints),
        indent="        ",
        empty="TODO: map candidate entrypoints to protocol calls",
    )
    locations = "\n".join(
        f"// - {loc.file}:{loc.line_start or '?'} {loc.contract or ''}.{loc.function or ''}".rstrip()
        for loc in candidate.root_cause_locations
    ) or "// - TODO: add root cause locations"
    plan_header = _plan_header(state_plan)
    fixtures = _top_level_section("Suggested fixtures", state_plan.suggested_fixtures if state_plan else [])
    missing = _top_level_section("Missing dependencies", state_plan.missing_dependencies if state_plan else [])
    evidence = _top_level_section("Evidence still needed", state_plan.evidence_to_collect if state_plan else [])
    return f"""// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

// ZeroPath generated hypothesis skeleton. This is not proof until the test is
// completed and a backend records a passing result.
//
// Candidate: {candidate.id}
// Title: {candidate.title}
// Affected invariant: {candidate.affected_invariant or "unknown"}
// Attacker model: {candidate.attacker_model or "TODO"}
{plan_header}
//
// Root cause signals:
{locations}
{fixtures}
{missing}
{evidence}

import "forge-std/Test.sol";

contract {class_name} is Test {{
    address internal attacker = address(0xA11CE);
    address internal victim = address(0xB0B);

    function setUp() public {{
{setup}
    }}

    function test_{candidate.id.replace("-", "_")}_hypothesis() public {{
{sequence}

        // Entrypoint call hints:
{call_hints}

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


def _plan_header(state_plan: CandidateStatePlan | None) -> str:
    if state_plan is None:
        return "// State plan: transient plan generated from candidate fields"
    artifact = state_plan.artifact_path or "not persisted"
    return f"// State plan: {artifact}\n// Plan confidence: {state_plan.confidence}"


def _top_level_section(title: str, items: list[str]) -> str:
    lines = [f"// {title}:"]
    if not items:
        lines.append("// - None recorded")
    else:
        lines.extend(f"// - {item}" for item in items)
    return "\n" + "\n".join(lines)


def _comment_block(items: list[str], *, indent: str, empty: str) -> str:
    if not items:
        return f"{indent}// TODO: {empty}"
    return "\n".join(f"{indent}// TODO: {item}" for item in items)


def _entrypoint_call_hints(entrypoints: list[str]) -> list[str]:
    hints: list[str] = []
    for entrypoint in entrypoints:
        parsed = _parse_entrypoint(entrypoint)
        if parsed is None:
            hints.append(f"vm.prank(attacker); call `{entrypoint}` with attacker-controlled parameters.")
            continue
        name, params = parsed
        args = ", ".join(_placeholder_arg(param, idx) for idx, param in enumerate(params))
        call = f"protocol.{name}({args});" if args else f"protocol.{name}();"
        hints.append(f"vm.prank(attacker); {call}")
    return hints


def _parse_entrypoint(entrypoint: str) -> tuple[str, list[str]] | None:
    match = re.match(r"^\s*(?P<name>[A-Za-z_][A-Za-z0-9_]*)\((?P<params>.*)\)\s*$", entrypoint)
    if not match:
        if re.match(r"^\s*[A-Za-z_][A-Za-z0-9_]*\s*$", entrypoint):
            return entrypoint.strip(), []
        return None
    params = [
        _clean_param(param)
        for param in match.group("params").split(",")
        if param.strip()
    ]
    return match.group("name"), params


def _clean_param(param: str) -> str:
    tokens = [token for token in param.strip().split() if token not in {"calldata", "memory", "storage"}]
    return tokens[0] if tokens else "unknown"


def _placeholder_arg(param_type: str, idx: int) -> str:
    lowered = param_type.lower()
    if lowered.startswith("address"):
        return "attacker" if idx == 0 else "victim"
    if lowered.startswith("uint") or lowered.startswith("int"):
        return "amount"
    if lowered == "bool":
        return "true"
    if lowered.startswith("bytes") or lowered == "string":
        return '""'
    if lowered.endswith("[]"):
        return f"{_identifier_type(lowered)}Array"
    return f"arg{idx}"


def _identifier_type(param_type: str) -> str:
    return re.sub(r"[^A-Za-z0-9_]", "_", param_type).strip("_") or "arg"
