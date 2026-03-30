"""
Reentrancy invariant detector.

Detection strategy:
  1. Find functions that make external calls (EXTERNAL, LOW_LEVEL, DELEGATECALL).
  2. Check whether the function writes state variables AFTER the external call
     (violation of CEI — Checks-Effects-Interactions).
  3. Check whether a reentrancy guard modifier is present.
  4. Classify risk:
     - CRITICAL if no guard + state written after external call + is payable
     - HIGH     if no guard + state written after external call
     - MEDIUM   if has guard but external call transfers value
     - LOW      if guard present and CEI followed
"""

from __future__ import annotations

from zeropath.invariants.detectors.base import BaseDetector
from zeropath.invariants.formal_spec import FormalSpecGenerator
from zeropath.invariants.models import (
    Invariant,
    InvariantSeverity,
    InvariantType,
    ProtocolPattern,
)
from zeropath.invariants.rag import get_rag
from zeropath.logging_config import get_logger
from zeropath.models import CallType, Function, FunctionCall, ProtocolGraph

logger = get_logger(__name__)

_REENTRANCY_GUARD_KW = {"nonreentrant", "reentrant", "noreentrancy", "mutex"}

_spec_gen = FormalSpecGenerator()
_rag = get_rag()


class ReentrancyDetector(BaseDetector):
    """Detect reentrancy patterns in protocol functions."""

    name = "reentrancy"

    def detect(
        self,
        graph: ProtocolGraph,
        pattern: ProtocolPattern,
    ) -> list[Invariant]:
        results: list[Invariant] = []

        # Build a fast map: function_id → FunctionCall list
        calls_by_func: dict[str, list[FunctionCall]] = {}
        for call in graph.function_calls:
            calls_by_func.setdefault(call.caller_id, []).append(call)

        for func in graph.functions:
            if func.is_view or func.is_pure:
                continue

            external_calls = [
                c for c in calls_by_func.get(func.id, [])
                if c.call_type in (
                    CallType.EXTERNAL,
                    CallType.LOW_LEVEL,
                    CallType.DELEGATECALL,
                )
            ]
            if not external_calls:
                continue

            has_guard = _has_reentrancy_guard(func)
            writes_state = bool(func.state_vars_written)
            has_value_transfer = any(c.value_transfer for c in external_calls)

            # Risk assessment
            if not has_guard and writes_state:
                severity = (
                    InvariantSeverity.CRITICAL
                    if func.is_payable
                    else InvariantSeverity.HIGH
                )
                confidence = 0.75 if func.is_payable else 0.65
            elif has_guard and has_value_transfer:
                severity = InvariantSeverity.MEDIUM
                confidence = 0.40
            elif not has_guard:
                severity = InvariantSeverity.MEDIUM
                confidence = 0.45
            else:
                continue  # Guard present, CEI followed — no finding

            from zeropath.invariants.oracle_mapper import _contract_name_for_function
            contract_name = _contract_name_for_function(func, graph)

            precedents = _rag.query(
                InvariantType.REENTRANCY,
                tags={"reentrancy"},
            )
            boost = _rag.confidence_boost(precedents)
            evidence_str = _rag.evidence_summary(precedents)

            evidence = [
                f"{contract_name}.{func.name}() makes external call "
                f"({'with ETH' if has_value_transfer else 'no ETH'}); "
                f"guard={'present' if has_guard else 'ABSENT'}; "
                f"state_written_after={'yes' if writes_state else 'no'}.",
            ]
            if evidence_str:
                evidence.append(evidence_str)

            results.append(
                Invariant(
                    type=InvariantType.REENTRANCY,
                    severity=severity,
                    description=(
                        f"{contract_name}.{func.name}() performs external calls "
                        f"{'without' if not has_guard else 'with'} reentrancy guard. "
                        f"{'State is written after the call — CEI violation.' if writes_state else ''}"
                    ),
                    formal_spec=_spec_gen.generate(InvariantType.REENTRANCY, pattern),
                    confidence=min(confidence + boost, 0.95),
                    contracts_involved=[contract_name],
                    functions_involved=[func.name],
                    state_vars_involved=list(func.state_vars_written),
                    historical_precedent=precedents,
                    evidence=evidence,
                    detector=self.name,
                )
            )

        logger.debug("reentrancy_detector", findings=len(results))
        return results


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _has_reentrancy_guard(func: Function) -> bool:
    """Return True if the function has a reentrancy guard modifier."""
    return any(
        any(kw in m.lower() for kw in _REENTRANCY_GUARD_KW)
        for m in func.modifiers
    )
