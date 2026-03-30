"""
Oracle manipulation invariant detector.

Wraps the OracleMapper (oracle_mapper.py) to produce Invariant objects
from oracle dependency analysis.

Classification:
  - HIGH  risk oracle in state-changing function → CRITICAL invariant
  - HIGH  risk oracle in view function           → HIGH invariant
  - MEDIUM risk oracle in state-changing         → HIGH invariant
  - MEDIUM risk oracle in view                   → MEDIUM invariant
  - LOW   risk oracle (Chainlink/long TWAP)      → LOW invariant (informational)
"""

from __future__ import annotations

from zeropath.invariants.detectors.base import BaseDetector
from zeropath.invariants.formal_spec import FormalSpecGenerator
from zeropath.invariants.models import (
    Invariant,
    InvariantSeverity,
    InvariantType,
    OracleManipulationRisk,
    ProtocolPattern,
)
from zeropath.invariants.oracle_mapper import OracleMapper
from zeropath.invariants.rag import get_rag
from zeropath.logging_config import get_logger
from zeropath.models import ProtocolGraph

logger = get_logger(__name__)

_spec_gen = FormalSpecGenerator()
_rag = get_rag()
_mapper = OracleMapper()


class OracleManipulationDetector(BaseDetector):
    """Convert OracleDependency detections into Invariant findings."""

    name = "oracle_manipulation"

    def detect(
        self,
        graph: ProtocolGraph,
        pattern: ProtocolPattern,
    ) -> list[Invariant]:
        oracle_deps = _mapper.map(graph)
        if not oracle_deps:
            return []

        results: list[Invariant] = []
        # Group by (contract, function) to avoid duplicate invariants
        seen: set[tuple[str, str]] = set()

        for dep in oracle_deps:
            key = (dep.contract_name, dep.function_name)
            if key in seen:
                continue
            seen.add(key)

            severity, confidence = _classify(dep)
            tags: set[str] = {"oracle"}
            if dep.is_single_block:
                tags.add("flash_loan")
            if dep.used_in_state_changing_function:
                tags.add("lending")

            precedents = _rag.query(InvariantType.ORACLE_MANIPULATION, tags=tags)
            boost = _rag.confidence_boost(precedents)
            evidence_str = _rag.evidence_summary(precedents)

            evidence = [dep.evidence]
            if dep.is_single_block:
                evidence.append(
                    f"Single-block oracle read ({dep.oracle_type.value}) in "
                    f"{dep.contract_name}.{dep.function_name}() — "
                    f"manipulable within one transaction."
                )
            if dep.used_in_state_changing_function:
                evidence.append(
                    "Oracle read occurs inside a state-mutating function — "
                    "manipulation directly affects protocol state."
                )
            if evidence_str:
                evidence.append(evidence_str)

            results.append(
                Invariant(
                    type=InvariantType.ORACLE_MANIPULATION,
                    severity=severity,
                    description=(
                        f"Oracle manipulation risk in {dep.contract_name}.{dep.function_name}(): "
                        f"reads {dep.oracle_type.value} oracle ({dep.oracle_contract}) via "
                        f"{dep.read_function}(). "
                        f"Risk: {dep.manipulation_risk.value.upper()}. "
                        + ("Single-block read — flash-loan manipulable. " if dep.is_single_block else "")
                    ),
                    formal_spec=_spec_gen.generate(InvariantType.ORACLE_MANIPULATION, pattern),
                    confidence=min(confidence + boost, 0.95),
                    contracts_involved=[dep.contract_name],
                    functions_involved=[dep.function_name],
                    oracle_dependencies=[dep],
                    historical_precedent=precedents,
                    evidence=evidence,
                    detector=self.name,
                )
            )

        logger.debug("oracle_manipulation_detector", findings=len(results))
        return results


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _classify(dep: "OracleDependency") -> tuple[InvariantSeverity, float]:  # noqa: F821
    """Map (risk, is_state_changing) → (severity, confidence)."""
    from zeropath.invariants.models import OracleManipulationRisk
    risk = dep.manipulation_risk
    mutating = dep.used_in_state_changing_function

    if risk == OracleManipulationRisk.HIGH and mutating:
        return InvariantSeverity.CRITICAL, 0.85
    if risk == OracleManipulationRisk.HIGH:
        return InvariantSeverity.HIGH, 0.70
    if risk == OracleManipulationRisk.MEDIUM and mutating:
        return InvariantSeverity.HIGH, 0.65
    if risk == OracleManipulationRisk.MEDIUM:
        return InvariantSeverity.MEDIUM, 0.50
    # LOW risk — informational
    return InvariantSeverity.LOW, 0.30
