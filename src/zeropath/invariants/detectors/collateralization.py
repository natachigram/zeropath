"""
Collateralization invariant detector.

For lending protocols: every borrower's collateral value must exceed
their debt value * minimum collateral ratio.

Detection strategy:
  1. Detect lending protocol (borrow + repay + liquidate functions).
  2. Detect collateral and debt state variables.
  3. Check if liquidation is possible (liquidate functions present).
  4. Check if oracle dependency exists (collateral valuation via oracle).
  5. Flag single-block oracle reads in borrow/liquidate paths as HIGH risk.
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
from zeropath.models import ProtocolGraph

logger = get_logger(__name__)

_spec_gen = FormalSpecGenerator()
_rag = get_rag()


class CollateralizationDetector(BaseDetector):
    """Detect collateralization invariants in lending protocols."""

    name = "collateralization"

    def detect(
        self,
        graph: ProtocolGraph,
        pattern: ProtocolPattern,
    ) -> list[Invariant]:
        results: list[Invariant] = []

        is_lending = (
            bool(pattern.borrow_functions) and bool(pattern.repay_functions)
        ) or (
            bool(pattern.liquidate_functions) and
            (bool(pattern.debt_vars) or bool(pattern.collateral_vars))
        )

        if not is_lending:
            return results

        has_oracle = pattern.has_oracle
        has_liquidation = bool(pattern.liquidate_functions)
        has_collateral_vars = bool(pattern.collateral_vars)
        has_debt_vars = bool(pattern.debt_vars)

        # Base severity
        if has_oracle and not has_liquidation:
            severity = InvariantSeverity.CRITICAL
            confidence = 0.80
        elif has_oracle:
            severity = InvariantSeverity.HIGH
            confidence = 0.75
        else:
            severity = InvariantSeverity.MEDIUM
            confidence = 0.60

        tags = {"collateral", "lending"}
        if has_oracle:
            tags.add("oracle")
        if not has_liquidation:
            tags.add("bad_debt")

        precedents = _rag.query(InvariantType.COLLATERALIZATION, tags=tags)
        boost = _rag.confidence_boost(precedents)
        evidence_str = _rag.evidence_summary(precedents)

        evidence = [
            f"Lending protocol detected. "
            f"Borrow: {pattern.borrow_functions[:3]}, "
            f"Repay: {pattern.repay_functions[:3]}, "
            f"Liquidate: {pattern.liquidate_functions[:3]}.",
        ]
        if has_collateral_vars:
            evidence.append(f"Collateral vars: {pattern.collateral_vars[:3]}")
        if has_debt_vars:
            evidence.append(f"Debt vars: {pattern.debt_vars[:3]}")
        if has_oracle:
            evidence.append(
                "Oracle detected for collateral valuation — oracle manipulation "
                "can bypass collateral ratio check (see Cream Finance, $130M)."
            )
        if not has_liquidation:
            evidence.append(
                "No liquidation function detected — under-collateralised positions "
                "cannot be cleared, risking protocol bad debt."
            )
        if evidence_str:
            evidence.append(evidence_str)

        results.append(
            Invariant(
                type=InvariantType.COLLATERALIZATION,
                severity=severity,
                description=(
                    "Collateralization invariant: every borrower's collateral value "
                    "must exceed their debt * minimum collateral ratio at all times. "
                    + ("Oracle manipulation can inflate collateral value. " if has_oracle else "")
                    + ("No liquidation path detected — bad debt risk. " if not has_liquidation else "")
                ),
                formal_spec=_spec_gen.generate(InvariantType.COLLATERALIZATION, pattern),
                confidence=min(confidence + boost, 0.95),
                functions_involved=(
                    pattern.borrow_functions +
                    pattern.repay_functions +
                    pattern.liquidate_functions
                )[:10],
                state_vars_involved=(pattern.collateral_vars + pattern.debt_vars)[:5],
                historical_precedent=precedents,
                evidence=evidence,
                detector=self.name,
            )
        )

        logger.debug("collateralization_detector", findings=len(results))
        return results
