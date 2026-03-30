"""
Value conservation invariant detector.

Detects protocols that move assets (deposit/withdraw, mint/burn) and
infers that total value in must equal total value out + fees.

Detection strategy:
  1. Find deposit + withdraw function pairs.
  2. Find mint + burn function pairs.
  3. Check whether the same balance/supply variables are read and written
     in both directions.
  4. If the protocol uses an internal price oracle for asset valuation
     (e.g. vault strategy), flag additional oracle manipulation risk.
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


class ValueConservationDetector(BaseDetector):
    """Infer value conservation invariants from asset flow patterns."""

    name = "value_conservation"

    def detect(
        self,
        graph: ProtocolGraph,
        pattern: ProtocolPattern,
    ) -> list[Invariant]:
        results: list[Invariant] = []

        # 1. Deposit/withdraw pair
        if pattern.deposit_functions and pattern.withdraw_functions:
            has_oracle = pattern.has_oracle
            severity = InvariantSeverity.HIGH if has_oracle else InvariantSeverity.MEDIUM
            confidence = 0.70 if has_oracle else 0.55

            tags = {"conservation", "vault"}
            if has_oracle:
                tags.add("oracle")
                tags.add("flash_loan")

            precedents = _rag.query(InvariantType.VALUE_CONSERVATION, tags=tags)
            boost = _rag.confidence_boost(precedents)
            evidence_str = _rag.evidence_summary(precedents)

            evidence = [
                f"Protocol has deposit functions {pattern.deposit_functions[:3]} "
                f"and withdraw functions {pattern.withdraw_functions[:3]}.",
                "Value conservation requires: totalDeposited - totalWithdrawn == currentBalance.",
            ]
            if has_oracle:
                evidence.append(
                    "Oracle-based asset valuation detected — flash loan price manipulation "
                    "could inflate deposit value or deflate withdrawal cost."
                )
            if evidence_str:
                evidence.append(evidence_str)

            all_funcs = pattern.deposit_functions + pattern.withdraw_functions
            all_vars = pattern.balance_vars + pattern.supply_vars

            results.append(
                Invariant(
                    type=InvariantType.VALUE_CONSERVATION,
                    severity=severity,
                    description=(
                        "Value conservation: total assets deposited must equal total assets "
                        "withdrawn plus fees. No transaction may remove more value than it deposits."
                        + (" Oracle-based valuation creates flash-loan manipulation risk." if has_oracle else "")
                    ),
                    formal_spec=_spec_gen.generate(InvariantType.VALUE_CONSERVATION, pattern),
                    confidence=min(confidence + boost, 0.95),
                    functions_involved=all_funcs[:10],
                    state_vars_involved=all_vars[:5],
                    historical_precedent=precedents,
                    evidence=evidence,
                    detector=self.name,
                )
            )

        # 2. Mint/burn pair (token inflation)
        if pattern.mint_functions and pattern.burn_functions:
            precedents_mb = _rag.query(InvariantType.VALUE_CONSERVATION, tags={"mint_inflation"})
            boost_mb = _rag.confidence_boost(precedents_mb)
            evidence_mb = _rag.evidence_summary(precedents_mb)

            evidence = [
                f"Protocol mints via {pattern.mint_functions[:3]} "
                f"and burns via {pattern.burn_functions[:3]}.",
                "Mint/burn accounting: tokens_minted - tokens_burned == totalSupply_delta.",
            ]
            if evidence_mb:
                evidence.append(evidence_mb)

            results.append(
                Invariant(
                    type=InvariantType.VALUE_CONSERVATION,
                    severity=InvariantSeverity.MEDIUM,
                    description=(
                        "Mint/burn accounting invariant: total tokens minted minus total "
                        "tokens burned must equal the change in totalSupply."
                    ),
                    formal_spec=_spec_gen.generate(InvariantType.VALUE_CONSERVATION, pattern),
                    confidence=min(0.55 + boost_mb, 0.95),
                    functions_involved=(pattern.mint_functions + pattern.burn_functions)[:10],
                    state_vars_involved=pattern.supply_vars[:5],
                    historical_precedent=precedents_mb,
                    evidence=evidence,
                    detector=self.name,
                )
            )

        logger.debug("value_conservation_detector", findings=len(results))
        return results
