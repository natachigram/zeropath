"""
Flash loan safety invariant detector.

Flash loans allow borrowing any amount in one transaction with the
constraint it is returned before the transaction ends.  They are
dangerous when:
  1. The protocol has flash loan functionality itself.
  2. The protocol can be exploited by receiving a flash loan from elsewhere.

Detection strategy:
  1. Detect flash loan functions (executeOperation, onFlashLoan, etc.).
  2. Detect protocols that perform single-block oracle reads AND have
     state-changing functions (external flash loan attack surface).
  3. Check whether the balance check that validates repayment compares
     pre- vs post-call balance, not an external oracle price.
  4. Detect protocols where a flash loan could allow voting manipulation
     (governance + flash loan = CRITICAL).
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


class FlashLoanSafetyDetector(BaseDetector):
    """Detect flash loan safety invariants."""

    name = "flash_loan_safety"

    def detect(
        self,
        graph: ProtocolGraph,
        pattern: ProtocolPattern,
    ) -> list[Invariant]:
        results: list[Invariant] = []

        # 1. Protocol has its own flash loan functionality
        if pattern.has_flash_loan:
            results.extend(self._own_flash_loan(pattern))

        # 2. Oracle + lending = external flash loan attack surface
        if pattern.has_oracle and (
            pattern.borrow_functions or pattern.deposit_functions
        ):
            results.extend(self._external_flash_loan_oracle(pattern))

        # 3. Governance + no timelock = flash loan governance attack
        if (
            pattern.governance_functions
            and not pattern.has_timelock
        ):
            results.extend(self._flash_loan_governance(pattern))

        logger.debug("flash_loan_safety_detector", findings=len(results))
        return results

    # ------------------------------------------------------------------

    def _own_flash_loan(self, pattern: ProtocolPattern) -> list[Invariant]:
        precedents = _rag.query(
            InvariantType.FLASH_LOAN_SAFETY,
            tags={"flash_loan"},
        )
        boost = _rag.confidence_boost(precedents)
        evidence_str = _rag.evidence_summary(precedents)

        evidence = [
            f"Protocol implements flash loan callbacks: {pattern.flash_loan_functions[:3]}.",
            "Repayment must be validated by comparing pre/post contract balance, "
            "not by a parameter the caller controls.",
        ]
        if evidence_str:
            evidence.append(evidence_str)

        return [
            Invariant(
                type=InvariantType.FLASH_LOAN_SAFETY,
                severity=InvariantSeverity.HIGH,
                description=(
                    "Protocol has flash loan functionality. The repayment invariant must hold: "
                    "protocol balance after the flash loan callback >= balance before."
                ),
                formal_spec=_spec_gen.generate(InvariantType.FLASH_LOAN_SAFETY, pattern),
                confidence=min(0.70 + boost, 0.95),
                functions_involved=pattern.flash_loan_functions[:10],
                historical_precedent=precedents,
                evidence=evidence,
                detector=self.name,
            )
        ]

    def _external_flash_loan_oracle(self, pattern: ProtocolPattern) -> list[Invariant]:
        precedents = _rag.query(
            InvariantType.FLASH_LOAN_SAFETY,
            tags={"flash_loan", "oracle"},
        )
        boost = _rag.confidence_boost(precedents)
        evidence_str = _rag.evidence_summary(precedents)

        evidence = [
            "Oracle dependency detected in protocol with lending/deposit functions.",
            "An attacker can use an external flash loan to manipulate the oracle price "
            "within the same transaction, then exploit the lending/deposit logic.",
        ]
        if evidence_str:
            evidence.append(evidence_str)

        return [
            Invariant(
                type=InvariantType.FLASH_LOAN_SAFETY,
                severity=InvariantSeverity.CRITICAL,
                description=(
                    "Flash loan oracle attack surface: protocol reads external price oracle "
                    "in state-changing functions. An external flash loan can manipulate the "
                    "oracle price within the same block."
                ),
                formal_spec=_spec_gen.generate(InvariantType.FLASH_LOAN_SAFETY, pattern),
                confidence=min(0.75 + boost, 0.95),
                functions_involved=(
                    pattern.borrow_functions + pattern.deposit_functions
                )[:10],
                historical_precedent=precedents,
                evidence=evidence,
                detector=self.name,
            )
        ]

    def _flash_loan_governance(self, pattern: ProtocolPattern) -> list[Invariant]:
        precedents = _rag.query(
            InvariantType.GOVERNANCE_SAFETY,
            tags={"flash_loan", "governance"},
        )
        boost = _rag.confidence_boost(precedents)
        evidence_str = _rag.evidence_summary(precedents)

        evidence = [
            f"Governance functions detected: {pattern.governance_functions[:3]}.",
            "No timelock detected. A flash loan can temporarily grant majority "
            "voting power, execute a malicious proposal, and repay in one transaction.",
        ]
        if evidence_str:
            evidence.append(evidence_str)

        return [
            Invariant(
                type=InvariantType.FLASH_LOAN_SAFETY,
                severity=InvariantSeverity.CRITICAL,
                description=(
                    "Flash loan governance attack: governance voting power can be obtained "
                    "via flash loan within a single block. No time-lock prevents immediate "
                    "execution after vote passage. (See Beanstalk, $182M)."
                ),
                formal_spec=_spec_gen.generate(InvariantType.GOVERNANCE_SAFETY, pattern),
                confidence=min(0.80 + boost, 0.95),
                functions_involved=pattern.governance_functions[:10],
                historical_precedent=precedents,
                evidence=evidence,
                detector=self.name,
            )
        ]
