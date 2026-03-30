"""
Phase 2 Invariant Inference Engine.

Orchestrates all invariant detectors over a ProtocolGraph and produces
an InvariantReport.

Pipeline:
  1. Run DeFiPatternDetector → ProtocolPattern
  2. Run OracleMapper → list[OracleDependency]
  3. Run all BaseDetector subclasses in order
  4. Deduplicate by (type, contract, function)
  5. Sort by severity + confidence
  6. Build and return InvariantReport

Usage::

    engine = InvariantInferenceEngine()
    report = engine.analyse(graph, protocol_name="MyProtocol")
"""

from __future__ import annotations

import time
from typing import Optional

from zeropath.invariants.detectors.access_control import AccessControlDetector
from zeropath.invariants.detectors.balance_consistency import BalanceConsistencyDetector
from zeropath.invariants.detectors.base import BaseDetector
from zeropath.invariants.detectors.collateralization import CollateralizationDetector
from zeropath.invariants.detectors.cross_protocol import CrossProtocolDetector
from zeropath.invariants.detectors.flash_loan_safety import FlashLoanSafetyDetector
from zeropath.invariants.detectors.governance import GovernanceSafetyDetector
from zeropath.invariants.detectors.liquidity_conservation import LiquidityConservationDetector
from zeropath.invariants.detectors.oracle_manipulation import OracleManipulationDetector
from zeropath.invariants.detectors.reentrancy import ReentrancyDetector
from zeropath.invariants.detectors.share_accounting import ShareAccountingDetector
from zeropath.invariants.detectors.value_conservation import ValueConservationDetector
from zeropath.invariants.models import (
    Invariant,
    InvariantReport,
    InvariantSeverity,
    InvariantType,
    OracleDependency,
    ProtocolPattern,
)
from zeropath.invariants.oracle_mapper import OracleMapper
from zeropath.invariants.patterns import DeFiPatternDetector
from zeropath.logging_config import get_logger
from zeropath.models import ProtocolGraph

logger = get_logger(__name__)


# Severity ordering for sorting (CRITICAL first)
_SEVERITY_ORDER = {
    InvariantSeverity.CRITICAL: 0,
    InvariantSeverity.HIGH: 1,
    InvariantSeverity.MEDIUM: 2,
    InvariantSeverity.LOW: 3,
    InvariantSeverity.INFO: 4,
}


class InvariantInferenceEngine:
    """
    Orchestrates the full Phase 2 invariant inference pipeline.

    Usage::

        engine = InvariantInferenceEngine()
        report = engine.analyse(graph, protocol_name="Aave V3")
    """

    def __init__(
        self,
        detectors: Optional[list[BaseDetector]] = None,
    ) -> None:
        """
        Args:
            detectors: Override the default detector set.  Useful for testing
                       specific detectors in isolation.
        """
        self._pattern_detector = DeFiPatternDetector()
        self._oracle_mapper = OracleMapper()
        self._detectors: list[BaseDetector] = detectors or _default_detectors()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def analyse(
        self,
        graph: ProtocolGraph,
        protocol_name: str = "unknown",
    ) -> InvariantReport:
        """
        Run the full invariant inference pipeline.

        Args:
            graph:         Phase 1 protocol graph.
            protocol_name: Human-readable protocol name for the report.

        Returns:
            InvariantReport with all detected invariants.
        """
        start_ts = time.time()
        logger.info("invariant_engine_start", protocol=protocol_name)

        # Step 1: Detect DeFi patterns
        pattern = self._pattern_detector.detect(graph)
        logger.info(
            "pattern_detected",
            types=pattern.protocol_types,
            has_oracle=pattern.has_oracle,
            has_flash_loan=pattern.has_flash_loan,
        )

        # Step 2: Map oracle dependencies (shared across detectors)
        oracle_deps = self._oracle_mapper.map(graph)

        # Step 3: Run all detectors
        all_invariants: list[Invariant] = []
        for detector in self._detectors:
            try:
                found = detector.detect(graph, pattern)
                all_invariants.extend(found)
                logger.debug(
                    "detector_ran",
                    detector=detector.name,
                    found=len(found),
                )
            except Exception as exc:
                # Individual detector failures must not break the pipeline
                logger.error(
                    "detector_error",
                    detector=detector.name,
                    error=str(exc),
                )

        # Step 4: Deduplicate
        invariants = _deduplicate(all_invariants)

        # Step 5: Sort by severity (critical first), then confidence (highest first)
        invariants.sort(
            key=lambda i: (
                _SEVERITY_ORDER.get(i.severity, 99),
                -i.confidence,
            )
        )

        elapsed = time.time() - start_ts
        logger.info(
            "invariant_engine_done",
            protocol=protocol_name,
            total=len(invariants),
            critical=sum(1 for i in invariants if i.severity == InvariantSeverity.CRITICAL),
            high=sum(1 for i in invariants if i.severity == InvariantSeverity.HIGH),
            elapsed_s=round(elapsed, 3),
        )

        return InvariantReport(
            protocol_name=protocol_name,
            protocol_pattern=pattern,
            invariants=invariants,
            oracle_dependencies=oracle_deps,
            analysis_metadata={
                "detectors_run": [d.name for d in self._detectors],
                "elapsed_seconds": round(elapsed, 3),
                "graph_contracts": len(graph.contracts),
                "graph_functions": len(graph.functions),
                "graph_state_vars": len(graph.state_variables),
                "external_dependencies": len(graph.external_dependencies),
            },
        )


# ---------------------------------------------------------------------------
# Default detector set
# ---------------------------------------------------------------------------


def _default_detectors() -> list[BaseDetector]:
    """Return the full set of invariant detectors in priority order."""
    return [
        # Oracle first — other detectors use oracle context
        OracleManipulationDetector(),
        # Structural
        ReentrancyDetector(),
        AccessControlDetector(),
        # Economic
        ValueConservationDetector(),
        BalanceConsistencyDetector(),
        CollateralizationDetector(),
        ShareAccountingDetector(),
        # Protocol-type specific
        LiquidityConservationDetector(),
        GovernanceSafetyDetector(),
        FlashLoanSafetyDetector(),
        # Cross-protocol (runs last, most context needed)
        CrossProtocolDetector(),
    ]


# ---------------------------------------------------------------------------
# Deduplication
# ---------------------------------------------------------------------------


def _deduplicate(invariants: list[Invariant]) -> list[Invariant]:
    """
    Remove duplicate invariants by (type, primary_contract, primary_function).

    When duplicates exist, keep the one with higher confidence.
    """
    seen: dict[tuple[str, str, str], Invariant] = {}

    for inv in invariants:
        contract = inv.contracts_involved[0] if inv.contracts_involved else ""
        func = inv.functions_involved[0] if inv.functions_involved else ""
        key = (inv.type.value, contract, func)

        existing = seen.get(key)
        if existing is None or inv.confidence > existing.confidence:
            seen[key] = inv

    return list(seen.values())
