"""
SequenceOrchestrator — Phase 4 core.

Takes a Phase 3 SwarmReport and produces a SequenceReport:
  1. Selects the right builder per AttackClass
  2. Builds concrete TransactionSequences for each hypothesis
  3. Runs Foundry + Hardhat code generators
  4. Ranks sequences by completeness + confidence
  5. Returns SequenceReport

Design:
  - Each hypothesis is processed independently (fail-safe per hypothesis)
  - Code generation failures don't block sequence generation
  - Both Foundry and Hardhat are generated unless framework is specified
"""

from __future__ import annotations

import logging
import time
from typing import Any

from zeropath.adversarial.models import AttackClass, AttackHypothesis, HypothesisStatus
from zeropath.adversarial.models import SwarmReport
from zeropath.models import ProtocolGraph
from zeropath.sequencer.base import BaseSequenceBuilder
from zeropath.sequencer.builders import (
    AccessControlSequenceBuilder,
    FlashLoanSequenceBuilder,
    GovernanceSequenceBuilder,
    IntegerMathSequenceBuilder,
    OracleManipulationSequenceBuilder,
    ReentrancySequenceBuilder,
)
from zeropath.sequencer.codegen import FoundryTestGenerator, HardhatScriptGenerator
from zeropath.sequencer.models import (
    SequenceReport,
    SequenceStatus,
    TestFramework,
    TransactionSequence,
)

logger = logging.getLogger(__name__)

# Map AttackClass → builder
_BUILDER_MAP: dict[AttackClass, BaseSequenceBuilder] = {
    AttackClass.FLASH_LOAN: FlashLoanSequenceBuilder(),
    AttackClass.ORACLE_MANIPULATION: OracleManipulationSequenceBuilder(),
    AttackClass.REENTRANCY: ReentrancySequenceBuilder(),
    AttackClass.ACCESS_CONTROL: AccessControlSequenceBuilder(),
    AttackClass.GOVERNANCE: GovernanceSequenceBuilder(),
    AttackClass.INTEGER_MATH: IntegerMathSequenceBuilder(),
    # COMPOSABILITY → FlashLoan builder (closest match)
    AttackClass.COMPOSABILITY: FlashLoanSequenceBuilder(),
    AttackClass.PRICE_MANIPULATION: OracleManipulationSequenceBuilder(),
}

# Statuses that qualify for sequence generation
_GENERATE_FOR_STATUSES = {
    HypothesisStatus.CONSENSUS,
    HypothesisStatus.ENDORSED,
    HypothesisStatus.PROPOSED,
    HypothesisStatus.CHALLENGED,
}

# Minimum confidence to generate a sequence
_MIN_CONFIDENCE = 0.40


class SequenceOrchestrator:
    """
    Converts a Phase 3 SwarmReport into a Phase 4 SequenceReport.

    Parameters
    ----------
    frameworks : TestFramework
        Which test frameworks to generate code for.
    min_confidence : float
        Minimum hypothesis confidence to process.
    skip_rejected : bool
        Skip REJECTED hypotheses (default True).
    """

    def __init__(
        self,
        frameworks: TestFramework = TestFramework.BOTH,
        min_confidence: float = _MIN_CONFIDENCE,
        skip_rejected: bool = True,
    ) -> None:
        self.frameworks = frameworks
        self.min_confidence = min_confidence
        self.skip_rejected = skip_rejected
        self._foundry_gen = FoundryTestGenerator()
        self._hardhat_gen = HardhatScriptGenerator()

    def run(
        self,
        swarm_report: SwarmReport,
        graph: ProtocolGraph,
    ) -> SequenceReport:
        """Build sequences for all qualifying hypotheses in the swarm report."""
        start = time.monotonic()

        # Filter hypotheses to process
        candidates = self._select_candidates(swarm_report.hypotheses)
        logger.info(
            "SequenceOrchestrator: processing %d / %d hypotheses",
            len(candidates), len(swarm_report.hypotheses),
        )

        sequences: list[TransactionSequence] = []
        for hyp in candidates:
            seq = self._process_hypothesis(hyp, graph)
            if seq:
                sequences.append(seq)

        # Sort by completeness DESC, then hypothesis confidence DESC
        sequences.sort(
            key=lambda s: (s.completeness_score, s.context.requires_single_block),
            reverse=True,
        )

        elapsed = time.monotonic() - start

        full_poc_count = sum(
            1 for s in sequences
            if s.foundry_test is not None or s.hardhat_test is not None
        )
        manual_param_count = sum(
            1 for s in sequences if s.requires_manual_params
        )

        return SequenceReport(
            protocol_name=swarm_report.protocol_name,
            swarm_report_id=swarm_report.id,
            sequences=sequences,
            total_hypotheses_input=len(swarm_report.hypotheses),
            sequences_generated=len(sequences),
            sequences_with_full_poc=full_poc_count,
            sequences_requiring_manual_params=manual_param_count,
            analysis_metadata={
                "frameworks": self.frameworks.value,
                "min_confidence_threshold": self.min_confidence,
                "elapsed_seconds": round(elapsed, 3),
                "candidates_processed": len(candidates),
            },
        )

    def _select_candidates(
        self, hypotheses: list[AttackHypothesis]
    ) -> list[AttackHypothesis]:
        """Filter hypotheses worth generating sequences for."""
        result = []
        for h in hypotheses:
            if self.skip_rejected and h.status == HypothesisStatus.REJECTED:
                continue
            if h.confidence < self.min_confidence:
                continue
            if h.status not in _GENERATE_FOR_STATUSES and self.skip_rejected:
                continue
            result.append(h)
        return result

    def _process_hypothesis(
        self,
        hypothesis: AttackHypothesis,
        graph: ProtocolGraph,
    ) -> TransactionSequence | None:
        """Build sequence + code for one hypothesis."""
        attack_class = hypothesis.attack_class

        builder = _BUILDER_MAP.get(attack_class)
        if builder is None:
            logger.debug(
                "No builder for attack class %s — skipping hypothesis '%s'",
                attack_class.value, hypothesis.title,
            )
            return None

        # Build sequence
        seq = builder.build(hypothesis, graph)
        if seq is None:
            return None

        # Generate code
        if self.frameworks in (TestFramework.FOUNDRY, TestFramework.BOTH):
            try:
                seq.foundry_test = self._foundry_gen.generate(seq)
            except Exception:
                logger.exception(
                    "Foundry codegen failed for hypothesis '%s'", hypothesis.title
                )

        if self.frameworks in (TestFramework.HARDHAT, TestFramework.BOTH):
            try:
                seq.hardhat_test = self._hardhat_gen.generate(seq)
            except Exception:
                logger.exception(
                    "Hardhat codegen failed for hypothesis '%s'", hypothesis.title
                )

        logger.debug(
            "Generated sequence for '%s' (completeness=%.2f, foundry=%s, hardhat=%s)",
            hypothesis.title,
            seq.completeness_score,
            seq.foundry_test is not None,
            seq.hardhat_test is not None,
        )
        return seq
