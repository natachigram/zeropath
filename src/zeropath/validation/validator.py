"""
ValidationOrchestrator — Phase 6 top-level coordinator.

Pipeline per (hypothesis, sequence, simulation) triple::

    1. Atomic validators (profit → permission → realism)
         on first failure: build a rejected ValidationResult and return.
    2. SeverityScorer
    3. DuplicateDetector
         on hit: mark duplicate, recommended_action = DISCARD.
    4. ContrarianAgent
         objections adjust confidence and recommended_action.
    5. Compose final ValidationResult.

Per spec: "Reject false positives aggressively. When in doubt, reject."
"""

from __future__ import annotations

import logging
import time
from typing import Iterable, Optional

from zeropath.adversarial.models import AttackHypothesis, SwarmReport
from zeropath.sequencer.models import SequenceReport, TransactionSequence
from zeropath.simulator.models import SimulationReport, SimulationResult
from zeropath.validation.contrarian import ContrarianAgent
from zeropath.validation.duplicate_detector import DuplicateDetector
from zeropath.validation.models import (
    ContrarianObjection,
    ProfitTier,
    RecommendedAction,
    RejectionReason,
    SeverityScore,
    ValidationReport,
    ValidationResult,
)
from zeropath.validation.severity_scorer import SeverityScorer
from zeropath.validation.validators import (
    BaseValidator,
    PermissionValidator,
    ProfitValidator,
    RealismValidator,
    ValidatorVerdict,
)

logger = logging.getLogger(__name__)


# Tunable thresholds — chosen to err on the side of rejection per spec.
_DEFAULT_VALIDATORS: list[BaseValidator] = [
    ProfitValidator(),
    PermissionValidator(),
    RealismValidator(),
]

# Confidence model:
#   start at 0.50 (neutral),
#   +0.20 if simulation succeeded with positive profit,
#   +0.05 per consensus / high-confidence input,
#   −Σ(objection.severity * 0.15) from contrarian.
_BASE_CONFIDENCE = 0.50
_PROFIT_BOOST = 0.20
_CONTRARIAN_PENALTY = 0.15
_NO_OBJECTION_BOOST = 0.05

# Recommended-action thresholds.
_REPORT_MIN_COMPOSITE = 0.50
_REPORT_MIN_CONFIDENCE = 0.55
_DISCARD_MAX_COMPOSITE = 0.20

# Total contrarian objection weight above which we downgrade REPORT → SIMULATE_FURTHER.
_BORDERLINE_OBJECTION_WEIGHT = 1.0
# Single-objection severity that flips us to CONTRARIAN_INVALIDATED.
_CONTRARIAN_KILL_SEVERITY = 0.9


class ValidationOrchestrator:
    """
    Compose validators + scorer + duplicate detector + contrarian into one
    pipeline.

    Parameters
    ----------
    validators : list[BaseValidator] | None
        Override the default validator chain. ``None`` uses
        ProfitValidator + PermissionValidator + RealismValidator.
    severity_scorer : SeverityScorer | None
        Optional custom scorer (e.g. with a real ETH price).
    duplicate_detector : DuplicateDetector | None
        Optional custom detector. ``None`` instantiates an in-memory
        detector — fine for batch runs; Phase 8 will plug a Neo4j one.
    contrarian : ContrarianAgent | None
        ``None`` uses the default deterministic contrarian.
    aggressive_rejection : bool
        When True (default), the orchestrator rejects on the first failing
        validator. False runs every validator and aggregates rejection
        reasons (useful for diagnostics).
    """

    def __init__(
        self,
        *,
        validators: Optional[list[BaseValidator]] = None,
        severity_scorer: Optional[SeverityScorer] = None,
        duplicate_detector: Optional[DuplicateDetector] = None,
        contrarian: Optional[ContrarianAgent] = None,
        aggressive_rejection: bool = True,
    ) -> None:
        self.validators = validators if validators is not None else list(_DEFAULT_VALIDATORS)
        self.severity_scorer = severity_scorer or SeverityScorer()
        self.duplicate_detector = duplicate_detector or DuplicateDetector()
        self.contrarian = contrarian or ContrarianAgent()
        self.aggressive_rejection = aggressive_rejection

    # ------------------------------------------------------------------
    # Single-triple API
    # ------------------------------------------------------------------

    def validate(
        self,
        *,
        hypothesis: AttackHypothesis,
        sequence: TransactionSequence,
        simulation: SimulationResult,
    ) -> ValidationResult:
        result = ValidationResult(
            hypothesis_id=hypothesis.id,
            sequence_id=sequence.id,
            simulation_id=simulation.id,
            protocol_name=simulation.protocol_name or "unknown",
            profit_wei=simulation.profit_wei,
        )

        # ---------- Stage 1: validators ----------
        all_passed = True
        for validator in self.validators:
            verdict: ValidatorVerdict = validator.validate(
                hypothesis=hypothesis,
                sequence=sequence,
                simulation=simulation,
            )
            if not verdict.passed:
                all_passed = False
                result.rejection_reasons.extend(verdict.rejection_reasons)
                if verdict.notes:
                    result.analysis_metadata.setdefault("validator_notes", []).extend(
                        f"[{validator.name}] {n}" for n in verdict.notes
                    )
                if self.aggressive_rejection:
                    break

        # ---------- Stage 2: severity (always, even on reject) ----------
        severity = self.severity_scorer.score(
            hypothesis=hypothesis, sequence=sequence, simulation=simulation
        )
        result.severity = severity
        result.profit_usd = self.severity_scorer._profit_usd(simulation)  # noqa: SLF001
        result.capital_required_usd = severity.capital_required_usd

        # Early exit on validator rejection.
        if not all_passed:
            result.valid = False
            result.confidence = 0.0
            result.reason = self._summarise_rejection(result.rejection_reasons)
            result.recommended_action = RecommendedAction.DISCARD
            # Record fingerprint anyway so later identical hypotheses are
            # auto-dedupped instead of re-running expensive checks.
            fp, _ = self.duplicate_detector.check(hypothesis, validation_id=result.id)
            result.fingerprint = fp
            return result

        # ---------- Stage 3: duplicate detection ----------
        fp, dup_of = self.duplicate_detector.check(hypothesis, validation_id=result.id)
        result.fingerprint = fp
        if dup_of is not None:
            result.valid = False
            result.duplicate_of = dup_of
            result.rejection_reasons.append(RejectionReason.DUPLICATE)
            result.reason = f"duplicate of validation {dup_of}"
            result.confidence = 0.0
            result.recommended_action = RecommendedAction.DISCARD
            return result

        # ---------- Stage 4: contrarian review ----------
        objections = self.contrarian.review(
            hypothesis=hypothesis,
            sequence=sequence,
            simulation=simulation,
            severity=severity,
        )
        result.contrarian_objections = objections

        # ---------- Stage 5: compose final verdict ----------
        kill_objection = next(
            (o for o in objections if o.severity >= _CONTRARIAN_KILL_SEVERITY), None
        )
        if kill_objection is not None:
            result.valid = False
            result.confidence = 0.0
            result.rejection_reasons.append(RejectionReason.CONTRARIAN_INVALIDATED)
            result.reason = (
                f"contrarian invalidated: {kill_objection.category.value} — "
                f"{kill_objection.explanation}"
            )
            result.recommended_action = RecommendedAction.DISCARD
            return result

        confidence = self._compute_confidence(
            simulation=simulation, hypothesis=hypothesis, objections=objections
        )
        result.confidence = confidence
        result.valid = True
        result.reason = "all checks passed"

        result.recommended_action = self._recommend_action(
            severity=severity,
            confidence=confidence,
            objections=objections,
        )

        if result.recommended_action == RecommendedAction.DISCARD:
            result.rejection_reasons.append(RejectionReason.BELOW_SEVERITY_THRESHOLD)
            result.reason = "below severity threshold for actionable reporting"

        return result

    # ------------------------------------------------------------------
    # Batch API
    # ------------------------------------------------------------------

    def run(
        self,
        *,
        swarm_report: SwarmReport,
        sequence_report: SequenceReport,
        simulation_report: SimulationReport,
    ) -> ValidationReport:
        """
        Validate every (hypothesis, sequence, simulation) triple in a batch.

        Triples are matched by (sequence.hypothesis_id, simulation.sequence_id).
        Sequences without a matching simulation are dropped from the
        validation report (they were never executed).
        """
        start = time.monotonic()
        report = ValidationReport(
            protocol_name=simulation_report.protocol_name,
            simulation_report_id=simulation_report.id,
        )

        hyp_by_id = {h.id: h for h in swarm_report.hypotheses}
        sim_by_seq = {s.sequence_id: s for s in simulation_report.results}

        # Optionally seed: same-batch fingerprints already in the store.
        for seq in sequence_report.sequences:
            hyp = hyp_by_id.get(seq.hypothesis_id)
            sim = sim_by_seq.get(seq.id)
            if hyp is None or sim is None:
                continue
            v = self.validate(hypothesis=hyp, sequence=seq, simulation=sim)
            report.results.append(v)

        # Aggregate stats
        report.total_validated = len(report.results)
        report.valid_count = sum(1 for r in report.results if r.valid)
        report.rejected_count = sum(1 for r in report.results if not r.valid)
        report.duplicate_count = sum(1 for r in report.results if r.duplicate_of is not None)
        report.report_count = sum(
            1 for r in report.results if r.recommended_action == RecommendedAction.REPORT
        )
        report.simulate_further_count = sum(
            1 for r in report.results if r.recommended_action == RecommendedAction.SIMULATE_FURTHER
        )
        report.discard_count = sum(
            1 for r in report.results if r.recommended_action == RecommendedAction.DISCARD
        )
        report.severity_breakdown = self._severity_breakdown(report.results)
        report.analysis_metadata = {
            "elapsed_seconds": round(time.monotonic() - start, 3),
            "aggressive_rejection": self.aggressive_rejection,
            "duplicate_store_size": len(self.duplicate_detector.store.fingerprints())
            if hasattr(self.duplicate_detector.store, "fingerprints") else None,
        }
        return report

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _summarise_rejection(reasons: Iterable[RejectionReason]) -> str:
        codes = sorted({r.value for r in reasons})
        return "rejected: " + ", ".join(codes) if codes else "rejected"

    @staticmethod
    def _compute_confidence(
        *,
        simulation: SimulationResult,
        hypothesis: AttackHypothesis,
        objections: list[ContrarianObjection],
    ) -> float:
        confidence = _BASE_CONFIDENCE
        if simulation.is_profitable:
            confidence += _PROFIT_BOOST
        if hypothesis.confidence >= 0.75:
            confidence += _NO_OBJECTION_BOOST
        if not objections:
            # Spec: "If it cannot invalidate the exploit, confidence goes up."
            confidence += _NO_OBJECTION_BOOST
        for o in objections:
            confidence -= o.severity * _CONTRARIAN_PENALTY
        return max(0.0, min(1.0, round(confidence, 3)))

    @staticmethod
    def _recommend_action(
        *,
        severity: SeverityScore,
        confidence: float,
        objections: list[ContrarianObjection],
    ) -> RecommendedAction:
        composite = severity.composite_score
        objection_weight = sum(o.severity for o in objections)

        if composite < _DISCARD_MAX_COMPOSITE:
            return RecommendedAction.DISCARD

        meets_report_bar = (
            composite >= _REPORT_MIN_COMPOSITE
            and confidence >= _REPORT_MIN_CONFIDENCE
            and objection_weight < _BORDERLINE_OBJECTION_WEIGHT
        )
        if meets_report_bar:
            return RecommendedAction.REPORT

        return RecommendedAction.SIMULATE_FURTHER

    @staticmethod
    def _severity_breakdown(results: list[ValidationResult]) -> dict[str, int]:
        counts = {tier.value: 0 for tier in ProfitTier}
        for r in results:
            counts[r.severity.profit_tier.value] += 1
        return counts
