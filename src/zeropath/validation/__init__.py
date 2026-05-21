"""
Phase 6: Exploit Validation Engine.

Takes Phase 3 :class:`AttackHypothesis` + Phase 4 :class:`TransactionSequence`
+ Phase 5 :class:`SimulationResult` and produces a :class:`ValidationResult`
that tells Phase 7 / Phase 8 / Phase 9 whether the exploit is real, how bad
it is, whether we've seen it before, and what to do with it.

Public API::

    from zeropath.validation import ValidationOrchestrator

    orch = ValidationOrchestrator()
    report = orch.run(
        swarm_report=swarm,
        sequence_report=seqs,
        simulation_report=sims,
    )
    for finding in report.actionable_results:
        print(finding.severity.profit_tier, finding.protocol_name)
"""

from zeropath.validation.contrarian import ContrarianAgent
from zeropath.validation.duplicate_detector import (
    DuplicateDetector,
    DuplicateStore,
    InMemoryDuplicateStore,
    compute_fingerprint,
)
from zeropath.validation.models import (
    ContrarianObjection,
    ObjectionCategory,
    ProfitTier,
    RecommendedAction,
    RejectionReason,
    SeverityScore,
    ValidationReport,
    ValidationResult,
)
from zeropath.validation.severity_scorer import SeverityScorer
from zeropath.validation.validator import ValidationOrchestrator
from zeropath.validation.validators import (
    BaseValidator,
    PermissionValidator,
    ProfitValidator,
    RealismValidator,
    ValidatorVerdict,
)

__all__ = [
    # Orchestrator
    "ValidationOrchestrator",
    # Validators
    "BaseValidator", "ProfitValidator", "PermissionValidator", "RealismValidator",
    "ValidatorVerdict",
    # Components
    "SeverityScorer",
    "DuplicateDetector", "DuplicateStore", "InMemoryDuplicateStore",
    "compute_fingerprint",
    "ContrarianAgent",
    # Models
    "ValidationResult", "ValidationReport",
    "SeverityScore", "ContrarianObjection",
    "ProfitTier", "RecommendedAction", "RejectionReason", "ObjectionCategory",
]
