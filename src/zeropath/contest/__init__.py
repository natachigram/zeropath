"""
Contest mode — the audit-contest-winning pipeline.

Wraps every prior phase plus an LLM Reasoner, Spec Miner, Foundry PoC
Verifier, and platform-specific submission formatters so ZeroPath can
compete head-to-head with V12 / Cantina AI in Code4rena, Cantina,
Sherlock, and Immunefi contests.

Public API::

    from zeropath.contest import ContestConfig, ContestOrchestrator, ContestPlatform

    cfg = ContestConfig(
        platform=ContestPlatform.CANTINA,
        repo_path="./contracts",
        llm_budget_usd=200.0,
        submit_confidence_threshold=0.70,
    )
    report = ContestOrchestrator(cfg, knowledge=kg).run()
    for sub in report.ready_to_submit:
        print(sub.rank, sub.finding.title, sub.finding.severity)
"""

from zeropath.contest.models import (
    ContestConfig,
    ContestPlatform,
    ContestReport,
    Submission,
    SubmissionDisposition,
    SubmissionFinding,
)
from zeropath.contest.orchestrator import ContestOrchestrator
from zeropath.contest.platforms import (
    BasePlatformFormatter,
    CantinaFormatter,
    Code4renaFormatter,
    ImmunefiFormatter,
    SherlockFormatter,
    for_platform,
)
from zeropath.contest.strategy import (
    SubmissionStrategy,
    estimate_duplicate_likelihood,
)

__all__ = [
    # Orchestrator
    "ContestOrchestrator",
    # Strategy + duplicate scoring
    "SubmissionStrategy", "estimate_duplicate_likelihood",
    # Platform formatters
    "for_platform", "BasePlatformFormatter",
    "CantinaFormatter", "Code4renaFormatter",
    "SherlockFormatter", "ImmunefiFormatter",
    # Models
    "ContestConfig", "ContestReport",
    "Submission", "SubmissionFinding", "SubmissionDisposition",
    "ContestPlatform",
]
