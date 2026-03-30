"""
Governance safety invariant detector.

Governance attacks exploit weak voting mechanisms to pass malicious proposals.

Detection strategy:
  1. Detect governance functions (propose, vote, execute, queue, cancel).
  2. Check for timelock presence (timelock variable or function).
  3. Flag missing timelock as CRITICAL.
  4. Flag flash-loan-exploitable governance (no snapshot-based voting).
  5. Check for quorum and delay parameters.
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

# Variables/functions indicating snapshot-based voting (safer)
_SNAPSHOT_KW = {
    "snapshot", "checkpoint", "blocknumber", "pastbalance",
    "getPastVotes", "getPriorVotes",
}

# Variables/functions indicating a delay / timelock
_TIMELOCK_KW = {
    "timelock", "delay", "eta", "votingdelay", "executiondelay",
    "timelockcontroller",
}


class GovernanceSafetyDetector(BaseDetector):
    """Detect governance safety invariants."""

    name = "governance_safety"

    def detect(
        self,
        graph: ProtocolGraph,
        pattern: ProtocolPattern,
    ) -> list[Invariant]:
        results: list[Invariant] = []

        if not pattern.governance_functions:
            return results

        has_timelock = pattern.has_timelock or _has_timelock(graph)
        has_snapshot = _has_snapshot_voting(graph)

        # Missing timelock — CRITICAL
        if not has_timelock:
            results.append(self._missing_timelock_finding(pattern, has_snapshot))

        # Timelock present but no snapshot voting — flash loan risk
        elif not has_snapshot:
            results.append(self._no_snapshot_finding(pattern))

        # General governance invariant (always emit)
        results.append(self._general_governance_finding(pattern, has_timelock, has_snapshot))

        logger.debug("governance_safety_detector", findings=len(results))
        return results

    # ------------------------------------------------------------------

    def _missing_timelock_finding(
        self, pattern: ProtocolPattern, has_snapshot: bool
    ) -> Invariant:
        precedents = _rag.query(
            InvariantType.GOVERNANCE_SAFETY,
            tags={"governance", "timelock"},
        )
        boost = _rag.confidence_boost(precedents)
        evidence_str = _rag.evidence_summary(precedents)

        evidence = [
            f"Governance functions: {pattern.governance_functions[:5]}.",
            "NO timelock detected between proposal passage and execution.",
            "An attacker with sufficient voting power can propose and execute "
            "a malicious transaction atomically.",
        ]
        if not has_snapshot:
            evidence.append(
                "No snapshot voting detected — flash loan can temporarily inflate "
                "voting power to pass proposals."
            )
        if evidence_str:
            evidence.append(evidence_str)

        return Invariant(
            type=InvariantType.GOVERNANCE_SAFETY,
            severity=InvariantSeverity.CRITICAL,
            description=(
                "Governance safety: NO timelock between proposal passage and execution. "
                "Malicious proposals can be executed immediately after passing. "
                + ("Flash loan can manipulate voting power (no snapshot). " if not has_snapshot else "")
                + "(See Beanstalk $182M, Build Finance $470K)."
            ),
            formal_spec=_spec_gen.generate(InvariantType.GOVERNANCE_SAFETY, pattern),
            confidence=min(0.80 + boost, 0.95),
            functions_involved=pattern.governance_functions[:10],
            state_vars_involved=pattern.timelock_vars[:3],
            historical_precedent=precedents,
            evidence=evidence,
            detector=self.name,
        )

    def _no_snapshot_finding(self, pattern: ProtocolPattern) -> Invariant:
        precedents = _rag.query(
            InvariantType.GOVERNANCE_SAFETY,
            tags={"flash_loan", "voting"},
        )
        boost = _rag.confidence_boost(precedents)
        evidence_str = _rag.evidence_summary(precedents)

        evidence = [
            "Timelock present but voting uses current token balance, not historical snapshot.",
            "Flash loan can temporarily acquire voting majority within the same block.",
        ]
        if evidence_str:
            evidence.append(evidence_str)

        return Invariant(
            type=InvariantType.GOVERNANCE_SAFETY,
            severity=InvariantSeverity.HIGH,
            description=(
                "Governance snapshot risk: voting power uses current token balance, "
                "not a historical snapshot. Flash loans can temporarily inflate voting "
                "power to meet quorum within a single transaction."
            ),
            formal_spec=_spec_gen.generate(InvariantType.GOVERNANCE_SAFETY, pattern),
            confidence=min(0.65 + boost, 0.95),
            functions_involved=pattern.governance_functions[:10],
            historical_precedent=precedents,
            evidence=evidence,
            detector=self.name,
        )

    def _general_governance_finding(
        self,
        pattern: ProtocolPattern,
        has_timelock: bool,
        has_snapshot: bool,
    ) -> Invariant:
        precedents = _rag.query(InvariantType.GOVERNANCE_SAFETY)
        boost = _rag.confidence_boost(precedents)

        evidence = [
            f"Governance protocol with {len(pattern.governance_functions)} governance functions.",
            f"Timelock: {'present' if has_timelock else 'ABSENT'}. "
            f"Snapshot voting: {'present' if has_snapshot else 'ABSENT'}.",
        ]

        severity = InvariantSeverity.MEDIUM if (has_timelock and has_snapshot) else InvariantSeverity.HIGH
        confidence = 0.55 if (has_timelock and has_snapshot) else 0.65

        return Invariant(
            type=InvariantType.GOVERNANCE_SAFETY,
            severity=severity,
            description=(
                "Governance execution safety: proposals must not be executable "
                "within the same block as they pass voting."
            ),
            formal_spec=_spec_gen.generate(InvariantType.GOVERNANCE_SAFETY, pattern),
            confidence=min(confidence + boost, 0.95),
            functions_involved=pattern.governance_functions[:10],
            state_vars_involved=pattern.timelock_vars[:3],
            historical_precedent=precedents,
            evidence=evidence,
            detector=self.name,
        )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _has_timelock(graph: ProtocolGraph) -> bool:
    all_names = (
        [v.name.lower() for v in graph.state_variables]
        + [f.name.lower() for f in graph.functions]
    )
    return any(any(kw in n for kw in _TIMELOCK_KW) for n in all_names)


def _has_snapshot_voting(graph: ProtocolGraph) -> bool:
    all_names = (
        [v.name.lower() for v in graph.state_variables]
        + [f.name.lower() for f in graph.functions]
    )
    return any(any(kw in n for kw in _SNAPSHOT_KW) for n in all_names)
