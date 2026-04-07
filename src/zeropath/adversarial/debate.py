"""
DebateEngine — Phase 3 cross-agent critique system.

Each agent reviews every peer hypothesis and submits a DebateNote:
  - endorse: confirms the attack is viable from its domain expertise
  - challenge: raises a specific objection but doesn't disqualify
  - reject: deems the hypothesis non-viable

Confidence is adjusted by ±delta from each note.
A hypothesis rejected by a majority of relevant agents is marked REJECTED.

Inter-agent validation rules
-----------------------------
  OracleManipulator  → endorses any hypothesis that requires oracle reading
  ReentrancyAgent    → endorses if external call precondition is present
  FlashLoanAgent     → endorses if flash_loan_available precondition is present
  AccessControl      → challenges if function is protected by guard
  IntegerMath        → endorses if integer_truncation precondition is present
  Governance         → endorses governance hypotheses; challenges if timelock present
  Composability      → endorses cross_protocol hypotheses
"""

from __future__ import annotations

import logging

from zeropath.adversarial.base import BaseAdversarialAgent
from zeropath.adversarial.models import (
    AttackClass,
    AttackHypothesis,
    ConditionType,
    DebateNote,
    DebateRound,
    HypothesisStatus,
)

logger = logging.getLogger(__name__)

# Minimum endorsement ratio to mark CONSENSUS
_CONSENSUS_THRESHOLD = 0.5
# Minimum rejection ratio to mark REJECTED
_REJECT_THRESHOLD = 0.6


class DebateEngine:
    """
    Runs inter-agent debate rounds.

    Each round: all agents review all hypotheses and submit notes.
    Confidence is updated after each round.
    """

    def __init__(self, agents: list[BaseAdversarialAgent]) -> None:
        self.agents = agents

    def run_round(
        self,
        hypotheses: list[AttackHypothesis],
        round_number: int = 1,
    ) -> DebateRound:
        """Execute one full debate round over all hypotheses."""
        all_notes: list[DebateNote] = []
        updated = 0
        rejected = 0

        for hyp in hypotheses:
            if hyp.status == HypothesisStatus.REJECTED:
                continue

            notes_for_hyp: list[DebateNote] = []
            for agent in self.agents:
                if agent.name == hyp.proposed_by:
                    continue  # agents don't debate their own hypotheses
                note = self._evaluate(agent, hyp)
                if note:
                    notes_for_hyp.append(note)

            if notes_for_hyp:
                self._apply_notes(hyp, notes_for_hyp)
                all_notes.extend(notes_for_hyp)
                updated += 1
                if hyp.status == HypothesisStatus.REJECTED:
                    rejected += 1

        return DebateRound(
            round_number=round_number,
            notes=all_notes,
            hypotheses_updated=updated,
            hypotheses_rejected=rejected,
        )

    # ------------------------------------------------------------------
    # Per-agent evaluation rules
    # ------------------------------------------------------------------

    def _evaluate(
        self, agent: BaseAdversarialAgent, hyp: AttackHypothesis
    ) -> DebateNote | None:
        """Return a DebateNote from `agent` about `hyp`, or None if irrelevant."""
        rule = self._RULES.get(agent.name)
        if rule is None:
            return None
        return rule(self, agent, hyp)

    def _oracle_review(self, agent, hyp: AttackHypothesis) -> DebateNote | None:
        """OracleManipulatorAgent reviews: endorses if oracle precondition present."""
        has_oracle_cond = any(
            p.condition_type == ConditionType.ORACLE_READ_SINGLE_BLOCK
            for p in hyp.preconditions
        )
        if hyp.attack_class in (AttackClass.ORACLE_MANIPULATION, AttackClass.FLASH_LOAN) and has_oracle_cond:
            return DebateNote(
                from_agent=agent.name,
                verdict="endorse",
                reasoning="Oracle precondition present and attack class matches my domain. Single-block read is confirmed manipulable.",
                confidence_delta=0.08,
            )
        if hyp.attack_class == AttackClass.ORACLE_MANIPULATION and not has_oracle_cond:
            return DebateNote(
                from_agent=agent.name,
                verdict="challenge",
                reasoning="Oracle manipulation attack but no oracle_read_single_block precondition found. May be TWAP (harder to exploit).",
                confidence_delta=-0.05,
            )
        return None

    def _reentrancy_review(self, agent, hyp: AttackHypothesis) -> DebateNote | None:
        """ReentrancyAgent reviews: endorses reentrancy; challenges if guard present."""
        if hyp.attack_class != AttackClass.REENTRANCY:
            return None
        has_external_call = any(
            p.condition_type == ConditionType.EXTERNAL_CALL_BEFORE_UPDATE
            for p in hyp.preconditions
        )
        has_guard = any(
            p.condition_type == ConditionType.OPEN_CALL and p.is_met_by_protocol is False
            for p in hyp.preconditions
        )
        if has_guard:
            return DebateNote(
                from_agent=agent.name,
                verdict="reject",
                reasoning="Reentrancy hypothesis but target function has a reentrancy guard. Not exploitable.",
                confidence_delta=-0.30,
            )
        if has_external_call:
            return DebateNote(
                from_agent=agent.name,
                verdict="endorse",
                reasoning="External call before state update confirmed. CEI violation is the classic reentrancy vector.",
                confidence_delta=0.10,
            )
        return DebateNote(
            from_agent=agent.name,
            verdict="challenge",
            reasoning="Reentrancy hypothesis but CEI violation not explicitly confirmed in preconditions.",
            confidence_delta=-0.05,
        )

    def _flash_loan_review(self, agent, hyp: AttackHypothesis) -> DebateNote | None:
        """FlashLoanAgent reviews: endorses if flash loan is required and available."""
        requires_flash_loan = any(
            p.condition_type == ConditionType.FLASH_LOAN_AVAILABLE
            for p in hyp.preconditions
        )
        if not requires_flash_loan:
            return None
        if hyp.attack_class in (AttackClass.FLASH_LOAN, AttackClass.ORACLE_MANIPULATION,
                                  AttackClass.GOVERNANCE):
            return DebateNote(
                from_agent=agent.name,
                verdict="endorse",
                reasoning="Flash loan precondition confirmed available (Aave V3, Balancer, Uniswap V3 all support it). Capital requirement is satisfied.",
                confidence_delta=0.08,
            )
        return None

    def _access_review(self, agent, hyp: AttackHypothesis) -> DebateNote | None:
        """AccessControlAgent reviews: challenges flash loan governance if snapshot present."""
        if hyp.attack_class == AttackClass.GOVERNANCE:
            has_no_timelock = any(
                p.condition_type == ConditionType.NO_TIMELOCK and p.is_met_by_protocol is True
                for p in hyp.preconditions
            )
            if has_no_timelock:
                return DebateNote(
                    from_agent=agent.name,
                    verdict="endorse",
                    reasoning="Confirmed: no timelock present. Governance execution is immediate. CRITICAL access control gap.",
                    confidence_delta=0.10,
                )
        if hyp.attack_class == AttackClass.ACCESS_CONTROL:
            has_guard = any(
                p.condition_type == ConditionType.UNGUARDED_FUNCTION
                and p.is_met_by_protocol is False
                for p in hyp.preconditions
            )
            if has_guard:
                return DebateNote(
                    from_agent=agent.name,
                    verdict="reject",
                    reasoning="Access control precondition says function is protected. Hypothesis invalid.",
                    confidence_delta=-0.35,
                )
        return None

    def _integer_review(self, agent, hyp: AttackHypothesis) -> DebateNote | None:
        """IntegerMathAgent reviews: endorses integer math hypotheses."""
        if hyp.attack_class != AttackClass.INTEGER_MATH:
            return None
        has_truncation = any(
            p.condition_type == ConditionType.INTEGER_TRUNCATION
            for p in hyp.preconditions
        )
        if has_truncation:
            return DebateNote(
                from_agent=agent.name,
                verdict="endorse",
                reasoning="Integer truncation precondition present. Old compiler or unchecked block enables this class of attack.",
                confidence_delta=0.08,
            )
        return DebateNote(
            from_agent=agent.name,
            verdict="challenge",
            reasoning="Integer math attack but no truncation precondition specified. May be Solidity >= 0.8 with safemath.",
            confidence_delta=-0.05,
        )

    def _governance_review(self, agent, hyp: AttackHypothesis) -> DebateNote | None:
        """GovernanceAttackAgent reviews: endorses governance; challenges if timelock present."""
        if hyp.attack_class != AttackClass.GOVERNANCE:
            return None
        has_timelock_present = any(
            p.condition_type == ConditionType.NO_TIMELOCK and p.is_met_by_protocol is False
            for p in hyp.preconditions
        )
        if has_timelock_present:
            return DebateNote(
                from_agent=agent.name,
                verdict="challenge",
                reasoning="Governance attack but timelock IS present. Flash loan capture is much harder — attacker needs sustained voting power.",
                confidence_delta=-0.15,
            )
        return DebateNote(
            from_agent=agent.name,
            verdict="endorse",
            reasoning="Governance attack pattern is valid. No effective timelock protection detected.",
            confidence_delta=0.07,
        )

    def _composability_review(self, agent, hyp: AttackHypothesis) -> DebateNote | None:
        """ComposabilityAgent reviews: endorses cross-protocol attacks."""
        if hyp.attack_class != AttackClass.COMPOSABILITY:
            return None
        has_cross_dep = any(
            p.condition_type == ConditionType.CROSS_PROTOCOL_DEPENDENCY
            for p in hyp.preconditions
        )
        if has_cross_dep:
            return DebateNote(
                from_agent=agent.name,
                verdict="endorse",
                reasoning="Cross-protocol dependency confirmed. External protocol state can be weaponised.",
                confidence_delta=0.08,
            )
        return None

    # Map agent name → review method
    _RULES: dict[str, object] = {
        "OracleManipulatorAgent": _oracle_review,
        "ReentrancyAgent": _reentrancy_review,
        "FlashLoanAgent": _flash_loan_review,
        "AccessControlAgent": _access_review,
        "IntegerMathAgent": _integer_review,
        "GovernanceAttackAgent": _governance_review,
        "ComposabilityAgent": _composability_review,
    }

    # ------------------------------------------------------------------
    # Apply notes to a hypothesis
    # ------------------------------------------------------------------

    def _apply_notes(
        self, hyp: AttackHypothesis, notes: list[DebateNote]
    ) -> None:
        """Update hypothesis confidence, status, and agent lists from debate notes."""
        hyp.debate_notes.extend(notes)

        endorsements = [n for n in notes if n.verdict == "endorse"]
        rejections = [n for n in notes if n.verdict == "reject"]
        challenges = [n for n in notes if n.verdict == "challenge"]

        hyp.endorsing_agents.extend(n.from_agent for n in endorsements)
        hyp.dissenting_agents.extend(n.from_agent for n in rejections + challenges)

        # Adjust confidence
        delta = sum(n.confidence_delta for n in notes)
        hyp.confidence = max(0.0, min(1.0, hyp.confidence + delta))

        # Update status
        total = len(notes)
        if total == 0:
            return

        reject_ratio = len(rejections) / total
        endorse_ratio = len(endorsements) / total

        if reject_ratio >= _REJECT_THRESHOLD:
            hyp.status = HypothesisStatus.REJECTED
        elif endorse_ratio >= _CONSENSUS_THRESHOLD:
            hyp.status = HypothesisStatus.CONSENSUS
            hyp.agent_consensus_score = endorse_ratio
        elif endorsements:
            hyp.status = HypothesisStatus.ENDORSED
            hyp.agent_consensus_score = endorse_ratio
        elif challenges:
            hyp.status = HypothesisStatus.CHALLENGED
        # PROPOSED stays if no notes
