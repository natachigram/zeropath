"""
Abstract base class for all Phase 3 adversarial agents.

Each agent specialises in one attack class.  It receives:
  - A list of Phase 2 Invariant objects (the full invariant report)
  - The Phase 1 ProtocolGraph
  - The ProtocolPattern (DeFi category summary from Phase 2)

It returns a list of AttackHypothesis objects — concrete, testable exploit paths.

Design principles
-----------------
* Deterministic: no LLM calls, pure graph reasoning over the protocol model.
* Concrete: vague hypotheses (no exploit_steps, no preconditions) are rejected.
* Focused: each agent only generates hypotheses within its attack class.
* Lightweight: runs in < 100ms per invariant for a typical protocol.
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod

from zeropath.adversarial.models import (
    AttackClass,
    AttackHypothesis,
    AttackStep,
    ConditionType,
    HypothesisStatus,
    Precondition,
    ProfitMechanism,
)
from zeropath.invariants.models import (
    Invariant,
    InvariantReport,
    InvariantType,
    ProtocolPattern,
)
from zeropath.models import ProtocolGraph

logger = logging.getLogger(__name__)

# Minimum number of exploit steps required for a hypothesis to be non-vague
MIN_EXPLOIT_STEPS = 2
# Minimum specificity score to keep a hypothesis
MIN_SPECIFICITY = 0.30


class BaseAdversarialAgent(ABC):
    """Abstract base for all adversarial agents."""

    #: Unique name identifying this agent (used in DebateNotes)
    name: str = "base"

    #: Primary attack class this agent generates hypotheses for
    attack_class: AttackClass = AttackClass.UNKNOWN

    #: InvariantTypes this agent is most relevant for (used by DebateEngine)
    relevant_invariant_types: list[InvariantType] = []

    def run(
        self,
        report: InvariantReport,
        graph: ProtocolGraph,
    ) -> list[AttackHypothesis]:
        """
        Entry point called by the SwarmOrchestrator.

        Filters invariants to those relevant for this agent, calls
        ``analyse_invariant`` for each, and post-filters vague results.
        """
        hypotheses: list[AttackHypothesis] = []
        pattern = report.protocol_pattern

        for invariant in report.invariants:
            if not self._is_relevant(invariant):
                continue
            try:
                candidates = self.analyse_invariant(invariant, graph, pattern)
                for h in candidates:
                    h.specificity_score = self._compute_specificity(h)
                    if h.specificity_score >= MIN_SPECIFICITY:
                        hypotheses.append(h)
                    else:
                        logger.debug(
                            "%s: dropped vague hypothesis '%s' (specificity=%.2f)",
                            self.name, h.title, h.specificity_score,
                        )
            except Exception:
                logger.exception(
                    "%s: unhandled error analysing invariant %s",
                    self.name, invariant.id,
                )
        return hypotheses

    @abstractmethod
    def analyse_invariant(
        self,
        invariant: Invariant,
        graph: ProtocolGraph,
        pattern: ProtocolPattern,
    ) -> list[AttackHypothesis]:
        """
        Generate attack hypotheses for a single invariant.

        Subclasses must return a list of AttackHypothesis objects.
        Returning an empty list is valid (the agent found nothing).
        """

    # ------------------------------------------------------------------
    # Helpers for subclasses
    # ------------------------------------------------------------------

    def _is_relevant(self, invariant: Invariant) -> bool:
        """Return True if this agent should attempt to analyse the invariant."""
        if not self.relevant_invariant_types:
            return True
        return invariant.type in self.relevant_invariant_types

    @staticmethod
    def _compute_specificity(h: AttackHypothesis) -> float:
        """
        Score how concrete a hypothesis is on [0, 1].

        Rubric:
          - Has >= 2 exploit steps         +0.30
          - Steps have target_contract     +0.10
          - Steps have target_function     +0.10
          - Has >= 1 precondition          +0.15
          - precondition.is_met_by_protocol set  +0.10
          - Has profit_mechanism           +0.15
          - Has poc_sketch                 +0.10
        """
        score = 0.0
        if len(h.exploit_steps) >= MIN_EXPLOIT_STEPS:
            score += 0.30
        if any(s.target_contract for s in h.exploit_steps):
            score += 0.10
        if any(s.target_function for s in h.exploit_steps):
            score += 0.10
        if h.preconditions:
            score += 0.15
        if any(p.is_met_by_protocol is not None for p in h.preconditions):
            score += 0.10
        if h.profit_mechanism is not None:
            score += 0.15
        if h.poc_sketch:
            score += 0.10
        return min(score, 1.0)

    # ------------------------------------------------------------------
    # Factories / builders used by all agents
    # ------------------------------------------------------------------

    def _step(
        self,
        step: int,
        action: str,
        purpose: str,
        target_contract: str | None = None,
        target_function: str | None = None,
    ) -> AttackStep:
        return AttackStep(
            step=step,
            action=action,
            target_contract=target_contract,
            target_function=target_function,
            purpose=purpose,
        )

    def _precondition(
        self,
        condition_type: ConditionType,
        description: str,
        is_met: bool | None = None,
        evidence: str = "",
    ) -> Precondition:
        return Precondition(
            condition_type=condition_type,
            description=description,
            is_met_by_protocol=is_met,
            evidence=evidence,
        )

    def _profit(
        self,
        description: str,
        asset: str = "ETH",
        max_usd: int | None = None,
        scales_with_tvl: bool = True,
    ) -> ProfitMechanism:
        return ProfitMechanism(
            description=description,
            asset=asset,
            estimated_max_usd=max_usd,
            depends_on_protocol_tvl=scales_with_tvl,
        )

    def _make_hypothesis(
        self,
        invariant: Invariant,
        title: str,
        attack_class: AttackClass,
        narrative: str,
        steps: list[AttackStep],
        preconditions: list[Precondition],
        profit: ProfitMechanism | None,
        confidence: float,
        historical_protocols: list[str] | None = None,
        historical_loss: int | None = None,
        poc_sketch: str = "",
        suggested_fix: str = "",
    ) -> AttackHypothesis:
        return AttackHypothesis(
            invariant_id=invariant.id,
            invariant_description=invariant.description,
            attack_class=attack_class,
            title=title,
            proposed_by=self.name,
            attack_narrative=narrative,
            exploit_steps=steps,
            preconditions=preconditions,
            profit_mechanism=profit,
            contracts_involved=list(invariant.contracts_involved),
            functions_involved=list(invariant.functions_involved),
            state_vars_involved=list(invariant.state_vars_involved),
            historical_precedent_protocols=historical_protocols or [],
            historical_loss_usd=historical_loss,
            status=HypothesisStatus.PROPOSED,
            confidence=confidence,
            poc_sketch=poc_sketch,
            suggested_fix=suggested_fix,
        )
