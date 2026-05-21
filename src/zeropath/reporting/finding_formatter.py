"""
Finding formatter — Phase 9.

Converts the artefacts upstream phases produce into the typed
:class:`Finding` records the report writers consume. The formatter is
responsible only for *shaping*; severity ranking and dedup happen in
:mod:`ranking`.

Inputs the formatter understands:
  * Phase 4 :class:`TransactionSequence` (for the proof-of-concept block)
  * Phase 5 :class:`SimulationResult` (gas, profit, fork block)
  * Phase 6 :class:`ValidationResult` (severity + decision)
  * Phase 8 :class:`KnowledgeGraphOrchestrator` (historical precedent lookup)
"""

from __future__ import annotations

import logging
from typing import Iterable, Optional

from zeropath.adversarial.models import AttackHypothesis
from zeropath.knowledge.knowledge import KnowledgeGraphOrchestrator
from zeropath.knowledge.models import ExternalIncidentRecord
from zeropath.reporting.models import (
    Finding,
    FindingStatus,
    HistoricalPrecedentRef,
    ProofOfConcept,
    SeverityTier,
)
from zeropath.sequencer.models import TransactionSequence
from zeropath.simulator.models import SimulationResult
from zeropath.validation.models import ProfitTier, ValidationResult

logger = logging.getLogger(__name__)


# Map Phase 6 ProfitTier → Phase 9 SeverityTier. Reports use a slightly
# wider scale (we add INFORMATIONAL for items not driven by profit).
_TIER_MAP: dict[ProfitTier, SeverityTier] = {
    ProfitTier.CRITICAL: SeverityTier.CRITICAL,
    ProfitTier.HIGH: SeverityTier.HIGH,
    ProfitTier.MEDIUM: SeverityTier.MEDIUM,
    ProfitTier.LOW: SeverityTier.LOW,
    ProfitTier.NONE: SeverityTier.INFORMATIONAL,
}


class FindingFormatter:
    """
    Build :class:`Finding` records from the upstream artefacts.

    Parameters
    ----------
    knowledge : KnowledgeGraphOrchestrator | None
        When supplied, the formatter pulls matching external incidents from
        the KG into the finding's ``historical_precedent``.
    """

    def __init__(
        self,
        knowledge: Optional[KnowledgeGraphOrchestrator] = None,
    ) -> None:
        self.knowledge = knowledge

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def format_finding(
        self,
        *,
        validation: ValidationResult,
        hypothesis: Optional[AttackHypothesis] = None,
        sequence: Optional[TransactionSequence] = None,
        simulation: Optional[SimulationResult] = None,
    ) -> Finding:
        attack_class = (
            hypothesis.attack_class.value if hypothesis else
            validation.analysis_metadata.get("attack_class", "unknown")
        )
        protocol_name = validation.protocol_name or (
            sequence.context.chain if sequence else "unknown"
        )

        return Finding(
            title=self._build_title(hypothesis, attack_class, protocol_name),
            severity=_TIER_MAP.get(validation.severity.profit_tier, SeverityTier.MEDIUM),
            attack_class=attack_class,
            status=FindingStatus.NEW,
            validation_result_id=validation.id,
            hypothesis_id=validation.hypothesis_id,
            sequence_id=validation.sequence_id,
            simulation_id=validation.simulation_id,
            fingerprint=validation.fingerprint,
            protocol_name=protocol_name,
            contracts_involved=list(hypothesis.contracts_involved) if hypothesis else [],
            functions_involved=list(hypothesis.functions_involved) if hypothesis else [],
            description=self._build_description(hypothesis, validation),
            impact=self._build_impact(validation, simulation),
            proof_of_concept=self._build_poc(sequence, simulation),
            recommended_fix="",  # filled by orchestrator via RemediationEngine
            historical_precedent=self._lookup_precedent(hypothesis, attack_class),
            profit_wei=validation.profit_wei,
            profit_usd=validation.profit_usd,
            capital_required_usd=validation.capital_required_usd,
            requires_flash_loan=validation.severity.requires_flash_loan,
            mev_frontrunnable=validation.severity.mev_frontrunnable,
            protocol_pausable=validation.severity.protocol_pausable,
            confidence=validation.confidence,
            contrarian_objections=[
                f"[{o.category.value}] {o.explanation}"
                for o in validation.contrarian_objections
            ],
        )

    def format_findings(
        self,
        items: Iterable[
            tuple[
                ValidationResult,
                Optional[AttackHypothesis],
                Optional[TransactionSequence],
                Optional[SimulationResult],
            ]
        ],
    ) -> list[Finding]:
        return [
            self.format_finding(
                validation=v, hypothesis=h, sequence=s, simulation=sim,
            )
            for (v, h, s, sim) in items
        ]

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    @staticmethod
    def _build_title(
        hypothesis: Optional[AttackHypothesis],
        attack_class: str,
        protocol_name: str,
    ) -> str:
        if hypothesis and hypothesis.title:
            return hypothesis.title
        prettier_class = attack_class.replace("_", " ").title()
        return f"{prettier_class} in {protocol_name}"

    @staticmethod
    def _build_description(
        hypothesis: Optional[AttackHypothesis],
        validation: ValidationResult,
    ) -> str:
        parts: list[str] = []
        if hypothesis:
            parts.append(hypothesis.attack_narrative or "")
            if hypothesis.preconditions:
                parts.append("\n**Preconditions:**")
                for p in hypothesis.preconditions:
                    parts.append(
                        f"- {p.description} "
                        f"({'met' if p.is_met_by_protocol else 'unverified'})"
                    )
        if validation.reason and not parts:
            parts.append(validation.reason)
        return "\n".join(p for p in parts if p).strip()

    @staticmethod
    def _build_impact(
        validation: ValidationResult,
        simulation: Optional[SimulationResult],
    ) -> str:
        profit = validation.profit_usd or (
            (simulation.profit_wei if simulation else 0) / 10**18 * 3000
        )
        lines = [
            f"Estimated attacker profit: ~${profit:,.0f}",
            f"Capital required: ${validation.capital_required_usd:,} "
            f"({'flash-loan-funded' if validation.severity.requires_flash_loan else 'attacker-funded'})",
        ]
        if validation.severity.mev_frontrunnable:
            lines.append("Attack is observable in the public mempool and frontrunnable.")
        if validation.severity.protocol_pausable:
            lines.append("Protocol exposes a pause mechanism — admin can mitigate post-launch.")
        if simulation and simulation.gas_used:
            lines.append(f"Simulated gas used: {simulation.gas_used:,}")
        return "\n".join(lines)

    @staticmethod
    def _build_poc(
        sequence: Optional[TransactionSequence],
        simulation: Optional[SimulationResult],
    ) -> Optional[ProofOfConcept]:
        if sequence is None:
            return None
        calls_summary = [
            f"Step {c.step}: {c.description}"
            for c in sequence.calls
        ]
        return ProofOfConcept(
            sequence_id=sequence.id,
            foundry_test_path=(
                sequence.foundry_test.filename if sequence.foundry_test else None
            ),
            foundry_test_code=(
                sequence.foundry_test.code if sequence.foundry_test else None
            ),
            hardhat_script_path=(
                sequence.hardhat_test.filename if sequence.hardhat_test else None
            ),
            hardhat_script_code=(
                sequence.hardhat_test.code if sequence.hardhat_test else None
            ),
            fork_block=(
                simulation.block_number if simulation and simulation.block_number
                else sequence.block_number
            ),
            fork_url_env=sequence.fork_url_env,
            calls_summary=calls_summary,
        )

    def _lookup_precedent(
        self,
        hypothesis: Optional[AttackHypothesis],
        attack_class: str,
    ) -> list[HistoricalPrecedentRef]:
        if self.knowledge is None or hypothesis is None:
            return []
        try:
            _boost, matches = self.knowledge.lookup_historical_grounding(hypothesis)
        except Exception:
            logger.exception("historical-precedent lookup failed")
            return []
        return [
            HistoricalPrecedentRef(
                incident_id=m.id,
                protocol=m.protocol,
                incident_date=m.incident_date,
                loss_usd=m.loss_usd,
                source=m.source.value if hasattr(m.source, "value") else str(m.source),
                source_url=m.source_url,
            )
            for m in matches
        ]
