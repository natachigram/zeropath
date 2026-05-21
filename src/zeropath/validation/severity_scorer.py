"""
Multi-dimensional severity scorer — Phase 6.

Spec (phases.md, PHASE 6 critical additions, "Severity scoring"):
    "A valid exploit is not binary. Score on multiple dimensions:
       - profit magnitude (low / medium / high / critical)
       - capital required (flash loan = $0 upfront vs. requires $10M)
       - time sensitivity (exploitable now vs. requires specific market conditions)
       - stealth (can it be front-run by MEV bots before the attacker?)
       - reversibility (can the protocol pause and recover?)"
"""

from __future__ import annotations

import logging
from typing import Optional

from zeropath.adversarial.models import (
    AttackClass,
    AttackHypothesis,
    ConditionType,
    Precondition,
)
from zeropath.sequencer.models import TransactionSequence
from zeropath.simulator.models import SimulationResult
from zeropath.validation.models import ProfitTier, SeverityScore

logger = logging.getLogger(__name__)


# ETH/USD price used when the simulator didn't supply one. Easy to override
# at construction time when running against a fork with live prices.
DEFAULT_ETH_USD = 3000.0


# Heuristic per-class flags for MEV competition and protocol pausability.
# A frontrunnable attack is one that depends on observable mempool state
# (oracle / flash loan / AMM). Governance attacks are not mempool-observable
# until proposal execution, so they're not frontrunnable in the same sense.
_MEV_FRONTRUNNABLE_CLASSES = {
    AttackClass.ORACLE_MANIPULATION,
    AttackClass.FLASH_LOAN,
    AttackClass.PRICE_MANIPULATION,
    AttackClass.COMPOSABILITY,
}

# Time-sensitive precondition types: the window for exploitation closes
# automatically (oracle goes stale, governance vote ends, block reorg).
_TIME_SENSITIVE_CONDITIONS = {
    ConditionType.ORACLE_READ_SINGLE_BLOCK,
    ConditionType.NO_TIMELOCK,
    ConditionType.OPEN_CALL,
}

_TIME_SENSITIVE_KEYWORDS = (
    "stale",
    "single block",
    "this block",
    "block.timestamp",
    "governance window",
    "voting period",
    "round",
)


class SeverityScorer:
    """
    Compute a :class:`SeverityScore` from (hypothesis, sequence, simulation).

    The scorer is intentionally cheap (no I/O, no external calls). All
    inputs come from earlier-phase artefacts, and the output is a flat
    record matching the spec's ``severity`` sub-object.

    Parameters
    ----------
    eth_usd_price : float
        Conversion rate when the simulation didn't capture USD. Defaults
        to a conservative DEFAULT_ETH_USD; set explicitly when running
        production scoring against live prices.
    critical_threshold_usd : int
        Profit above this is tagged CRITICAL.
    high_threshold_usd : int
        Profit above this (and below critical) is HIGH.
    medium_threshold_usd : int
        Profit above this is MEDIUM.
    """

    def __init__(
        self,
        eth_usd_price: float = DEFAULT_ETH_USD,
        *,
        critical_threshold_usd: int = 1_000_000,
        high_threshold_usd: int = 100_000,
        medium_threshold_usd: int = 1_000,
    ) -> None:
        self.eth_usd_price = eth_usd_price
        self.critical_threshold_usd = critical_threshold_usd
        self.high_threshold_usd = high_threshold_usd
        self.medium_threshold_usd = medium_threshold_usd

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def score(
        self,
        *,
        hypothesis: AttackHypothesis,
        sequence: TransactionSequence,
        simulation: SimulationResult,
    ) -> SeverityScore:
        profit_usd = self._profit_usd(simulation)
        tier = self._profit_tier(profit_usd)
        capital_usd = self._capital_required_usd(hypothesis, sequence)
        requires_flash = sequence.uses_flash_loan or self._hypothesis_uses_flash(hypothesis)
        time_sensitive = self._is_time_sensitive(hypothesis)
        mev_frontrunnable = self._is_mev_frontrunnable(hypothesis, sequence)
        pausable = self._is_pausable(hypothesis)

        composite = self._composite(
            tier=tier,
            requires_flash=requires_flash,
            capital_usd=capital_usd,
            time_sensitive=time_sensitive,
            mev_frontrunnable=mev_frontrunnable,
            pausable=pausable,
        )

        return SeverityScore(
            profit_tier=tier,
            capital_required_usd=capital_usd,
            requires_flash_loan=requires_flash,
            time_sensitive=time_sensitive,
            mev_frontrunnable=mev_frontrunnable,
            protocol_pausable=pausable,
            composite_score=composite,
        )

    # ------------------------------------------------------------------
    # Dimension helpers
    # ------------------------------------------------------------------

    def _profit_usd(self, simulation: SimulationResult) -> float:
        if simulation.profit_usd > 0:
            return simulation.profit_usd
        if simulation.profit_wei > 0:
            return (simulation.profit_wei / 10 ** 18) * self.eth_usd_price
        return 0.0

    def _profit_tier(self, profit_usd: float) -> ProfitTier:
        if profit_usd <= 0:
            return ProfitTier.NONE
        if profit_usd >= self.critical_threshold_usd:
            return ProfitTier.CRITICAL
        if profit_usd >= self.high_threshold_usd:
            return ProfitTier.HIGH
        if profit_usd >= self.medium_threshold_usd:
            return ProfitTier.MEDIUM
        return ProfitTier.LOW

    def _capital_required_usd(
        self, hypothesis: AttackHypothesis, sequence: TransactionSequence
    ) -> int:
        """
        Upfront capital. Flash-loan attacks have $0 upfront. Otherwise the
        scorer reads the hypothesis profit_mechanism.estimated_max_usd as a
        rough proxy (an attacker willing to risk X to extract Y).
        """
        if sequence.uses_flash_loan or self._hypothesis_uses_flash(hypothesis):
            return 0
        if hypothesis.profit_mechanism and hypothesis.profit_mechanism.estimated_max_usd:
            # Assume ~10% of upper-bound profit is the required capital.
            return max(1, hypothesis.profit_mechanism.estimated_max_usd // 10)
        return 0

    @staticmethod
    def _hypothesis_uses_flash(hypothesis: AttackHypothesis) -> bool:
        for pc in hypothesis.preconditions:
            if pc.condition_type == ConditionType.FLASH_LOAN_AVAILABLE:
                return True
        return False

    @staticmethod
    def _is_time_sensitive(hypothesis: AttackHypothesis) -> bool:
        for pc in hypothesis.preconditions:
            if pc.condition_type in _TIME_SENSITIVE_CONDITIONS:
                return True
            descr = (pc.description or "").lower()
            if any(kw in descr for kw in _TIME_SENSITIVE_KEYWORDS):
                return True
        return False

    @staticmethod
    def _is_mev_frontrunnable(
        hypothesis: AttackHypothesis, sequence: TransactionSequence
    ) -> bool:
        if hypothesis.attack_class in _MEV_FRONTRUNNABLE_CLASSES:
            return True
        # Any sequence that opens with a swap-like step against a public pool
        # is observable in the mempool and therefore frontrunnable.
        if sequence.calls:
            first = sequence.calls[0]
            if first.function_signature and "swap" in first.function_signature.lower():
                return True
        return False

    @staticmethod
    def _is_pausable(hypothesis: AttackHypothesis) -> bool:
        """
        Best-effort: presence of a Pausable-like signal anywhere in the
        hypothesis text suggests the protocol can freeze. The contrarian
        agent revisits this and may downgrade severity if so.
        """
        haystack = " ".join([
            hypothesis.attack_narrative or "",
            hypothesis.suggested_fix or "",
            *(pc.description or "" for pc in hypothesis.preconditions),
        ]).lower()
        return ("pausable" in haystack) or ("emergency stop" in haystack) or ("circuit breaker" in haystack)

    # ------------------------------------------------------------------
    # Composite
    # ------------------------------------------------------------------

    _TIER_WEIGHT = {
        ProfitTier.NONE: 0.0,
        ProfitTier.LOW: 0.2,
        ProfitTier.MEDIUM: 0.5,
        ProfitTier.HIGH: 0.8,
        ProfitTier.CRITICAL: 1.0,
    }

    def _composite(
        self,
        *,
        tier: ProfitTier,
        requires_flash: bool,
        capital_usd: int,
        time_sensitive: bool,
        mev_frontrunnable: bool,
        pausable: bool,
    ) -> float:
        """
        Composite severity in [0,1]. Profit tier dominates; modifiers nudge
        it up or down to reflect practical exploitability.
        """
        score = self._TIER_WEIGHT[tier]
        # Flash-loan + low capital → easier to pull off → bump severity.
        if requires_flash and capital_usd == 0:
            score = min(1.0, score + 0.05)
        # Time-sensitive attacks are harder → small penalty.
        if time_sensitive:
            score = max(0.0, score - 0.05)
        # MEV-frontrunnable → searchers eat the profit → moderate penalty.
        if mev_frontrunnable:
            score = max(0.0, score - 0.10)
        # Pausable protocol can stop the attack → moderate penalty.
        if pausable:
            score = max(0.0, score - 0.10)
        return round(score, 3)
