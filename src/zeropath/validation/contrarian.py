"""
Contrarian agent — Phase 6.

Spec (phases.md, PHASE 6 critical additions, "Second-opinion adversarial review"):
    "After validation passes, run one contrarian agent whose only job is to
     find reasons the exploit will fail in practice. This agent looks for:
     MEV competition, gas limit issues, liquidity assumptions, admin key
     mitigations. If it cannot invalidate the exploit, confidence goes up."

The contrarian is a *deterministic* adversary — no LLM call required. It
applies a battery of rules against (hypothesis, sequence, simulation,
severity) and emits :class:`ContrarianObjection` records. The orchestrator
uses the objection set to:

  * Adjust confidence (each strong objection drops it by `severity * 0.15`).
  * Flip ``recommended_action`` to SIMULATE_FURTHER when total objection
    weight crosses a threshold.
  * If a single objection has severity ≥ 0.9, mark the exploit
    CONTRARIAN_INVALIDATED and DISCARD.

Categories checked (mapping to spec):

  * MEV competition / sandwich risk     — `MEV_COMPETITION`, `SANDWICH_RISK`
  * Gas limit issues                    — `GAS_LIMIT`
  * Liquidity assumptions               — `LIQUIDITY_DEPTH`
  * Admin key mitigations               — `ADMIN_MITIGATION`
  * Block reorg vulnerability           — `BLOCK_REORG`
  * Slippage on huge swaps              — `SLIPPAGE`
"""

from __future__ import annotations

import logging
from typing import Optional

from zeropath.adversarial.models import AttackClass, AttackHypothesis
from zeropath.sequencer.models import TransactionSequence
from zeropath.simulator.models import SimulationResult
from zeropath.validation.models import (
    ContrarianObjection,
    ObjectionCategory,
    SeverityScore,
)

logger = logging.getLogger(__name__)


# Sequence gas above this fraction of block limit triggers a GAS_LIMIT
# objection (not auto-reject — that's RealismValidator).
_GAS_PRESSURE_RATIO = 0.50
_BLOCK_GAS_LIMIT = 30_000_000

# Flash amount to pool depth ratio that starts triggering slippage warnings.
_SLIPPAGE_FLASH_RATIO = 0.05
# Above this, the swap will eat all the profit.
_SLIPPAGE_KILL_RATIO = 0.20


class ContrarianAgent:
    """
    Single contrarian reviewer. Designed for one-shot use::

        agent = ContrarianAgent()
        objections = agent.review(hypothesis=..., sequence=..., simulation=...,
                                  severity=...)
        if not objections:
            confidence += 0.05  # nothing failed — confidence boost
    """

    name = "ContrarianAgent"

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def review(
        self,
        *,
        hypothesis: AttackHypothesis,
        sequence: TransactionSequence,
        simulation: SimulationResult,
        severity: SeverityScore,
    ) -> list[ContrarianObjection]:
        objections: list[ContrarianObjection] = []
        objections.extend(self._check_mev_competition(hypothesis, sequence, severity))
        objections.extend(self._check_gas_limit(sequence))
        objections.extend(self._check_liquidity_depth(sequence))
        objections.extend(self._check_admin_mitigation(hypothesis, severity))
        objections.extend(self._check_block_reorg(hypothesis))
        objections.extend(self._check_slippage(sequence))
        return objections

    # ------------------------------------------------------------------
    # Rules
    # ------------------------------------------------------------------

    def _check_mev_competition(
        self,
        hypothesis: AttackHypothesis,
        sequence: TransactionSequence,
        severity: SeverityScore,
    ) -> list[ContrarianObjection]:
        if not severity.mev_frontrunnable:
            return []
        # Single-block atomicity + frontrunnable = sandwich-able.
        sub_category = ObjectionCategory.SANDWICH_RISK if sequence.context.requires_single_block \
            else ObjectionCategory.MEV_COMPETITION
        sev = 0.7 if hypothesis.attack_class in (
            AttackClass.ORACLE_MANIPULATION, AttackClass.FLASH_LOAN,
            AttackClass.PRICE_MANIPULATION,
        ) else 0.4
        return [ContrarianObjection(
            category=sub_category,
            severity=sev,
            explanation=(
                "Attack is observable in the public mempool and uses a "
                "well-known DeFi primitive. A faster searcher can backrun "
                "or sandwich the manipulation."
            ),
            evidence=[
                f"attack_class={hypothesis.attack_class.value}",
                f"single_block={sequence.context.requires_single_block}",
                f"frontrunnable={severity.mev_frontrunnable}",
            ],
        )]

    def _check_gas_limit(
        self, sequence: TransactionSequence
    ) -> list[ContrarianObjection]:
        if not sequence.total_gas_estimate:
            return []
        ratio = sequence.total_gas_estimate / _BLOCK_GAS_LIMIT
        if ratio < _GAS_PRESSURE_RATIO:
            return []
        sev = min(1.0, ratio)
        return [ContrarianObjection(
            category=ObjectionCategory.GAS_LIMIT,
            severity=sev,
            explanation=(
                f"Sequence consumes {sequence.total_gas_estimate:_} gas "
                f"({ratio * 100:.0f}% of mainnet block limit). A competing "
                f"tx in the same block could push it over."
            ),
            evidence=[
                f"total_gas_estimate={sequence.total_gas_estimate}",
                f"block_limit={_BLOCK_GAS_LIMIT}",
                f"ratio={ratio:.2f}",
            ],
        )]

    def _check_liquidity_depth(
        self, sequence: TransactionSequence
    ) -> list[ContrarianObjection]:
        snap = sequence.context.onchain_snapshot
        if not snap or not snap.pool_reserves:
            return []
        flash_amount = self._infer_flash_amount(sequence)
        if not flash_amount:
            return []
        max_reserve = max(max(r0, r1) for (r0, r1, _) in snap.pool_reserves.values())
        if max_reserve == 0:
            return []
        ratio = flash_amount / max_reserve
        if ratio < 0.5:
            return []
        sev = min(1.0, ratio / 2.0)  # ratio 1.0 → severity 0.5; ratio 2.0 → 1.0
        return [ContrarianObjection(
            category=ObjectionCategory.LIQUIDITY_DEPTH,
            severity=sev,
            explanation=(
                f"Flash amount {flash_amount:_} is {ratio:.1%} of the "
                f"largest observed pool reserve ({max_reserve:_}). Real "
                f"slippage will deviate significantly from simulation."
            ),
            evidence=[
                f"flash_amount={flash_amount}",
                f"max_pool_reserve={max_reserve}",
            ],
        )]

    def _check_admin_mitigation(
        self, hypothesis: AttackHypothesis, severity: SeverityScore
    ) -> list[ContrarianObjection]:
        if not severity.protocol_pausable:
            return []
        return [ContrarianObjection(
            category=ObjectionCategory.ADMIN_MITIGATION,
            severity=0.5,
            explanation=(
                "Protocol exposes a pause / circuit-breaker. If the admin "
                "is responsive, the attacker has only a short window."
            ),
            evidence=["narrative or fix mentions pausable / circuit breaker"],
        )]

    def _check_block_reorg(
        self, hypothesis: AttackHypothesis
    ) -> list[ContrarianObjection]:
        """
        Cross-block sequences are vulnerable to reorgs and validator
        censorship. TWAP manipulation is the classic example.
        """
        title = (hypothesis.title or "").lower()
        narrative = (hypothesis.attack_narrative or "").lower()
        if "twap" in title or "twap" in narrative or "multi-block" in narrative:
            return [ContrarianObjection(
                category=ObjectionCategory.BLOCK_REORG,
                severity=0.4,
                explanation=(
                    "Multi-block manipulation (e.g. TWAP) is vulnerable to "
                    "validator censorship and chain reorgs. Builder may "
                    "exclude attacker txs once the pattern is detected."
                ),
                evidence=["TWAP / multi-block attack pattern"],
            )]
        return []

    def _check_slippage(
        self, sequence: TransactionSequence
    ) -> list[ContrarianObjection]:
        snap = sequence.context.onchain_snapshot
        if not snap or not snap.pool_reserves:
            return []
        flash_amount = self._infer_flash_amount(sequence)
        if not flash_amount:
            return []
        max_reserve = max(max(r0, r1) for (r0, r1, _) in snap.pool_reserves.values())
        if max_reserve == 0:
            return []
        ratio = flash_amount / max_reserve
        if ratio < _SLIPPAGE_FLASH_RATIO:
            return []
        sev = min(1.0, max(0.3, ratio / _SLIPPAGE_KILL_RATIO))
        return [ContrarianObjection(
            category=ObjectionCategory.SLIPPAGE,
            severity=sev,
            explanation=(
                f"Single-leg swap of {flash_amount:_} against pool with "
                f"{max_reserve:_} reserves moves price by ~{ratio * 100:.1f}%. "
                f"Real slippage may eliminate the modeled profit."
            ),
            evidence=[
                f"swap_to_reserve_ratio={ratio:.3f}",
            ],
        )]

    # ------------------------------------------------------------------

    @staticmethod
    def _infer_flash_amount(sequence: TransactionSequence) -> Optional[int]:
        for call in sequence.calls:
            sig = (call.function_signature or "").lower()
            if "flashloan" not in sig and "flash" not in sig:
                continue
            for ptype, pval in zip(call.param_types, call.params):
                if ptype.startswith("uint") and isinstance(pval, int) and pval > 0:
                    return pval
        return None
