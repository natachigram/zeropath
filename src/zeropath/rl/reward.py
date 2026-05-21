"""
Shaped reward function — Phase 7.

Spec (phases.md, PHASE 7 critical additions, "Sparse reward problem"):

    reward = (
        profit_wei * 0.5
      + invariant_violation_score * 0.3
      + novel_state_coverage * 0.1
      + sequence_diversity_bonus * 0.1
      - gas_cost * 0.05
      - capital_required * 0.05
    )

The raw weights from the spec multiply *normalised* quantities — without
normalisation, ``profit_wei`` (1e18-scale) would dwarf every other term and
the shaping would collapse back into the original sparse signal. Each term
is mapped to roughly the same [-1, 1] range before the weighted sum:

  * ``profit_wei``      → log10-saturating curve over (1 ETH → 1k ETH).
  * ``invariant_score`` → already in [0, 1] (validator boolean × fixed weight).
  * ``novel_state``     → 1.0 if state hash unseen, else 0.0.
  * ``sequence_diversity`` → 1.0 minus the fraction of (action_seq) repeats.
  * ``gas_cost``        → log10-saturating curve over (200k → 30M gas).
  * ``capital_required`` → log10-saturating curve over ($0 → $10M).

HITL signals add an additional ``hitl_term`` outside the spec formula:
researcher PROMISING signals nudge reward up, NOT_VIABLE pushes it down.
The shape is multiplicative on the positive total so signals can't push a
zero-profit failure into a positive verdict on their own.
"""

from __future__ import annotations

import logging
import math
from dataclasses import dataclass
from typing import Iterable, Optional

from zeropath.simulator.models import SimulationOutcome
from zeropath.rl.models import HITLSignal, HITLSignalType, RewardBreakdown

logger = logging.getLogger(__name__)


# Spec weights ------------------------------------------------------------
W_PROFIT = 0.50
W_INVARIANT = 0.30
W_NOVELTY = 0.10
W_DIVERSITY = 0.10
W_GAS = 0.05
W_CAPITAL = 0.05


# Normalisation breakpoints ----------------------------------------------
_PROFIT_SAT_WEI = 1000 * 10 ** 18    # 1000 ETH saturates the profit term.
_GAS_SAT_UNITS = 30_000_000           # mainnet block limit.
_CAPITAL_SAT_USD = 10_000_000         # $10M saturates the capital penalty.


def _log_saturate(value: float, saturation: float) -> float:
    """Map [0, sat] → [0, 1] via log10; values above sat clamp at 1.0."""
    if value <= 0:
        return 0.0
    return min(1.0, math.log10(1 + value) / math.log10(1 + saturation))


# ---------------------------------------------------------------------------
# Per-episode raw inputs (built by environment + agent)
# ---------------------------------------------------------------------------


@dataclass
class RewardInputs:
    """All raw numerical inputs the shaper needs for one episode."""

    profit_wei: int = 0
    gas_used: int = 0
    capital_required_usd: int = 0

    # 1.0 when the executed sequence violated a Phase 2 invariant (a hint
    # that the bug is real even if profit didn't extract). Validator /
    # simulator both feed this.
    invariant_violation_score: float = 0.0

    # Was the state hash unseen by *this agent* before this episode?
    state_hash: str = ""
    is_novel_state: bool = False

    # Action sequence diversity: 1.0 = unique sequence; lower if previously seen.
    sequence_diversity: float = 1.0

    # The simulator outcome — used to gate certain terms (no profit credit
    # if the sim never executed, etc.).
    outcome: Optional[SimulationOutcome] = None


# ---------------------------------------------------------------------------
# Shaper
# ---------------------------------------------------------------------------


class RewardShaper:
    """
    Stateless shaper that turns :class:`RewardInputs` into a
    :class:`RewardBreakdown`.

    Parameters
    ----------
    weights : dict | None
        Override individual weights. Keys: 'profit', 'invariant', 'novelty',
        'diversity', 'gas', 'capital'. Missing keys keep the spec default.
    hitl_multiplier_cap : float
        Maximum absolute reward shift from HITL signals (default ±1.0).
    """

    def __init__(
        self,
        *,
        weights: Optional[dict[str, float]] = None,
        hitl_multiplier_cap: float = 1.0,
    ) -> None:
        w = weights or {}
        self.w_profit = w.get("profit", W_PROFIT)
        self.w_invariant = w.get("invariant", W_INVARIANT)
        self.w_novelty = w.get("novelty", W_NOVELTY)
        self.w_diversity = w.get("diversity", W_DIVERSITY)
        self.w_gas = w.get("gas", W_GAS)
        self.w_capital = w.get("capital", W_CAPITAL)
        self.hitl_multiplier_cap = hitl_multiplier_cap

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def shape(
        self,
        inputs: RewardInputs,
        *,
        hitl_signals: Iterable[HITLSignal] = (),
    ) -> RewardBreakdown:
        # ---- Positive terms ----
        profit_norm = _log_saturate(inputs.profit_wei, _PROFIT_SAT_WEI)
        invariant_norm = max(0.0, min(1.0, inputs.invariant_violation_score))
        novelty_norm = 1.0 if inputs.is_novel_state else 0.0
        diversity_norm = max(0.0, min(1.0, inputs.sequence_diversity))

        profit_term = self.w_profit * profit_norm
        invariant_term = self.w_invariant * invariant_norm
        novelty_term = self.w_novelty * novelty_norm
        diversity_term = self.w_diversity * diversity_norm

        # ---- Negative terms (costs) ----
        gas_norm = _log_saturate(inputs.gas_used, _GAS_SAT_UNITS)
        capital_norm = _log_saturate(inputs.capital_required_usd, _CAPITAL_SAT_USD)

        gas_term = -self.w_gas * gas_norm
        capital_term = -self.w_capital * capital_norm

        # ---- HITL bonus / penalty ----
        hitl_term = self._apply_hitl(hitl_signals)

        total = (
            profit_term + invariant_term + novelty_term + diversity_term
            + gas_term + capital_term + hitl_term
        )

        return RewardBreakdown(
            profit_term=round(profit_term, 6),
            invariant_term=round(invariant_term, 6),
            novelty_term=round(novelty_term, 6),
            diversity_term=round(diversity_term, 6),
            gas_term=round(gas_term, 6),
            capital_term=round(capital_term, 6),
            hitl_term=round(hitl_term, 6),
            total=round(total, 6),
        )

    # ------------------------------------------------------------------

    def _apply_hitl(self, signals: Iterable[HITLSignal]) -> float:
        if not signals:
            return 0.0
        total = 0.0
        for s in signals:
            if s.signal_type == HITLSignalType.PROMISING:
                total += abs(s.weight) * 0.20
            elif s.signal_type == HITLSignalType.NOT_VIABLE:
                total -= abs(s.weight) * 0.50
            # SUGGESTED_MUTATION carries no direct reward — it influences
            # the policy via the HITL interface instead.
        return max(-self.hitl_multiplier_cap, min(self.hitl_multiplier_cap, total))
