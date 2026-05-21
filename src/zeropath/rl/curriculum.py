"""
CurriculumScheduler — Phase 7.

Spec (phases.md, PHASE 7 critical additions, "Curriculum learning"):
    "Start training on simple protocols (single-contract, no oracles).
     Graduate to complex protocols only after the agent demonstrates
     competence. Prevents the agent from being permanently confused by
     protocol complexity early in training."

The scheduler watches a rolling window of episode rewards across the
population. When the rolling mean clears a tier-specific threshold for at
least ``required_consecutive`` evaluations, it promotes to the next tier.
Tier never regresses automatically — the orchestrator can demote via
:meth:`force_set_tier` if curriculum collapse is observed.
"""

from __future__ import annotations

import logging
from collections import deque
from typing import Iterable

from zeropath.rl.models import CurriculumTier, Episode

logger = logging.getLogger(__name__)


# Reward threshold per tier — the rolling mean must beat this to promote.
# Calibrated against the RewardShaper output range [-0.15, ~0.9].
_TIER_PROMOTION_THRESHOLDS: dict[CurriculumTier, float] = {
    CurriculumTier.SINGLE_CONTRACT_NO_ORACLE: 0.15,
    CurriculumTier.MULTI_CONTRACT:             0.20,
    CurriculumTier.WITH_ORACLE:                0.25,
    CurriculumTier.WITH_FLASH_LOAN:            0.30,
    # CROSS_PROTOCOL is the top tier — no promotion from here.
}

# Default window over which the rolling mean is computed.
DEFAULT_WINDOW = 50

# Default number of *consecutive* promotion checks the threshold must hold.
DEFAULT_REQUIRED_CONSECUTIVE = 2


class CurriculumScheduler:
    """
    Promotion-only difficulty ladder.

    Parameters
    ----------
    starting_tier : CurriculumTier
        Where the swarm begins. Default: simplest tier.
    window : int
        Episodes counted in the rolling mean.
    required_consecutive : int
        Threshold must be cleared this many consecutive promotion checks
        before tier advances. Guards against single-batch noise.
    promotion_thresholds : dict | None
        Override per-tier promotion targets.
    """

    def __init__(
        self,
        *,
        starting_tier: CurriculumTier = CurriculumTier.SINGLE_CONTRACT_NO_ORACLE,
        window: int = DEFAULT_WINDOW,
        required_consecutive: int = DEFAULT_REQUIRED_CONSECUTIVE,
        promotion_thresholds: dict[CurriculumTier, float] | None = None,
    ) -> None:
        self._tier = starting_tier
        self._window = max(1, window)
        self._required_consecutive = max(1, required_consecutive)
        self._thresholds = dict(promotion_thresholds or _TIER_PROMOTION_THRESHOLDS)
        self._rewards: deque[float] = deque(maxlen=self._window)
        self._consecutive_clears = 0

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    @property
    def tier(self) -> CurriculumTier:
        return self._tier

    @property
    def rolling_mean(self) -> float:
        return sum(self._rewards) / len(self._rewards) if self._rewards else 0.0

    def record_episode(self, episode: Episode) -> None:
        """Update the rolling window with one episode's terminal reward."""
        self._rewards.append(episode.reward.total)

    def record_episodes(self, episodes: Iterable[Episode]) -> None:
        for ep in episodes:
            self.record_episode(ep)

    def maybe_promote(self) -> bool:
        """
        Check whether the rolling mean crosses the current tier's threshold
        and, if so, promote.

        Returns True iff the tier was actually advanced. The window is reset
        on promotion so the new tier collects its own samples.
        """
        if self._tier == CurriculumTier.CROSS_PROTOCOL:
            return False  # already at top tier
        threshold = self._thresholds.get(self._tier, 0.0)
        if not self._rewards or len(self._rewards) < self._window // 2:
            # Not enough data to make a stable decision.
            return False
        if self.rolling_mean >= threshold:
            self._consecutive_clears += 1
        else:
            self._consecutive_clears = 0
        if self._consecutive_clears < self._required_consecutive:
            return False
        next_tier = self._next_tier(self._tier)
        if next_tier == self._tier:
            return False
        logger.info(
            "Curriculum promote: %s → %s (rolling_mean=%.3f, threshold=%.3f)",
            self._tier.name, next_tier.name, self.rolling_mean, threshold,
        )
        self._tier = next_tier
        self._rewards.clear()
        self._consecutive_clears = 0
        return True

    def force_set_tier(self, tier: CurriculumTier) -> None:
        """Manual override — e.g. resume from checkpoint or HITL escalation."""
        if tier != self._tier:
            logger.info("Curriculum force_set: %s → %s", self._tier.name, tier.name)
            self._tier = tier
            self._rewards.clear()
            self._consecutive_clears = 0

    # ------------------------------------------------------------------
    # Serialisation
    # ------------------------------------------------------------------

    def to_dict(self) -> dict:
        return {
            "tier": int(self._tier),
            "rewards": list(self._rewards),
            "consecutive_clears": self._consecutive_clears,
            "window": self._window,
            "required_consecutive": self._required_consecutive,
            "thresholds": {int(k): v for k, v in self._thresholds.items()},
        }

    @classmethod
    def from_dict(cls, data: dict) -> "CurriculumScheduler":
        sched = cls(
            starting_tier=CurriculumTier(data.get("tier", 0)),
            window=data.get("window", DEFAULT_WINDOW),
            required_consecutive=data.get("required_consecutive", DEFAULT_REQUIRED_CONSECUTIVE),
            promotion_thresholds={
                CurriculumTier(int(k)): v
                for k, v in (data.get("thresholds") or {}).items()
            } or None,
        )
        sched._rewards = deque(data.get("rewards", []), maxlen=sched._window)
        sched._consecutive_clears = data.get("consecutive_clears", 0)
        return sched

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    @staticmethod
    def _next_tier(tier: CurriculumTier) -> CurriculumTier:
        ordered = list(CurriculumTier)
        idx = ordered.index(tier)
        if idx + 1 >= len(ordered):
            return tier
        return ordered[idx + 1]
