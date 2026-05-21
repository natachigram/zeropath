"""
CheckpointManager — Phase 7.

Spec (phases.md, PHASE 7 LLM prompt):
    "Allow continuous training. Checkpoint regularly. Support resume from
     checkpoint."

Serialises the full training state — population, agent stats, curriculum
tier, HITL inbox, RNG seed — as JSON. Single-file format for portability;
no torch tensors, no pickle, so checkpoints are diff-able and survive
Python version upgrades.

Checkpoint files include an integer ``schema_version`` so the loader can
refuse mismatched payloads early instead of crashing mid-restore.
"""

from __future__ import annotations

import json
import logging
import os
import tempfile
from pathlib import Path
from typing import Optional

from zeropath.rl.curriculum import CurriculumScheduler
from zeropath.rl.hitl import HumanInTheLoop
from zeropath.rl.models import (
    AgentSpec,
    AgentStats,
    CurriculumTier,
    HITLSignal,
    PopulationStats,
    TrainingState,
)
from zeropath.rl.population import PopulationManager
from zeropath.rl.agent import RLAgent
from zeropath.rl.policy import StochasticPolicy

logger = logging.getLogger(__name__)


CHECKPOINT_SCHEMA_VERSION = 1


class CheckpointError(Exception):
    """Raised when a checkpoint file is corrupt or schema-mismatched."""


class CheckpointManager:
    """
    Save / load helper bound to a directory.

    Each save writes ``checkpoint-<step>.json`` (atomic via temp file +
    rename) plus updates ``latest.json`` as a convenience pointer.
    """

    def __init__(self, root: str | os.PathLike) -> None:
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def save(
        self,
        *,
        population: PopulationManager,
        curriculum: CurriculumScheduler,
        hitl: HumanInTheLoop,
        total_episodes: int,
        rng_seed: int = 0,
        protocol_name: str = "unknown",
        notes: str = "",
    ) -> Path:
        """
        Write a checkpoint. Filename keyed by ``total_episodes`` so a
        well-behaved trainer overwrites cleanly across resume.
        """
        state = TrainingState(
            protocol_name=protocol_name,
            generation=population.generation,
            total_episodes=total_episodes,
            curriculum_tier=curriculum.tier,
            population=[a.spec for a in population.agents],
            agent_stats=[a.stats for a in population.agents],
            generation_history=list(population.history),
            hitl_signals=hitl.all_signals(),
            rng_seed=rng_seed,
            notes=notes,
        )
        payload = {
            "schema_version": CHECKPOINT_SCHEMA_VERSION,
            "state": state.model_dump(mode="json"),
            "curriculum": curriculum.to_dict(),
            "policies": [
                {"agent_id": a.spec.id, "policy_class": type(a.policy).__name__,
                 "policy": a.policy.to_dict()}
                for a in population.agents
            ],
        }
        target = self.root / f"checkpoint-{total_episodes:08d}.json"
        self._atomic_write(target, payload)
        latest = self.root / "latest.json"
        self._atomic_write(latest, payload)
        logger.info("Checkpoint saved: %s", target)
        return target

    def load(self, path: Optional[str | os.PathLike] = None) -> dict:
        """
        Load a checkpoint. ``path=None`` picks ``latest.json``.

        Returns the raw payload dict so callers can rehydrate piecemeal
        (some users only want the curriculum tier, not the whole swarm).
        """
        target = Path(path) if path else (self.root / "latest.json")
        if not target.exists():
            raise CheckpointError(f"no checkpoint at {target}")
        with target.open("r", encoding="utf-8") as f:
            payload = json.load(f)
        sv = payload.get("schema_version")
        if sv != CHECKPOINT_SCHEMA_VERSION:
            raise CheckpointError(
                f"schema mismatch: expected {CHECKPOINT_SCHEMA_VERSION}, got {sv}"
            )
        return payload

    def restore(
        self,
        path: Optional[str | os.PathLike] = None,
    ) -> tuple[PopulationManager, CurriculumScheduler, HumanInTheLoop, TrainingState]:
        """
        Convenience: hydrate population / curriculum / HITL / state.
        """
        payload = self.load(path)
        state = TrainingState.model_validate(payload["state"])
        curriculum = CurriculumScheduler.from_dict(payload["curriculum"])

        hitl = HumanInTheLoop.from_list(state.hitl_signals)

        # Rebuild PopulationManager *without* triggering its own __init__
        # population scaffold (we replace it with the persisted agents).
        pop = PopulationManager.__new__(PopulationManager)
        pop.population_size = len(state.population) or 1
        pop.elite_fraction = 0.20
        pop.reseed_fraction = 0.30
        pop.policy_factory = StochasticPolicy
        import random as _rng_mod
        pop._rng = _rng_mod.Random(state.rng_seed)
        pop._generation = state.generation
        pop.history = list(state.generation_history)

        # Restore agents (spec + stats + policy state).
        stats_by_id = {s.agent_id: s for s in state.agent_stats}
        policy_by_id = {p["agent_id"]: p for p in payload.get("policies", [])}

        agents: list[RLAgent] = []
        for spec in state.population:
            policy_payload = policy_by_id.get(spec.id)
            policy = None
            if policy_payload and policy_payload.get("policy"):
                policy = StochasticPolicy.from_dict(policy_payload["policy"])
            agent = RLAgent(spec, policy=policy)
            stats = stats_by_id.get(spec.id)
            if stats:
                agent.stats = stats
            agents.append(agent)
        pop.agents = agents

        return pop, curriculum, hitl, state

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _atomic_write(target: Path, payload: dict) -> None:
        target.parent.mkdir(parents=True, exist_ok=True)
        tmp_fd, tmp_path = tempfile.mkstemp(
            prefix=target.name + ".", dir=str(target.parent)
        )
        try:
            with os.fdopen(tmp_fd, "w", encoding="utf-8") as f:
                json.dump(payload, f, indent=2, sort_keys=True)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp_path, target)
        except Exception:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
            raise
