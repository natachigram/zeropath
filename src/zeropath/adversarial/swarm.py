"""
SwarmOrchestrator — Phase 3 core.

Runs all adversarial agents in parallel (asyncio), collects hypotheses,
feeds them through the DebateEngine, and returns a ranked SwarmReport.

Design:
  - Each agent runs in its own asyncio task (concurrent, not threaded)
  - A ThreadPoolExecutor is used for agents whose analysis is CPU-bound
  - Agents are isolated: a failure in one does not affect others
  - Debate and consensus happen after all agents complete
"""

from __future__ import annotations

import asyncio
import logging
import time
from concurrent.futures import ThreadPoolExecutor
from typing import TYPE_CHECKING

from zeropath.adversarial.agents import (
    AccessControlAgent,
    ComposabilityAgent,
    FlashLoanAgent,
    GovernanceAttackAgent,
    IntegerMathAgent,
    OracleManipulatorAgent,
    ReentrancyAgent,
)
from zeropath.adversarial.base import BaseAdversarialAgent
from zeropath.adversarial.consensus import ConsensusAggregator
from zeropath.adversarial.debate import DebateEngine
from zeropath.adversarial.models import AttackHypothesis, SwarmReport
from zeropath.invariants.models import InvariantReport
from zeropath.models import ProtocolGraph

if TYPE_CHECKING:
    pass

logger = logging.getLogger(__name__)

_DEFAULT_AGENTS: list[BaseAdversarialAgent] = [
    OracleManipulatorAgent(),
    ReentrancyAgent(),
    AccessControlAgent(),
    FlashLoanAgent(),
    ComposabilityAgent(),
    GovernanceAttackAgent(),
    IntegerMathAgent(),
]


class SwarmOrchestrator:
    """
    Orchestrates the full Phase 3 pipeline:

      1. Parallel agent execution (all 7 agents run simultaneously)
      2. Debate round (cross-agent critique and confidence adjustment)
      3. Consensus aggregation (dedup, rank, reject low-quality)
      4. SwarmReport assembly
    """

    def __init__(
        self,
        agents: list[BaseAdversarialAgent] | None = None,
        max_workers: int = 4,
        debate_rounds: int = 2,
    ) -> None:
        self.agents = agents or list(_DEFAULT_AGENTS)
        self.max_workers = max_workers
        self.debate_rounds = debate_rounds
        self._debate_engine = DebateEngine(self.agents)
        self._consensus = ConsensusAggregator()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def run(
        self,
        report: InvariantReport,
        graph: ProtocolGraph,
    ) -> SwarmReport:
        """Synchronous entry point — runs the full swarm pipeline."""
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                # Already inside an event loop (e.g. Jupyter) — run in thread
                import concurrent.futures
                with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
                    future = ex.submit(asyncio.run, self._run_async(report, graph))
                    return future.result()
        except RuntimeError:
            pass
        return asyncio.run(self._run_async(report, graph))

    async def run_async(
        self,
        report: InvariantReport,
        graph: ProtocolGraph,
    ) -> SwarmReport:
        """Async entry point for callers already in an event loop."""
        return await self._run_async(report, graph)

    # ------------------------------------------------------------------
    # Internal pipeline
    # ------------------------------------------------------------------

    async def _run_async(
        self,
        report: InvariantReport,
        graph: ProtocolGraph,
    ) -> SwarmReport:
        start = time.monotonic()
        logger.info(
            "Swarm starting: %d agents, %d invariants",
            len(self.agents), len(report.invariants),
        )

        # Step 1: Parallel agent execution
        all_hypotheses = await self._run_agents_parallel(report, graph)
        logger.info("Swarm collected %d raw hypotheses", len(all_hypotheses))

        # Step 2: Debate rounds
        debate_records = []
        for round_num in range(1, self.debate_rounds + 1):
            debate_record = self._debate_engine.run_round(
                all_hypotheses, round_number=round_num
            )
            debate_records.append(debate_record)
            logger.info(
                "Debate round %d: %d notes, %d updated, %d rejected",
                round_num,
                len(debate_record.notes),
                debate_record.hypotheses_updated,
                debate_record.hypotheses_rejected,
            )

        # Step 3: Consensus aggregation
        final_hypotheses = self._consensus.aggregate(all_hypotheses)
        logger.info("Consensus: %d hypotheses after dedup + ranking", len(final_hypotheses))

        elapsed = time.monotonic() - start

        # Step 4: Assemble report
        return SwarmReport(
            protocol_name=report.protocol_name,
            invariant_report_id=report.id,
            hypotheses=final_hypotheses,
            debate_rounds=debate_records,
            agent_stats=self._build_agent_stats(all_hypotheses),
            analysis_metadata={
                "agents": [a.name for a in self.agents],
                "total_raw_hypotheses": len(all_hypotheses),
                "debate_rounds": self.debate_rounds,
                "elapsed_seconds": round(elapsed, 3),
                "invariant_count": len(report.invariants),
                "protocol_types": [t.value for t in report.protocol_pattern.protocol_types],
            },
        )

    async def _run_agents_parallel(
        self,
        report: InvariantReport,
        graph: ProtocolGraph,
    ) -> list[AttackHypothesis]:
        """Run all agents concurrently in a thread pool."""
        loop = asyncio.get_event_loop()

        with ThreadPoolExecutor(max_workers=min(self.max_workers, len(self.agents))) as executor:
            tasks = [
                loop.run_in_executor(executor, agent.run, report, graph)
                for agent in self.agents
            ]
            results = await asyncio.gather(*tasks, return_exceptions=True)

        all_hypotheses: list[AttackHypothesis] = []
        for agent, result in zip(self.agents, results):
            if isinstance(result, Exception):
                logger.error("Agent %s failed: %s", agent.name, result)
            else:
                count = len(result)
                logger.debug("Agent %s generated %d hypotheses", agent.name, count)
                all_hypotheses.extend(result)

        return all_hypotheses

    def _build_agent_stats(
        self, hypotheses: list[AttackHypothesis]
    ) -> dict[str, dict]:
        stats: dict[str, dict] = {}
        for agent in self.agents:
            agent_hyps = [h for h in hypotheses if h.proposed_by == agent.name]
            stats[agent.name] = {
                "hypotheses_generated": len(agent_hyps),
                "avg_confidence": (
                    sum(h.confidence for h in agent_hyps) / len(agent_hyps)
                    if agent_hyps else 0.0
                ),
                "attack_classes": list({h.attack_class.value for h in agent_hyps}),
            }
        return stats
