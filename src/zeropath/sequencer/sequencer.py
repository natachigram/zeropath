"""
SequenceOrchestrator — Phase 4 core.

Takes a Phase 3 SwarmReport and produces a SequenceReport:
  1. Selects the right builder per AttackClass
  2. Builds concrete TransactionSequences for each hypothesis
  3. Runs Foundry + Hardhat code generators
  4. Ranks sequences by completeness + confidence
  5. Returns SequenceReport

Design:
  - Each hypothesis is processed independently (fail-safe per hypothesis)
  - Code generation failures don't block sequence generation
  - Both Foundry and Hardhat are generated unless framework is specified
"""

from __future__ import annotations

import logging
import time
from typing import Any

from zeropath.adversarial.models import AttackClass, AttackHypothesis, HypothesisStatus
from zeropath.adversarial.models import SwarmReport
from zeropath.models import ProtocolGraph
from zeropath.sequencer.abi_encoder import ABIEncoder
from zeropath.sequencer.base import BaseSequenceBuilder
from zeropath.sequencer.builders import (
    AccessControlSequenceBuilder,
    ComposabilitySequenceBuilder,
    FlashLoanSequenceBuilder,
    GovernanceSequenceBuilder,
    IntegerMathSequenceBuilder,
    OracleManipulationSequenceBuilder,
    ReentrancySequenceBuilder,
)
from zeropath.sequencer.codegen import FoundryTestGenerator, HardhatScriptGenerator
from zeropath.sequencer.gas_estimator import GasEstimator, prune_unprofitable
from zeropath.sequencer.models import (
    OnChainStateSnapshot,
    SequenceReport,
    SequenceStatus,
    TestFramework,
    TransactionSequence,
)
from zeropath.sequencer.mutation import MutationEngine
from zeropath.sequencer.onchain_state import OnChainStateFetcher, OnChainStateError

logger = logging.getLogger(__name__)

# Map AttackClass → builder
_BUILDER_MAP: dict[AttackClass, BaseSequenceBuilder] = {
    AttackClass.FLASH_LOAN: FlashLoanSequenceBuilder(),
    AttackClass.ORACLE_MANIPULATION: OracleManipulationSequenceBuilder(),
    AttackClass.REENTRANCY: ReentrancySequenceBuilder(),
    AttackClass.ACCESS_CONTROL: AccessControlSequenceBuilder(),
    AttackClass.GOVERNANCE: GovernanceSequenceBuilder(),
    AttackClass.INTEGER_MATH: IntegerMathSequenceBuilder(),
    AttackClass.COMPOSABILITY: ComposabilitySequenceBuilder(),
    AttackClass.PRICE_MANIPULATION: OracleManipulationSequenceBuilder(),
}

# Fallback builder when the primary builder returns nothing (e.g. composability
# with only one protocol → fall back to flash-loan template).
_BUILDER_FALLBACK: dict[AttackClass, BaseSequenceBuilder] = {
    AttackClass.COMPOSABILITY: FlashLoanSequenceBuilder(),
}

# Statuses that qualify for sequence generation
_GENERATE_FOR_STATUSES = {
    HypothesisStatus.CONSENSUS,
    HypothesisStatus.ENDORSED,
    HypothesisStatus.PROPOSED,
    HypothesisStatus.CHALLENGED,
}

# Minimum confidence to generate a sequence
_MIN_CONFIDENCE = 0.40


class SequenceOrchestrator:
    """
    Converts a Phase 3 SwarmReport into a Phase 4 SequenceReport.

    Pipeline (per spec):

        candidates → builder → ABI encoding → on-chain state binding →
        gas estimation → mutation (optional) → profit pruning → codegen

    Parameters
    ----------
    frameworks : TestFramework
        Which test frameworks to generate code for.
    min_confidence : float
        Minimum hypothesis confidence to process.
    skip_rejected : bool
        Skip REJECTED hypotheses (default True).
    state_fetcher : OnChainStateFetcher | None
        When provided, the orchestrator pre-fetches live mainnet state at
        ``fork_block`` and binds the snapshot to each sequence's context.
        ``None`` keeps the pipeline offline-deterministic.
    fork_block : int | None
        Block to fetch state at. ``None`` → latest. Ignored when
        ``state_fetcher`` is None.
    mutation_engine : MutationEngine | None
        If provided, every successfully built sequence is expanded with up to
        ``mutation_engine.max_per_sequence`` variants.
    gas_price_wei : int
        Gas price used by the profit pruner (default 30 gwei).
    enable_pruning : bool
        Drop sequences whose parsable profit < gas cost.
    """

    def __init__(
        self,
        frameworks: TestFramework = TestFramework.BOTH,
        min_confidence: float = _MIN_CONFIDENCE,
        skip_rejected: bool = True,
        state_fetcher: OnChainStateFetcher | None = None,
        fork_block: int | None = None,
        mutation_engine: MutationEngine | None = None,
        gas_price_wei: int = 30_000_000_000,
        enable_pruning: bool = True,
    ) -> None:
        self.frameworks = frameworks
        self.min_confidence = min_confidence
        self.skip_rejected = skip_rejected
        self.state_fetcher = state_fetcher
        self.fork_block = fork_block
        self.mutation_engine = mutation_engine
        self.gas_price_wei = gas_price_wei
        self.enable_pruning = enable_pruning
        self._foundry_gen = FoundryTestGenerator()
        self._hardhat_gen = HardhatScriptGenerator()
        self._abi_encoder = ABIEncoder()
        self._gas_estimator = GasEstimator()

    def run(
        self,
        swarm_report: SwarmReport,
        graph: ProtocolGraph,
    ) -> SequenceReport:
        """Build sequences for all qualifying hypotheses in the swarm report."""
        start = time.monotonic()

        # Stage 1 — pre-fetch on-chain state once for the whole batch.
        snapshot = self._fetch_onchain_state(swarm_report, graph)

        # Stage 2 — filter hypotheses to process
        candidates = self._select_candidates(swarm_report.hypotheses)
        logger.info(
            "SequenceOrchestrator: processing %d / %d hypotheses",
            len(candidates), len(swarm_report.hypotheses),
        )

        # Stage 3 — build per-hypothesis sequences (without codegen yet).
        sequences: list[TransactionSequence] = []
        for hyp in candidates:
            seq = self._build_one(hyp, graph)
            if seq:
                self._attach_snapshot(seq, snapshot)
                sequences.append(seq)

        # Stage 4 — mutation expansion.
        if self.mutation_engine:
            sequences = self.mutation_engine.expand(sequences)
            logger.info(
                "MutationEngine expanded to %d sequences (parents + variants)",
                len(sequences),
            )

        # Stage 5 — ABI encoding + gas estimation on the full set.
        for seq in sequences:
            try:
                self._abi_encoder.encode_sequence(seq)
            except Exception:
                logger.exception("ABI encoding failed for sequence %s", seq.id)
            self._gas_estimator.estimate_sequence(seq)
            self._populate_protocols_touched(seq)
            seq.uses_flash_loan = seq.context.flash_loan_provider is not None
            if snapshot:
                seq.block_number = snapshot.block_number

        # Stage 6 — prune sequences whose profit < gas cost.
        pruned: list[TransactionSequence] = []
        if self.enable_pruning:
            sequences, pruned = prune_unprofitable(
                sequences, gas_price_wei=self.gas_price_wei
            )
            if pruned:
                logger.info("Pruner dropped %d unprofitable sequences", len(pruned))

        # Stage 7 — codegen on the survivors.
        for seq in sequences:
            self._generate_code(seq)

        # Stage 8 — sort by completeness DESC, then estimated_profit_wei DESC.
        sequences.sort(
            key=lambda s: (s.completeness_score, s.estimated_profit_wei),
            reverse=True,
        )

        elapsed = time.monotonic() - start

        full_poc_count = sum(
            1 for s in sequences
            if s.foundry_test is not None or s.hardhat_test is not None
        )
        manual_param_count = sum(
            1 for s in sequences if s.requires_manual_params
        )

        return SequenceReport(
            protocol_name=swarm_report.protocol_name,
            swarm_report_id=swarm_report.id,
            sequences=sequences,
            total_hypotheses_input=len(swarm_report.hypotheses),
            sequences_generated=len(sequences),
            sequences_with_full_poc=full_poc_count,
            sequences_requiring_manual_params=manual_param_count,
            analysis_metadata={
                "frameworks": self.frameworks.value,
                "min_confidence_threshold": self.min_confidence,
                "elapsed_seconds": round(elapsed, 3),
                "candidates_processed": len(candidates),
                "sequences_pruned": len(pruned),
                "onchain_state_fetched": snapshot is not None,
                "fork_block": snapshot.block_number if snapshot else None,
                "mutation_enabled": self.mutation_engine is not None,
            },
        )

    def _select_candidates(
        self, hypotheses: list[AttackHypothesis]
    ) -> list[AttackHypothesis]:
        """Filter hypotheses worth generating sequences for."""
        result = []
        for h in hypotheses:
            if self.skip_rejected and h.status == HypothesisStatus.REJECTED:
                continue
            if h.confidence < self.min_confidence:
                continue
            if h.status not in _GENERATE_FOR_STATUSES and self.skip_rejected:
                continue
            result.append(h)
        return result

    def _build_one(
        self,
        hypothesis: AttackHypothesis,
        graph: ProtocolGraph,
    ) -> TransactionSequence | None:
        """Build a sequence (no codegen) for one hypothesis."""
        attack_class = hypothesis.attack_class

        builder = _BUILDER_MAP.get(attack_class)
        if builder is None:
            logger.debug(
                "No builder for attack class %s — skipping hypothesis '%s'",
                attack_class.value, hypothesis.title,
            )
            return None

        seq = builder.build(hypothesis, graph)
        if seq is None:
            fallback = _BUILDER_FALLBACK.get(attack_class)
            if fallback is not None:
                seq = fallback.build(hypothesis, graph)
            if seq is None:
                return None
        return seq

    def _generate_code(self, seq: TransactionSequence) -> None:
        """Run Foundry / Hardhat codegen on a built sequence."""
        if self.frameworks in (TestFramework.FOUNDRY, TestFramework.BOTH):
            try:
                seq.foundry_test = self._foundry_gen.generate(seq)
            except Exception:
                logger.exception(
                    "Foundry codegen failed for sequence '%s'", seq.hypothesis_title
                )

        if self.frameworks in (TestFramework.HARDHAT, TestFramework.BOTH):
            try:
                seq.hardhat_test = self._hardhat_gen.generate(seq)
            except Exception:
                logger.exception(
                    "Hardhat codegen failed for sequence '%s'", seq.hypothesis_title
                )

        logger.debug(
            "Generated code for '%s' (completeness=%.2f, foundry=%s, hardhat=%s)",
            seq.hypothesis_title,
            seq.completeness_score,
            seq.foundry_test is not None,
            seq.hardhat_test is not None,
        )

    # ------------------------------------------------------------------
    # On-chain state binding
    # ------------------------------------------------------------------

    def _fetch_onchain_state(
        self,
        swarm_report: SwarmReport,
        graph: ProtocolGraph,
    ) -> OnChainStateSnapshot | None:
        """Fetch a snapshot once for the whole batch when configured."""
        if self.state_fetcher is None:
            return None
        # Collect addresses referenced across hypotheses + graph.
        pools: set[str] = set()
        oracles: set[str] = set()
        tokens: set[str] = set()
        for hyp in swarm_report.hypotheses:
            for dep in getattr(hyp, "oracle_dependencies", []) or []:
                addr = getattr(dep, "oracle_contract", None)
                if isinstance(addr, str) and addr.startswith("0x"):
                    oracles.add(addr)
        for contract in getattr(graph, "contracts", []) or []:
            addr = getattr(contract, "address", None)
            if isinstance(addr, str) and addr.startswith("0x"):
                if "pool" in (contract.name or "").lower() or "pair" in (contract.name or "").lower():
                    pools.add(addr)
                if "token" in (contract.name or "").lower():
                    tokens.add(addr)

        try:
            return self.state_fetcher.fetch_snapshot(
                block_number=self.fork_block,
                pools=list(pools),
                oracles=list(oracles),
                tokens_for_metadata=list(tokens),
            )
        except OnChainStateError as exc:
            logger.warning("On-chain state fetch failed: %s — proceeding without snapshot", exc)
            return None

    @staticmethod
    def _attach_snapshot(
        seq: TransactionSequence, snapshot: OnChainStateSnapshot | None
    ) -> None:
        if snapshot is None:
            return
        seq.context.onchain_snapshot = snapshot
        seq.context.fork_block = snapshot.block_number

    @staticmethod
    def _populate_protocols_touched(seq: TransactionSequence) -> None:
        """Derive ``protocols_touched`` from the call sequence."""
        seen: list[str] = []
        for call in seq.calls:
            target = call.target_address_expr or ""
            # Best-effort: pull the contract identifier out of `IFoo(0x...)`.
            if "(" in target:
                ident = target.split("(", 1)[0].lstrip("I")
                if ident and ident not in seen:
                    seen.append(ident)
            elif call.target_address and call.target_address not in seen:
                seen.append(call.target_address)
        seq.protocols_touched = seen
