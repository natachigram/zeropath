"""
SimulationOrchestrator — Phase 5 top-level coordinator.

Pipeline::

    SequenceReport (Phase 4) + InvariantReport (Phase 2)
       │
       ▼
    AnvilProcess  ← optional shared fork for the whole batch
       │
       ▼
    SequenceExecutor.execute()  per TransactionSequence
       │     ├─ pre-flight setup (impersonate + fund attacker)
       │     ├─ state snapshot before
       │     ├─ submit each TxCall  → StepResult
       │     ├─ revert? → RevertAnalyzer → mutation feedback
       │     └─ state snapshot after → BalanceDiff / StorageDiff
       │
       ▼
    EchidnaFuzzer.run() / MedusaFuzzer.run()  on invariants (optional)
       │
       ▼
    HalmosChecker.check()  on invariants with formal_spec (optional)
       │
       ▼
    SimulationReport
"""

from __future__ import annotations

import logging
import time
from typing import Optional

from zeropath.invariants.models import InvariantReport
from zeropath.sequencer.models import SequenceReport, TransactionSequence
from zeropath.simulator.anvil import AnvilNotAvailable, AnvilProcess
from zeropath.simulator.executor import SequenceExecutor
from zeropath.simulator.fuzzer import EchidnaFuzzer, MedusaFuzzer
from zeropath.simulator.halmos import HalmosChecker
from zeropath.simulator.models import (
    FuzzerKind,
    HalmosResult,
    SimulationOutcome,
    SimulationReport,
    SimulationResult,
)
from zeropath.simulator.revert_analyzer import RevertAnalyzer

logger = logging.getLogger(__name__)


class SimulationOrchestrator:
    """
    Execute every sequence in a Phase 4 :class:`SequenceReport`, run Echidna
    + Medusa + Halmos against the Phase 2 invariants, and return a
    :class:`SimulationReport`.

    Parameters
    ----------
    fork_url : str | None
        Upstream RPC for the Anvil fork. If None the orchestrator spawns
        Anvil in pure-EVM mode (no fork). Required for realistic mainnet
        simulation but optional for smoke tests.
    fork_block : int | None
        Block to fork at. Defaults to the ``block_number`` carried on the
        first sequence in the report (set by Phase 4's state fetcher).
    chain_id : int
        Chain ID exposed by Anvil. Default 1.
    anvil : AnvilProcess | None
        Inject a pre-built Anvil controller (useful for tests with a mocked
        RPC). If provided the orchestrator does NOT manage its lifecycle.
    fuzzer : EchidnaFuzzer | MedusaFuzzer | None
        Which fuzzer to run. None = skip fuzzing.
    halmos : HalmosChecker | None
        Halmos checker. None = skip symbolic checks.
    skip_simulation_if_anvil_missing : bool
        When True (default), missing anvil binary makes the orchestrator
        return a report full of ``NOT_EXECUTED`` results instead of raising.
    """

    def __init__(
        self,
        *,
        fork_url: Optional[str] = None,
        fork_block: Optional[int] = None,
        chain_id: int = 1,
        anvil: Optional[AnvilProcess] = None,
        executor: Optional[SequenceExecutor] = None,
        fuzzer: Optional[EchidnaFuzzer | MedusaFuzzer] = None,
        halmos: Optional[HalmosChecker] = None,
        skip_simulation_if_anvil_missing: bool = True,
    ) -> None:
        self.fork_url = fork_url
        self.fork_block = fork_block
        self.chain_id = chain_id
        self._user_supplied_anvil = anvil is not None
        self.anvil = anvil
        self.executor = executor
        self.fuzzer = fuzzer
        self.halmos = halmos
        self.skip_simulation_if_anvil_missing = skip_simulation_if_anvil_missing
        self.analyzer = RevertAnalyzer()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def run(
        self,
        sequence_report: SequenceReport,
        invariant_report: Optional[InvariantReport] = None,
    ) -> SimulationReport:
        start = time.monotonic()
        report = SimulationReport(
            protocol_name=sequence_report.protocol_name,
            sequence_report_id=sequence_report.id,
        )

        if not sequence_report.sequences:
            report.analysis_metadata = {"reason": "empty sequence report"}
            return report

        # ---------- Stage 1: simulation ----------
        results = self._run_simulation(sequence_report)
        report.results = results

        # ---------- Stage 2: fuzzing (per batch, not per sequence) ----------
        fuzzer_violations = []
        if self.fuzzer is not None and invariant_report is not None:
            try:
                fuzzer_violations = self.fuzzer.run(
                    invariant_report.invariants,
                    protocol_name=invariant_report.protocol_name,
                )
            except Exception:
                logger.exception("Fuzzer run failed")
                fuzzer_violations = []
            # Distribute violations across all results (they are batch-level).
            for r in results:
                r.fuzzer_violations = list(fuzzer_violations)

        # ---------- Stage 3: Halmos (per batch) ----------
        halmos_summary = HalmosResult.SKIPPED
        if self.halmos is not None and invariant_report is not None:
            try:
                checks = self.halmos.check(invariant_report.invariants)
                halmos_summary = HalmosChecker.summarise(checks)
                for r in results:
                    r.halmos_checks = list(checks)
                    r.halmos_result = halmos_summary
            except Exception:
                logger.exception("Halmos run failed")

        # ---------- Stage 4: aggregate stats ----------
        report.sequences_executed = sum(
            1 for r in results if r.outcome not in (SimulationOutcome.NOT_EXECUTED, SimulationOutcome.SIMULATION_ERROR)
        )
        report.sequences_profitable = sum(1 for r in results if r.is_profitable)
        report.sequences_reverted = sum(1 for r in results if r.reverted)
        report.sequences_skipped = sum(
            1 for r in results if r.outcome == SimulationOutcome.NOT_EXECUTED
        )
        report.total_profit_wei = sum(max(r.profit_wei, 0) for r in results)
        report.total_gas_used = sum(r.gas_used for r in results)

        elapsed = round(time.monotonic() - start, 3)
        report.analysis_metadata = {
            "fork_url_scrubbed": AnvilProcess.scrub_url(self.fork_url) if self.fork_url else "",
            "fork_block": self.fork_block,
            "chain_id": self.chain_id,
            "elapsed_seconds": elapsed,
            "fuzzer_kind": self.fuzzer.kind.value if self.fuzzer else FuzzerKind.NONE.value,
            "fuzzer_violation_count": len(fuzzer_violations),
            "halmos_summary": halmos_summary.value,
            "anvil_attached": self.anvil is not None,
        }
        return report

    # ------------------------------------------------------------------
    # Stage helpers
    # ------------------------------------------------------------------

    def _run_simulation(self, sequence_report: SequenceReport) -> list[SimulationResult]:
        # Resolve fork block: explicit > first sequence's block > None
        fork_block = self.fork_block
        if fork_block is None and sequence_report.sequences:
            fork_block = sequence_report.sequences[0].block_number

        anvil = self.anvil
        owns_anvil = False
        if anvil is None:
            try:
                anvil = AnvilProcess(
                    fork_url=self.fork_url,
                    fork_block=fork_block,
                    chain_id=self.chain_id,
                )
                anvil.start()
                owns_anvil = True
            except AnvilNotAvailable:
                if not self.skip_simulation_if_anvil_missing:
                    raise
                logger.warning(
                    "anvil binary not available — emitting NOT_EXECUTED for %d sequences",
                    len(sequence_report.sequences),
                )
                return [
                    self._not_executed_result(seq, reason="anvil binary not installed")
                    for seq in sequence_report.sequences
                ]

        executor = self.executor or SequenceExecutor(anvil, analyzer=self.analyzer)
        results: list[SimulationResult] = []
        try:
            for seq in sequence_report.sequences:
                result = self._execute_one(executor, seq)
                results.append(result)
        finally:
            if owns_anvil:
                anvil.stop()
        return results

    def _execute_one(
        self,
        executor: SequenceExecutor,
        seq: TransactionSequence,
    ) -> SimulationResult:
        try:
            result = executor.execute(seq)
            result.protocol_name = ""  # filled at report level
            return result
        except Exception as exc:
            logger.exception("executor.execute failed for sequence %s", seq.id)
            return SimulationResult(
                sequence_id=seq.id,
                hypothesis_id=seq.hypothesis_id,
                outcome=SimulationOutcome.SIMULATION_ERROR,
                revert_reason=str(exc),
            )

    @staticmethod
    def _not_executed_result(seq: TransactionSequence, *, reason: str) -> SimulationResult:
        return SimulationResult(
            sequence_id=seq.id,
            hypothesis_id=seq.hypothesis_id,
            outcome=SimulationOutcome.NOT_EXECUTED,
            revert_reason=reason,
        )
