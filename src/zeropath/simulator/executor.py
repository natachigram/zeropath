"""
SequenceExecutor — Phase 5.

Executes one :class:`TransactionSequence` against an Anvil fork and produces
a :class:`SimulationResult`. Coordinates with:

  * :class:`AnvilProcess`     — JSON-RPC + cheat codes
  * :class:`StateTracker`     — balance / storage diffs
  * :class:`RevertAnalyzer`   — revert decoding + mutation hints

The executor is *reproducible by design*: a snapshot is captured before any
step runs so a caller can revert + re-execute with mutated calldata to get
identical baseline state. The spec requires "same block number + same
sequence = same result, always."
"""

from __future__ import annotations

import logging
import time
from typing import Optional, Protocol

from zeropath.sequencer.models import (
    CallerType,
    OnChainStateSnapshot,
    TransactionSequence,
    TxCall,
)
from zeropath.simulator.models import (
    SimulationOutcome,
    SimulationResult,
    StepResult,
)
from zeropath.simulator.revert_analyzer import RevertAnalyzer
from zeropath.simulator.state_tracker import StateTracker

logger = logging.getLogger(__name__)


# Default WETH addresses per chain — used for profit accounting in
# attacker_profit_wei(). Builders can override via attacker_token_balances.
_WETH_BY_CHAIN: dict[int, str] = {
    1:     "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2",
    10:    "0x4200000000000000000000000000000000000006",
    42161: "0x82aF49447D8a07e3bd95BD0d56f35241523fBab1",
    8453:  "0x4200000000000000000000000000000000000006",
    137:   "0x7ceB23fD6bC0adD59E62ac25578270cFf1b9f619",
}


class _RpcLike(Protocol):
    """Subset of AnvilProcess that the executor needs (also enables mocking)."""

    url: str
    chain_id: int

    def block_number(self) -> int: ...
    def get_balance(self, address: str, block: str = "latest") -> int: ...
    def get_storage_at(self, address: str, slot: str, block: str = "latest") -> str: ...
    def eth_call(self, to: str, data_hex: str, block: str = "latest") -> str: ...
    def send_transaction(self, tx: dict) -> str: ...
    def get_transaction_receipt(self, tx_hash: str) -> Optional[dict]: ...
    def impersonate(self, account: str) -> None: ...
    def set_balance(self, account: str, wei: int) -> None: ...
    def snapshot(self) -> str: ...
    def revert_to(self, snap_id: str) -> bool: ...


class SequenceExecutor:
    """Run a TransactionSequence against an Anvil fork."""

    DEFAULT_ATTACKER = "0x000000000000000000000000000000000000C0DE"
    DEFAULT_ATTACKER_ETH = 100 * 10 ** 18  # 100 ETH

    def __init__(
        self,
        rpc: _RpcLike,
        *,
        analyzer: Optional[RevertAnalyzer] = None,
        attacker_address: Optional[str] = None,
        attacker_eth_seed: int = DEFAULT_ATTACKER_ETH,
        default_gas_limit: int = 5_000_000,
    ) -> None:
        self.rpc = rpc
        self.analyzer = analyzer or RevertAnalyzer()
        self.attacker_address = (attacker_address or self.DEFAULT_ATTACKER).lower()
        self.attacker_eth_seed = attacker_eth_seed
        self.default_gas_limit = default_gas_limit

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def execute(self, sequence: TransactionSequence) -> SimulationResult:
        start = time.monotonic()
        result = SimulationResult(
            sequence_id=sequence.id,
            hypothesis_id=sequence.hypothesis_id,
            chain_id=self.rpc.chain_id,
        )

        if not sequence.calls:
            result.outcome = SimulationOutcome.NOT_EXECUTED
            return result

        # ---------- Pre-flight: seed attacker + impersonate ----------
        try:
            self.rpc.impersonate(self.attacker_address)
            self.rpc.set_balance(self.attacker_address, self.attacker_eth_seed)
        except Exception as exc:
            logger.warning("Pre-flight setup failed: %s", exc)
            result.outcome = SimulationOutcome.SIMULATION_ERROR
            result.revert_reason = f"pre-flight setup: {exc}"
            return result

        # ---------- Snapshot before any tx ----------
        try:
            snap_id = self.rpc.snapshot()
        except Exception:
            snap_id = None

        # ---------- Subscribe state tracker ----------
        tracker = StateTracker(self.rpc)
        tracker.track_from_sequence(sequence, attacker=self.attacker_address)
        weth_addr = self._weth_for_chain()
        if weth_addr:
            tracker.track_token_balance(weth_addr, self.attacker_address)
        tracker.snapshot_before()

        # ---------- Run each step ----------
        total_gas = 0
        events: list[dict] = []
        revert_step: Optional[int] = None
        revert_return: Optional[str] = None
        for call in sequence.calls:
            step_result = self._run_step(call)
            result.step_results.append(step_result)
            total_gas += step_result.gas_used
            events.extend(step_result.logs)
            if step_result.status == "reverted":
                revert_step = call.step
                revert_return = step_result.return_data_hex
                break
            if step_result.status == "rpc_error":
                result.outcome = SimulationOutcome.SIMULATION_ERROR
                result.revert_reason = step_result.revert_reason
                break

        # ---------- Snapshot after ----------
        tracker.snapshot_after()

        # ---------- Compose result ----------
        result.gas_used = total_gas
        result.events_emitted = events
        result.block_number = self._safe_block_number()
        result.fork_url = getattr(self.rpc, "url", "")
        if hasattr(self.rpc, "scrub_url") and getattr(self.rpc, "fork_url", None):
            result.fork_url_scrubbed = self.rpc.scrub_url(self.rpc.fork_url)  # type: ignore[arg-type]
        if hasattr(self.rpc, "anvil_version"):
            result.anvil_version = getattr(self.rpc, "anvil_version", "") or ""

        result.balance_diffs = tracker.balance_diffs()
        result.storage_diffs = tracker.storage_diffs()
        result.profit_wei = tracker.attacker_profit_wei(self.attacker_address, weth_addr)

        if revert_step is not None:
            info = self.analyzer.analyse(
                step=revert_step,
                return_data_hex=revert_return,
                call_stack=[c.description for c in sequence.calls[: revert_step]],
            )
            result.revert_info = info
            result.revert_reason = info.reason
            result.revert_call_stack = info.call_stack
            result.outcome = SimulationOutcome.REVERTED
        elif result.outcome != SimulationOutcome.SIMULATION_ERROR:
            result.success = True
            if result.profit_wei > 0:
                result.outcome = SimulationOutcome.PROFITABLE
            else:
                result.outcome = SimulationOutcome.EXECUTED_NO_PROFIT

        # Always populate top-level state_diff dict for spec parity.
        result.state_diff = {
            "balances": [d.model_dump() for d in result.balance_diffs],
            "storage": [d.model_dump() for d in result.storage_diffs],
        }

        # ---------- Restore baseline for the next run ----------
        if snap_id is not None:
            try:
                self.rpc.revert_to(snap_id)
            except Exception as exc:
                logger.debug("evm_revert failed (non-fatal): %s", exc)

        result.elapsed_seconds = round(time.monotonic() - start, 3)
        return result

    # ------------------------------------------------------------------
    # Per-step submission
    # ------------------------------------------------------------------

    def _run_step(self, call: TxCall) -> StepResult:
        sr = StepResult(step=call.step)
        if not call.target_address:
            sr.status = "rpc_error"
            sr.revert_reason = "no concrete target_address on TxCall — not executable"
            return sr
        if not call.calldata_hex and call.function_signature:
            sr.status = "rpc_error"
            sr.revert_reason = "ABI encoding missing — call has signature but no calldata_hex"
            return sr

        tx: dict[str, object] = {
            "from": self._sender_for(call),
            "to": call.target_address,
            "data": call.calldata_hex or "0x",
            "value": hex(call.value_wei),
            "gas": hex(call.estimated_gas or self.default_gas_limit),
        }

        try:
            tx_hash = self.rpc.send_transaction(tx)
        except Exception as exc:
            sr.status = "rpc_error"
            sr.revert_reason = f"send_transaction failed: {exc}"
            return sr

        sr.tx_hash = tx_hash
        try:
            receipt = self.rpc.get_transaction_receipt(tx_hash)
        except Exception as exc:
            sr.status = "rpc_error"
            sr.revert_reason = f"get_transaction_receipt failed: {exc}"
            return sr

        if receipt is None:
            sr.status = "rpc_error"
            sr.revert_reason = "no receipt returned by RPC"
            return sr

        sr.gas_used = int(receipt.get("gasUsed", "0x0"), 16)
        sr.block_number = int(receipt.get("blockNumber", "0x0"), 16)
        sr.logs = receipt.get("logs", []) or []
        status_hex = receipt.get("status", "0x0")
        if status_hex == "0x1":
            sr.status = "success"
        else:
            sr.status = "reverted"
            # Anvil exposes revert reason via debug_traceTransaction in some
            # versions; for the portable path we re-execute as eth_call.
            sr.return_data_hex = self._fetch_revert_reason(tx, sr.block_number)
        return sr

    def _sender_for(self, call: TxCall) -> str:
        if call.caller_type in (CallerType.ATTACKER_EOA, CallerType.ANY_EOA):
            return self.attacker_address
        return self.attacker_address  # attacker contract → same EOA in flat mode

    def _fetch_revert_reason(self, tx: dict, block: int) -> Optional[str]:
        try:
            data = self.rpc.eth_call(
                tx["to"],
                tx["data"],
                hex(max(block - 1, 0)) if block > 0 else "latest",
            )
            return data
        except Exception as exc:
            # RPC's eth_call surfaces the revert payload in the error message.
            return f"0x{str(exc).encode().hex()}"

    def _weth_for_chain(self) -> Optional[str]:
        return _WETH_BY_CHAIN.get(self.rpc.chain_id)

    def _safe_block_number(self) -> int:
        try:
            return self.rpc.block_number()
        except Exception:
            return 0
