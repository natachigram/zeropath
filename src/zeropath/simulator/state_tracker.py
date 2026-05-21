"""
Balance / storage state tracker — Phase 5.

Captures pre/post deltas around a sequence execution so Phase 6 can compute
profit and Phase 7 can reward novel state coverage.

Tracking is best-effort: balances we always sample, storage slots only when
the builder marked them in ``TxCall.expected_state_change`` so we don't pay
RPC cost for slots no one cares about.
"""

from __future__ import annotations

import logging
from typing import Iterable, Optional, Protocol

from zeropath.sequencer.abi_encoder import encode_call
from zeropath.simulator.models import BalanceDiff, StorageDiff

logger = logging.getLogger(__name__)


class _RpcLike(Protocol):
    """Minimal interface the tracker needs — implemented by AnvilProcess and tests."""

    def get_balance(self, address: str, block: str = "latest") -> int: ...
    def get_storage_at(self, address: str, slot: str, block: str = "latest") -> str: ...
    def eth_call(self, to: str, data_hex: str, block: str = "latest") -> str: ...


class StateTracker:
    """
    Sample balances + storage before and after a sequence runs.

    Usage::

        tracker = StateTracker(anvil)
        tracker.track_eth_balance(attacker)
        tracker.track_token_balance(WETH, attacker)
        tracker.snapshot_before()
        ... execute sequence ...
        tracker.snapshot_after()
        diffs = tracker.balance_diffs()
    """

    ETH = "ETH"

    def __init__(self, rpc: _RpcLike) -> None:
        self._rpc = rpc
        self._eth_targets: set[str] = set()
        self._token_targets: set[tuple[str, str]] = set()  # (token, holder)
        self._storage_targets: set[tuple[str, str]] = set()
        self._pre_eth: dict[str, int] = {}
        self._pre_token: dict[tuple[str, str], int] = {}
        self._pre_storage: dict[tuple[str, str], str] = {}
        self._post_eth: dict[str, int] = {}
        self._post_token: dict[tuple[str, str], int] = {}
        self._post_storage: dict[tuple[str, str], str] = {}

    # ------------------------------------------------------------------
    # Subscription API
    # ------------------------------------------------------------------

    def track_eth_balance(self, address: str) -> None:
        self._eth_targets.add(address.lower())

    def track_token_balance(self, token: str, holder: str) -> None:
        self._token_targets.add((token.lower(), holder.lower()))

    def track_storage_slot(self, contract: str, slot: str) -> None:
        self._storage_targets.add((contract.lower(), slot.lower()))

    def track_from_sequence(self, sequence, attacker: Optional[str] = None) -> None:
        """
        Bulk-subscribe targets relevant to a TransactionSequence.

        Always tracks the attacker's ETH balance. Adds token tracking for any
        ERC-20 contract referenced in the sequence's ``contract_addresses``,
        plus any explicit ``expected_state_change`` storage slots.
        """
        attacker = attacker or sequence.context.attacker_address
        if attacker and attacker.startswith("0x"):
            self.track_eth_balance(attacker)
            for tok_name, tok_addr in (sequence.context.contract_addresses or {}).items():
                if isinstance(tok_addr, str) and tok_addr.startswith("0x"):
                    self.track_token_balance(tok_addr, attacker)
        for call in sequence.calls or []:
            for key, _ in (call.expected_state_change or {}).items():
                if ":" in key and call.target_address:
                    # Convention: "storage:0x..slot"
                    _, slot = key.split(":", 1)
                    self.track_storage_slot(call.target_address, slot)

    # ------------------------------------------------------------------
    # Snapshots
    # ------------------------------------------------------------------

    def snapshot_before(self, block: str = "latest") -> None:
        self._pre_eth = {a: self._safe_eth(a, block) for a in self._eth_targets}
        self._pre_token = {
            (t, h): self._safe_token(t, h, block) for (t, h) in self._token_targets
        }
        self._pre_storage = {
            (c, s): self._safe_storage(c, s, block) for (c, s) in self._storage_targets
        }

    def snapshot_after(self, block: str = "latest") -> None:
        self._post_eth = {a: self._safe_eth(a, block) for a in self._eth_targets}
        self._post_token = {
            (t, h): self._safe_token(t, h, block) for (t, h) in self._token_targets
        }
        self._post_storage = {
            (c, s): self._safe_storage(c, s, block) for (c, s) in self._storage_targets
        }

    # ------------------------------------------------------------------
    # Diffs
    # ------------------------------------------------------------------

    def balance_diffs(self) -> list[BalanceDiff]:
        out: list[BalanceDiff] = []
        for addr in self._eth_targets:
            out.append(BalanceDiff(
                account=addr,
                asset=self.ETH,
                before=self._pre_eth.get(addr, 0),
                after=self._post_eth.get(addr, 0),
            ))
        for token, holder in self._token_targets:
            out.append(BalanceDiff(
                account=holder,
                asset=token,
                before=self._pre_token.get((token, holder), 0),
                after=self._post_token.get((token, holder), 0),
            ))
        return out

    def storage_diffs(self) -> list[StorageDiff]:
        out: list[StorageDiff] = []
        for contract, slot in self._storage_targets:
            before = self._pre_storage.get((contract, slot), "0x" + "00" * 32)
            after = self._post_storage.get((contract, slot), "0x" + "00" * 32)
            if before != after:
                out.append(StorageDiff(contract=contract, slot=slot, before=before, after=after))
        return out

    def attacker_profit_wei(self, attacker: str, weth_address: Optional[str] = None) -> int:
        """
        Profit accounting:

          * ETH delta on the attacker account
          * Plus WETH delta (since WETH ≈ ETH for profit purposes)

        Other token gains are *not* counted here — Phase 6 prices those.
        """
        attacker = attacker.lower()
        eth_delta = self._post_eth.get(attacker, 0) - self._pre_eth.get(attacker, 0)
        weth_delta = 0
        if weth_address:
            key = (weth_address.lower(), attacker)
            weth_delta = self._post_token.get(key, 0) - self._pre_token.get(key, 0)
        return eth_delta + weth_delta

    # ------------------------------------------------------------------
    # Safe RPC wrappers
    # ------------------------------------------------------------------

    def _safe_eth(self, addr: str, block: str) -> int:
        try:
            return self._rpc.get_balance(addr, block)
        except Exception as exc:
            logger.debug("eth_getBalance(%s) failed: %s", addr, exc)
            return 0

    def _safe_storage(self, addr: str, slot: str, block: str) -> str:
        try:
            return self._rpc.get_storage_at(addr, slot, block)
        except Exception as exc:
            logger.debug("eth_getStorageAt(%s,%s) failed: %s", addr, slot, exc)
            return "0x" + "00" * 32

    def _safe_token(self, token: str, holder: str, block: str) -> int:
        try:
            data = encode_call("balanceOf(address)", [holder])
            result = self._rpc.eth_call(token, "0x" + data.hex(), block)
            if not result or result == "0x":
                return 0
            return int(result, 16)
        except Exception as exc:
            logger.debug("balanceOf(%s,%s) failed: %s", token, holder, exc)
            return 0
