"""
Phase 5 test suite — EVM Simulation Engine.

Coverage:
  - RevertAnalyzer: Error(string), Panic, custom selectors, mutation hints
  - StateTracker: balance/storage diff, profit accounting
  - SequenceExecutor (FakeRpc): success / revert / rpc_error step classification
  - EchidnaFuzzer / MedusaFuzzer: graceful degradation when binary absent,
    parse-only test with sample stdout
  - HalmosChecker: skip-when-absent path, parser with sample stdout, summarise
  - SimulationOrchestrator: end-to-end with FakeRpc-backed executor + missing
    fuzzer + missing halmos
  - Pydantic models: enums, predicates, sub-model defaults

No network or external binaries required.
"""

from __future__ import annotations

import json
from typing import Any, Optional
from uuid import uuid4

import pytest

from zeropath.adversarial.models import AttackHypothesis as _Hyp, AttackStep
from zeropath.invariants.models import (
    FormalSpec,
    Invariant,
    InvariantReport,
    InvariantSeverity,
    InvariantType,
    DeFiProtocolType,
    ProtocolPattern,
)
from zeropath.sequencer.abi_encoder import ABIEncoder
from zeropath.sequencer.models import (
    AttackContext,
    CallerType,
    ProfitEstimate,
    SequenceReport,
    TransactionSequence,
    TxCall,
)
from zeropath.simulator import (
    AnvilNotAvailable,
    EchidnaFuzzer,
    FuzzerKind,
    HalmosCheck,
    HalmosChecker,
    HalmosResult,
    MedusaFuzzer,
    RevertAnalyzer,
    SequenceExecutor,
    SimulationOrchestrator,
    SimulationOutcome,
    SimulationReport,
    SimulationResult,
    StateTracker,
    decode_revert,
    suggest_mutation,
)


# ===========================================================================
# Fake RPC — speaks the AnvilProcess protocol used by Executor + StateTracker
# ===========================================================================


class FakeRpc:
    """
    In-memory stand-in for AnvilProcess.

    Scriptable: tests pre-load ``step_outcomes`` and ``balances`` then call
    ``executor.execute(seq)``. No subprocess, no JSON-RPC, deterministic.
    """

    def __init__(
        self,
        *,
        chain_id: int = 1,
        balances: Optional[dict[str, int]] = None,
        token_balances: Optional[dict[tuple[str, str], int]] = None,
        step_outcomes: Optional[list[dict[str, Any]]] = None,
        block_number_value: int = 18_000_000,
    ) -> None:
        self.url = "http://127.0.0.1:8545"
        self.chain_id = chain_id
        self.fork_url = self.url
        self.anvil_version = "anvil/fake/0.0.0"
        self._balances = dict(balances or {})
        self._token_balances = dict(token_balances or {})
        self._step_outcomes = list(step_outcomes or [])
        self._step_idx = 0
        self._block_number = block_number_value
        # Call recorders
        self.impersonated: list[str] = []
        self.balance_sets: list[tuple[str, int]] = []
        self.txs_sent: list[dict[str, Any]] = []
        self._snap_counter = 0
        self._reverts: list[str] = []

    # --- AnvilProcess interface ---------------------------------------

    def block_number(self) -> int:
        return self._block_number

    def get_balance(self, address: str, block: str = "latest") -> int:
        return self._balances.get(address.lower(), 0)

    def get_storage_at(self, address: str, slot: str, block: str = "latest") -> str:
        return "0x" + "00" * 32

    def eth_call(self, to: str, data_hex: str, block: str = "latest") -> str:
        # balanceOf(address) → return scripted token balance
        if data_hex.startswith("0x70a08231"):
            holder = "0x" + data_hex[34:].lower()  # last 20 bytes
            bal = self._token_balances.get((to.lower(), holder.lower()), 0)
            return "0x" + bal.to_bytes(32, "big").hex()
        return "0x"

    def send_transaction(self, tx: dict) -> str:
        self.txs_sent.append(tx)
        return f"0x{len(self.txs_sent):064x}"

    def get_transaction_receipt(self, tx_hash: str) -> dict:
        idx = self._step_idx
        self._step_idx += 1
        if idx < len(self._step_outcomes):
            outcome = dict(self._step_outcomes[idx])
        else:
            outcome = {"status": "success", "gas_used": 100_000, "logs": []}

        receipt: dict[str, Any] = {
            "transactionHash": tx_hash,
            "blockNumber": hex(self._block_number),
            "gasUsed": hex(outcome.get("gas_used", 100_000)),
            "logs": outcome.get("logs", []),
            "status": "0x1" if outcome.get("status") == "success" else "0x0",
        }
        # Apply state mutations declared on the outcome
        for addr, new_bal in (outcome.get("set_eth_balance") or {}).items():
            self._balances[addr.lower()] = new_bal
        for (tok, holder), new_bal in (outcome.get("set_token_balance") or {}).items():
            self._token_balances[(tok.lower(), holder.lower())] = new_bal
        return receipt

    def impersonate(self, account: str) -> None:
        self.impersonated.append(account.lower())

    def stop_impersonate(self, account: str) -> None:
        pass

    def set_balance(self, account: str, wei: int) -> None:
        self._balances[account.lower()] = wei
        self.balance_sets.append((account.lower(), wei))

    def set_code(self, account: str, code_hex: str) -> None:
        pass

    def set_storage_at(self, account: str, slot: str, value: str) -> None:
        pass

    def snapshot(self) -> str:
        self._snap_counter += 1
        return f"0x{self._snap_counter:x}"

    def revert_to(self, snap_id: str) -> bool:
        self._reverts.append(snap_id)
        return True

    def mine(self, count: int = 1) -> None:
        self._block_number += count

    @staticmethod
    def scrub_url(url: str) -> str:
        return url


# ===========================================================================
# Helpers
# ===========================================================================


_NO_CALLS = object()


def _mk_seq(calls=_NO_CALLS, **kw) -> TransactionSequence:
    ctx = AttackContext(chain="mainnet")
    if calls is _NO_CALLS:
        calls = [
            TxCall(
                step=1, description="approve",
                target_address_expr="WETH",
                target_address="0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2",
                function_signature="approve(address,uint256)",
                params=["0x000000000000000000000000000000000000dEaD", 1000],
                param_types=["address", "uint256"],
            ),
            TxCall(
                step=2, description="transfer",
                target_address_expr="WETH",
                target_address="0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2",
                function_signature="transfer(address,uint256)",
                params=["0x000000000000000000000000000000000000dEaD", 1000],
                param_types=["address", "uint256"],
            ),
        ]
    return TransactionSequence(
        hypothesis_id=str(uuid4()),
        hypothesis_title="t",
        attack_class="flash_loan",
        calls=calls,
        context=ctx,
        profit_estimate=ProfitEstimate(
            asset="WETH",
            min_profit_expression="1e16",
            max_profit_expression="1e21",
            cost_expression="(flashAmount * 9) / 10000",
        ),
        **kw,
    )


def _mk_seq_with_encoding() -> TransactionSequence:
    seq = _mk_seq()
    ABIEncoder().encode_sequence(seq)
    return seq


# ===========================================================================
# RevertAnalyzer
# ===========================================================================


class TestRevertDecoder:
    def test_no_data(self):
        assert "no reason" in decode_revert(None)
        assert "no reason" in decode_revert("0x")

    def test_error_string_decoded(self):
        # ABI-encode Error("AAA"): selector + offset(32) + length(3) + "AAA"<<padding
        payload = (
            "08c379a0"
            + (32).to_bytes(32, "big").hex()
            + (3).to_bytes(32, "big").hex()
            + b"AAA".hex()
            + "00" * 29
        )
        assert decode_revert("0x" + payload) == "AAA"

    def test_panic_arithmetic(self):
        payload = "0x4e487b71" + (0x11).to_bytes(32, "big").hex()
        msg = decode_revert(payload)
        assert "Panic(0x11)" in msg and "arithmetic" in msg

    def test_panic_unknown_code(self):
        payload = "0x4e487b71" + (0xff).to_bytes(32, "big").hex()
        assert "Panic(0xff)" in decode_revert(payload)

    def test_custom_error_selector_known(self):
        from zeropath.sequencer.abi_encoder import function_selector
        sel = "0x" + function_selector("ReentrancyGuardReentrantCall()").hex()
        assert "reentrancy" in decode_revert(sel).lower()

    def test_custom_error_unknown_selector(self):
        result = decode_revert("0xdeadbeef")
        assert "selector" in result and "deadbeef" in result


class TestSuggestMutation:
    @pytest.mark.parametrize(
        "reason,keyword",
        [
            ("ERC20: insufficient allowance", "approve()"),
            ("ERC20 insufficient balance (OZ v5)", "flash-loan"),
            ("slippage tolerance exceeded", "scale_amount_10x"),
            ("ReentrancyGuard: reentrant call", "reorder_inner_steps"),
            ("Pausable: paused", "infeasible"),
            ("Ownable: caller is not the owner", "AccessControlAgent"),
        ],
    )
    def test_known_reasons_map_to_hints(self, reason, keyword):
        hint = suggest_mutation(reason)
        assert hint is not None
        assert keyword.lower() in hint.lower()

    def test_unknown_reason_returns_none(self):
        assert suggest_mutation("something totally exotic") is None


class TestRevertAnalyzer:
    def test_produces_revert_info(self):
        analyzer = RevertAnalyzer()
        # Encode "boom"
        payload = (
            "0x08c379a0"
            + (32).to_bytes(32, "big").hex()
            + (4).to_bytes(32, "big").hex()
            + b"boom".hex()
            + "00" * 28
        )
        info = analyzer.analyse(step=3, return_data_hex=payload, call_stack=["a", "b", "c"])
        assert info.step == 3
        assert info.reason == "boom"
        assert info.call_stack == ["a", "b", "c"]


# ===========================================================================
# StateTracker
# ===========================================================================


class TestStateTracker:
    def test_balance_diff_eth(self):
        rpc = FakeRpc(balances={"0xabc": 100, "0xdef": 0})
        t = StateTracker(rpc)
        t.track_eth_balance("0xabc")
        t.snapshot_before()
        rpc._balances["0xabc"] = 250
        t.snapshot_after()
        diffs = t.balance_diffs()
        assert len(diffs) == 1
        assert diffs[0].delta == 150

    def test_balance_diff_token(self):
        token = "0x000000000000000000000000000000000000aaaa"
        holder = "0x000000000000000000000000000000000000bbbb"
        rpc = FakeRpc(token_balances={(token, holder): 1000})
        t = StateTracker(rpc)
        t.track_token_balance(token, holder)
        t.snapshot_before()
        rpc._token_balances[(token, holder)] = 5000
        t.snapshot_after()
        diffs = t.balance_diffs()
        assert any(d.asset == token and d.delta == 4000 for d in diffs)

    def test_attacker_profit_includes_weth(self):
        weth = "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2".lower()
        attacker = "0x000000000000000000000000000000000000c0de"
        rpc = FakeRpc(
            balances={attacker: 0},
            token_balances={(weth, attacker): 0},
        )
        t = StateTracker(rpc)
        t.track_eth_balance(attacker)
        t.track_token_balance(weth, attacker)
        t.snapshot_before()
        rpc._balances[attacker] = 10**18      # +1 ETH
        rpc._token_balances[(weth, attacker)] = 2 * 10**18  # +2 WETH
        t.snapshot_after()
        assert t.attacker_profit_wei(attacker, weth) == 3 * 10**18

    def test_storage_diff_only_records_changed(self):
        rpc = FakeRpc()
        t = StateTracker(rpc)
        t.track_storage_slot("0xc", "0x1")
        t.snapshot_before()
        t.snapshot_after()  # nothing changed → empty
        assert t.storage_diffs() == []


# ===========================================================================
# SequenceExecutor (FakeRpc-backed)
# ===========================================================================


class TestSequenceExecutor:
    def test_successful_sequence(self):
        attacker = SequenceExecutor.DEFAULT_ATTACKER.lower()
        rpc = FakeRpc(
            balances={attacker: 100 * 10**18},
            step_outcomes=[
                {"status": "success", "gas_used": 55_000, "logs": []},
                {"status": "success", "gas_used": 65_000, "logs": [{"a": "log"}],
                 "set_token_balance": {(
                     "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2", attacker): 5 * 10**18}},
            ],
        )
        executor = SequenceExecutor(rpc)
        seq = _mk_seq_with_encoding()
        result = executor.execute(seq)

        assert result.success is True
        assert result.outcome == SimulationOutcome.PROFITABLE
        assert result.gas_used == 120_000
        assert result.profit_wei == 5 * 10**18  # WETH delta
        assert len(result.step_results) == 2
        assert all(s.status == "success" for s in result.step_results)
        assert result.events_emitted == [{"a": "log"}]
        # Reproducibility: executor snapshots once at start and reverts at end.
        assert len(rpc._reverts) == 1
        # Attacker funded via cheat code.
        assert (attacker, SequenceExecutor.DEFAULT_ATTACKER_ETH) in rpc.balance_sets
        assert attacker in rpc.impersonated

    def test_revert_short_circuits(self):
        # Step 2 reverts → step 3 not submitted; revert_info populated.
        attacker = SequenceExecutor.DEFAULT_ATTACKER.lower()
        rpc = FakeRpc(
            balances={attacker: 100 * 10**18},
            step_outcomes=[
                {"status": "success", "gas_used": 55_000},
                {"status": "reverted", "gas_used": 30_000},
            ],
        )
        seq = _mk_seq_with_encoding()
        result = SequenceExecutor(rpc).execute(seq)
        assert result.outcome == SimulationOutcome.REVERTED
        assert result.revert_info is not None
        assert result.revert_info.step == 2
        # Only 2 txs were submitted (the second one reverted)
        assert len(rpc.txs_sent) == 2

    def test_unencoded_call_classified_as_rpc_error(self):
        rpc = FakeRpc()
        seq = _mk_seq()  # not encoded → calldata_hex is None
        result = SequenceExecutor(rpc).execute(seq)
        # First step has signature but no calldata_hex → step error
        assert result.step_results[0].status == "rpc_error"
        assert "ABI encoding missing" in (result.step_results[0].revert_reason or "")

    def test_no_target_address(self):
        rpc = FakeRpc()
        seq = _mk_seq(calls=[TxCall(
            step=1, description="nowhere",
            target_address_expr="X",
            function_signature="foo()",
        )])
        result = SequenceExecutor(rpc).execute(seq)
        assert result.step_results[0].status == "rpc_error"

    def test_no_calls(self):
        rpc = FakeRpc()
        seq = _mk_seq(calls=[])
        result = SequenceExecutor(rpc).execute(seq)
        assert result.outcome == SimulationOutcome.NOT_EXECUTED


# ===========================================================================
# Fuzzers
# ===========================================================================


class TestEchidnaFuzzer:
    def test_unavailable_skips_silently(self, monkeypatch):
        monkeypatch.setattr("shutil.which", lambda _: None)
        result = EchidnaFuzzer().run(
            invariants=[_dummy_inv()],
            protocol_name="X",
        )
        assert result == []

    def test_parser_extracts_failures(self):
        # No subprocess: invoke the parser directly with sample stdout.
        # Property name format is built by _safe_property_name() so we mirror it.
        inv = _dummy_inv()
        prop = f"echidna_{inv.type.value}_0"
        stdout = (
            f"{prop}: failed!\n"
            "Call sequence, shrunk (12 transactions):\n"
            "  1. doStuff(uint256 5)\n"
            "  2. transfer(address 0xabc, uint256 100)\n"
            "echidna_other: passing\n"
        )
        violations = EchidnaFuzzer()._parse(stdout, [inv])
        assert len(violations) == 1
        v = violations[0]
        assert v.fuzzer == FuzzerKind.ECHIDNA
        assert v.invariant_id == inv.id
        assert "doStuff" in v.counter_example_calls[0]


class TestMedusaFuzzer:
    def test_unavailable_skips_silently(self, monkeypatch):
        monkeypatch.setattr("shutil.which", lambda _: None)
        result = MedusaFuzzer().run(invariants=[], protocol_name="X")
        assert result == []

    def test_parser_extracts_failures(self):
        inv = _dummy_inv()
        prop = f"echidna_{inv.type.value}_0"
        stdout = f"[FAILED] {prop}\n  reverted with: bad math"
        violations = MedusaFuzzer()._parse(stdout, [inv])
        assert len(violations) == 1
        assert violations[0].fuzzer == FuzzerKind.MEDUSA
        assert violations[0].invariant_id == inv.id


# ===========================================================================
# Halmos
# ===========================================================================


class TestHalmosChecker:
    def test_no_eligible_invariants_returns_empty(self):
        result = HalmosChecker().check([_dummy_inv()])  # no formal_spec
        assert result == []

    def test_unavailable_emits_skipped(self, monkeypatch):
        monkeypatch.setattr("shutil.which", lambda _: None)
        inv = _dummy_inv_with_spec("x > 0")
        result = HalmosChecker().check([inv])
        assert len(result) == 1
        assert result[0].result == HalmosResult.SKIPPED

    def test_parser_classifies(self):
        inv1 = _dummy_inv_with_spec("x > 0")
        inv2 = _dummy_inv_with_spec("x < 100", inv_type=InvariantType.REENTRANCY)
        stdout = (
            "[PASS] check_oracle_manipulation_0\n"
            "[FAIL] check_reentrancy_1\n"
            "Counterexample:\n  x = 0xdead\n\n"
        )
        results = HalmosChecker()._parse(stdout, [inv1, inv2], elapsed=1.2)
        by_id = {r.invariant_id: r for r in results}
        assert by_id[inv1.id].result == HalmosResult.PROVED
        assert by_id[inv2.id].result == HalmosResult.FALSIFIED
        assert by_id[inv2.id].counter_example is not None

    def test_summarise(self):
        c1 = HalmosCheck(invariant_id="a", formal_spec="x", result=HalmosResult.PROVED)
        c2 = HalmosCheck(invariant_id="b", formal_spec="x", result=HalmosResult.FALSIFIED)
        c3 = HalmosCheck(invariant_id="c", formal_spec="x", result=HalmosResult.UNKNOWN)
        assert HalmosChecker.summarise([]) == HalmosResult.SKIPPED
        assert HalmosChecker.summarise([c1]) == HalmosResult.PROVED
        assert HalmosChecker.summarise([c1, c3]) == HalmosResult.UNKNOWN
        assert HalmosChecker.summarise([c1, c2, c3]) == HalmosResult.FALSIFIED
        assert HalmosChecker.summarise([
            HalmosCheck(invariant_id="d", formal_spec="x", result=HalmosResult.SKIPPED)
        ]) == HalmosResult.SKIPPED


# ===========================================================================
# Orchestrator end-to-end
# ===========================================================================


def _dummy_inv(inv_type: InvariantType = InvariantType.ORACLE_MANIPULATION) -> Invariant:
    return Invariant(
        type=inv_type,
        severity=InvariantSeverity.HIGH,
        description="test inv",
        confidence=0.7,
    )


def _dummy_inv_with_spec(
    spec: str,
    inv_type: InvariantType = InvariantType.ORACLE_MANIPULATION,
) -> Invariant:
    inv = _dummy_inv(inv_type)
    inv.formal_spec = FormalSpec(halmos=spec, natural_language="test")
    return inv


def _mk_seq_report() -> SequenceReport:
    seqs = [_mk_seq_with_encoding() for _ in range(2)]
    for s in seqs:
        s.block_number = 18_500_000
    return SequenceReport(
        protocol_name="TestProtocol",
        sequences=seqs,
        total_hypotheses_input=2,
        sequences_generated=2,
    )


def _mk_inv_report() -> InvariantReport:
    pattern = ProtocolPattern(
        protocol_types=[DeFiProtocolType.LENDING],
        has_oracle=True,
        borrow_functions=["borrow"],
    )
    return InvariantReport(
        protocol_name="TestProtocol",
        protocol_pattern=pattern,
        invariants=[_dummy_inv_with_spec("balance >= 0")],
    )


class TestOrchestrator:
    def test_anvil_missing_returns_not_executed(self, monkeypatch):
        """When anvil binary is absent, every sequence becomes NOT_EXECUTED."""
        monkeypatch.setattr("shutil.which", lambda binary: None)
        orch = SimulationOrchestrator(skip_simulation_if_anvil_missing=True)
        report = orch.run(_mk_seq_report(), _mk_inv_report())
        assert isinstance(report, SimulationReport)
        assert all(r.outcome == SimulationOutcome.NOT_EXECUTED for r in report.results)
        assert report.sequences_skipped == 2

    def test_anvil_missing_strict_raises(self, monkeypatch):
        monkeypatch.setattr("shutil.which", lambda binary: None)
        orch = SimulationOrchestrator(skip_simulation_if_anvil_missing=False)
        with pytest.raises(AnvilNotAvailable):
            orch.run(_mk_seq_report(), _mk_inv_report())

    def test_end_to_end_with_fake_anvil(self):
        """Inject FakeRpc as the anvil to exercise the full pipeline offline."""
        attacker = SequenceExecutor.DEFAULT_ATTACKER.lower()
        weth = "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2"
        # Each seq has 2 calls; provide 4 success outcomes (2 per seq).
        rpc = FakeRpc(
            balances={attacker: 100 * 10**18},
            step_outcomes=[{"status": "success", "gas_used": 50_000}] * 4 + [
                # Last seq's second call adds WETH so profit > 0
            ],
        )
        # Inject the fake "anvil" plus a matching executor.
        executor = SequenceExecutor(rpc)
        orch = SimulationOrchestrator(anvil=rpc, executor=executor)
        report = orch.run(_mk_seq_report(), _mk_inv_report())
        assert report.sequences_executed == 2
        assert all(r.outcome == SimulationOutcome.EXECUTED_NO_PROFIT for r in report.results)
        assert report.total_gas_used == 4 * 50_000
        # Halmos/fuzzer were not configured → summary = skipped, no violations.
        assert report.analysis_metadata["halmos_summary"] == HalmosResult.SKIPPED.value
        assert report.analysis_metadata["fuzzer_kind"] == FuzzerKind.NONE.value

    def test_revert_propagates_to_simulation_report(self):
        attacker = SequenceExecutor.DEFAULT_ATTACKER.lower()
        rpc = FakeRpc(
            balances={attacker: 100 * 10**18},
            step_outcomes=[
                {"status": "success", "gas_used": 50_000},
                {"status": "reverted", "gas_used": 30_000},
                {"status": "success", "gas_used": 50_000},
                {"status": "success", "gas_used": 50_000},
            ],
        )
        orch = SimulationOrchestrator(anvil=rpc, executor=SequenceExecutor(rpc))
        report = orch.run(_mk_seq_report(), _mk_inv_report())
        # First seq reverted; second succeeded.
        assert report.sequences_reverted == 1

    def test_empty_sequence_report(self):
        rpc = FakeRpc()
        orch = SimulationOrchestrator(anvil=rpc, executor=SequenceExecutor(rpc))
        empty = SequenceReport(protocol_name="X", sequences=[])
        report = orch.run(empty, _mk_inv_report())
        assert report.results == []

    def test_orchestrator_skips_halmos_when_not_configured(self):
        rpc = FakeRpc()
        orch = SimulationOrchestrator(anvil=rpc, executor=SequenceExecutor(rpc), halmos=None)
        report = orch.run(_mk_seq_report(), _mk_inv_report())
        # No halmos → metadata shows skipped.
        assert report.analysis_metadata["halmos_summary"] == HalmosResult.SKIPPED.value


# ===========================================================================
# Models — output shape conformance vs spec
# ===========================================================================


class TestSimulationResultShape:
    """Spec (phases.md PHASE 5) lists the exact required JSON keys."""

    SPEC_KEYS = {
        "success", "profit_wei", "profit_usd", "state_diff", "events_emitted",
        "gas_used", "revert_reason", "revert_call_stack", "fuzzer_violations",
        "halmos_result", "block_number", "fork_url",
    }

    def test_all_spec_keys_present_in_default_result(self):
        r = SimulationResult(sequence_id="x")
        dumped = r.model_dump()
        assert self.SPEC_KEYS.issubset(dumped.keys())

    def test_halmos_result_enum_serialises_as_spec_value(self):
        r = SimulationResult(sequence_id="x", halmos_result=HalmosResult.PROVED)
        dumped = r.model_dump(mode="json")
        assert dumped["halmos_result"] in {"proved", "falsified", "unknown", "skipped"}

    def test_is_profitable_predicate(self):
        r = SimulationResult(sequence_id="x", success=True, profit_wei=10**18)
        assert r.is_profitable is True
        r2 = SimulationResult(sequence_id="x", success=True, profit_wei=0)
        assert r2.is_profitable is False

    def test_reverted_predicate(self):
        r = SimulationResult(sequence_id="x", outcome=SimulationOutcome.REVERTED)
        assert r.reverted is True

    def test_round_trip_json(self):
        r = SimulationResult(
            sequence_id="x", success=True, profit_wei=42, gas_used=21_000,
            halmos_result=HalmosResult.PROVED,
        )
        s = r.model_dump_json()
        roundtrip = SimulationResult.model_validate_json(s)
        assert roundtrip.profit_wei == 42
        assert roundtrip.halmos_result == HalmosResult.PROVED
