"""
Tests for Phase 2: Invariant Inference Engine.

Covers:
  - Exploit database
  - RAG retrieval
  - Formal spec generation
  - Individual detectors (all 11)
  - Engine orchestration + deduplication
  - CLI infer command (smoke test)
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Optional
from uuid import uuid4

import pytest

from zeropath.invariants.exploit_db import (
    EXPLOIT_DB,
    get_high_value_precedents,
    get_precedents_for_type,
)
from zeropath.invariants.formal_spec import FormalSpecGenerator
from zeropath.invariants.models import (
    DeFiProtocolType,
    FormalSpec,
    HistoricalPrecedent,
    Invariant,
    InvariantReport,
    InvariantSeverity,
    InvariantType,
    OracleDependency,
    OracleManipulationRisk,
    OracleType,
    ProtocolPattern,
)
from zeropath.invariants.rag import ExploitRAG, get_rag
from zeropath.models import (
    AccessControl,
    AssetFlow,
    CallType,
    Contract,
    ContractLanguage,
    ExternalDependency,
    Function,
    FunctionCall,
    FunctionSignature,
    ProxyType,
    StateVariable,
    StateVariableType,
    Visibility,
    ProtocolGraph,
)


# ---------------------------------------------------------------------------
# Helpers: build minimal ProtocolGraph fixtures
# ---------------------------------------------------------------------------

def _contract(name: str = "MyContract") -> Contract:
    return Contract(
        id=str(uuid4()),
        name=name,
        language=ContractLanguage.SOLIDITY,
        file_path="MyContract.sol",
        proxy_type=ProxyType.NONE,
    )


def _func(
    name: str,
    contract_id: str,
    visibility: Visibility = Visibility.PUBLIC,
    is_view: bool = False,
    is_pure: bool = False,
    is_payable: bool = False,
    modifiers: Optional[list[str]] = None,
    state_vars_written: Optional[list[str]] = None,
    state_vars_read: Optional[list[str]] = None,
) -> Function:
    return Function(
        id=str(uuid4()),
        name=name,
        contract_id=contract_id,
        visibility=visibility,
        signature=FunctionSignature(name=name),
        is_view=is_view,
        is_pure=is_pure,
        is_payable=is_payable,
        modifiers=modifiers or [],
        state_vars_written=state_vars_written or [],
        state_vars_read=state_vars_read or [],
        access_control=AccessControl(),
    )


def _state_var(
    name: str,
    type_: str,
    contract_id: str,
    visibility: Visibility = Visibility.PRIVATE,
) -> StateVariable:
    return StateVariable(
        id=str(uuid4()),
        name=name,
        type=type_,
        contract_id=contract_id,
        visibility=visibility,
        type_category=StateVariableType.PRIMITIVE,
    )


def _call(
    caller_id: str,
    callee_name: str,
    call_type: CallType = CallType.EXTERNAL,
    callee_contract: Optional[str] = None,
    value_transfer: bool = False,
) -> FunctionCall:
    return FunctionCall(
        id=str(uuid4()),
        caller_id=caller_id,
        callee_name=callee_name,
        call_type=call_type,
        callee_contract=callee_contract,
        value_transfer=value_transfer,
    )


def _ext_dep(name: str, interface: Optional[str] = None, call_sites: Optional[list[str]] = None) -> ExternalDependency:
    return ExternalDependency(
        id=str(uuid4()),
        name=name,
        interface=interface,
        call_sites=call_sites or [],
    )


def _empty_graph() -> ProtocolGraph:
    return ProtocolGraph(contracts=[], functions=[], state_variables=[])


# ---------------------------------------------------------------------------
# Exploit database tests
# ---------------------------------------------------------------------------


class TestExploitDB:
    def test_has_enough_entries(self):
        assert len(EXPLOIT_DB) >= 30

    def test_all_entries_have_required_fields(self):
        for entry in EXPLOIT_DB:
            assert entry.protocol
            assert entry.date
            assert entry.invariant_type
            assert entry.loss_usd >= 0
            assert entry.root_cause

    def test_get_precedents_for_type(self):
        oracle = get_precedents_for_type(InvariantType.ORACLE_MANIPULATION)
        assert len(oracle) >= 3
        assert all(e.invariant_type == InvariantType.ORACLE_MANIPULATION for e in oracle)

    def test_get_high_value_precedents(self):
        hits = get_high_value_precedents(InvariantType.ORACLE_MANIPULATION, min_loss_usd=10_000_000)
        assert all(e.loss_usd >= 10_000_000 for e in hits)
        # Should be sorted by loss descending
        if len(hits) >= 2:
            assert hits[0].loss_usd >= hits[1].loss_usd

    def test_covers_all_invariant_types(self):
        covered = {e.invariant_type for e in EXPLOIT_DB}
        # At minimum these critical types must be covered
        required = {
            InvariantType.ORACLE_MANIPULATION,
            InvariantType.REENTRANCY,
            InvariantType.ACCESS_CONTROL,
            InvariantType.FLASH_LOAN_SAFETY,
            InvariantType.GOVERNANCE_SAFETY,
            InvariantType.SHARE_ACCOUNTING,
            InvariantType.COLLATERALIZATION,
        }
        assert required.issubset(covered)


# ---------------------------------------------------------------------------
# RAG tests
# ---------------------------------------------------------------------------


class TestExploitRAG:
    def test_query_returns_for_known_type(self):
        rag = ExploitRAG()
        results = rag.query(InvariantType.ORACLE_MANIPULATION)
        assert len(results) >= 1

    def test_max_results_respected(self):
        rag = ExploitRAG()
        results = rag.query(InvariantType.ORACLE_MANIPULATION, max_results=2)
        assert len(results) <= 2

    def test_tag_filtering_ranks_higher(self):
        rag = ExploitRAG()
        # "flash_loan" tag should surface Cream Finance / Harvest
        results = rag.query(InvariantType.ORACLE_MANIPULATION, tags={"flash_loan"})
        assert len(results) >= 1
        # All results should be for oracle type
        assert all(r.invariant_type == InvariantType.ORACLE_MANIPULATION for r in results)

    def test_confidence_boost_zero_for_empty(self):
        rag = ExploitRAG()
        assert rag.confidence_boost([]) == 0.0

    def test_confidence_boost_positive(self):
        rag = ExploitRAG()
        results = rag.query(InvariantType.ORACLE_MANIPULATION)
        boost = rag.confidence_boost(results)
        assert 0 < boost <= 0.35

    def test_evidence_summary_nonempty(self):
        rag = ExploitRAG()
        results = rag.query(InvariantType.REENTRANCY)
        summary = rag.evidence_summary(results)
        assert "Historically violated" in summary

    def test_evidence_summary_empty_list(self):
        rag = ExploitRAG()
        assert rag.evidence_summary([]) == ""

    def test_singleton_get_rag(self):
        r1 = get_rag()
        r2 = get_rag()
        assert r1 is r2


# ---------------------------------------------------------------------------
# Formal spec generator tests
# ---------------------------------------------------------------------------


class TestFormalSpecGenerator:
    def test_all_types_produce_spec(self):
        gen = FormalSpecGenerator()
        for inv_type in InvariantType:
            spec = gen.generate(inv_type)
            assert isinstance(spec, FormalSpec)
            assert spec.natural_language

    def test_halmos_spec_present_for_main_types(self):
        gen = FormalSpecGenerator()
        for inv_type in [
            InvariantType.VALUE_CONSERVATION,
            InvariantType.BALANCE_CONSISTENCY,
            InvariantType.ORACLE_MANIPULATION,
            InvariantType.REENTRANCY,
        ]:
            spec = gen.generate(inv_type)
            assert spec.halmos, f"No Halmos spec for {inv_type}"

    def test_certora_cvl_present(self):
        gen = FormalSpecGenerator()
        spec = gen.generate(InvariantType.ORACLE_MANIPULATION)
        assert spec.certora_cvl

    def test_pattern_context_used(self):
        gen = FormalSpecGenerator()
        pattern = ProtocolPattern(balance_vars=["userBalance"])
        spec = gen.generate(InvariantType.BALANCE_CONSISTENCY, pattern=pattern)
        assert isinstance(spec, FormalSpec)


# ---------------------------------------------------------------------------
# Pattern detector tests (via ProtocolPattern model)
# ---------------------------------------------------------------------------


class TestProtocolPatternModel:
    def test_defaults(self):
        p = ProtocolPattern()
        assert not p.is_erc20
        assert not p.has_oracle
        assert p.deposit_functions == []

    def test_protocol_types_list(self):
        p = ProtocolPattern(protocol_types=[DeFiProtocolType.AMM])
        assert DeFiProtocolType.AMM in p.protocol_types


# ---------------------------------------------------------------------------
# Reentrancy detector tests
# ---------------------------------------------------------------------------


class TestReentrancyDetector:
    def _make_graph_with_reentrancy(self) -> ProtocolGraph:
        """A function with external call + state write + no guard."""
        contract = _contract("Vault")
        func = _func(
            "withdraw",
            contract.id,
            state_vars_written=["userBalance"],
        )
        ext_call = _call(
            caller_id=func.id,
            callee_name="transfer",
            call_type=CallType.EXTERNAL,
            value_transfer=True,
        )
        return ProtocolGraph(
            contracts=[contract],
            functions=[func],
            function_calls=[ext_call],
            state_variables=[],
        )

    def test_detects_reentrancy_no_guard(self):
        from zeropath.invariants.detectors.reentrancy import ReentrancyDetector
        from zeropath.invariants.patterns import DeFiPatternDetector

        graph = self._make_graph_with_reentrancy()
        pattern = DeFiPatternDetector().detect(graph)
        detector = ReentrancyDetector()
        results = detector.detect(graph, pattern)

        assert len(results) >= 1
        inv = results[0]
        assert inv.type == InvariantType.REENTRANCY
        assert inv.severity in (InvariantSeverity.CRITICAL, InvariantSeverity.HIGH)
        assert "withdraw" in inv.functions_involved

    def test_no_finding_for_view_function(self):
        from zeropath.invariants.detectors.reentrancy import ReentrancyDetector
        from zeropath.invariants.patterns import DeFiPatternDetector

        contract = _contract()
        func = _func("getBalance", contract.id, is_view=True)
        ext_call = _call(func.id, "balanceOf", CallType.EXTERNAL)
        graph = ProtocolGraph(
            contracts=[contract],
            functions=[func],
            function_calls=[ext_call],
        )
        pattern = DeFiPatternDetector().detect(graph)
        results = ReentrancyDetector().detect(graph, pattern)
        assert results == []

    def test_no_finding_with_guard(self):
        from zeropath.invariants.detectors.reentrancy import ReentrancyDetector
        from zeropath.invariants.patterns import DeFiPatternDetector

        contract = _contract()
        func = _func(
            "withdraw",
            contract.id,
            modifiers=["nonReentrant"],
            state_vars_written=["balance"],
        )
        ext_call = _call(func.id, "call", CallType.LOW_LEVEL)
        graph = ProtocolGraph(
            contracts=[contract],
            functions=[func],
            function_calls=[ext_call],
        )
        pattern = DeFiPatternDetector().detect(graph)
        results = ReentrancyDetector().detect(graph, pattern)
        assert results == []


# ---------------------------------------------------------------------------
# Access control detector tests
# ---------------------------------------------------------------------------


class TestAccessControlDetector:
    def test_detects_unprotected_upgrade(self):
        from zeropath.invariants.detectors.access_control import AccessControlDetector
        from zeropath.invariants.patterns import DeFiPatternDetector

        contract = _contract()
        func = _func("upgradeTo", contract.id, visibility=Visibility.PUBLIC)
        graph = ProtocolGraph(contracts=[contract], functions=[func])
        pattern = DeFiPatternDetector().detect(graph)
        results = AccessControlDetector().detect(graph, pattern)

        assert any(inv.severity == InvariantSeverity.CRITICAL for inv in results)

    def test_detects_unprotected_mint(self):
        from zeropath.invariants.detectors.access_control import AccessControlDetector
        from zeropath.invariants.patterns import DeFiPatternDetector

        contract = _contract()
        func = _func("mint", contract.id, visibility=Visibility.EXTERNAL)
        graph = ProtocolGraph(contracts=[contract], functions=[func])
        pattern = DeFiPatternDetector().detect(graph)
        results = AccessControlDetector().detect(graph, pattern)

        assert any(inv.severity == InvariantSeverity.HIGH for inv in results)

    def test_protected_function_no_finding(self):
        from zeropath.invariants.detectors.access_control import AccessControlDetector
        from zeropath.invariants.patterns import DeFiPatternDetector

        contract = _contract()
        ac = AccessControl(only_owner=True)
        func = Function(
            id=str(uuid4()),
            name="mint",
            contract_id=contract.id,
            visibility=Visibility.EXTERNAL,
            signature=FunctionSignature(name="mint"),
            access_control=ac,
        )
        graph = ProtocolGraph(contracts=[contract], functions=[func])
        pattern = DeFiPatternDetector().detect(graph)
        results = AccessControlDetector().detect(graph, pattern)
        assert results == []

    def test_view_function_skipped(self):
        from zeropath.invariants.detectors.access_control import AccessControlDetector
        from zeropath.invariants.patterns import DeFiPatternDetector

        contract = _contract()
        func = _func("getOwner", contract.id, is_view=True)
        graph = ProtocolGraph(contracts=[contract], functions=[func])
        pattern = DeFiPatternDetector().detect(graph)
        results = AccessControlDetector().detect(graph, pattern)
        assert results == []


# ---------------------------------------------------------------------------
# Value conservation detector tests
# ---------------------------------------------------------------------------


class TestValueConservationDetector:
    def test_detects_deposit_withdraw_pair(self):
        from zeropath.invariants.detectors.value_conservation import ValueConservationDetector
        from zeropath.invariants.patterns import DeFiPatternDetector

        contract = _contract()
        deposit = _func("deposit", contract.id)
        withdraw = _func("withdraw", contract.id)
        graph = ProtocolGraph(contracts=[contract], functions=[deposit, withdraw])
        pattern = DeFiPatternDetector().detect(graph)
        results = ValueConservationDetector().detect(graph, pattern)
        assert len(results) >= 1
        assert any(inv.type == InvariantType.VALUE_CONSERVATION for inv in results)

    def test_no_finding_without_flows(self):
        from zeropath.invariants.detectors.value_conservation import ValueConservationDetector
        from zeropath.invariants.patterns import DeFiPatternDetector

        graph = _empty_graph()
        pattern = DeFiPatternDetector().detect(graph)
        results = ValueConservationDetector().detect(graph, pattern)
        assert results == []

    def test_mint_burn_pair_detected(self):
        from zeropath.invariants.detectors.value_conservation import ValueConservationDetector
        from zeropath.invariants.patterns import DeFiPatternDetector

        contract = _contract()
        mint = _func("mint", contract.id)
        burn = _func("burn", contract.id)
        graph = ProtocolGraph(contracts=[contract], functions=[mint, burn])
        pattern = DeFiPatternDetector().detect(graph)
        results = ValueConservationDetector().detect(graph, pattern)
        assert any("Mint/burn" in r.description for r in results)


# ---------------------------------------------------------------------------
# Balance consistency detector tests
# ---------------------------------------------------------------------------


class TestBalanceConsistencyDetector:
    def test_erc20_generates_invariant(self):
        from zeropath.invariants.detectors.balance_consistency import BalanceConsistencyDetector
        from zeropath.invariants.patterns import DeFiPatternDetector

        contract = _contract("Token")
        funcs = [
            _func(name, contract.id)
            for name in ["transfer", "transferFrom", "balanceOf", "approve", "totalSupply", "mint"]
        ]
        bal_var = _state_var("balances", "mapping(address=>uint256)", contract.id)
        supply_var = _state_var("totalSupply", "uint256", contract.id)
        graph = ProtocolGraph(
            contracts=[contract],
            functions=funcs,
            state_variables=[bal_var, supply_var],
        )
        pattern = DeFiPatternDetector().detect(graph)
        results = BalanceConsistencyDetector().detect(graph, pattern)
        assert len(results) >= 1
        assert all(inv.type == InvariantType.BALANCE_CONSISTENCY for inv in results)

    def test_no_finding_without_token(self):
        from zeropath.invariants.detectors.balance_consistency import BalanceConsistencyDetector
        from zeropath.invariants.patterns import DeFiPatternDetector

        graph = _empty_graph()
        pattern = DeFiPatternDetector().detect(graph)
        results = BalanceConsistencyDetector().detect(graph, pattern)
        assert results == []


# ---------------------------------------------------------------------------
# Collateralization detector tests
# ---------------------------------------------------------------------------


class TestCollateralizationDetector:
    def test_lending_protocol_detected(self):
        from zeropath.invariants.detectors.collateralization import CollateralizationDetector
        from zeropath.invariants.patterns import DeFiPatternDetector

        contract = _contract("LendingPool")
        funcs = [
            _func("borrow", contract.id),
            _func("repay", contract.id),
            _func("liquidate", contract.id),
        ]
        col_var = _state_var("collateral", "mapping(address=>uint256)", contract.id)
        debt_var = _state_var("debt", "mapping(address=>uint256)", contract.id)
        graph = ProtocolGraph(
            contracts=[contract],
            functions=funcs,
            state_variables=[col_var, debt_var],
        )
        pattern = DeFiPatternDetector().detect(graph)
        results = CollateralizationDetector().detect(graph, pattern)
        assert len(results) >= 1
        assert results[0].type == InvariantType.COLLATERALIZATION

    def test_no_finding_without_lending(self):
        from zeropath.invariants.detectors.collateralization import CollateralizationDetector
        from zeropath.invariants.patterns import DeFiPatternDetector

        graph = _empty_graph()
        pattern = DeFiPatternDetector().detect(graph)
        results = CollateralizationDetector().detect(graph, pattern)
        assert results == []


# ---------------------------------------------------------------------------
# Flash loan safety detector tests
# ---------------------------------------------------------------------------


class TestFlashLoanSafetyDetector:
    def test_own_flash_loan_detected(self):
        from zeropath.invariants.detectors.flash_loan_safety import FlashLoanSafetyDetector
        from zeropath.invariants.patterns import DeFiPatternDetector

        contract = _contract("FlashLender")
        flash = _func("flashLoan", contract.id)
        callback = _func("executeOperation", contract.id)
        graph = ProtocolGraph(contracts=[contract], functions=[flash, callback])
        pattern = DeFiPatternDetector().detect(graph)
        results = FlashLoanSafetyDetector().detect(graph, pattern)
        assert any(inv.type == InvariantType.FLASH_LOAN_SAFETY for inv in results)

    def test_governance_without_timelock_detected(self):
        from zeropath.invariants.detectors.flash_loan_safety import FlashLoanSafetyDetector
        from zeropath.invariants.patterns import DeFiPatternDetector

        contract = _contract("Governor")
        propose = _func("propose", contract.id)
        vote = _func("castVote", contract.id)
        execute = _func("execute", contract.id)
        graph = ProtocolGraph(contracts=[contract], functions=[propose, vote, execute])
        pattern = DeFiPatternDetector().detect(graph)
        assert pattern.governance_functions
        results = FlashLoanSafetyDetector().detect(graph, pattern)
        assert any(inv.severity == InvariantSeverity.CRITICAL for inv in results)


# ---------------------------------------------------------------------------
# Share accounting detector tests
# ---------------------------------------------------------------------------


class TestShareAccountingDetector:
    def test_erc4626_without_protection_detected(self):
        from zeropath.invariants.detectors.share_accounting import ShareAccountingDetector
        from zeropath.invariants.patterns import DeFiPatternDetector

        contract = _contract("Vault4626")
        funcs = [
            _func("convertToShares", contract.id, is_view=True),
            _func("convertToAssets", contract.id, is_view=True),
            _func("maxDeposit", contract.id, is_view=True),
            _func("previewDeposit", contract.id, is_view=True),
            _func("deposit", contract.id),
        ]
        shares_var = _state_var("totalShares", "uint256", contract.id)
        graph = ProtocolGraph(
            contracts=[contract],
            functions=funcs,
            state_variables=[shares_var],
        )
        pattern = DeFiPatternDetector().detect(graph)
        results = ShareAccountingDetector().detect(graph, pattern)
        assert len(results) >= 1
        assert any(inv.type == InvariantType.SHARE_ACCOUNTING for inv in results)

    def test_no_finding_without_vault(self):
        from zeropath.invariants.detectors.share_accounting import ShareAccountingDetector
        from zeropath.invariants.patterns import DeFiPatternDetector

        graph = _empty_graph()
        pattern = DeFiPatternDetector().detect(graph)
        results = ShareAccountingDetector().detect(graph, pattern)
        assert results == []


# ---------------------------------------------------------------------------
# Governance detector tests
# ---------------------------------------------------------------------------


class TestGovernanceSafetyDetector:
    def test_governance_without_timelock_critical(self):
        from zeropath.invariants.detectors.governance import GovernanceSafetyDetector
        from zeropath.invariants.patterns import DeFiPatternDetector

        contract = _contract("DAO")
        funcs = [
            _func("propose", contract.id),
            _func("castVote", contract.id),
            _func("execute", contract.id),
            _func("queue", contract.id),
        ]
        graph = ProtocolGraph(contracts=[contract], functions=funcs)
        pattern = DeFiPatternDetector().detect(graph)
        results = GovernanceSafetyDetector().detect(graph, pattern)
        assert any(inv.severity == InvariantSeverity.CRITICAL for inv in results)

    def test_no_finding_without_governance(self):
        from zeropath.invariants.detectors.governance import GovernanceSafetyDetector
        from zeropath.invariants.patterns import DeFiPatternDetector

        graph = _empty_graph()
        pattern = DeFiPatternDetector().detect(graph)
        results = GovernanceSafetyDetector().detect(graph, pattern)
        assert results == []


# ---------------------------------------------------------------------------
# Liquidity conservation detector tests
# ---------------------------------------------------------------------------


class TestLiquidityConservationDetector:
    def test_amm_k_invariant_detected(self):
        from zeropath.invariants.detectors.liquidity_conservation import LiquidityConservationDetector
        from zeropath.invariants.patterns import DeFiPatternDetector

        contract = _contract("UniV2Pair")
        swap = _func("swap", contract.id)
        reserve0 = _state_var("reserve0", "uint112", contract.id)
        reserve1 = _state_var("reserve1", "uint112", contract.id)
        graph = ProtocolGraph(
            contracts=[contract],
            functions=[swap],
            state_variables=[reserve0, reserve1],
        )
        pattern = DeFiPatternDetector().detect(graph)
        results = LiquidityConservationDetector().detect(graph, pattern)
        assert any(inv.type == InvariantType.LIQUIDITY_CONSERVATION for inv in results)

    def test_no_finding_without_swap(self):
        from zeropath.invariants.detectors.liquidity_conservation import LiquidityConservationDetector
        from zeropath.invariants.patterns import DeFiPatternDetector

        graph = _empty_graph()
        pattern = DeFiPatternDetector().detect(graph)
        results = LiquidityConservationDetector().detect(graph, pattern)
        assert results == []


# ---------------------------------------------------------------------------
# Oracle manipulation detector tests
# ---------------------------------------------------------------------------


class TestOracleManipulationDetector:
    def test_detects_getreserves_call(self):
        from zeropath.invariants.detectors.oracle_manipulation import OracleManipulationDetector
        from zeropath.invariants.patterns import DeFiPatternDetector

        contract = _contract("LendingPool")
        borrow_fn = _func("borrow", contract.id, state_vars_written=["debt"])
        call = _call(
            caller_id=borrow_fn.id,
            callee_name="getReserves",
            call_type=CallType.EXTERNAL,
            callee_contract="IUniswapV2Pair",
        )
        graph = ProtocolGraph(
            contracts=[contract],
            functions=[borrow_fn],
            function_calls=[call],
        )
        pattern = DeFiPatternDetector().detect(graph)
        results = OracleManipulationDetector().detect(graph, pattern)
        assert any(inv.type == InvariantType.ORACLE_MANIPULATION for inv in results)
        # getReserves is HIGH risk + state-changing → should be CRITICAL
        assert any(inv.severity == InvariantSeverity.CRITICAL for inv in results)

    def test_chainlink_low_risk(self):
        from zeropath.invariants.detectors.oracle_manipulation import OracleManipulationDetector
        from zeropath.invariants.patterns import DeFiPatternDetector

        contract = _contract("Oracle")
        read_fn = _func("getPrice", contract.id, is_view=True)
        call = _call(
            caller_id=read_fn.id,
            callee_name="latestRoundData",
            call_type=CallType.EXTERNAL,
            callee_contract="AggregatorV3Interface",
        )
        graph = ProtocolGraph(
            contracts=[contract],
            functions=[read_fn],
            function_calls=[call],
        )
        pattern = DeFiPatternDetector().detect(graph)
        results = OracleManipulationDetector().detect(graph, pattern)
        # Chainlink in a view function is LOW risk
        chainlink_results = [r for r in results if r.type == InvariantType.ORACLE_MANIPULATION]
        assert all(
            r.severity in (InvariantSeverity.LOW, InvariantSeverity.MEDIUM)
            for r in chainlink_results
        )

    def test_no_finding_for_empty_graph(self):
        from zeropath.invariants.detectors.oracle_manipulation import OracleManipulationDetector
        from zeropath.invariants.patterns import DeFiPatternDetector

        graph = _empty_graph()
        pattern = DeFiPatternDetector().detect(graph)
        results = OracleManipulationDetector().detect(graph, pattern)
        assert results == []


# ---------------------------------------------------------------------------
# Cross-protocol detector tests
# ---------------------------------------------------------------------------


class TestCrossProtocolDetector:
    def test_bridge_dependency_critical(self):
        from zeropath.invariants.detectors.cross_protocol import CrossProtocolDetector
        from zeropath.invariants.patterns import DeFiPatternDetector

        contract = _contract("Bridge")
        bridge_dep = _ext_dep("WormholeRelayer")
        graph = ProtocolGraph(
            contracts=[contract],
            functions=[_func("bridge", contract.id)],
            external_dependencies=[bridge_dep],
        )
        pattern = DeFiPatternDetector().detect(graph)
        results = CrossProtocolDetector().detect(graph, pattern)
        # Bridge naming in function → bridge finding
        assert len(results) >= 1

    def test_high_dep_count_finding(self):
        from zeropath.invariants.detectors.cross_protocol import CrossProtocolDetector
        from zeropath.invariants.patterns import DeFiPatternDetector

        contract = _contract()
        deps = [
            _ext_dep("ProtocolA"),
            _ext_dep("ProtocolB"),
            _ext_dep("ProtocolC"),
            _ext_dep("ProtocolD"),
        ]
        graph = ProtocolGraph(
            contracts=[contract],
            functions=[_func("doSomething", contract.id)],
            external_dependencies=deps,
        )
        pattern = DeFiPatternDetector().detect(graph)
        results = CrossProtocolDetector().detect(graph, pattern)
        assert any(
            "external" in r.description.lower() or "composability" in r.description.lower()
            for r in results
        )

    def test_no_finding_for_no_deps(self):
        from zeropath.invariants.detectors.cross_protocol import CrossProtocolDetector
        from zeropath.invariants.patterns import DeFiPatternDetector

        graph = _empty_graph()
        pattern = DeFiPatternDetector().detect(graph)
        results = CrossProtocolDetector().detect(graph, pattern)
        assert results == []


# ---------------------------------------------------------------------------
# Engine tests
# ---------------------------------------------------------------------------


class TestInvariantInferenceEngine:
    def test_empty_graph_produces_report(self):
        from zeropath.invariants import InvariantInferenceEngine

        graph = _empty_graph()
        engine = InvariantInferenceEngine()
        report = engine.analyse(graph, protocol_name="Empty")
        assert isinstance(report, InvariantReport)
        assert report.protocol_name == "Empty"
        assert isinstance(report.invariants, list)
        assert isinstance(report.oracle_dependencies, list)

    def test_lending_protocol_produces_invariants(self):
        from zeropath.invariants import InvariantInferenceEngine

        contract = _contract("LendingPool")
        funcs = [
            _func("deposit", contract.id),
            _func("borrow", contract.id),
            _func("repay", contract.id),
            _func("liquidate", contract.id),
        ]
        col_var = _state_var("collateral", "mapping(address=>uint256)", contract.id)
        debt_var = _state_var("debt", "mapping(address=>uint256)", contract.id)
        graph = ProtocolGraph(
            contracts=[contract],
            functions=funcs,
            state_variables=[col_var, debt_var],
        )

        engine = InvariantInferenceEngine()
        report = engine.analyse(graph, protocol_name="TestLender")
        assert len(report.invariants) >= 1
        assert report.protocol_name == "TestLender"
        types_found = {i.type for i in report.invariants}
        assert InvariantType.COLLATERALIZATION in types_found

    def test_invariants_sorted_by_severity(self):
        from zeropath.invariants import InvariantInferenceEngine

        contract = _contract("Protocol")
        # Build a graph that will trigger multiple detectors
        funcs = [
            _func("deposit", contract.id),
            _func("withdraw", contract.id),
            _func("mint", contract.id, visibility=Visibility.EXTERNAL),  # unprotected
            _func("borrow", contract.id),
            _func("repay", contract.id),
        ]
        graph = ProtocolGraph(contracts=[contract], functions=funcs)
        engine = InvariantInferenceEngine()
        report = engine.analyse(graph)

        sev_order = {
            InvariantSeverity.CRITICAL: 0,
            InvariantSeverity.HIGH: 1,
            InvariantSeverity.MEDIUM: 2,
            InvariantSeverity.LOW: 3,
            InvariantSeverity.INFO: 4,
        }
        for a, b in zip(report.invariants, report.invariants[1:]):
            assert sev_order[a.severity] <= sev_order[b.severity], (
                f"Order violation: {a.severity} before {b.severity}"
            )

    def test_metadata_populated(self):
        from zeropath.invariants import InvariantInferenceEngine

        graph = _empty_graph()
        report = InvariantInferenceEngine().analyse(graph)
        meta = report.analysis_metadata
        assert "detectors_run" in meta
        assert "elapsed_seconds" in meta
        assert len(meta["detectors_run"]) >= 5

    def test_deduplication_no_exact_duplicates(self):
        from zeropath.invariants import InvariantInferenceEngine

        contract = _contract("DupTest")
        # Multiple functions with identical names that might trigger multiple detectors
        funcs = [
            _func("deposit", contract.id),
            _func("withdraw", contract.id),
            _func("borrow", contract.id),
            _func("repay", contract.id),
        ]
        graph = ProtocolGraph(contracts=[contract], functions=funcs)
        report = InvariantInferenceEngine().analyse(graph)

        # No two invariants should have identical (type, primary_contract, primary_func)
        seen = set()
        for inv in report.invariants:
            contract_key = inv.contracts_involved[0] if inv.contracts_involved else ""
            func_key = inv.functions_involved[0] if inv.functions_involved else ""
            key = (inv.type.value, contract_key, func_key)
            assert key not in seen, f"Duplicate invariant: {key}"
            seen.add(key)

    def test_custom_detector_set(self):
        from zeropath.invariants import InvariantInferenceEngine
        from zeropath.invariants.detectors.reentrancy import ReentrancyDetector

        graph = _empty_graph()
        engine = InvariantInferenceEngine(detectors=[ReentrancyDetector()])
        report = engine.analyse(graph)
        # Only reentrancy detector ran — metadata should show that
        assert report.analysis_metadata["detectors_run"] == ["reentrancy"]

    def test_oracle_manipulation_with_real_oracle_dep(self):
        """End-to-end: uniswap getReserves in borrow function → CRITICAL."""
        from zeropath.invariants import InvariantInferenceEngine

        contract = _contract("BadLending")
        borrow = _func("borrow", contract.id, state_vars_written=["debt"])
        oracle_call = _call(
            caller_id=borrow.id,
            callee_name="getReserves",
            call_type=CallType.EXTERNAL,
            callee_contract="IUniswapV2Pair",
        )
        graph = ProtocolGraph(
            contracts=[contract],
            functions=[borrow],
            function_calls=[oracle_call],
        )

        engine = InvariantInferenceEngine()
        report = engine.analyse(graph, protocol_name="BadLending")

        oracle_invs = [
            i for i in report.invariants
            if i.type == InvariantType.ORACLE_MANIPULATION
        ]
        assert len(oracle_invs) >= 1
        assert any(i.severity == InvariantSeverity.CRITICAL for i in oracle_invs)

    def test_report_critical_invariants_property(self):
        from zeropath.invariants import InvariantInferenceEngine

        contract = _contract()
        upgrade = _func("upgradeTo", contract.id, visibility=Visibility.PUBLIC)
        graph = ProtocolGraph(contracts=[contract], functions=[upgrade])
        report = InvariantInferenceEngine().analyse(graph)

        # critical_invariants property must return only CRITICAL
        assert all(
            i.severity == InvariantSeverity.CRITICAL
            for i in report.critical_invariants
        )

    def test_invariants_by_type_grouping(self):
        from zeropath.invariants import InvariantInferenceEngine

        contract = _contract()
        funcs = [
            _func("deposit", contract.id),
            _func("withdraw", contract.id),
            _func("mint", contract.id, visibility=Visibility.EXTERNAL),
        ]
        graph = ProtocolGraph(contracts=[contract], functions=funcs)
        report = InvariantInferenceEngine().analyse(graph)

        by_type = report.invariants_by_type
        for inv_type, invs in by_type.items():
            assert all(i.type == inv_type for i in invs)
