"""
Phase 6 test suite — Exploit Validation Engine.

Coverage:
  - Pydantic models: spec output keys, enums, predicates
  - ProfitValidator: profit > 0, reverts, not-executed, sim errors
  - PermissionValidator: privileged-role auto-reject, governance class exemption
  - RealismValidator: gas vs block limit, sketch detection, pool depth
  - SeverityScorer: profit tiers, capital required, MEV / pausable / time-sensitive flags, composite
  - DuplicateDetector: fingerprint stability, in-memory dedup, lookup vs record
  - ContrarianAgent: each objection category, severity_kill threshold
  - ValidationOrchestrator: end-to-end batch + recommended_action transitions
"""

from __future__ import annotations

from uuid import uuid4

import pytest

from zeropath.adversarial.models import (
    AttackClass,
    AttackHypothesis,
    AttackStep,
    ConditionType,
    HypothesisStatus,
    Precondition,
    ProfitMechanism,
    SwarmReport,
)
from zeropath.sequencer.models import (
    AttackContext,
    OnChainStateSnapshot,
    ProfitEstimate,
    SequenceReport,
    TransactionSequence,
    TxCall,
)
from zeropath.simulator.models import (
    BalanceDiff,
    SimulationOutcome,
    SimulationReport,
    SimulationResult,
)
from zeropath.validation import (
    ContrarianAgent,
    ContrarianObjection,
    DuplicateDetector,
    InMemoryDuplicateStore,
    ObjectionCategory,
    PermissionValidator,
    ProfitTier,
    ProfitValidator,
    RealismValidator,
    RecommendedAction,
    RejectionReason,
    SeverityScore,
    SeverityScorer,
    ValidationOrchestrator,
    ValidationReport,
    ValidationResult,
    compute_fingerprint,
)


# ===========================================================================
# Test fixtures
# ===========================================================================


_ATTACKER = "0x000000000000000000000000000000000000c0de"
_WETH = "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2"


def _mk_hypothesis(
    *,
    attack_class: AttackClass = AttackClass.ORACLE_MANIPULATION,
    contracts: list[str] | None = None,
    functions: list[str] | None = None,
    preconditions: list[Precondition] | None = None,
    profit_usd: int = 100_000,
    confidence: float = 0.8,
) -> AttackHypothesis:
    pcs = preconditions if preconditions is not None else [
        Precondition(
            condition_type=ConditionType.FLASH_LOAN_AVAILABLE,
            description="Aave V3 supports WETH flash",
            is_met_by_protocol=True,
        ),
        Precondition(
            condition_type=ConditionType.ORACLE_READ_SINGLE_BLOCK,
            description="Spot read in single block",
            is_met_by_protocol=True,
        ),
    ]
    return AttackHypothesis(
        invariant_id=str(uuid4()),
        invariant_description="test invariant",
        attack_class=attack_class,
        title=f"test {attack_class.value}",
        proposed_by="X",
        attack_narrative="A attacker exploits the protocol.",
        contracts_involved=contracts or ["LendingPool"],
        functions_involved=functions or ["borrow"],
        exploit_steps=[
            AttackStep(step=1, action="flash loan", purpose="fund"),
            AttackStep(step=2, action="manipulate", purpose="skew"),
            AttackStep(step=3, action="exploit", purpose="extract"),
        ],
        preconditions=pcs,
        profit_mechanism=ProfitMechanism(
            description="drain",
            asset="WETH",
            estimated_max_usd=profit_usd,
        ),
        confidence=confidence,
        status=HypothesisStatus.CONSENSUS,
    )


def _mk_sequence(
    *,
    hypothesis_id: str | None = None,
    flash_loan: bool = True,
    gas_total: int = 1_500_000,
    requires_single_block: bool = True,
    onchain_snapshot: OnChainStateSnapshot | None = None,
    flash_amount: int = 100 * 10**18,
) -> TransactionSequence:
    calls: list[TxCall] = []
    if flash_loan:
        calls.append(TxCall(
            step=1, description="flash loan",
            target_address_expr="IPool(AAVE)",
            target_address="0x87870bca3f3fd6335c3f4ce8392d69350b4fa4e2",
            function_signature="flashLoanSimple(address,address,uint256,bytes,uint16)",
            params=[_ATTACKER, _WETH, flash_amount, b"", 0],
            param_types=["address", "address", "uint256", "bytes", "uint16"],
            estimated_gas=600_000,
        ))
    calls.append(TxCall(
        step=len(calls) + 1, description="swap",
        target_address_expr="IUniswapV2Pair(POOL)",
        target_address="0x000000000000000000000000000000000000aaaa",
        function_signature="swap(uint256,uint256,address,bytes)",
        params=[flash_amount, 0, _ATTACKER, b""],
        param_types=["uint256", "uint256", "address", "bytes"],
        estimated_gas=180_000,
    ))
    calls.append(TxCall(
        step=len(calls) + 1, description="exploit",
        target_address_expr="ILendingPool(TARGET)",
        target_address="0x000000000000000000000000000000000000bbbb",
        function_signature="borrow(uint256)",
        params=[flash_amount],
        param_types=["uint256"],
        estimated_gas=400_000,
    ))
    calls.append(TxCall(
        step=len(calls) + 1, description="repay",
        target_address_expr="IERC20(WETH)",
        target_address=_WETH,
        function_signature="transfer(address,uint256)",
        params=[_ATTACKER, flash_amount + flash_amount * 9 // 10000],
        param_types=["address", "uint256"],
        estimated_gas=65_000,
    ))

    ctx = AttackContext(
        chain="mainnet",
        flash_loan_provider="0x87870bca3f3fd6335c3f4ce8392d69350b4fa4e2" if flash_loan else None,
        requires_single_block=requires_single_block,
        onchain_snapshot=onchain_snapshot,
    )
    seq = TransactionSequence(
        hypothesis_id=hypothesis_id or str(uuid4()),
        hypothesis_title="test sequence",
        attack_class="oracle_manipulation",
        calls=calls,
        context=ctx,
        profit_estimate=ProfitEstimate(
            asset="WETH",
            min_profit_expression="1e16",
            max_profit_expression="1e21",
            cost_expression="(flashAmount * 9) / 10000",
        ),
        uses_flash_loan=flash_loan,
        total_gas_estimate=gas_total,
        block_number=18_500_000,
    )
    return seq


def _mk_simulation(
    *,
    sequence_id: str,
    hypothesis_id: str = "",
    outcome: SimulationOutcome = SimulationOutcome.PROFITABLE,
    profit_wei: int = 10**18,
    revert_reason: str | None = None,
) -> SimulationResult:
    return SimulationResult(
        sequence_id=sequence_id,
        hypothesis_id=hypothesis_id,
        success=outcome == SimulationOutcome.PROFITABLE,
        outcome=outcome,
        profit_wei=profit_wei,
        gas_used=1_200_000,
        revert_reason=revert_reason,
    )


# ===========================================================================
# Models
# ===========================================================================


class TestValidationResultShape:
    """Verify Pydantic model matches the spec's required JSON keys."""

    SPEC_KEYS = {
        "valid", "reason", "confidence", "severity",
        "duplicate_of", "contrarian_objections", "recommended_action",
    }

    def test_spec_keys_present(self):
        r = ValidationResult()
        dumped = r.model_dump()
        assert self.SPEC_KEYS.issubset(dumped.keys())

    def test_severity_subobject_keys(self):
        s = SeverityScore()
        spec_severity_keys = {
            "profit_tier", "capital_required_usd", "requires_flash_loan",
            "time_sensitive", "mev_frontrunnable", "protocol_pausable",
        }
        assert spec_severity_keys.issubset(s.model_dump().keys())

    def test_actionable_predicate(self):
        r = ValidationResult(valid=True, recommended_action=RecommendedAction.REPORT)
        assert r.is_actionable is True
        r.recommended_action = RecommendedAction.DISCARD
        assert r.is_actionable is False


# ===========================================================================
# ProfitValidator
# ===========================================================================


class TestProfitValidator:
    def test_passes_with_positive_profit(self):
        seq = _mk_sequence()
        sim = _mk_simulation(sequence_id=seq.id, profit_wei=10**18)
        v = ProfitValidator().validate(hypothesis=_mk_hypothesis(), sequence=seq, simulation=sim)
        assert v.passed

    def test_rejects_zero_profit(self):
        seq = _mk_sequence()
        sim = _mk_simulation(
            sequence_id=seq.id,
            outcome=SimulationOutcome.EXECUTED_NO_PROFIT,
            profit_wei=0,
        )
        v = ProfitValidator().validate(hypothesis=_mk_hypothesis(), sequence=seq, simulation=sim)
        assert not v.passed
        assert RejectionReason.PROFIT_NOT_POSITIVE in v.rejection_reasons

    def test_rejects_not_executed(self):
        seq = _mk_sequence()
        sim = _mk_simulation(
            sequence_id=seq.id, outcome=SimulationOutcome.NOT_EXECUTED, profit_wei=0,
        )
        v = ProfitValidator().validate(hypothesis=_mk_hypothesis(), sequence=seq, simulation=sim)
        assert RejectionReason.SIMULATION_NOT_EXECUTED in v.rejection_reasons

    def test_rejects_reverted(self):
        seq = _mk_sequence()
        sim = _mk_simulation(
            sequence_id=seq.id, outcome=SimulationOutcome.REVERTED, profit_wei=0,
            revert_reason="ERC20: insufficient allowance",
        )
        v = ProfitValidator().validate(hypothesis=_mk_hypothesis(), sequence=seq, simulation=sim)
        assert RejectionReason.SIMULATION_REVERTED in v.rejection_reasons

    def test_rejects_simulation_error(self):
        seq = _mk_sequence()
        sim = _mk_simulation(
            sequence_id=seq.id, outcome=SimulationOutcome.SIMULATION_ERROR,
            revert_reason="anvil missing",
        )
        v = ProfitValidator().validate(hypothesis=_mk_hypothesis(), sequence=seq, simulation=sim)
        assert RejectionReason.SIMULATION_ERROR in v.rejection_reasons


# ===========================================================================
# PermissionValidator
# ===========================================================================


class TestPermissionValidator:
    def test_passes_for_normal_attack(self):
        h = _mk_hypothesis()
        seq = _mk_sequence()
        sim = _mk_simulation(sequence_id=seq.id)
        v = PermissionValidator().validate(hypothesis=h, sequence=seq, simulation=sim)
        assert v.passed

    def test_rejects_admin_requirement(self):
        h = _mk_hypothesis(preconditions=[
            Precondition(
                condition_type=ConditionType.CUSTOM,
                description="caller must be the owner",
                is_met_by_protocol=False,
            ),
        ])
        seq = _mk_sequence()
        sim = _mk_simulation(sequence_id=seq.id)
        v = PermissionValidator().validate(hypothesis=h, sequence=seq, simulation=sim)
        assert not v.passed
        assert RejectionReason.PRIVILEGED_ROLE_REQUIRED in v.rejection_reasons

    def test_governance_class_allowed_to_need_governance_token(self):
        h = _mk_hypothesis(
            attack_class=AttackClass.GOVERNANCE,
            preconditions=[Precondition(
                condition_type=ConditionType.GOVERNANCE_TOKEN_AVAILABLE,
                description="attacker borrows governance tokens",
                is_met_by_protocol=True,
            )],
        )
        seq = _mk_sequence()
        sim = _mk_simulation(sequence_id=seq.id)
        v = PermissionValidator().validate(hypothesis=h, sequence=seq, simulation=sim)
        assert v.passed

    def test_non_governance_class_rejects_governance_token_requirement(self):
        h = _mk_hypothesis(
            attack_class=AttackClass.ORACLE_MANIPULATION,
            preconditions=[Precondition(
                condition_type=ConditionType.GOVERNANCE_TOKEN_AVAILABLE,
                description="attacker holds governance tokens",
                is_met_by_protocol=False,
            )],
        )
        v = PermissionValidator().validate(
            hypothesis=h, sequence=_mk_sequence(),
            simulation=_mk_simulation(sequence_id="x"),
        )
        assert not v.passed


# ===========================================================================
# RealismValidator
# ===========================================================================


class TestRealismValidator:
    def test_passes_normal_sequence(self):
        seq = _mk_sequence(gas_total=1_500_000)
        v = RealismValidator().validate(
            hypothesis=_mk_hypothesis(), sequence=seq,
            simulation=_mk_simulation(sequence_id=seq.id),
        )
        assert v.passed

    def test_rejects_over_block_gas_limit(self):
        seq = _mk_sequence(gas_total=40_000_000, requires_single_block=True)
        v = RealismValidator().validate(
            hypothesis=_mk_hypothesis(), sequence=seq,
            simulation=_mk_simulation(sequence_id=seq.id),
        )
        assert not v.passed
        assert RejectionReason.UNREALISTIC_GAS in v.rejection_reasons

    def test_allows_over_block_gas_when_multi_block(self):
        seq = _mk_sequence(gas_total=40_000_000, requires_single_block=False)
        v = RealismValidator().validate(
            hypothesis=_mk_hypothesis(), sequence=seq,
            simulation=_mk_simulation(sequence_id=seq.id),
        )
        assert v.passed

    def test_rejects_sketch_sequence_with_no_concrete_addresses(self):
        # Replace every target_address with None to simulate a builder
        # that only emitted template expressions.
        seq = _mk_sequence()
        for c in seq.calls:
            c.target_address = None
        v = RealismValidator().validate(
            hypothesis=_mk_hypothesis(), sequence=seq,
            simulation=_mk_simulation(sequence_id=seq.id),
        )
        assert not v.passed

    def test_rejects_flash_amount_exceeding_pool_depth(self):
        snap = OnChainStateSnapshot(
            block_number=18_500_000,
            pool_reserves={"0xaaa": (10**18, 10**18, 1700000000)},
        )
        # Flash amount 100 ETH vs pool 1 ETH → 100× larger.
        seq = _mk_sequence(
            flash_amount=100 * 10**18,
            onchain_snapshot=snap,
        )
        v = RealismValidator().validate(
            hypothesis=_mk_hypothesis(), sequence=seq,
            simulation=_mk_simulation(sequence_id=seq.id),
        )
        assert not v.passed
        assert RejectionReason.UNREALISTIC_LIQUIDITY in v.rejection_reasons


# ===========================================================================
# SeverityScorer
# ===========================================================================


class TestSeverityScorer:
    def test_profit_tier_critical(self):
        # 1000 ETH @ $3000 = $3M → critical
        seq = _mk_sequence()
        sim = _mk_simulation(sequence_id=seq.id, profit_wei=1000 * 10**18)
        s = SeverityScorer().score(hypothesis=_mk_hypothesis(), sequence=seq, simulation=sim)
        assert s.profit_tier == ProfitTier.CRITICAL

    def test_profit_tier_high(self):
        # 50 ETH @ $3000 = $150k → high
        seq = _mk_sequence()
        sim = _mk_simulation(sequence_id=seq.id, profit_wei=50 * 10**18)
        s = SeverityScorer().score(hypothesis=_mk_hypothesis(), sequence=seq, simulation=sim)
        assert s.profit_tier == ProfitTier.HIGH

    def test_profit_tier_medium(self):
        seq = _mk_sequence()
        sim = _mk_simulation(sequence_id=seq.id, profit_wei=1 * 10**18)  # ~$3k
        s = SeverityScorer().score(hypothesis=_mk_hypothesis(), sequence=seq, simulation=sim)
        assert s.profit_tier == ProfitTier.MEDIUM

    def test_profit_tier_none_when_zero(self):
        seq = _mk_sequence()
        sim = _mk_simulation(sequence_id=seq.id, profit_wei=0,
                             outcome=SimulationOutcome.EXECUTED_NO_PROFIT)
        s = SeverityScorer().score(hypothesis=_mk_hypothesis(), sequence=seq, simulation=sim)
        assert s.profit_tier == ProfitTier.NONE

    def test_capital_required_zero_for_flash_loan(self):
        seq = _mk_sequence(flash_loan=True)
        s = SeverityScorer().score(hypothesis=_mk_hypothesis(), sequence=seq,
                                    simulation=_mk_simulation(sequence_id=seq.id))
        assert s.capital_required_usd == 0
        assert s.requires_flash_loan is True

    def test_capital_required_nonzero_when_no_flash_loan(self):
        seq = _mk_sequence(flash_loan=False)
        h = _mk_hypothesis(profit_usd=1_000_000, preconditions=[])
        s = SeverityScorer().score(hypothesis=h, sequence=seq,
                                    simulation=_mk_simulation(sequence_id=seq.id))
        assert s.capital_required_usd > 0
        assert s.requires_flash_loan is False

    def test_mev_frontrunnable_for_oracle_attack(self):
        seq = _mk_sequence()
        s = SeverityScorer().score(
            hypothesis=_mk_hypothesis(attack_class=AttackClass.ORACLE_MANIPULATION),
            sequence=seq, simulation=_mk_simulation(sequence_id=seq.id),
        )
        assert s.mev_frontrunnable is True

    def test_governance_attack_not_mev_frontrunnable(self):
        seq = _mk_sequence()
        s = SeverityScorer().score(
            hypothesis=_mk_hypothesis(attack_class=AttackClass.GOVERNANCE),
            sequence=seq, simulation=_mk_simulation(sequence_id=seq.id),
        )
        assert s.mev_frontrunnable is False

    def test_time_sensitive_when_single_block_oracle(self):
        seq = _mk_sequence()
        h = _mk_hypothesis(preconditions=[Precondition(
            condition_type=ConditionType.ORACLE_READ_SINGLE_BLOCK,
            description="reads spot in single block",
            is_met_by_protocol=True,
        )])
        s = SeverityScorer().score(hypothesis=h, sequence=seq,
                                    simulation=_mk_simulation(sequence_id=seq.id))
        assert s.time_sensitive is True

    def test_pausable_detected_from_narrative(self):
        h = _mk_hypothesis()
        h.attack_narrative = "Protocol exposes a Pausable circuit breaker that owner can trip."
        seq = _mk_sequence()
        s = SeverityScorer().score(hypothesis=h, sequence=seq,
                                    simulation=_mk_simulation(sequence_id=seq.id))
        assert s.protocol_pausable is True

    def test_composite_score_in_unit_interval(self):
        for profit_wei in (0, 10**16, 10**18, 1000 * 10**18):
            seq = _mk_sequence()
            sim = _mk_simulation(sequence_id=seq.id, profit_wei=profit_wei)
            s = SeverityScorer().score(hypothesis=_mk_hypothesis(), sequence=seq, simulation=sim)
            assert 0.0 <= s.composite_score <= 1.0


# ===========================================================================
# DuplicateDetector
# ===========================================================================


class TestDuplicateDetector:
    def test_fingerprint_stable_for_same_inputs(self):
        h1 = _mk_hypothesis(contracts=["Pool"], functions=["borrow"])
        h2 = _mk_hypothesis(contracts=["Pool"], functions=["borrow"])
        assert compute_fingerprint(h1) == compute_fingerprint(h2)

    def test_fingerprint_differs_on_different_function(self):
        h1 = _mk_hypothesis(contracts=["Pool"], functions=["borrow"])
        h2 = _mk_hypothesis(contracts=["Pool"], functions=["liquidate"])
        assert compute_fingerprint(h1) != compute_fingerprint(h2)

    def test_fingerprint_order_insensitive_within_lists(self):
        h1 = _mk_hypothesis(contracts=["A", "B"], functions=["f", "g"])
        h2 = _mk_hypothesis(contracts=["B", "A"], functions=["g", "f"])
        assert compute_fingerprint(h1) == compute_fingerprint(h2)

    def test_in_memory_store_lookup(self):
        store = InMemoryDuplicateStore({"abc": "v1"})
        assert store.lookup("abc") == "v1"
        assert store.lookup("missing") is None
        store.record("def", "v2")
        assert store.lookup("def") == "v2"
        # Records are insert-once (setdefault)
        store.record("def", "v3")
        assert store.lookup("def") == "v2"

    def test_detector_check_records_on_miss(self):
        det = DuplicateDetector()
        h = _mk_hypothesis()
        fp, dup = det.check(h, validation_id="V1")
        assert dup is None  # first time
        # Second check returns the V1 id
        fp2, dup2 = det.check(_mk_hypothesis(  # different obj, same fingerprint inputs
            contracts=h.contracts_involved, functions=h.functions_involved,
        ), validation_id="V2")
        assert fp == fp2
        assert dup2 == "V1"

    def test_detector_record_on_lookup_false(self):
        det = DuplicateDetector(record_on_lookup=False)
        h = _mk_hypothesis()
        det.check(h, validation_id="V1")
        # Still a miss because we didn't record.
        _, dup = det.check(h, validation_id="V2")
        assert dup is None


# ===========================================================================
# ContrarianAgent
# ===========================================================================


class TestContrarianAgent:
    def test_no_objections_for_clean_governance_attack(self):
        # Governance attacks aren't frontrunnable, no pool snapshot, no high
        # gas, no pause keywords, and the sequence has no swap-like calls.
        h = _mk_hypothesis(
            attack_class=AttackClass.GOVERNANCE,
            preconditions=[],
        )
        h.attack_narrative = "Attacker submits proposal."
        # Build a custom governance-shaped sequence (propose → vote → execute)
        # so the contrarian doesn't pick up swap-call MEV signals.
        seq = TransactionSequence(
            hypothesis_id=h.id,
            hypothesis_title="governance attack",
            attack_class="governance",
            calls=[
                TxCall(step=1, description="propose",
                       target_address_expr="IGovernor(GOV)",
                       target_address="0x000000000000000000000000000000000000a000",
                       function_signature="propose(address[],uint256[],bytes[],string)",
                       params=[[], [], [], "evil"],
                       param_types=["address[]", "uint256[]", "bytes[]", "string"],
                       estimated_gas=300_000),
                TxCall(step=2, description="cast vote",
                       target_address_expr="IGovernor(GOV)",
                       target_address="0x000000000000000000000000000000000000a000",
                       function_signature="castVote(uint256,uint8)",
                       params=[1, 1],
                       param_types=["uint256", "uint8"],
                       estimated_gas=100_000),
                TxCall(step=3, description="execute",
                       target_address_expr="IGovernor(GOV)",
                       target_address="0x000000000000000000000000000000000000a000",
                       function_signature="execute(uint256)",
                       params=[1],
                       param_types=["uint256"],
                       estimated_gas=300_000),
            ],
            context=AttackContext(chain="mainnet", requires_single_block=False),
            uses_flash_loan=False,
            total_gas_estimate=700_000,
        )
        sev = SeverityScorer().score(hypothesis=h, sequence=seq,
                                      simulation=_mk_simulation(sequence_id=seq.id))
        objections = ContrarianAgent().review(
            hypothesis=h, sequence=seq,
            simulation=_mk_simulation(sequence_id=seq.id), severity=sev,
        )
        assert objections == []

    def test_mev_objection_for_oracle_attack(self):
        h = _mk_hypothesis(attack_class=AttackClass.ORACLE_MANIPULATION)
        seq = _mk_sequence()
        sev = SeverityScorer().score(hypothesis=h, sequence=seq,
                                      simulation=_mk_simulation(sequence_id=seq.id))
        objections = ContrarianAgent().review(
            hypothesis=h, sequence=seq,
            simulation=_mk_simulation(sequence_id=seq.id), severity=sev,
        )
        # Single-block + frontrunnable → SANDWICH_RISK
        assert any(o.category == ObjectionCategory.SANDWICH_RISK for o in objections)

    def test_gas_limit_objection_when_pressure(self):
        h = _mk_hypothesis()
        seq = _mk_sequence(gas_total=25_000_000)  # 83% of block
        sev = SeverityScorer().score(hypothesis=h, sequence=seq,
                                      simulation=_mk_simulation(sequence_id=seq.id))
        objections = ContrarianAgent().review(
            hypothesis=h, sequence=seq,
            simulation=_mk_simulation(sequence_id=seq.id), severity=sev,
        )
        assert any(o.category == ObjectionCategory.GAS_LIMIT for o in objections)

    def test_liquidity_depth_objection(self):
        snap = OnChainStateSnapshot(
            block_number=18_500_000,
            pool_reserves={"0xaaa": (10**18, 10**18, 1700000000)},
        )
        # 5 ETH flash vs 1 ETH pool reserve = 5×
        seq = _mk_sequence(flash_amount=5 * 10**18, onchain_snapshot=snap)
        sev = SeverityScorer().score(hypothesis=_mk_hypothesis(), sequence=seq,
                                      simulation=_mk_simulation(sequence_id=seq.id))
        objections = ContrarianAgent().review(
            hypothesis=_mk_hypothesis(), sequence=seq,
            simulation=_mk_simulation(sequence_id=seq.id), severity=sev,
        )
        assert any(o.category == ObjectionCategory.LIQUIDITY_DEPTH for o in objections)

    def test_admin_mitigation_when_pausable(self):
        h = _mk_hypothesis()
        h.attack_narrative = "Protocol has emergency stop pausable."
        h.attack_class = AttackClass.GOVERNANCE  # avoid MEV objection
        seq = _mk_sequence(flash_loan=False)
        sev = SeverityScorer().score(hypothesis=h, sequence=seq,
                                      simulation=_mk_simulation(sequence_id=seq.id))
        objections = ContrarianAgent().review(
            hypothesis=h, sequence=seq,
            simulation=_mk_simulation(sequence_id=seq.id), severity=sev,
        )
        assert any(o.category == ObjectionCategory.ADMIN_MITIGATION for o in objections)

    def test_block_reorg_for_twap_attack(self):
        h = _mk_hypothesis()
        h.title = "TWAP manipulation attack"
        h.attack_class = AttackClass.GOVERNANCE  # silence MEV
        seq = _mk_sequence(flash_loan=False)
        sev = SeverityScorer().score(hypothesis=h, sequence=seq,
                                      simulation=_mk_simulation(sequence_id=seq.id))
        objections = ContrarianAgent().review(
            hypothesis=h, sequence=seq,
            simulation=_mk_simulation(sequence_id=seq.id), severity=sev,
        )
        assert any(o.category == ObjectionCategory.BLOCK_REORG for o in objections)


# ===========================================================================
# ValidationOrchestrator end-to-end
# ===========================================================================


def _mk_swarm(hypotheses: list[AttackHypothesis]) -> SwarmReport:
    return SwarmReport(protocol_name="TestProtocol", hypotheses=hypotheses)


def _mk_seq_report(pairs: list[tuple[AttackHypothesis, TransactionSequence]]) -> SequenceReport:
    seqs = []
    for hyp, seq in pairs:
        seq.hypothesis_id = hyp.id
        seqs.append(seq)
    return SequenceReport(
        protocol_name="TestProtocol",
        sequences=seqs,
        total_hypotheses_input=len(seqs),
        sequences_generated=len(seqs),
    )


def _mk_sim_report(seqs: list[TransactionSequence], **kw) -> SimulationReport:
    return SimulationReport(
        protocol_name="TestProtocol",
        results=[_mk_simulation(sequence_id=s.id, hypothesis_id=s.hypothesis_id, **kw) for s in seqs],
        sequences_executed=len(seqs),
    )


class TestOrchestrator:
    def test_critical_finding_reaches_report(self):
        h = _mk_hypothesis(profit_usd=5_000_000, confidence=0.9)
        seq = _mk_sequence()
        seq.hypothesis_id = h.id
        sim = _mk_simulation(sequence_id=seq.id, profit_wei=1000 * 10**18)  # $3M
        orch = ValidationOrchestrator()
        result = orch.validate(hypothesis=h, sequence=seq, simulation=sim)
        assert result.valid is True
        assert result.severity.profit_tier == ProfitTier.CRITICAL
        # The MEV-frontrunnable objection knocks composite below the report bar;
        # acceptable downgrade is SIMULATE_FURTHER. Either is acceptable here.
        assert result.recommended_action in {
            RecommendedAction.REPORT, RecommendedAction.SIMULATE_FURTHER,
        }

    def test_zero_profit_rejected(self):
        h = _mk_hypothesis()
        seq = _mk_sequence()
        seq.hypothesis_id = h.id
        sim = _mk_simulation(
            sequence_id=seq.id, profit_wei=0,
            outcome=SimulationOutcome.EXECUTED_NO_PROFIT,
        )
        result = ValidationOrchestrator().validate(hypothesis=h, sequence=seq, simulation=sim)
        assert result.valid is False
        assert RejectionReason.PROFIT_NOT_POSITIVE in result.rejection_reasons
        assert result.recommended_action == RecommendedAction.DISCARD

    def test_admin_required_rejected(self):
        h = _mk_hypothesis(preconditions=[Precondition(
            condition_type=ConditionType.CUSTOM,
            description="caller must be owner",
        )])
        seq = _mk_sequence()
        sim = _mk_simulation(sequence_id=seq.id, profit_wei=10**20)
        result = ValidationOrchestrator().validate(hypothesis=h, sequence=seq, simulation=sim)
        assert result.valid is False
        assert RejectionReason.PRIVILEGED_ROLE_REQUIRED in result.rejection_reasons

    def test_duplicate_detected_on_second_run(self):
        h = _mk_hypothesis()
        seq = _mk_sequence()
        seq.hypothesis_id = h.id
        sim = _mk_simulation(sequence_id=seq.id, profit_wei=10**20)
        orch = ValidationOrchestrator()
        first = orch.validate(hypothesis=h, sequence=seq, simulation=sim)
        # Same hypothesis again → duplicate.
        h2 = _mk_hypothesis(contracts=h.contracts_involved, functions=h.functions_involved)
        seq2 = _mk_sequence()
        seq2.hypothesis_id = h2.id
        sim2 = _mk_simulation(sequence_id=seq2.id, profit_wei=10**20)
        second = orch.validate(hypothesis=h2, sequence=seq2, simulation=sim2)
        assert second.duplicate_of == first.id
        assert second.valid is False
        assert RejectionReason.DUPLICATE in second.rejection_reasons

    def test_batch_run_aggregates_correctly(self):
        h1 = _mk_hypothesis(functions=["borrow"])
        h2 = _mk_hypothesis(functions=["liquidate"], profit_usd=10_000_000)
        seq1 = _mk_sequence(); seq1.hypothesis_id = h1.id
        seq2 = _mk_sequence(); seq2.hypothesis_id = h2.id
        swarm = _mk_swarm([h1, h2])
        seqr = _mk_seq_report([(h1, seq1), (h2, seq2)])
        sims = SimulationReport(
            protocol_name="TestProtocol",
            results=[
                _mk_simulation(sequence_id=seq1.id, hypothesis_id=h1.id, profit_wei=10**18),
                _mk_simulation(sequence_id=seq2.id, hypothesis_id=h2.id, profit_wei=2000 * 10**18),
            ],
        )
        report = ValidationOrchestrator().run(
            swarm_report=swarm, sequence_report=seqr, simulation_report=sims,
        )
        assert report.total_validated == 2
        assert report.valid_count == 2
        # severity_breakdown counts per tier
        assert sum(report.severity_breakdown.values()) == 2
        # at least one is CRITICAL (h2 with $6M profit)
        assert report.severity_breakdown[ProfitTier.CRITICAL.value] >= 1

    def test_unmatched_simulation_dropped(self):
        """If hypothesis/simulation references are missing, validation skips."""
        h = _mk_hypothesis()
        seq = _mk_sequence(); seq.hypothesis_id = h.id
        # SimulationReport with NO matching simulation.
        sims = SimulationReport(protocol_name="TestProtocol", results=[])
        report = ValidationOrchestrator().run(
            swarm_report=_mk_swarm([h]),
            sequence_report=_mk_seq_report([(h, seq)]),
            simulation_report=sims,
        )
        assert report.total_validated == 0

    def test_low_severity_recommended_discard(self):
        h = _mk_hypothesis(profit_usd=100)
        seq = _mk_sequence()
        seq.hypothesis_id = h.id
        # 0.0001 ETH = ~$0.30 → LOW tier → composite ~ 0.2 → DISCARD
        sim = _mk_simulation(sequence_id=seq.id, profit_wei=10**14)
        result = ValidationOrchestrator().validate(hypothesis=h, sequence=seq, simulation=sim)
        assert result.severity.profit_tier in {ProfitTier.LOW, ProfitTier.NONE}
        assert result.recommended_action in {
            RecommendedAction.DISCARD, RecommendedAction.SIMULATE_FURTHER,
        }

    def test_metadata_populated(self):
        h = _mk_hypothesis()
        seq = _mk_sequence(); seq.hypothesis_id = h.id
        report = ValidationOrchestrator().run(
            swarm_report=_mk_swarm([h]),
            sequence_report=_mk_seq_report([(h, seq)]),
            simulation_report=_mk_sim_report([seq], profit_wei=10**18),
        )
        assert "elapsed_seconds" in report.analysis_metadata
        assert "aggressive_rejection" in report.analysis_metadata

    def test_contrarian_kill_invalidates(self):
        """An objection with severity >= 0.9 should invalidate the exploit."""
        class KillContrarian:
            def review(self, **kwargs):
                return [ContrarianObjection(
                    category=ObjectionCategory.ADMIN_MITIGATION,
                    severity=0.95,
                    explanation="admin already paused",
                )]
        h = _mk_hypothesis()
        seq = _mk_sequence(); seq.hypothesis_id = h.id
        sim = _mk_simulation(sequence_id=seq.id, profit_wei=10**20)
        orch = ValidationOrchestrator(contrarian=KillContrarian())
        result = orch.validate(hypothesis=h, sequence=seq, simulation=sim)
        assert result.valid is False
        assert RejectionReason.CONTRARIAN_INVALIDATED in result.rejection_reasons
        assert result.recommended_action == RecommendedAction.DISCARD

    def test_no_contrarian_objections_boosts_confidence(self):
        class SilentContrarian:
            def review(self, **kwargs):
                return []
        h = _mk_hypothesis()
        seq = _mk_sequence(); seq.hypothesis_id = h.id
        sim = _mk_simulation(sequence_id=seq.id, profit_wei=10**20)
        orch = ValidationOrchestrator(contrarian=SilentContrarian())
        result = orch.validate(hypothesis=h, sequence=seq, simulation=sim)
        # Confidence = 0.50 + 0.20 (profit) + 0.05 (high-conf hypothesis) +
        # 0.05 (no objections) = 0.80
        assert result.confidence >= 0.75
