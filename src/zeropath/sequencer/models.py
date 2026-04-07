"""
Data models for Phase 4: Transaction Sequence Generator.

A TransactionSequence is the concrete, executable form of a Phase 3
AttackHypothesis.  It specifies the exact on-chain calls an attacker
must make, in order, with parameters — plus the generated PoC code.

Downstream phases:
  Phase 5 — Simulation Engine (executes sequence on Foundry fork)
  Phase 6 — Exploit Validation Engine (asserts profit > 0)
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Optional
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------


class CallerType(str, Enum):
    """Who initiates a transaction."""

    ATTACKER_EOA = "attacker_eoa"
    """Standard externally owned account (no special contract)."""

    ATTACKER_CONTRACT = "attacker_contract"
    """Attacker deploys a contract (required for callbacks: receive, executeOperation)."""

    FLASHBOT_BUNDLE = "flashbot_bundle"
    """Multiple txs must land atomically in one block via Flashbots."""

    ANY_EOA = "any_eoa"
    """Any address can call — no special caller required."""


class CallEncoding(str, Enum):
    """How the call is encoded."""

    SOLIDITY_CALL = "solidity_call"
    """Direct Solidity function call with ABI-encoded arguments."""

    LOW_LEVEL_CALL = "low_level_call"
    """address.call{value: X}(abi.encodeWithSelector(...))"""

    DELEGATECALL = "delegatecall"
    """address.delegatecall(...)"""

    ETH_TRANSFER = "eth_transfer"
    """payable(addr).transfer(amount) — no calldata"""

    STATIC_CALL = "static_call"
    """View-only call used to read state before/after attack step."""


class TestFramework(str, Enum):
    """Target framework for generated PoC code."""

    FOUNDRY = "foundry"
    HARDHAT = "hardhat"
    BOTH = "both"


class SequenceStatus(str, Enum):
    """Lifecycle state of a sequence."""

    GENERATED = "generated"
    """Sequence built from hypothesis — not yet tested."""

    SIMULATION_PENDING = "simulation_pending"
    """Queued for Phase 5 simulation."""

    SIMULATION_PASSED = "simulation_passed"
    """Simulation confirmed the attack executes without revert."""

    SIMULATION_FAILED = "simulation_failed"
    """Simulation reverted — sequence needs repair or hypothesis is invalid."""

    VALIDATED = "validated"
    """Phase 6 confirmed profitable under realistic conditions."""

    REJECTED = "rejected"
    """Not profitable or requires unrealistic preconditions."""


# ---------------------------------------------------------------------------
# Sub-models
# ---------------------------------------------------------------------------


class TxCall(BaseModel):
    """A single transaction or call within an attack sequence."""

    model_config = ConfigDict(populate_by_name=True)

    step: int = Field(description="1-indexed step number within the sequence")
    description: str = Field(description="Human-readable description of this call")

    # Target
    target_address_expr: str = Field(
        description="Solidity expression resolving to target address (e.g. 'address(vault)', 'AAVE_V3')"
    )
    function_signature: Optional[str] = Field(
        None,
        description="Full Solidity signature e.g. 'flashLoan(address[],uint256[],uint256[],bytes)'"
    )
    function_selector: Optional[str] = Field(
        None, description="4-byte selector hex e.g. '0xab123456'"
    )
    calldata_expr: str = Field(
        "", description="Solidity expression for calldata or argument list"
    )
    value_expr: str = Field(
        "0", description="ETH value expression e.g. '1 ether', 'flashAmount'"
    )

    # Caller
    caller_type: CallerType = CallerType.ATTACKER_CONTRACT
    encoding: CallEncoding = CallEncoding.SOLIDITY_CALL

    # Assertions at this step
    pre_assertions: list[str] = Field(
        default_factory=list,
        description="Solidity assert/require statements to validate state BEFORE this call"
    )
    post_assertions: list[str] = Field(
        default_factory=list,
        description="Solidity assert/require statements to validate state AFTER this call"
    )

    # Expected gas
    estimated_gas: Optional[int] = None

    # Revert-safe: if True, this call is expected to potentially revert (try/catch)
    revert_safe: bool = False


class AttackContext(BaseModel):
    """
    Environment configuration needed to execute the attack sequence.

    Encodes the fork configuration, initial balances, and any
    mock contracts that need to be deployed before the sequence runs.
    """

    model_config = ConfigDict(populate_by_name=True)

    # Fork configuration
    chain: str = Field("mainnet", description="Chain name (mainnet, arbitrum, polygon, etc.)")
    fork_block: Optional[int] = Field(
        None,
        description="Specific block to fork at. None = latest."
    )
    rpc_url_env_var: str = Field(
        "ETH_RPC_URL",
        description="Environment variable name holding the RPC URL"
    )

    # Known contract addresses (populated from on-chain data or graph)
    contract_addresses: dict[str, str] = Field(
        default_factory=dict,
        description="Map of contract_name → address (e.g. {'Vault': '0x...'})"
    )

    # Attacker setup
    attacker_address: str = Field(
        "address(this)",
        description="Solidity expression for attacker address"
    )
    attacker_eth_balance: str = Field(
        "100 ether",
        description="Initial ETH balance to give the attacker (for deal() calls)"
    )
    attacker_token_balances: dict[str, str] = Field(
        default_factory=dict,
        description="Map of token_address → amount expression"
    )

    # External dependencies
    flash_loan_provider: Optional[str] = Field(
        None,
        description="Address of flash loan provider (Aave V3, Balancer, etc.)"
    )
    oracle_address: Optional[str] = Field(
        None, description="Address of the oracle being manipulated"
    )

    # MEV configuration
    requires_private_mempool: bool = Field(
        False,
        description="True if attack must be submitted via Flashbots to avoid front-running"
    )
    requires_single_block: bool = Field(
        True,
        description="True if all steps must occur within one block"
    )

    # Deployment prerequisites
    requires_attacker_contract: bool = Field(
        False,
        description="True if attacker must deploy a contract (for callbacks)"
    )


class GeneratedTest(BaseModel):
    """Generated PoC code for a specific test framework."""

    model_config = ConfigDict(populate_by_name=True)

    framework: TestFramework
    filename: str = Field(description="Suggested filename (e.g. 'TestOracleAttack.t.sol')")
    code: str = Field(description="Complete, runnable test file content")
    run_command: str = Field(description="Command to execute the test")
    notes: list[str] = Field(
        default_factory=list,
        description="Notes for the user (e.g. 'set ETH_RPC_URL before running')"
    )


class ProfitEstimate(BaseModel):
    """Estimated financial impact of the attack."""

    model_config = ConfigDict(populate_by_name=True)

    asset: str = Field(description="Asset extracted (ETH, token symbol, etc.)")
    min_profit_expression: str = Field(
        description="Solidity expression for minimum expected profit"
    )
    max_profit_expression: str = Field(
        description="Upper bound (often = protocol TVL)"
    )
    cost_expression: str = Field(
        description="Total attacker cost (flash loan fee + gas)"
    )
    scales_with_tvl: bool = True
    notes: str = ""


# ---------------------------------------------------------------------------
# Core sequence model
# ---------------------------------------------------------------------------


class TransactionSequence(BaseModel):
    """
    A concrete, executable attack sequence derived from a Phase 3 hypothesis.

    This is the primary output of Phase 4.
    It is consumed by:
      Phase 5 (EVM simulation engine)
      Phase 6 (exploit validation engine)
    """

    model_config = ConfigDict(populate_by_name=True)

    id: str = Field(default_factory=lambda: str(uuid4()))

    # Source hypothesis
    hypothesis_id: str
    hypothesis_title: str
    attack_class: str

    # Sequence
    calls: list[TxCall] = Field(
        default_factory=list,
        description="Ordered transaction calls — must be executed in this order"
    )
    context: AttackContext = Field(default_factory=AttackContext)
    profit_estimate: Optional[ProfitEstimate] = None

    # Generated code
    foundry_test: Optional[GeneratedTest] = None
    hardhat_test: Optional[GeneratedTest] = None

    # Lifecycle
    status: SequenceStatus = SequenceStatus.GENERATED

    # Quality metrics
    completeness_score: float = Field(
        0.5, ge=0.0, le=1.0,
        description=(
            "How complete the sequence is: 1.0 = all addresses known, all params specified; "
            "0.5 = some placeholders; 0.0 = skeleton only"
        )
    )
    requires_manual_params: list[str] = Field(
        default_factory=list,
        description="Parameters that require manual lookup (e.g. exact token addresses)"
    )

    # Notes for the auditor
    auditor_notes: list[str] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Sequence report (root output of Phase 4)
# ---------------------------------------------------------------------------


class SequenceReport(BaseModel):
    """
    Complete output of one Phase 4 run.

    Input:  Phase 3 SwarmReport
    Output: Ranked list of TransactionSequences with PoC code
    """

    model_config = ConfigDict(populate_by_name=True)

    id: str = Field(default_factory=lambda: str(uuid4()))
    protocol_name: str = "unknown"

    # Link back to Phase 3
    swarm_report_id: str = ""

    # The sequences — sorted by completeness DESC, then hypothesis confidence DESC
    sequences: list[TransactionSequence] = Field(default_factory=list)

    # Aggregate stats
    total_hypotheses_input: int = 0
    sequences_generated: int = 0
    sequences_with_full_poc: int = 0
    sequences_requiring_manual_params: int = 0

    # Run metadata
    analysis_metadata: dict[str, Any] = Field(default_factory=dict)

    @property
    def ready_to_simulate(self) -> list[TransactionSequence]:
        """Sequences complete enough to submit directly to Phase 5."""
        return [s for s in self.sequences if s.completeness_score >= 0.70]

    @property
    def by_attack_class(self) -> dict[str, list[TransactionSequence]]:
        result: dict[str, list[TransactionSequence]] = {}
        for s in self.sequences:
            result.setdefault(s.attack_class, []).append(s)
        return result
