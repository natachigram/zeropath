"""
Data models for Phase 2: Invariant Inference Engine.

Every model here is the structured output of the invariant inference
pipeline.  Downstream phases (3 = attack hypothesis, 5 = simulation,
6 = validation) consume these models directly.
"""

from enum import Enum
from typing import Any, Optional
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------


class InvariantType(str, Enum):
    """The class of protocol property being expressed."""

    VALUE_CONSERVATION = "value_conservation"
    """Total assets entering a protocol equal total assets leaving + fees."""

    BALANCE_CONSISTENCY = "balance_consistency"
    """Sum of all user balances equals totalSupply at all times."""

    COLLATERALIZATION = "collateralization"
    """Collateral value always exceeds debt * min_collateral_ratio."""

    ORACLE_MANIPULATION = "oracle_manipulation"
    """Protocol's price feeds cannot be manipulated within a single block."""

    ACCESS_CONTROL = "access_control"
    """Privileged operations require the correct role or ownership."""

    REENTRANCY = "reentrancy"
    """External calls do not allow re-entry into partially-updated state."""

    FLASH_LOAN_SAFETY = "flash_loan_safety"
    """Flash-loan-funded operations cannot permanently drain protocol funds."""

    SHARE_ACCOUNTING = "share_accounting"
    """Share-to-asset exchange rate never decreases unexpectedly."""

    GOVERNANCE_SAFETY = "governance_safety"
    """Governance execution cannot be weaponised via flash loans or instant voting."""

    CROSS_PROTOCOL = "cross_protocol"
    """Invariant spans multiple protocols; all trust assumptions must hold simultaneously."""

    LIQUIDITY_CONSERVATION = "liquidity_conservation"
    """AMM constant product (or sum) invariant x*y ≥ k is never violated."""


class OracleType(str, Enum):
    """Classification of a price oracle source."""

    CHAINLINK = "chainlink"
    UNISWAP_SPOT = "uniswap_spot"     # getReserves() — single-block, HIGH risk
    UNISWAP_TWAP = "uniswap_twap"     # consult() / observe() — safer
    BALANCER_TWAP = "balancer_twap"
    BAND_PROTOCOL = "band_protocol"
    CUSTOM = "custom"
    UNKNOWN = "unknown"


class OracleManipulationRisk(str, Enum):
    """Qualitative risk of oracle price manipulation."""

    HIGH = "high"       # single-block spot price (getReserves)
    MEDIUM = "medium"   # short TWAP (<= 10 min)
    LOW = "low"         # Chainlink / long TWAP (>= 30 min)


class InvariantSeverity(str, Enum):
    """Severity of an invariant violation."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class DeFiProtocolType(str, Enum):
    """Detected DeFi protocol category (may be multi-valued)."""

    ERC20 = "erc20"
    ERC721 = "erc721"
    ERC4626 = "erc4626"       # tokenised vault
    LENDING = "lending"        # Aave/Compound-style
    AMM = "amm"                # Uniswap/Curve-style
    STAKING = "staking"
    GOVERNANCE = "governance"
    FLASH_LOAN = "flash_loan"
    BRIDGE = "bridge"
    ORACLE = "oracle"
    UNKNOWN = "unknown"


# ---------------------------------------------------------------------------
# Supporting models
# ---------------------------------------------------------------------------


class OracleDependency(BaseModel):
    """A detected dependency on an external price oracle."""

    model_config = ConfigDict(populate_by_name=True)

    id: str = Field(default_factory=lambda: str(uuid4()))
    contract_name: str
    function_name: str
    oracle_contract: str           # e.g. "AggregatorV3Interface", "IUniswapV2Pair"
    oracle_type: OracleType = OracleType.UNKNOWN
    read_function: str             # e.g. "latestRoundData", "getReserves", "slot0"
    is_single_block: bool = False  # True = spot price, manipulable in one block
    manipulation_risk: OracleManipulationRisk = OracleManipulationRisk.MEDIUM
    used_in_state_changing_function: bool = False
    evidence: str = ""


class HistoricalPrecedent(BaseModel):
    """A real-world exploit that violated an invariant of the same class."""

    model_config = ConfigDict(populate_by_name=True)

    protocol: str
    date: str
    loss_usd: int
    attack_class: str
    invariant_type: InvariantType
    description: str
    root_cause: str
    source_url: str
    tags: list[str] = Field(default_factory=list)


class FormalSpec(BaseModel):
    """Machine-checkable formal specification for an invariant."""

    model_config = ConfigDict(populate_by_name=True)

    halmos: Optional[str] = Field(
        None,
        description="Python assertion string for Halmos symbolic execution"
    )
    certora_cvl: Optional[str] = Field(
        None,
        description="Certora Verification Language rule"
    )
    natural_language: str = Field(
        description="Human-readable statement of the invariant property"
    )


# ---------------------------------------------------------------------------
# Core invariant model
# ---------------------------------------------------------------------------


class Invariant(BaseModel):
    """
    A single inferred protocol invariant.

    This is the primary output of Phase 2.  Each invariant describes a
    property that must hold for the protocol to be secure, grounded in:
      - the structural analysis of the protocol graph
      - historical exploit precedent from DeFiHackLabs / Rekt / Immunefi
      - cross-protocol composability reasoning
    """

    model_config = ConfigDict(populate_by_name=True)

    id: str = Field(default_factory=lambda: str(uuid4()))
    type: InvariantType
    severity: InvariantSeverity = InvariantSeverity.MEDIUM
    description: str
    formal_spec: Optional[FormalSpec] = None

    # Confidence: boosted by historical precedent, lowered by ambiguity
    confidence: float = Field(0.5, ge=0.0, le=1.0)

    # Graph elements involved
    contracts_involved: list[str] = Field(default_factory=list)
    functions_involved: list[str] = Field(default_factory=list)
    state_vars_involved: list[str] = Field(default_factory=list)

    # Oracle and cross-protocol context
    oracle_dependencies: list[OracleDependency] = Field(default_factory=list)
    cross_protocol_scope: list[str] = Field(default_factory=list)

    # Exploit grounding
    historical_precedent: list[HistoricalPrecedent] = Field(default_factory=list)

    # Human-readable evidence for the inference
    evidence: list[str] = Field(default_factory=list)

    # Which detector produced this
    detector: str = ""


# ---------------------------------------------------------------------------
# Protocol pattern (output of patterns.py)
# ---------------------------------------------------------------------------


class ProtocolPattern(BaseModel):
    """
    Summary of detected DeFi patterns in a ProtocolGraph.

    Produced by DeFiPatternDetector and consumed by every invariant detector.
    """

    model_config = ConfigDict(populate_by_name=True)

    protocol_types: list[DeFiProtocolType] = Field(default_factory=list)

    # Token pattern
    is_erc20: bool = False
    is_erc721: bool = False
    is_erc4626: bool = False

    # Function buckets (function names matching each category)
    deposit_functions: list[str] = Field(default_factory=list)
    withdraw_functions: list[str] = Field(default_factory=list)
    mint_functions: list[str] = Field(default_factory=list)
    burn_functions: list[str] = Field(default_factory=list)
    borrow_functions: list[str] = Field(default_factory=list)
    repay_functions: list[str] = Field(default_factory=list)
    liquidate_functions: list[str] = Field(default_factory=list)
    swap_functions: list[str] = Field(default_factory=list)
    stake_functions: list[str] = Field(default_factory=list)
    governance_functions: list[str] = Field(default_factory=list)
    flash_loan_functions: list[str] = Field(default_factory=list)
    admin_functions: list[str] = Field(default_factory=list)
    payable_functions: list[str] = Field(default_factory=list)

    # State variable buckets
    balance_vars: list[str] = Field(default_factory=list)
    supply_vars: list[str] = Field(default_factory=list)
    oracle_vars: list[str] = Field(default_factory=list)
    share_vars: list[str] = Field(default_factory=list)
    debt_vars: list[str] = Field(default_factory=list)
    collateral_vars: list[str] = Field(default_factory=list)
    fee_vars: list[str] = Field(default_factory=list)
    timelock_vars: list[str] = Field(default_factory=list)

    # Security features
    has_reentrancy_guard: bool = False
    has_access_control: bool = False
    has_timelock: bool = False
    has_flash_loan: bool = False
    has_oracle: bool = False
    is_upgradeable: bool = False


# ---------------------------------------------------------------------------
# Report (root output of Phase 2)
# ---------------------------------------------------------------------------


class InvariantReport(BaseModel):
    """
    Complete output of one invariant inference run.

    This is the top-level output consumed by Phase 3 (attack hypothesis).
    """

    model_config = ConfigDict(populate_by_name=True)

    id: str = Field(default_factory=lambda: str(uuid4()))
    protocol_name: str = "unknown"
    protocol_pattern: ProtocolPattern = Field(default_factory=ProtocolPattern)
    invariants: list[Invariant] = Field(default_factory=list)
    oracle_dependencies: list[OracleDependency] = Field(default_factory=list)
    analysis_metadata: dict[str, Any] = Field(default_factory=dict)

    @property
    def critical_invariants(self) -> list[Invariant]:
        return [i for i in self.invariants if i.severity == InvariantSeverity.CRITICAL]

    @property
    def high_invariants(self) -> list[Invariant]:
        return [i for i in self.invariants if i.severity == InvariantSeverity.HIGH]

    @property
    def invariants_by_type(self) -> dict[InvariantType, list[Invariant]]:
        result: dict[InvariantType, list[Invariant]] = {}
        for inv in self.invariants:
            result.setdefault(inv.type, []).append(inv)
        return result
