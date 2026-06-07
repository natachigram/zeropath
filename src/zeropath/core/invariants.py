"""Protocol invariant templates used by adapters and intent generation."""

from __future__ import annotations

from zeropath.core.schemas import Invariant


def invariants_for_protocol_type(protocol_type: str | None, contracts: list[str] | None = None) -> list[Invariant]:
    """Return initial invariant suggestions for a protocol type."""

    contracts = contracts or []
    ptype = (protocol_type or "unknown").lower()
    if ptype in {"vault", "erc4626"}:
        return [
            Invariant(
                id="INV-VLT-001",
                title="Share price must not be profitably manipulable",
                description="Deposits, withdrawals, donations, and rounding must not let an attacker extract more assets than economically justified.",
                invariant_type="asset_accounting",
                protocol_type="vault",
                affected_contracts=contracts,
                severity_if_broken="high",
                source="evm heuristic",
            ),
            Invariant(
                id="INV-VLT-002",
                title="Total shares must correspond to withdrawable assets",
                description="Accounting must preserve the relationship between total supply, total assets, and user redeemability.",
                invariant_type="redeemability",
                protocol_type="vault",
                affected_contracts=contracts,
                severity_if_broken="high",
                source="evm heuristic",
            ),
        ]
    if ptype == "lending":
        return [
            Invariant(
                id="INV-LEND-001",
                title="Borrows must be bounded by collateral value",
                description="An account must not borrow or remain undercollateralized beyond protocol-defined collateral constraints.",
                invariant_type="collateralization",
                protocol_type="lending",
                affected_contracts=contracts,
                severity_if_broken="critical",
                source="evm heuristic",
            ),
            Invariant(
                id="INV-LEND-002",
                title="Liquidation must not create bad debt or theft",
                description="Liquidation thresholds, close factors, incentives, and oracle values must preserve solvency.",
                invariant_type="liquidation",
                protocol_type="lending",
                affected_contracts=contracts,
                severity_if_broken="high",
                source="evm heuristic",
            ),
        ]
    if ptype in {"staking", "rewards", "staking/rewards"}:
        return [
            Invariant(
                id="INV-REWARD-001",
                title="Reward indexes must stay synchronized with balance changes",
                description="Stake, unstake, transfer, mint, burn, and claim paths must not let users claim unearned rewards.",
                invariant_type="reward_accounting",
                protocol_type="staking/rewards",
                affected_contracts=contracts,
                severity_if_broken="high",
                source="evm heuristic",
            )
        ]
    if ptype == "bridge":
        return [
            Invariant(
                id="INV-BRIDGE-001",
                title="Messages must not be replayable or double executable",
                description="Source domains, senders, nonces, and execution state must authenticate every bridge message exactly once.",
                invariant_type="cross_chain_authentication",
                protocol_type="bridge",
                affected_contracts=contracts,
                severity_if_broken="critical",
                source="evm heuristic",
            )
        ]
    if ptype == "oracle":
        return [
            Invariant(
                id="INV-ORACLE-001",
                title="Prices must be fresh and bounded before value-sensitive use",
                description="Oracle reads feeding minting, borrowing, redemption, or liquidation must reject stale or invalid prices.",
                invariant_type="oracle_integrity",
                protocol_type="oracle",
                affected_contracts=contracts,
                severity_if_broken="high",
                source="evm heuristic",
            )
        ]
    return [
        Invariant(
            id="INV-GEN-001",
            title="Value-sensitive state transitions must preserve protocol accounting",
            description="Entrypoints that move or account for assets should have a concrete invariant before exploit claims are reported.",
            invariant_type="generic_accounting",
            protocol_type=protocol_type,
            affected_contracts=contracts,
            severity_if_broken="unknown",
            source="core fallback",
        )
    ]
