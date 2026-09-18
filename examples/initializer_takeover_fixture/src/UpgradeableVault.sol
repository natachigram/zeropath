// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @notice Upgradeable-style vault whose one-time setup function is left open.
/// `initialize` has no one-time guard, no constructor lockout, and no access
/// control, so any caller can run it and become `owner`, then use owner-only
/// controls (e.g. `sweep`). The protected shape lives in the protected fixture.
contract UpgradeableVault {
    address public owner;
    uint256 public totalManaged;

    function initialize(address owner_) external {
        owner = owner_;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    function setOwner(address newOwner) external onlyOwner {
        owner = newOwner;
    }

    receive() external payable {
        totalManaged += msg.value;
    }

    function sweep(address payable to) external onlyOwner {
        uint256 amount = address(this).balance;
        totalManaged = 0;
        to.transfer(amount);
    }
}
