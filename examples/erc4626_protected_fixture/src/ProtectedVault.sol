// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract MockERC20 {
    string public name = "Mock Asset";
    string public symbol = "MOCK";
    uint8 public decimals = 18;
    uint256 public totalSupply;

    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
        totalSupply += amount;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        require(balanceOf[msg.sender] >= amount, "balance");
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        uint256 allowed = allowance[from][msg.sender];
        require(allowed >= amount, "allowance");
        require(balanceOf[from] >= amount, "balance");
        if (allowed != type(uint256).max) {
            allowance[from][msg.sender] = allowed - amount;
        }
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        return true;
    }
}

/// @notice Donation-resistant vault: it tracks deposited assets internally and
/// applies a decimals offset (virtual shares), so a direct token donation does
/// not move the share price and a tiny first deposit cannot inflate it. This is
/// the inverse of `VulnerableVault` and exists to exercise ZeroPath's
/// anti-condition (inflation-mitigation) detection.
contract ProtectedVault {
    MockERC20 public immutable asset;
    string public name = "Protected Vault Share";
    string public symbol = "pMOCK";
    uint8 public decimals = 18;
    uint256 public totalSupply;

    // Internal asset accounting: direct donations to the vault are ignored.
    uint256 private _totalAssets;
    // Virtual shares via a decimals offset blunt first-deposit manipulation.
    uint8 private constant _DECIMALS_OFFSET = 3;

    mapping(address => uint256) public balanceOf;

    constructor(MockERC20 asset_) {
        asset = asset_;
    }

    function totalAssets() public view returns (uint256) {
        return _totalAssets;
    }

    function _decimalsOffset() internal pure returns (uint8) {
        return _DECIMALS_OFFSET;
    }

    function convertToShares(uint256 assets) public view returns (uint256) {
        return assets * (totalSupply + 10 ** _DECIMALS_OFFSET) / (_totalAssets + 1);
    }

    function convertToAssets(uint256 shares) public view returns (uint256) {
        return shares * (_totalAssets + 1) / (totalSupply + 10 ** _DECIMALS_OFFSET);
    }

    function deposit(uint256 assets, address receiver) external returns (uint256 shares) {
        shares = convertToShares(assets);
        require(asset.transferFrom(msg.sender, address(this), assets), "transfer failed");
        _totalAssets += assets;
        balanceOf[receiver] += shares;
        totalSupply += shares;
    }

    function redeem(uint256 shares, address receiver, address owner) external returns (uint256 assets) {
        require(owner == msg.sender, "owner");
        require(balanceOf[owner] >= shares, "shares");
        assets = convertToAssets(shares);
        balanceOf[owner] -= shares;
        totalSupply -= shares;
        _totalAssets -= assets;
        require(asset.transfer(receiver, assets), "transfer failed");
    }

    function withdraw(uint256 assets, address receiver, address owner) external returns (uint256 shares) {
        require(owner == msg.sender, "owner");
        shares = convertToShares(assets);
        require(balanceOf[owner] >= shares, "shares");
        balanceOf[owner] -= shares;
        totalSupply -= shares;
        _totalAssets -= assets;
        require(asset.transfer(receiver, assets), "transfer failed");
    }
}
