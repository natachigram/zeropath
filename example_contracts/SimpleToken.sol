// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * SimpleToken - Example ERC20-like contract for testing protocol analysis.
 *
 * This contract demonstrates:
 * - State variables and their visibility
 * - Function visibility levels
 * - Access control patterns
 * - Internal and external calls
 * - Asset transfers (ETH/tokens)
 */

contract SimpleToken {
    // State variables - various visibility and types
    string public name = "Simple Token";
    uint256 public totalSupply;
    address public owner;

    mapping(address => uint256) public balances;
    mapping(address => mapping(address => uint256)) public allowances;

    // Events
    event Transfer(address indexed from, address indexed to, uint256 amount);
    event Approval(
        address indexed owner,
        address indexed spender,
        uint256 amount
    );

    // Constructor - initializes owner and supply
    constructor(uint256 initialSupply) {
        owner = msg.sender;
        totalSupply = initialSupply;
        balances[owner] = initialSupply;
    }

    // Access control modifier
    modifier onlyOwner() {
        require(msg.sender == owner, "Only owner");
        _;
    }

    // External function to transfer tokens
    function transfer(address to, uint256 amount) external returns (bool) {
        require(balances[msg.sender] >= amount, "Insufficient balance");

        balances[msg.sender] -= amount;
        balances[to] += amount;

        emit Transfer(msg.sender, to, amount);
        return true;
    }

    // External function with access control
    function mint(address to, uint256 amount) external onlyOwner {
        totalSupply += amount;
        balances[to] += amount;
        emit Transfer(address(0), to, amount);
    }

    // Public view function
    function balanceOf(address account) public view returns (uint256) {
        return balances[account];
    }

    // Approval flow
    function approve(address spender, uint256 amount) external returns (bool) {
        allowances[msg.sender][spender] = amount;
        emit Approval(msg.sender, spender, amount);
        return true;
    }

    // TransferFrom - internal and external calls
    function transferFrom(
        address from,
        address to,
        uint256 amount
    ) external returns (bool) {
        require(allowances[from][msg.sender] >= amount, "Not approved");
        require(balances[from] >= amount, "Insufficient balance");

        allowances[from][msg.sender] -= amount;
        balances[from] -= amount;
        balances[to] += amount;

        emit Transfer(from, to, amount);
        return true;
    }

    // Internal helper function
    function _updateBalance(address account, uint256 amount) internal {
        balances[account] = amount;
    }
}

/**
 * TokenManager - Demonstrates more complex patterns
 */
contract TokenManager {
    SimpleToken public token;
    mapping(address => bool) public managers;

    constructor(address tokenAddress) {
        token = SimpleToken(tokenAddress);
        managers[msg.sender] = true;
    }

    modifier onlyManager() {
        require(managers[msg.sender], "Only manager");
        _;
    }

    // Delegate function - external call with complex flow
    function delegateTransfer(
        address from,
        address to,
        uint256 amount
    ) external onlyManager {
        // This demonstrates an external call to another contract
        token.transferFrom(from, to, amount);
    }

    // Batch operation
    function batchTransfer(
        address[] calldata recipients,
        uint256[] calldata amounts
    ) external onlyManager {
        require(recipients.length == amounts.length, "Length mismatch");

        for (uint256 i = 0; i < recipients.length; i++) {
            token.transferFrom(msg.sender, recipients[i], amounts[i]);
        }
    }
}
