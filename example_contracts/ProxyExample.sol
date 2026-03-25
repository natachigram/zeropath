// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * ProxyExample.sol
 *
 * Demonstrates a UUPS (EIP-1822) upgradeable proxy pattern with:
 *   - ERC-1967 implementation slot
 *   - _authorizeUpgrade access control
 *   - Transparent storage separation between proxy and implementation
 *
 * Used by ZeroPath Phase 1 tests to verify proxy detection accuracy.
 */

// ---------------------------------------------------------------------------
// Minimal OpenZeppelin-compatible interfaces (self-contained for testing)
// ---------------------------------------------------------------------------

interface IBeacon {
    function implementation() external view returns (address);
}

// ---------------------------------------------------------------------------
// StorageSlot utility (from OZ)
// ---------------------------------------------------------------------------

library StorageSlot {
    struct AddressSlot {
        address value;
    }

    function getAddressSlot(bytes32 slot) internal pure returns (AddressSlot storage r) {
        assembly {
            r.slot := slot
        }
    }
}

// ---------------------------------------------------------------------------
// ERC-1967 storage slots (keccak256(name) - 1)
// ---------------------------------------------------------------------------

abstract contract ERC1967Upgrade {
    bytes32 internal constant _IMPLEMENTATION_SLOT =
        0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;

    bytes32 internal constant _ADMIN_SLOT =
        0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103;

    event Upgraded(address indexed implementation);
    event AdminChanged(address previousAdmin, address newAdmin);

    function _getImplementation() internal view returns (address) {
        return StorageSlot.getAddressSlot(_IMPLEMENTATION_SLOT).value;
    }

    function _setImplementation(address newImplementation) private {
        StorageSlot.getAddressSlot(_IMPLEMENTATION_SLOT).value = newImplementation;
    }

    function _upgradeTo(address newImplementation) internal {
        _setImplementation(newImplementation);
        emit Upgraded(newImplementation);
    }

    function _upgradeToAndCall(address newImplementation, bytes memory data) internal {
        _upgradeTo(newImplementation);
        if (data.length > 0) {
            (bool success, ) = newImplementation.delegatecall(data);
            require(success, "ERC1967: upgrade call reverted");
        }
    }

    function _getAdmin() internal view returns (address) {
        return StorageSlot.getAddressSlot(_ADMIN_SLOT).value;
    }

    function _setAdmin(address newAdmin) private {
        StorageSlot.getAddressSlot(_ADMIN_SLOT).value = newAdmin;
    }

    function _changeAdmin(address newAdmin) internal {
        emit AdminChanged(_getAdmin(), newAdmin);
        _setAdmin(newAdmin);
    }
}

// ---------------------------------------------------------------------------
// UUPS Proxy
// ---------------------------------------------------------------------------

/**
 * UUPSProxy — Minimal UUPS upgradeable proxy.
 *
 * Upgrade logic lives on the implementation, not the proxy.
 * The proxy only delegates all calls and exposes the admin slot.
 */
contract UUPSProxy is ERC1967Upgrade {
    constructor(address implementation_, bytes memory data) {
        _upgradeTo(implementation_);
        _changeAdmin(msg.sender);
        if (data.length > 0) {
            (bool success, ) = implementation_.delegatecall(data);
            require(success, "UUPSProxy: init failed");
        }
    }

    /// @notice Returns the current implementation address.
    function implementation() external view returns (address) {
        return _getImplementation();
    }

    /// @notice Returns the proxy admin address.
    function admin() external view returns (address) {
        return _getAdmin();
    }

    fallback() external payable {
        address impl = _getImplementation();
        require(impl != address(0), "UUPSProxy: no implementation");
        assembly {
            calldatacopy(0, 0, calldatasize())
            let result := delegatecall(gas(), impl, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            switch result
            case 0 { revert(0, returndatasize()) }
            default { return(0, returndatasize()) }
        }
    }

    receive() external payable {}
}

// ---------------------------------------------------------------------------
// UUPSUpgradeable base (implementation-side logic)
// ---------------------------------------------------------------------------

abstract contract UUPSUpgradeable is ERC1967Upgrade {
    address private immutable __self = address(this);

    modifier onlyProxy() {
        require(address(this) != __self, "UUPSUpgradeable: not delegated");
        _;
    }

    /// @dev Override to add upgrade authorization logic.
    function _authorizeUpgrade(address newImplementation) internal virtual;

    function upgradeTo(address newImplementation) external onlyProxy {
        _authorizeUpgrade(newImplementation);
        _upgradeTo(newImplementation);
    }

    function upgradeToAndCall(address newImplementation, bytes memory data) external payable onlyProxy {
        _authorizeUpgrade(newImplementation);
        _upgradeToAndCall(newImplementation, data);
    }
}

// ---------------------------------------------------------------------------
// Concrete implementation (example vault logic)
// ---------------------------------------------------------------------------

/**
 * VaultImplementationV1 — First implementation behind the UUPS proxy.
 *
 * Intentionally simple to demonstrate:
 *   - Payable functions (deposit)
 *   - Access-controlled mutation (withdraw only owner)
 *   - State variable layout
 *   - Emitted events
 */
contract VaultImplementationV1 is UUPSUpgradeable {
    address public owner;
    uint256 public totalDeposits;
    mapping(address => uint256) public deposits;

    event Deposited(address indexed user, uint256 amount);
    event Withdrawn(address indexed user, uint256 amount);

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    function initialize(address owner_) external {
        require(owner == address(0), "already initialized");
        owner = owner_;
    }

    function deposit() external payable {
        require(msg.value > 0, "zero deposit");
        deposits[msg.sender] += msg.value;
        totalDeposits += msg.value;
        emit Deposited(msg.sender, msg.value);
    }

    function withdraw(uint256 amount) external {
        require(deposits[msg.sender] >= amount, "insufficient balance");
        deposits[msg.sender] -= amount;
        totalDeposits -= amount;
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "transfer failed");
        emit Withdrawn(msg.sender, amount);
    }

    function balanceOf(address user) external view returns (uint256) {
        return deposits[user];
    }

    /// @dev Only the owner can authorize an upgrade.
    function _authorizeUpgrade(address) internal override onlyOwner {}
}

// ---------------------------------------------------------------------------
// V2 — adds a fee mechanism (demonstrates version diff surface expansion)
// ---------------------------------------------------------------------------

contract VaultImplementationV2 is UUPSUpgradeable {
    address public owner;
    uint256 public totalDeposits;
    uint256 public feeBps;          // NEW in v2: basis points fee
    address public feeRecipient;    // NEW in v2
    mapping(address => uint256) public deposits;

    event Deposited(address indexed user, uint256 amount);
    event Withdrawn(address indexed user, uint256 amount, uint256 fee);
    event FeeUpdated(uint256 newFeeBps);

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    function initialize(address owner_, uint256 feeBps_, address feeRecipient_) external {
        require(owner == address(0), "already initialized");
        owner = owner_;
        feeBps = feeBps_;
        feeRecipient = feeRecipient_;
    }

    function deposit() external payable {
        require(msg.value > 0, "zero deposit");
        deposits[msg.sender] += msg.value;
        totalDeposits += msg.value;
        emit Deposited(msg.sender, msg.value);
    }

    // NOTE: NEW external call to feeRecipient — new attack surface vs V1
    function withdraw(uint256 amount) external {
        require(deposits[msg.sender] >= amount, "insufficient balance");
        uint256 fee = (amount * feeBps) / 10_000;
        uint256 net = amount - fee;
        deposits[msg.sender] -= amount;
        totalDeposits -= amount;

        if (fee > 0 && feeRecipient != address(0)) {
            (bool feeOk, ) = feeRecipient.call{value: fee}("");
            require(feeOk, "fee transfer failed");
        }

        (bool ok, ) = msg.sender.call{value: net}("");
        require(ok, "transfer failed");
        emit Withdrawn(msg.sender, amount, fee);
    }

    // NEW in v2 — privileged function
    function setFee(uint256 newFeeBps) external onlyOwner {
        require(newFeeBps <= 1000, "fee too high");
        feeBps = newFeeBps;
        emit FeeUpdated(newFeeBps);
    }

    function balanceOf(address user) external view returns (uint256) {
        return deposits[user];
    }

    function _authorizeUpgrade(address) internal override onlyOwner {}
}
