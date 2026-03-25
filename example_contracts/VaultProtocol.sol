// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * VaultProtocol.sol
 *
 * A realistic multi-contract DeFi lending vault for ZeroPath Phase 1 analysis.
 *
 * Demonstrates all Phase 1 extraction targets:
 *   - Multiple contracts with inheritance
 *   - Complex call graph (cross-contract)
 *   - Diverse state variable types (mappings, arrays, structs, enums)
 *   - Access control patterns (onlyOwner, onlyRole, modifiers)
 *   - External dependencies (oracle interface, ERC20 interface)
 *   - ETH and token asset flows
 *   - Payable functions
 *   - Events
 *   - Library calls
 *   - Low-level calls
 *
 * Intentionally contains patterns that Phase 2+ will flag as invariant candidates:
 *   - totalDebt tracks sum of all borrows (conservation invariant)
 *   - collateral ratio must exceed threshold before borrow
 *   - only borrower can repay their own debt
 */

// ---------------------------------------------------------------------------
// External interfaces (become ExternalDependency nodes in Phase 1)
// ---------------------------------------------------------------------------

interface IERC20 {
    function totalSupply() external view returns (uint256);
    function balanceOf(address account) external view returns (uint256);
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function approve(address spender, uint256 amount) external returns (bool);
}

interface IPriceOracle {
    function getPrice(address token) external view returns (uint256);
    function getLatestPrice() external view returns (uint256, uint256); // price, timestamp
}

interface IFlashLoanReceiver {
    function executeOperation(
        address asset,
        uint256 amount,
        uint256 premium,
        address initiator,
        bytes calldata params
    ) external returns (bool);
}

// ---------------------------------------------------------------------------
// Libraries
// ---------------------------------------------------------------------------

library MathLib {
    function mulDiv(uint256 a, uint256 b, uint256 denominator) internal pure returns (uint256) {
        return (a * b) / denominator;
    }

    function percentOf(uint256 amount, uint256 bps) internal pure returns (uint256) {
        return (amount * bps) / 10_000;
    }
}

// ---------------------------------------------------------------------------
// Base access control
// ---------------------------------------------------------------------------

abstract contract AccessControl {
    address public owner;
    mapping(address => mapping(bytes32 => bool)) private _roles;

    bytes32 public constant ROLE_MANAGER = keccak256("ROLE_MANAGER");
    bytes32 public constant ROLE_LIQUIDATOR = keccak256("ROLE_LIQUIDATOR");

    event OwnershipTransferred(address indexed previous, address indexed next);
    event RoleGranted(bytes32 indexed role, address indexed account);
    event RoleRevoked(bytes32 indexed role, address indexed account);

    constructor() {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "AccessControl: not owner");
        _;
    }

    modifier onlyRole(bytes32 role) {
        require(_roles[msg.sender][role], "AccessControl: missing role");
        _;
    }

    function grantRole(bytes32 role, address account) external onlyOwner {
        _roles[account][role] = true;
        emit RoleGranted(role, account);
    }

    function revokeRole(bytes32 role, address account) external onlyOwner {
        _roles[account][role] = false;
        emit RoleRevoked(role, account);
    }

    function hasRole(bytes32 role, address account) public view returns (bool) {
        return _roles[account][role];
    }

    function transferOwnership(address newOwner) external onlyOwner {
        emit OwnershipTransferred(owner, newOwner);
        owner = newOwner;
    }
}

// ---------------------------------------------------------------------------
// Vault state types
// ---------------------------------------------------------------------------

/// @notice Position lifecycle states.
enum PositionStatus { Active, Liquidated, Repaid }

/// @notice A borrower's collateral + debt position.
struct Position {
    address borrower;
    address collateralToken;
    uint256 collateralAmount;
    uint256 debtAmount;
    uint256 openedAt;
    PositionStatus status;
}

// ---------------------------------------------------------------------------
// Core Lending Vault
// ---------------------------------------------------------------------------

/**
 * LendingVault — The primary contract.
 *
 * Key invariants (to be inferred by Phase 2):
 *   1. sum(positions[i].debtAmount) == totalDebt  (conservation)
 *   2. collateralValue(position) / position.debtAmount >= MIN_COLLATERAL_RATIO
 *      before any borrow succeeds  (collateralization)
 *   3. Only the position's borrower can repay it  (access control)
 *   4. Flash loan must be repaid within the same transaction  (atomicity)
 */
contract LendingVault is AccessControl {
    using MathLib for uint256;

    // --- Configuration ---
    IERC20 public immutable debtToken;
    IPriceOracle public oracle;
    address public treasuryAddress;

    uint256 public constant MIN_COLLATERAL_RATIO = 15_000; // 150% in bps (10_000 = 100%)
    uint256 public constant LIQUIDATION_THRESHOLD = 12_000; // 120%
    uint256 public constant FLASH_LOAN_FEE_BPS = 9;         // 0.09%
    uint256 public constant MAX_POSITIONS = 1000;

    // --- Vault state ---
    uint256 public totalDebt;
    uint256 public totalCollateral;
    uint256 public flashLoanActive;   // re-entrancy guard for flash loans
    bool public paused;

    // --- Positions ---
    mapping(uint256 => Position) public positions;
    mapping(address => uint256[]) public borrowerPositions;
    uint256 public nextPositionId;

    // --- Whitelisted collateral tokens ---
    mapping(address => bool) public approvedCollateral;
    address[] public collateralList;

    // --- Events ---
    event PositionOpened(uint256 indexed id, address indexed borrower, uint256 collateral, uint256 debt);
    event PositionRepaid(uint256 indexed id, address indexed borrower, uint256 amount);
    event PositionLiquidated(uint256 indexed id, address indexed liquidator, uint256 seized);
    event FlashLoan(address indexed receiver, address indexed token, uint256 amount, uint256 fee);
    event Paused(address indexed by);
    event Unpaused(address indexed by);
    event CollateralApproved(address indexed token);
    event OracleUpdated(address indexed newOracle);
    event TreasuryUpdated(address indexed newTreasury);

    constructor(address debtToken_, address oracle_, address treasury_) {
        debtToken = IERC20(debtToken_);
        oracle = IPriceOracle(oracle_);
        treasuryAddress = treasury_;
    }

    // ------------------------------------------------------------------
    // Admin functions
    // ------------------------------------------------------------------

    function pause() external onlyOwner {
        paused = true;
        emit Paused(msg.sender);
    }

    function unpause() external onlyOwner {
        paused = false;
        emit Unpaused(msg.sender);
    }

    function approveCollateralToken(address token) external onlyOwner {
        require(!approvedCollateral[token], "already approved");
        approvedCollateral[token] = true;
        collateralList.push(token);
        emit CollateralApproved(token);
    }

    function updateOracle(address newOracle) external onlyOwner {
        oracle = IPriceOracle(newOracle);
        emit OracleUpdated(newOracle);
    }

    function updateTreasury(address newTreasury) external onlyOwner {
        treasuryAddress = newTreasury;
        emit TreasuryUpdated(newTreasury);
    }

    // ------------------------------------------------------------------
    // Core: open a leveraged position
    // ------------------------------------------------------------------

    function openPosition(
        address collateralToken,
        uint256 collateralAmount,
        uint256 borrowAmount
    ) external returns (uint256 positionId) {
        require(!paused, "vault paused");
        require(approvedCollateral[collateralToken], "collateral not approved");
        require(borrowerPositions[msg.sender].length < 10, "too many positions");
        require(nextPositionId < MAX_POSITIONS, "vault full");

        // Pull collateral from borrower
        bool ok = IERC20(collateralToken).transferFrom(msg.sender, address(this), collateralAmount);
        require(ok, "collateral transfer failed");

        // Verify collateral ratio
        uint256 collateralValue = _getCollateralValue(collateralToken, collateralAmount);
        _requireSufficientCollateral(collateralValue, borrowAmount);

        // Mint / transfer debt tokens to borrower
        bool sent = debtToken.transfer(msg.sender, borrowAmount);
        require(sent, "debt token transfer failed");

        positionId = nextPositionId++;
        positions[positionId] = Position({
            borrower: msg.sender,
            collateralToken: collateralToken,
            collateralAmount: collateralAmount,
            debtAmount: borrowAmount,
            openedAt: block.timestamp,
            status: PositionStatus.Active
        });
        borrowerPositions[msg.sender].push(positionId);

        totalDebt += borrowAmount;
        totalCollateral += collateralAmount;

        emit PositionOpened(positionId, msg.sender, collateralAmount, borrowAmount);
    }

    // ------------------------------------------------------------------
    // Core: repay a position
    // ------------------------------------------------------------------

    function repay(uint256 positionId, uint256 amount) external {
        require(!paused, "vault paused");
        Position storage pos = positions[positionId];
        require(pos.status == PositionStatus.Active, "not active");
        require(pos.borrower == msg.sender, "not your position");
        require(amount > 0 && amount <= pos.debtAmount, "invalid amount");

        bool ok = debtToken.transferFrom(msg.sender, address(this), amount);
        require(ok, "repayment transfer failed");

        pos.debtAmount -= amount;
        totalDebt -= amount;

        if (pos.debtAmount == 0) {
            // Return collateral
            pos.status = PositionStatus.Repaid;
            totalCollateral -= pos.collateralAmount;
            bool ret = IERC20(pos.collateralToken).transfer(msg.sender, pos.collateralAmount);
            require(ret, "collateral return failed");
        }

        emit PositionRepaid(positionId, msg.sender, amount);
    }

    // ------------------------------------------------------------------
    // Core: liquidate an undercollateralised position
    // ------------------------------------------------------------------

    function liquidate(uint256 positionId) external onlyRole(ROLE_LIQUIDATOR) {
        require(!paused, "vault paused");
        Position storage pos = positions[positionId];
        require(pos.status == PositionStatus.Active, "not active");

        uint256 collateralValue = _getCollateralValue(pos.collateralToken, pos.collateralAmount);
        uint256 ratio = MathLib.mulDiv(collateralValue, 10_000, pos.debtAmount);
        require(ratio < LIQUIDATION_THRESHOLD, "position healthy");

        pos.status = PositionStatus.Liquidated;
        totalDebt -= pos.debtAmount;
        totalCollateral -= pos.collateralAmount;

        // Seize collateral, send to treasury
        bool ok = IERC20(pos.collateralToken).transfer(treasuryAddress, pos.collateralAmount);
        require(ok, "collateral seizure failed");

        emit PositionLiquidated(positionId, msg.sender, pos.collateralAmount);
    }

    // ------------------------------------------------------------------
    // Flash loans
    // ------------------------------------------------------------------

    function flashLoan(
        address receiver,
        address token,
        uint256 amount,
        bytes calldata params
    ) external {
        require(!paused, "vault paused");
        require(flashLoanActive == 0, "flash loan re-entrancy");
        flashLoanActive = 1;

        uint256 balanceBefore = IERC20(token).balanceOf(address(this));
        require(balanceBefore >= amount, "insufficient liquidity");

        uint256 fee = MathLib.percentOf(amount, FLASH_LOAN_FEE_BPS);

        // Send tokens to receiver
        bool sent = IERC20(token).transfer(receiver, amount);
        require(sent, "flash loan send failed");

        // Execute receiver callback
        bool success = IFlashLoanReceiver(receiver).executeOperation(
            token, amount, fee, msg.sender, params
        );
        require(success, "flash loan callback failed");

        // Verify repayment
        uint256 balanceAfter = IERC20(token).balanceOf(address(this));
        require(balanceAfter >= balanceBefore + fee, "flash loan not repaid");

        // Collect fee
        if (fee > 0) {
            IERC20(token).transfer(treasuryAddress, fee);
        }

        flashLoanActive = 0;
        emit FlashLoan(receiver, token, amount, fee);
    }

    // ------------------------------------------------------------------
    // ETH handling (accept ETH deposits for wrapped ETH positions)
    // ------------------------------------------------------------------

    receive() external payable {
        // ETH deposits tracked separately — Phase 1 should detect this as payable
    }

    function withdrawETH(uint256 amount) external onlyOwner {
        (bool ok, ) = treasuryAddress.call{value: amount}("");
        require(ok, "ETH withdrawal failed");
    }

    // ------------------------------------------------------------------
    // View helpers
    // ------------------------------------------------------------------

    function getPosition(uint256 positionId) external view returns (Position memory) {
        return positions[positionId];
    }

    function getCollateralRatio(uint256 positionId) external view returns (uint256) {
        Position memory pos = positions[positionId];
        if (pos.debtAmount == 0) return type(uint256).max;
        uint256 cv = _getCollateralValue(pos.collateralToken, pos.collateralAmount);
        return MathLib.mulDiv(cv, 10_000, pos.debtAmount);
    }

    function getBorrowerPositions(address borrower) external view returns (uint256[] memory) {
        return borrowerPositions[borrower];
    }

    function isHealthy(uint256 positionId) external view returns (bool) {
        Position memory pos = positions[positionId];
        if (pos.status != PositionStatus.Active) return false;
        uint256 cv = _getCollateralValue(pos.collateralToken, pos.collateralAmount);
        uint256 ratio = MathLib.mulDiv(cv, 10_000, pos.debtAmount);
        return ratio >= LIQUIDATION_THRESHOLD;
    }

    // ------------------------------------------------------------------
    // Internal helpers
    // ------------------------------------------------------------------

    function _getCollateralValue(address token, uint256 amount) internal view returns (uint256) {
        uint256 price = oracle.getPrice(token);
        return MathLib.mulDiv(amount, price, 1e18);
    }

    function _requireSufficientCollateral(
        uint256 collateralValue,
        uint256 borrowAmount
    ) internal pure {
        require(borrowAmount > 0, "zero borrow");
        uint256 ratio = MathLib.mulDiv(collateralValue, 10_000, borrowAmount);
        require(ratio >= MIN_COLLATERAL_RATIO, "undercollateralised");
    }
}

// ---------------------------------------------------------------------------
// Interest Rate Model
// ---------------------------------------------------------------------------

/**
 * InterestRateModel — Separate contract wired to LendingVault.
 * Demonstrates cross-contract call graph extraction.
 */
contract InterestRateModel {
    uint256 public constant BASE_RATE_BPS = 200;    // 2% per year
    uint256 public constant KINK_UTILISATION = 8000; // 80%
    uint256 public constant SLOPE_1_BPS = 400;
    uint256 public constant SLOPE_2_BPS = 10_000;

    function getBorrowRate(uint256 totalBorrowed, uint256 totalLiquidity)
        external
        pure
        returns (uint256 rateBps)
    {
        if (totalLiquidity == 0) return BASE_RATE_BPS;
        uint256 utilisation = MathLib.mulDiv(totalBorrowed, 10_000, totalLiquidity);
        if (utilisation <= KINK_UTILISATION) {
            rateBps = BASE_RATE_BPS + MathLib.mulDiv(utilisation, SLOPE_1_BPS, 10_000);
        } else {
            uint256 excess = utilisation - KINK_UTILISATION;
            rateBps = BASE_RATE_BPS
                + MathLib.mulDiv(KINK_UTILISATION, SLOPE_1_BPS, 10_000)
                + MathLib.mulDiv(excess, SLOPE_2_BPS, 10_000);
        }
    }
}
