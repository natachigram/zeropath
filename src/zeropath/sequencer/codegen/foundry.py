"""
Foundry test file generator — Phase 4.

Generates complete, runnable Foundry test files from a TransactionSequence.

Output format: forge-std Test.sol convention
  - Inherits Test
  - setUp() forks mainnet at configured block
  - test_<AttackName>() runs the full sequence
  - Callback functions (executeOperation, receive) auto-generated per attack class

The generated files follow these Foundry conventions:
  - vm.createSelectFork(url, block)
  - deal(token, addr, amount) for seeding balances
  - hoax(addr, ethAmount) for impersonating + seeding ETH
  - assertGt / assertEq / assertTrue for profit assertions
  - console.log for step-by-step debugging output
"""

from __future__ import annotations

import re
import textwrap
from datetime import datetime

from zeropath.adversarial.models import AttackClass
from zeropath.sequencer.models import (
    AttackContext,
    GeneratedTest,
    TestFramework,
    TransactionSequence,
    TxCall,
)

# Interfaces commonly needed in attack tests
_STANDARD_INTERFACES = """
// ─────────────────────────────────────────────
// Standard DeFi interfaces
// ─────────────────────────────────────────────
interface IERC20 {
    function approve(address spender, uint256 amount) external returns (bool);
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
    function totalSupply() external view returns (uint256);
    function allowance(address owner, address spender) external view returns (uint256);
}

interface IAaveV3Pool {
    function flashLoan(
        address receiverAddress,
        address[] calldata assets,
        uint256[] calldata amounts,
        uint256[] calldata interestRateModes,
        address onBehalfOf,
        bytes calldata params,
        uint16 referralCode
    ) external;
}

interface IFlashLoanSimpleReceiver {
    function executeOperation(
        address asset,
        uint256 amount,
        uint256 premium,
        address initiator,
        bytes calldata params
    ) external returns (bool);
}

interface IUniswapV2Pair {
    function getReserves() external view returns (uint112 reserve0, uint112 reserve1, uint32 blockTimestampLast);
    function swap(uint256 amount0Out, uint256 amount1Out, address to, bytes calldata data) external;
    function token0() external view returns (address);
    function token1() external view returns (address);
}

interface IUniswapV3Pool {
    function slot0() external view returns (
        uint160 sqrtPriceX96, int24 tick, uint16 observationIndex,
        uint16 observationCardinality, uint16 observationCardinalityNext,
        uint8 feeProtocol, bool unlocked
    );
    function swap(
        address recipient, bool zeroForOne, int256 amountSpecified,
        uint160 sqrtPriceLimitX96, bytes calldata data
    ) external returns (int256 amount0, int256 amount1);
}

interface IAggregatorV3 {
    function latestRoundData() external view returns (
        uint80 roundId, int256 answer, uint256 startedAt,
        uint256 updatedAt, uint80 answeredInRound
    );
}
"""

_CALLBACK_TEMPLATES = {
    AttackClass.FLASH_LOAN: """
    // ─── Aave V3 Flash Loan Callback ───────────────────────────────────────
    function executeOperation(
        address asset,
        uint256 amount,
        uint256 premium,
        address initiator,
        bytes calldata params
    ) external returns (bool) {
        require(msg.sender == AAVE_V3, "Untrusted lender");
        require(initiator == address(this), "Untrusted initiator");

        // ── Attack logic (injected from sequence) ──────────────────────────
{attack_steps}

        // Approve Aave to pull repayment
        IERC20(asset).approve(msg.sender, amount + premium);
        return true;
    }
""",
    AttackClass.ORACLE_MANIPULATION: """
    // ─── Aave V3 Flash Loan Callback ───────────────────────────────────────
    function executeOperation(
        address asset,
        uint256 amount,
        uint256 premium,
        address initiator,
        bytes calldata params
    ) external returns (bool) {
        require(msg.sender == AAVE_V3, "Untrusted lender");

        // ── Oracle manipulation + exploit (injected from sequence) ──────────
{attack_steps}

        IERC20(asset).approve(msg.sender, amount + premium);
        return true;
    }
""",
    AttackClass.REENTRANCY: """
    // ─── Reentrancy Callback ────────────────────────────────────────────────
    uint256 private _reentryCount;
    uint256 private constant MAX_REENTRY = 10;

    receive() external payable {
        if (_reentryCount < MAX_REENTRY) {
            _reentryCount++;
            // Re-enter the vulnerable function
{reentry_call}
        }
    }

    fallback() external payable {
        if (_reentryCount < MAX_REENTRY) {
            _reentryCount++;
{reentry_call}
        }
    }
""",
    AttackClass.GOVERNANCE: """
    // ─── Governance flash loan callback ────────────────────────────────────
    function executeOperation(
        address asset,
        uint256 amount,
        uint256 premium,
        address initiator,
        bytes calldata params
    ) external returns (bool) {
        require(msg.sender == AAVE_V3, "Untrusted lender");

        // Flash-loaned governance tokens: vote + execute in one tx
{attack_steps}

        IERC20(asset).approve(msg.sender, amount + premium);
        return true;
    }
""",
}


class FoundryTestGenerator:
    """Generates complete Foundry test files from a TransactionSequence."""

    def generate(self, sequence: TransactionSequence) -> GeneratedTest:
        """Generate a complete .t.sol Foundry test file."""
        protocol_name = self._sanitize_name(sequence.hypothesis_title)
        contract_name = f"ZP_{sequence.attack_class.replace('_', '')}_{protocol_name[:20]}"
        filename = f"{contract_name}.t.sol"

        code = self._render_file(sequence, contract_name)

        run_cmd = (
            f"forge test --match-contract {contract_name} "
            f"--fork-url $ETH_RPC_URL -vvvv"
        )
        if sequence.context.fork_block:
            run_cmd += f" --fork-block-number {sequence.context.fork_block}"

        notes = [
            f"Set ETH_RPC_URL before running: export ETH_RPC_URL=<your_rpc_endpoint>",
            "Install Foundry: https://getfoundry.sh",
            "Run: " + run_cmd,
        ]
        if sequence.requires_manual_params:
            notes.append(
                "MANUAL PARAMS REQUIRED: " + "; ".join(sequence.requires_manual_params)
            )

        return GeneratedTest(
            framework=TestFramework.FOUNDRY,
            filename=filename,
            code=code,
            run_command=run_cmd,
            notes=notes,
        )

    def _render_file(self, sequence: TransactionSequence, contract_name: str) -> str:
        ctx = sequence.context
        attack_class_enum = self._parse_attack_class(sequence.attack_class)

        # Generate contract addresses block
        addr_block = self._render_addresses(ctx, sequence)

        # Generate setUp
        setup_block = self._render_setup(ctx, sequence)

        # Generate main test function
        test_fn = self._render_test_function(sequence, attack_class_enum)

        # Generate callbacks
        callback_block = self._render_callbacks(sequence, attack_class_enum)

        # Generate interfaces (only what's needed)
        interfaces = _STANDARD_INTERFACES if attack_class_enum in (
            AttackClass.FLASH_LOAN, AttackClass.ORACLE_MANIPULATION,
            AttackClass.GOVERNANCE,
        ) else ""

        timestamp = datetime.now().strftime("%Y-%m-%d")

        return f"""// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

// ═══════════════════════════════════════════════════════════════════════════
// ZeroPath Phase 4 — Generated PoC Test
// Attack:    {sequence.hypothesis_title}
// Class:     {sequence.attack_class}
// Generated: {timestamp}
//
// Run:
//   forge test --match-contract {contract_name} --fork-url $ETH_RPC_URL -vvvv
//
// ⚠ Fill in all /* TODO */ and /* address */ placeholders before running.
// ═══════════════════════════════════════════════════════════════════════════

import "forge-std/Test.sol";
import "forge-std/console.sol";
{interfaces}

contract {contract_name} is Test {{

    // ─────────────────────────────────────────────────────────────────────
    // Constants & addresses
    // ─────────────────────────────────────────────────────────────────────
{addr_block}

    // Profit tracking
    uint256 internal _attackerBalBefore;

    // ─────────────────────────────────────────────────────────────────────
    // Setup
    // ─────────────────────────────────────────────────────────────────────
{setup_block}

    // ─────────────────────────────────────────────────────────────────────
    // Main attack test
    // ─────────────────────────────────────────────────────────────────────
{test_fn}
{callback_block}
    // Allow ETH receipt
    receive() external payable {{}}
}}
"""

    def _render_addresses(self, ctx: AttackContext, seq: TransactionSequence) -> str:
        lines = []

        # Flash loan provider
        if ctx.flash_loan_provider:
            lines.append(
                f"    address constant AAVE_V3 = {ctx.flash_loan_provider};"
            )

        # Contract addresses from context
        for name, addr in ctx.contract_addresses.items():
            sanitized = name.upper().replace(" ", "_")
            lines.append(f"    address constant {sanitized} = {addr};")

        # Oracle
        if ctx.oracle_address:
            lines.append(f"    address constant ORACLE = {ctx.oracle_address};")

        # WETH always useful
        lines.append("    address constant WETH = 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2;")
        lines.append("    address constant USDC = 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48;")

        if not lines:
            lines.append("    // TODO: Add target contract addresses here")

        return "\n".join(lines)

    def _render_setup(self, ctx: AttackContext, seq: TransactionSequence) -> str:
        fork_line = (
            f'        uint256 forkId = vm.createSelectFork(vm.envString("{ctx.rpc_url_env_var}")'
            + (f", {ctx.fork_block}" if ctx.fork_block else "")
            + ");"
        )

        balance_lines = []
        for token_addr, amount in ctx.attacker_token_balances.items():
            balance_lines.append(
                f"        deal({token_addr}, address(this), {amount});"
            )

        balance_block = "\n".join(balance_lines) if balance_lines else "        // No specific token balances required"

        return f"""    function setUp() public {{
        {fork_line}
        vm.deal(address(this), {ctx.attacker_eth_balance});
{balance_block}
        _attackerBalBefore = address(this).balance;
    }}
"""

    def _render_test_function(
        self, seq: TransactionSequence, attack_class: AttackClass
    ) -> str:
        fn_name = "test_" + self._sanitize_name(seq.hypothesis_title)[:40]

        # Build call statements
        call_stmts = []
        for call in seq.calls:
            call_stmts.extend(self._render_call(call))

        call_block = "\n".join(f"        {s}" for s in call_stmts)

        profit_assertion = self._profit_assertion(seq)

        return f"""    function {fn_name}() public {{
        console.log("=== ZeroPath PoC: {seq.hypothesis_title[:60]} ===");

{call_block}

        // ── Profit assertion ──────────────────────────────────────────────
{profit_assertion}
    }}
"""

    def _render_call(self, call: TxCall) -> list[str]:
        lines = []

        # Pre-assertions
        for pre in call.pre_assertions:
            lines.append(pre)

        # Comment: step description
        lines.append(f"// Step {call.step}: {call.description}")

        if call.function_signature is None or call.target_address_expr.startswith("/*"):
            # No actual call — just a comment block
            lines.append(f"// → {call.target_address_expr}")
        elif call.encoding.value == "eth_transfer":
            lines.append(
                f"payable({call.target_address_expr}).transfer({call.value_expr});"
            )
        elif call.value_expr and call.value_expr != "0":
            fn_name = call.function_signature.split("(")[0] if call.function_signature else "call"
            if call.calldata_expr:
                lines.append(
                    f"{call.target_address_expr}.{fn_name}{{value: {call.value_expr}}}({call.calldata_expr});"
                )
            else:
                lines.append(
                    f"{call.target_address_expr}.{fn_name}{{value: {call.value_expr}}}();"
                )
        elif call.function_signature:
            fn_name = call.function_signature.split("(")[0]
            if call.calldata_expr:
                lines.append(f"{call.target_address_expr}.{fn_name}({call.calldata_expr});")
            else:
                lines.append(f"{call.target_address_expr}.{fn_name}();")

        lines.append(f'console.log("  Step {call.step} complete");')

        # Post-assertions
        for post in call.post_assertions:
            lines.append(post)

        lines.append("")
        return lines

    def _render_callbacks(
        self, seq: TransactionSequence, attack_class: AttackClass
    ) -> str:
        template = _CALLBACK_TEMPLATES.get(attack_class)
        if template is None:
            return ""

        # Inject attack steps into callback template
        inner_steps = []
        for call in seq.calls:
            if call.function_signature and "/*" not in call.target_address_expr:
                fn_name = call.function_signature.split("(")[0]
                if call.calldata_expr:
                    inner_steps.append(
                        f"            {call.target_address_expr}.{fn_name}({call.calldata_expr});"
                    )
                else:
                    inner_steps.append(
                        f"            {call.target_address_expr}.{fn_name}();"
                    )

        attack_steps_str = "\n".join(inner_steps) if inner_steps else "            // TODO: inject attack steps"

        # For reentrancy: generate reentry call
        target_fn = (seq.hypothesis.functions_involved[0]
                     if hasattr(seq, 'hypothesis') and seq.hypothesis.functions_involved
                     else "withdraw")
        reentry_target = (seq.hypothesis.contracts_involved[0]
                          if hasattr(seq, 'hypothesis') and seq.hypothesis.contracts_involved
                          else "TARGET")
        reentry_call = f"            I{reentry_target}(TARGET).{target_fn}();"

        return template.format(
            attack_steps=attack_steps_str,
            reentry_call=reentry_call,
        )

    def _profit_assertion(self, seq: TransactionSequence) -> str:
        if seq.profit_estimate:
            asset = seq.profit_estimate.asset
            if "eth" in asset.lower():
                return (
                    "        uint256 _attackerBalAfter = address(this).balance;\n"
                    "        console.log('Profit (ETH):', _attackerBalAfter - _attackerBalBefore);\n"
                    "        assertGt(_attackerBalAfter, _attackerBalBefore, 'Attack not profitable — check sequence');"
                )
            else:
                return (
                    "        uint256 _tokenProfit = IERC20(/* profit token address */).balanceOf(address(this));\n"
                    f"        console.log('Profit ({asset}):', _tokenProfit);\n"
                    "        assertGt(_tokenProfit, 0, 'Attack not profitable — check sequence');"
                )
        return "        // TODO: add profit assertion"

    @staticmethod
    def _sanitize_name(title: str) -> str:
        """Convert hypothesis title to valid Solidity identifier."""
        cleaned = re.sub(r"[^a-zA-Z0-9_]", "_", title)
        cleaned = re.sub(r"_+", "_", cleaned).strip("_")
        return cleaned[:50]

    @staticmethod
    def _parse_attack_class(cls_str: str) -> AttackClass:
        try:
            return AttackClass(cls_str)
        except ValueError:
            return AttackClass.UNKNOWN
