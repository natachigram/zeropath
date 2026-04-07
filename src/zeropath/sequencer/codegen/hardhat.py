"""
Hardhat test script generator — Phase 4.

Generates TypeScript Hardhat tests from a TransactionSequence.
Uses ethers.js v6 + @nomicfoundation/hardhat-network-helpers for forking.
"""

from __future__ import annotations

import re
from datetime import datetime

from zeropath.sequencer.models import (
    GeneratedTest,
    TestFramework,
    TransactionSequence,
    TxCall,
)


class HardhatScriptGenerator:
    """Generates TypeScript Hardhat test files."""

    def generate(self, sequence: TransactionSequence) -> GeneratedTest:
        """Generate a complete Hardhat TypeScript test."""
        test_name = self._sanitize(sequence.hypothesis_title)[:40]
        filename = f"{test_name}.test.ts"
        code = self._render(sequence, test_name)
        run_cmd = f"npx hardhat test test/{filename} --network hardhat"

        return GeneratedTest(
            framework=TestFramework.HARDHAT,
            filename=filename,
            code=code,
            run_command=run_cmd,
            notes=[
                "Requires: npm install @nomicfoundation/hardhat-toolbox",
                "Set MAINNET_RPC_URL in .env or hardhat.config.ts",
                "Run: " + run_cmd,
                *([f"Manual params: {', '.join(sequence.requires_manual_params)}"]
                  if sequence.requires_manual_params else []),
            ],
        )

    def _render(self, seq: TransactionSequence, test_name: str) -> str:
        ctx = seq.context
        timestamp = datetime.now().strftime("%Y-%m-%d")
        addr_consts = self._render_addresses(ctx)
        setup_block = self._render_setup(ctx)
        test_body = self._render_test_body(seq)
        profit_assert = self._profit_assertion(seq)

        return f"""// ZeroPath Phase 4 — Generated Hardhat PoC
// Attack:    {seq.hypothesis_title}
// Class:     {seq.attack_class}
// Generated: {timestamp}
//
// Run: npx hardhat test test/{test_name}.test.ts --network hardhat
// ⚠ Fill in all /* TODO */ placeholders before running.

import {{ expect }} from "chai";
import {{ ethers }} from "hardhat";
import {{
  loadFixture,
  impersonateAccount,
  setBalance,
  reset,
}} from "@nomicfoundation/hardhat-network-helpers";

// ─── Target addresses ────────────────────────────────────────────────────────
{addr_consts}

describe("{seq.hypothesis_title[:60]}", function () {{
  async function deployFixture() {{
    // Fork mainnet
{setup_block}

    return {{ attacker, signer }};
  }}

  it("should be profitable", async function () {{
    const {{ attacker, signer }} = await loadFixture(deployFixture);
    const balBefore = await ethers.provider.getBalance(attacker.address);

{test_body}

    // ── Profit assertion ──────────────────────────────────────────────────
{profit_assert}
  }});
}});
"""

    def _render_addresses(self, ctx) -> str:
        lines = []
        if ctx.flash_loan_provider:
            lines.append(f'const AAVE_V3 = "{ctx.flash_loan_provider}";')
        for name, addr in ctx.contract_addresses.items():
            lines.append(f'const {name.upper()} = "{addr}";')
        lines.append('const WETH = "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2";')
        lines.append('const USDC = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48";')
        return "\n".join(lines) if lines else '// TODO: Add target addresses'

    def _render_setup(self, ctx) -> str:
        fork_line = (
            f'    await reset(process.env.MAINNET_RPC_URL'
            + (f', {ctx.fork_block}' if ctx.fork_block else '')
            + ');'
        )
        return f"""    {fork_line}
    const [signer] = await ethers.getSigners();
    await setBalance(signer.address, ethers.parseEther("{ctx.attacker_eth_balance.replace(' ether', '')}"));

    // Deploy attacker contract if needed
    // const AttackerFactory = await ethers.getContractFactory("AttackerContract");
    // const attacker = await AttackerFactory.deploy();
    const attacker = signer;  // For EOA attacks"""

    def _render_test_body(self, seq: TransactionSequence) -> str:
        lines = []
        for call in seq.calls:
            lines.extend(self._render_call(call))
        return "\n".join(f"    {l}" for l in lines)

    def _render_call(self, call: TxCall) -> list[str]:
        lines = []
        lines.append(f"// Step {call.step}: {call.description}")

        if call.function_signature is None or "/*" in call.target_address_expr:
            lines.append(f"// → {call.target_address_expr}")
        else:
            fn_name = call.function_signature.split("(")[0]
            target = call.target_address_expr
            args = call.calldata_expr if call.calldata_expr else ""
            value_part = (
                f", {{ value: ethers.parseEther('{call.value_expr.replace(' ether', '')}') }}"
                if call.value_expr and call.value_expr != "0" and "ether" in call.value_expr
                else ""
            )
            if args:
                lines.append(f"await (await ethers.getContractAt('I{target.split('(')[0].strip()}', {target.split('(')[-1].rstrip(')')}).{fn_name}({args}{value_part}));")
            else:
                lines.append(f"// TODO: call {fn_name}() on {target}")

        for post in call.post_assertions:
            lines.append(f"// assert: {post}")
        lines.append("")
        return lines

    def _profit_assertion(self, seq: TransactionSequence) -> str:
        if seq.profit_estimate:
            asset = seq.profit_estimate.asset
            if "eth" in asset.lower():
                return (
                    "    const balAfter = await ethers.provider.getBalance(attacker.address);\n"
                    "    console.log('Profit (ETH):', ethers.formatEther(balAfter - balBefore));\n"
                    "    expect(balAfter).to.be.gt(balBefore, 'Attack not profitable');"
                )
            return (
                "    const profit = await token.balanceOf(attacker.address);\n"
                f"    console.log('Profit ({asset}):', ethers.formatUnits(profit, 18));\n"
                "    expect(profit).to.be.gt(0n, 'Attack not profitable');"
            )
        return "    // TODO: add profit assertion"

    @staticmethod
    def _sanitize(title: str) -> str:
        cleaned = re.sub(r"[^a-zA-Z0-9_]", "_", title)
        return re.sub(r"_+", "_", cleaned).strip("_")[:50]
