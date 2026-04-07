"""
Abstract base class for Phase 4 sequence builders.

Each builder takes a Phase 3 AttackHypothesis and produces a
TransactionSequence — concrete on-chain calls + PoC code.

Design:
  - One builder per AttackClass (mirrors Phase 3 agent structure)
  - Each builder knows the EVM calling conventions for its attack class
  - Codegen is separate (codegen/ module) — builders produce TxCalls,
    codegen turns TxCalls into Solidity/TypeScript
  - Builders are stateless; all context comes from hypothesis + graph
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod

from zeropath.adversarial.models import AttackClass, AttackHypothesis, ConditionType
from zeropath.models import ProtocolGraph
from zeropath.sequencer.models import (
    AttackContext,
    CallerType,
    CallEncoding,
    ProfitEstimate,
    SequenceStatus,
    TransactionSequence,
    TxCall,
)

logger = logging.getLogger(__name__)

# Known flash loan provider addresses (mainnet)
FLASH_LOAN_PROVIDERS = {
    "aave_v3": "0x87870Bca3F3fD6335C3F4ce8392D69350B4fA4E2",
    "balancer": "0xBA12222222228d8Ba445958a75a0704d566BF2C8",
    "uniswap_v3": "0x1F98431c8aD98523631AE4a59f267346ea31F984",
}

# Known token addresses (mainnet)
KNOWN_TOKENS = {
    "weth": "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2",
    "usdc": "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
    "dai": "0x6B175474E89094C44Da98b954EedeAC495271d0F",
    "usdt": "0xdAC17F958D2ee523a2206206994597C13D831ec7",
}


class BaseSequenceBuilder(ABC):
    """Abstract base for all sequence builders."""

    #: Which AttackClass this builder handles
    attack_class: AttackClass = AttackClass.UNKNOWN

    def build(
        self,
        hypothesis: AttackHypothesis,
        graph: ProtocolGraph,
    ) -> TransactionSequence | None:
        """
        Build a TransactionSequence from a hypothesis.

        Returns None if the hypothesis doesn't have enough information
        to generate a meaningful sequence.
        """
        try:
            calls = self._build_calls(hypothesis, graph)
            if not calls:
                logger.debug(
                    "%s: no calls generated for hypothesis '%s'",
                    self.__class__.__name__, hypothesis.title,
                )
                return None

            context = self._build_context(hypothesis, graph)
            profit = self._build_profit_estimate(hypothesis)
            completeness = self._score_completeness(calls, context, hypothesis)
            manual_params = self._identify_manual_params(calls, context)
            notes = self._auditor_notes(hypothesis, completeness)

            return TransactionSequence(
                hypothesis_id=hypothesis.id,
                hypothesis_title=hypothesis.title,
                attack_class=hypothesis.attack_class.value,
                calls=calls,
                context=context,
                profit_estimate=profit,
                status=SequenceStatus.GENERATED,
                completeness_score=completeness,
                requires_manual_params=manual_params,
                auditor_notes=notes,
            )
        except Exception:
            logger.exception(
                "%s: failed to build sequence for hypothesis '%s'",
                self.__class__.__name__, hypothesis.title,
            )
            return None

    @abstractmethod
    def _build_calls(
        self,
        hypothesis: AttackHypothesis,
        graph: ProtocolGraph,
    ) -> list[TxCall]:
        """Build the ordered list of transaction calls."""

    def _build_context(
        self,
        hypothesis: AttackHypothesis,
        graph: ProtocolGraph,
    ) -> AttackContext:
        """Build environment context from hypothesis and graph."""
        needs_flash_loan = any(
            p.condition_type == ConditionType.FLASH_LOAN_AVAILABLE
            for p in hypothesis.preconditions
        )
        needs_contract = hypothesis.attack_class in (
            AttackClass.REENTRANCY,
            AttackClass.FLASH_LOAN,
            AttackClass.ORACLE_MANIPULATION,
        )

        # Map contract names to addresses from graph (or use placeholder)
        contract_addresses: dict[str, str] = {}
        for contract_name in hypothesis.contracts_involved:
            contract = next(
                (c for c in graph.contracts if c.name == contract_name), None
            )
            if contract:
                contract_addresses[contract_name] = f"/* {contract_name} address */"

        return AttackContext(
            chain="mainnet",
            fork_block=None,
            contract_addresses=contract_addresses,
            flash_loan_provider=FLASH_LOAN_PROVIDERS["aave_v3"] if needs_flash_loan else None,
            requires_attacker_contract=needs_contract,
            requires_single_block=True,
        )

    def _build_profit_estimate(
        self, hypothesis: AttackHypothesis
    ) -> ProfitEstimate | None:
        if hypothesis.profit_mechanism is None:
            return None
        asset = hypothesis.profit_mechanism.asset
        return ProfitEstimate(
            asset=asset,
            min_profit_expression="1 ether" if "eth" in asset.lower() else "1e18",
            max_profit_expression="type(uint256).max",
            cost_expression="(flashAmount * 9) / 10000",  # Aave 0.09% fee
            scales_with_tvl=hypothesis.profit_mechanism.depends_on_protocol_tvl,
            notes=hypothesis.profit_mechanism.description,
        )

    @staticmethod
    def _score_completeness(
        calls: list[TxCall],
        context: AttackContext,
        hypothesis: AttackHypothesis,
    ) -> float:
        """
        Completeness rubric:
          +0.30  all calls have function_signature
          +0.20  all target_address_expr are real (not placeholder comment)
          +0.20  context has flash_loan_provider or doesn't need one
          +0.15  profit_estimate present
          +0.15  calls have post_assertions
        """
        score = 0.0
        if calls and all(c.function_signature for c in calls):
            score += 0.30
        if calls and all("/*" not in c.target_address_expr for c in calls):
            score += 0.20
        if not context.flash_loan_provider or context.flash_loan_provider:
            score += 0.20
        if hypothesis.profit_mechanism:
            score += 0.15
        if any(c.post_assertions for c in calls):
            score += 0.15
        return min(score, 1.0)

    @staticmethod
    def _identify_manual_params(
        calls: list[TxCall], context: AttackContext
    ) -> list[str]:
        """Flag parameters that need manual lookup before testing."""
        manual = []
        for call in calls:
            if "/*" in call.target_address_expr:
                manual.append(f"step {call.step}: {call.target_address_expr} address")
            if "TODO" in call.calldata_expr:
                manual.append(f"step {call.step}: calldata parameters")
        if not context.fork_block:
            manual.append("fork_block: set specific block for reproducible results")
        return manual

    @staticmethod
    def _auditor_notes(
        hypothesis: AttackHypothesis, completeness: float
    ) -> list[str]:
        notes = []
        if completeness < 0.60:
            notes.append(
                "Sequence contains placeholders — review requires_manual_params "
                "and fill in contract addresses before running."
            )
        if hypothesis.historical_loss_usd:
            notes.append(
                f"Historical precedent: ${hypothesis.historical_loss_usd:,} lost via "
                f"the same attack class ({', '.join(hypothesis.historical_precedent_protocols[:2])})."
            )
        if hypothesis.suggested_fix:
            notes.append(f"Fix: {hypothesis.suggested_fix}")
        return notes

    # ------------------------------------------------------------------
    # Shared builders helpers
    # ------------------------------------------------------------------

    def _call(
        self,
        step: int,
        description: str,
        target: str,
        sig: str | None,
        calldata: str = "",
        value: str = "0",
        caller: CallerType = CallerType.ATTACKER_CONTRACT,
        encoding: CallEncoding = CallEncoding.SOLIDITY_CALL,
        pre: list[str] | None = None,
        post: list[str] | None = None,
        gas: int | None = None,
    ) -> TxCall:
        return TxCall(
            step=step,
            description=description,
            target_address_expr=target,
            function_signature=sig,
            calldata_expr=calldata,
            value_expr=value,
            caller_type=caller,
            encoding=encoding,
            pre_assertions=pre or [],
            post_assertions=post or [],
            estimated_gas=gas,
        )
