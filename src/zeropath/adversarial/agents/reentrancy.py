"""
ReentrancyAgent — Phase 3 adversarial agent.

Generates attack hypotheses for:
  - Classic read-only reentrancy (Curve/Vyper-style)
  - Cross-function reentrancy (re-enter a different function)
  - Reentrancy via ERC777 / ERC1155 hooks
  - Delegatecall reentrancy (context hijack)
"""

from __future__ import annotations

import logging

from zeropath.adversarial.base import BaseAdversarialAgent
from zeropath.adversarial.models import AttackClass, AttackHypothesis, ConditionType
from zeropath.invariants.models import (
    Invariant,
    InvariantType,
    ProtocolPattern,
)
from zeropath.models import CallType, ProtocolGraph

logger = logging.getLogger(__name__)

_HISTORICAL = [
    "The DAO ($55M, 2016)",
    "Lendf.me ($25M, 2020)",
    "CREAM Finance read-only reentrancy ($130M, 2021)",
    "Reentrancy in Curve Vyper pools ($73M, 2023)",
]


class ReentrancyAgent(BaseAdversarialAgent):
    """Generates reentrancy attack hypotheses."""

    name = "ReentrancyAgent"
    attack_class = AttackClass.REENTRANCY
    relevant_invariant_types = [
        InvariantType.REENTRANCY,
        InvariantType.VALUE_CONSERVATION,
        InvariantType.BALANCE_CONSISTENCY,
    ]

    def analyse_invariant(
        self,
        invariant: Invariant,
        graph: ProtocolGraph,
        pattern: ProtocolPattern,
    ) -> list[AttackHypothesis]:
        hypotheses: list[AttackHypothesis] = []

        # Find functions involved in the invariant that make external calls
        for fn_name in invariant.functions_involved:
            fn_obj = next(
                (f for f in graph.functions if f.name == fn_name), None
            )
            if fn_obj is None:
                continue

            # Find external calls from this function
            ext_calls = [
                c for c in graph.function_calls
                if c.caller_id == fn_obj.id
                and c.call_type in (CallType.EXTERNAL, CallType.LOW_LEVEL)
            ]
            delegatecalls = [
                c for c in graph.function_calls
                if c.caller_id == fn_obj.id
                and c.call_type == CallType.DELEGATECALL
            ]

            has_guard = any(
                kw in mod.lower()
                for mod in fn_obj.modifiers
                for kw in ("nonreentrant", "reentrant", "noreentrancy", "mutex")
            )

            if ext_calls and not has_guard:
                # Check CEI violation: any state var written after the call?
                # We use evidence from the invariant as proxy
                cei_violated = any(
                    "state" in ev.lower() or "after" in ev.lower() or "write" in ev.lower()
                    for ev in invariant.evidence
                )
                hypotheses.append(
                    self._classic_reentrancy(invariant, fn_obj, ext_calls[0], cei_violated, pattern)
                )
                # Cross-function reentrancy: re-enter a *different* function
                cross_targets = [
                    f for f in graph.functions
                    if f.name != fn_name
                    and f.state_vars_written
                    and f.visibility.value in ("public", "external")
                    and f.contract_id == fn_obj.contract_id
                ]
                if cross_targets:
                    hypotheses.append(
                        self._cross_function_reentrancy(
                            invariant, fn_obj, ext_calls[0], cross_targets[0]
                        )
                    )

            if delegatecalls and not has_guard:
                hypotheses.append(
                    self._delegatecall_reentrancy(invariant, fn_obj, delegatecalls[0])
                )

        # Read-only reentrancy pattern (AMM)
        if pattern.swap_functions and not pattern.has_reentrancy_guard:
            hypotheses.append(self._read_only_reentrancy(invariant, pattern))

        return hypotheses

    # ------------------------------------------------------------------
    # Hypothesis builders
    # ------------------------------------------------------------------

    def _classic_reentrancy(self, invariant, fn_obj, ext_call, cei_violated, pattern):
        contract_name = next(
            (c.name for c in [] if c.id == fn_obj.contract_id), fn_obj.contract_id
        )
        withdraw_fn = fn_obj.name

        steps = [
            self._step(1, "Deploy malicious contract with receive()/fallback() that re-enters the target",
                       "The callback is triggered when the target sends ETH or makes an external call"),
            self._step(2, f"Call `{withdraw_fn}()` on the target contract",
                       "Initiate the withdrawal / external call path",
                       target_function=withdraw_fn),
            self._step(3, "Inside receive()/fallback(): re-call `{withdraw_fn}()` before state update",
                       "State (balance, share count) hasn't been decremented yet — re-entry sees full balance",
                       target_function=withdraw_fn),
            self._step(4, "Repeat until target is drained or gas runs out",
                       "Each re-entrant call extracts the same amount"),
            self._step(5, "Withdraw accumulated funds from attacker contract",
                       "Collect all extracted value"),
        ]
        preconditions = [
            self._precondition(
                ConditionType.EXTERNAL_CALL_BEFORE_UPDATE,
                f"`{withdraw_fn}` sends ETH or calls external contract before updating balance",
                is_met=cei_violated,
                evidence="; ".join(invariant.evidence[:2]),
            ),
            self._precondition(
                ConditionType.OPEN_CALL,
                "No nonReentrant guard on the function",
                is_met=True,
            ),
        ]
        profit = self._profit(
            "Drain full balance of the contract",
            asset="ETH" if fn_obj.is_payable else "ERC20",
        )
        poc = f"""// Foundry PoC
contract Attacker {{
    Target target = Target(TARGET_ADDR);
    uint256 count;

    function attack() external payable {{
        target.{withdraw_fn}{{value: msg.value}}();
    }}

    receive() external payable {{
        if (count < 5) {{
            count++;
            target.{withdraw_fn}();
        }}
    }}
}}"""
        return self._make_hypothesis(
            invariant,
            title=f"Classic reentrancy drain via {withdraw_fn}() — no nonReentrant guard",
            attack_class=AttackClass.REENTRANCY,
            narrative=(
                f"`{withdraw_fn}` makes an external call (ETH transfer or contract call) before "
                f"updating the caller's balance.  An attacker contract re-enters `{withdraw_fn}` "
                f"in its `receive()` hook, repeatedly extracting funds before the balance is decremented."
            ),
            steps=steps,
            preconditions=preconditions,
            profit=profit,
            confidence=0.85 if cei_violated else 0.55,
            historical_protocols=_HISTORICAL[:2],
            historical_loss=55_000_000,
            poc_sketch=poc,
            suggested_fix=(
                "Add `nonReentrant` modifier to `{withdraw_fn}`.  Follow CEI pattern: "
                "update all state BEFORE any external calls or ETH transfers."
            ),
        )

    def _cross_function_reentrancy(self, invariant, fn_obj, ext_call, cross_target):
        steps = [
            self._step(1, f"Call `{fn_obj.name}()` to trigger external call",
                       "Initiates the external call path",
                       target_function=fn_obj.name),
            self._step(2, f"In callback, re-enter `{cross_target.name}()` (different function, same state)",
                       "Cross-function re-entry reads stale state set by fn_obj",
                       target_function=cross_target.name),
            self._step(3, "Cross-function re-entry operates on inconsistent state",
                       "e.g., balance not yet decremented but position marked active"),
            self._step(4, "Complete both function calls, leaving protocol in inconsistent state",
                       "May enable double-spend or permanent accounting error"),
        ]
        preconditions = [
            self._precondition(ConditionType.EXTERNAL_CALL_BEFORE_UPDATE,
                               f"{fn_obj.name} calls external before state finalised", is_met=True),
            self._precondition(ConditionType.OPEN_CALL,
                               f"{cross_target.name} has no reentrancy guard", is_met=True),
        ]
        profit = self._profit(
            f"Double-spend or accounting manipulation via {cross_target.name}",
            asset="ERC20",
        )
        return self._make_hypothesis(
            invariant,
            title=f"Cross-function reentrancy: {fn_obj.name}() → re-enter {cross_target.name}()",
            attack_class=AttackClass.REENTRANCY,
            narrative=(
                f"While `{fn_obj.name}` is mid-execution (after external call, before state update), "
                f"the attacker re-enters `{cross_target.name}`, which reads the not-yet-updated "
                f"state.  This can enable double-spends or privilege escalation."
            ),
            steps=steps,
            preconditions=preconditions,
            profit=profit,
            confidence=0.60,
            historical_protocols=["Uniswap V1 cross-function reentrancy (2019)"],
            suggested_fix=(
                "Use a global reentrancy lock (OpenZeppelin ReentrancyGuard) across all "
                "state-modifying functions in the contract."
            ),
        )

    def _delegatecall_reentrancy(self, invariant, fn_obj, dc_call):
        steps = [
            self._step(1, "Deploy malicious contract to act as implementation",
                       "If the delegatecall target is attacker-controlled, full context hijack"),
            self._step(2, f"Trigger `{fn_obj.name}()` which delegatecalls to attacker's contract",
                       "Attacker's code runs in the calling contract's storage context",
                       target_function=fn_obj.name),
            self._step(3, "Inside delegatecall: manipulate caller's storage slots directly",
                       "Overwrite balances, ownership, or admin slots"),
            self._step(4, "Re-enter or exit with modified state",
                       "Extract funds or escalate privileges"),
        ]
        preconditions = [
            self._precondition(ConditionType.OPEN_CALL,
                               f"Delegatecall target ({dc_call.callee_name}) may be attacker-controlled",
                               is_met=None),
        ]
        profit = self._profit("Full contract takeover or fund drain", asset="ETH")
        return self._make_hypothesis(
            invariant,
            title=f"Delegatecall context hijack via {fn_obj.name}()",
            attack_class=AttackClass.REENTRANCY,
            narrative=(
                f"`{fn_obj.name}` issues a `delegatecall` to `{dc_call.callee_name}`.  "
                f"If the callee is attacker-controlled or can be updated (proxy), the attacker "
                f"executes arbitrary code in the calling contract's storage context."
            ),
            steps=steps,
            preconditions=preconditions,
            profit=profit,
            confidence=0.55,
            historical_protocols=["Parity Multisig ($30M, 2017)"],
            historical_loss=30_000_000,
            suggested_fix="Validate delegatecall targets against an allowlist; use OpenZeppelin's Address library.",
        )

    def _read_only_reentrancy(self, invariant, pattern) -> AttackHypothesis:
        swap_fn = pattern.swap_functions[0] if pattern.swap_functions else "swap"

        steps = [
            self._step(1, f"Call `{swap_fn}()` in AMM which triggers a callback (e.g. uniswapV3SwapCallback)",
                       "AMM callbacks occur before reserves are updated"),
            self._step(2, "Inside callback, call a LENDING protocol that reads AMM reserves as price oracle",
                       "Lending protocol sees pre-update (stale) reserves"),
            self._step(3, "Borrow against inflated/deflated collateral value",
                       "Oracle price is wrong because reserves not yet updated",
                       target_function="borrow"),
            self._step(4, "Callback returns, AMM updates reserves",
                       "Lending protocol now holds bad debt"),
            self._step(5, "Repay flash loan or simply keep the borrowed funds",
                       "Profit from incorrect collateral valuation"),
        ]
        preconditions = [
            self._precondition(ConditionType.CROSS_PROTOCOL_DEPENDENCY,
                               "A lending protocol reads this AMM's reserves as a price oracle",
                               is_met=None),
            self._precondition(ConditionType.ORACLE_READ_SINGLE_BLOCK,
                               "Lending protocol uses spot reserves (not TWAP)",
                               is_met=True),
        ]
        profit = self._profit("Borrow at incorrect price from dependent lending protocol", asset="ERC20")
        return self._make_hypothesis(
            invariant,
            title=f"Read-only reentrancy via AMM callback — stale reserves used as oracle",
            attack_class=AttackClass.REENTRANCY,
            narrative=(
                f"During an AMM `{swap_fn}()`, the callback fires before reserves update.  "
                f"Any protocol that reads this AMM's reserves within the callback window sees "
                f"stale prices.  Lending protocols using spot AMM reserves for collateral "
                f"valuation are exploitable via this pattern (Curve Vyper reentrancy, 2023)."
            ),
            steps=steps,
            preconditions=preconditions,
            profit=profit,
            confidence=0.65,
            historical_protocols=["Curve Vyper pools ($73M, 2023)", "CREAM Finance ($130M, 2021)"],
            historical_loss=73_000_000,
            suggested_fix=(
                "Add `@nonreentrant` guard (Vyper) or `nonReentrant` modifier to all swap/add/remove "
                "functions.  Dependent protocols should use Chainlink or TWAP, never spot reserves."
            ),
        )
