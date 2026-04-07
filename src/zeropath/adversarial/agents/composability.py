"""
ComposabilityAgent — Phase 3 adversarial agent.

Generates attack hypotheses for cross-protocol composability risks:
  - External flash loan source enabling oracle manipulation
  - Bridge message replay / validation bypass
  - Aggregator calldata injection
  - Malicious callback via external flash loan (executeOperation, onFlashLoan)
  - Dependency on external protocol state (Compound, Aave, Curve)
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
from zeropath.models import ProtocolGraph

logger = logging.getLogger(__name__)

_BRIDGE_PROTOCOLS = {"wormhole", "hop", "portal", "celer", "across", "stargate", "layerzero"}
_AGGREGATOR_PROTOCOLS = {"1inch", "paraswap", "0x", "openocean", "kyberswap"}
_FLASH_LOAN_SOURCES = {"aave", "balancer", "uniswap", "dydx", "euler", "maker", "morpho"}
_LENDING_PROTOCOLS = {"compound", "aave", "maker", "euler", "benqi", "radiant"}

_HISTORICAL = [
    "Wormhole bridge ($320M, 2022)",
    "Nomad bridge ($190M, 2022)",
    "Ronin bridge ($625M, 2022)",
    "KyberSwap aggregator ($48M, 2023)",
    "Inverse Finance composability ($15.6M, 2022)",
]


class ComposabilityAgent(BaseAdversarialAgent):
    """Generates cross-protocol composability attack hypotheses."""

    name = "ComposabilityAgent"
    attack_class = AttackClass.COMPOSABILITY
    relevant_invariant_types = [
        InvariantType.CROSS_PROTOCOL,
        InvariantType.FLASH_LOAN_SAFETY,
        InvariantType.ORACLE_MANIPULATION,
    ]

    def analyse_invariant(
        self,
        invariant: Invariant,
        graph: ProtocolGraph,
        pattern: ProtocolPattern,
    ) -> list[AttackHypothesis]:
        hypotheses: list[AttackHypothesis] = []

        ext_deps_lower = {
            dep.name.lower(): dep
            for dep in graph.external_dependencies
        }

        # Check for bridge dependencies
        bridge_deps = [
            dep for name, dep in ext_deps_lower.items()
            if any(b in name for b in _BRIDGE_PROTOCOLS)
        ]
        if bridge_deps:
            hypotheses.append(self._bridge_message_replay(invariant, bridge_deps[0]))

        # Check for aggregator dependencies
        agg_deps = [
            dep for name, dep in ext_deps_lower.items()
            if any(a in name for a in _AGGREGATOR_PROTOCOLS)
        ]
        if agg_deps:
            hypotheses.append(self._aggregator_calldata_injection(invariant, agg_deps[0]))

        # Check for external flash loan callbacks
        _CALLBACK_NAMES = {
            "executeoperation", "onflashloan", "uniswapv2call",
            "pancakecall", "flashcallback", "flashloancallback",
            "executeflashloan",
        }
        flash_callbacks = [
            f for f in graph.functions
            if f.name.lower() in _CALLBACK_NAMES
            or "callback" in f.name.lower()
        ]
        if flash_callbacks:
            hypotheses.append(
                self._malicious_callback(invariant, flash_callbacks[0], pattern)
            )

        # High external dependency count = composability risk
        if len(graph.external_dependencies) >= 3:
            hypotheses.append(
                self._protocol_dependency_attack(invariant, graph, pattern)
            )

        return hypotheses

    # ------------------------------------------------------------------

    def _bridge_message_replay(self, invariant, dep) -> AttackHypothesis:
        contract = (invariant.contracts_involved or ["Bridge"])[0]

        steps = [
            self._step(1, "Capture a legitimate cross-chain message from source chain",
                       "Monitor bridge events for a high-value transfer message"),
            self._step(2, f"Replay the message on the destination chain via {dep.name}",
                       "If the bridge doesn't track message IDs, replay is accepted",
                       target_contract=dep.name),
            self._step(3, "Receive duplicate bridged funds on destination chain",
                       "Double the transferred amount"),
            self._step(4, "Sell or drain the duplicated assets before protocol detects",
                       "Exit before the bridge is paused"),
        ]
        preconditions = [
            self._precondition(ConditionType.CROSS_PROTOCOL_DEPENDENCY,
                               f"Protocol uses {dep.name} as bridge without nonce/ID tracking",
                               is_met=None,
                               evidence=f"Dependency: {dep.name}"),
            self._precondition(ConditionType.CUSTOM,
                               "Destination chain message validation is insufficient",
                               is_met=None),
        ]
        profit = self._profit("Double-spend bridged assets via message replay",
                               asset="ERC20/ETH", scales_with_tvl=True)
        return self._make_hypothesis(
            invariant,
            title=f"Bridge message replay via {dep.name} — duplicate cross-chain transfer",
            attack_class=AttackClass.COMPOSABILITY,
            narrative=(
                f"The protocol bridges assets via `{dep.name}`.  If the bridge doesn't track "
                f"consumed message IDs, an attacker can replay a captured message to receive "
                f"the same bridged funds twice."
            ),
            steps=steps,
            preconditions=preconditions,
            profit=profit,
            confidence=0.55,
            historical_protocols=_HISTORICAL[:3],
            historical_loss=320_000_000,
            suggested_fix=(
                f"Verify `{dep.name}` tracks message IDs (nonces) and marks them as consumed.  "
                f"Add replay-protection mapping: `mapping(bytes32 => bool) public processedMessages`."
            ),
        )

    def _aggregator_calldata_injection(self, invariant, dep) -> AttackHypothesis:
        contract = (invariant.contracts_involved or ["Aggregator"])[0]

        steps = [
            self._step(1, f"Call the protocol function that passes calldata to {dep.name}",
                       "Find the function that makes arbitrary external calls",
                       target_contract=contract),
            self._step(2, f"Inject malicious calldata into the {dep.name} call",
                       "Replace swap path with drain-to-attacker",
                       target_contract=dep.name),
            self._step(3, "Aggregator executes attacker-controlled calldata in protocol context",
                       "Protocol's ERC20 approvals are drained"),
            self._step(4, "Extract all approved tokens",
                       "Steal all assets for which the protocol has given approval"),
        ]
        preconditions = [
            self._precondition(ConditionType.CROSS_PROTOCOL_DEPENDENCY,
                               f"Protocol passes user-controlled calldata to {dep.name}",
                               is_met=None),
            self._precondition(ConditionType.CUSTOM,
                               "Protocol has unlimited ERC20 approvals to aggregator",
                               is_met=None),
        ]
        profit = self._profit("Drain all ERC20 approvals via arbitrary calldata",
                               asset="ERC20", scales_with_tvl=True)
        return self._make_hypothesis(
            invariant,
            title=f"Calldata injection via {dep.name} aggregator — drain ERC20 approvals",
            attack_class=AttackClass.COMPOSABILITY,
            narrative=(
                f"The protocol uses `{dep.name}` for token swaps and passes user-supplied calldata.  "
                f"An attacker injects calldata that redirects the swap output or drains ERC20 approvals."
            ),
            steps=steps,
            preconditions=preconditions,
            profit=profit,
            confidence=0.60,
            historical_protocols=["KyberSwap ($48M, 2023)", "Transit Swap ($21M, 2022)"],
            historical_loss=48_000_000,
            suggested_fix=(
                f"Validate aggregator calldata on-chain: check that `to` address is whitelisted, "
                f"token in/out match expected, and minimum output enforced.  "
                f"Use exact-output approvals (safeIncreaseAllowance) rather than max approvals."
            ),
        )

    def _malicious_callback(self, invariant, callback_fn, pattern) -> AttackHypothesis:
        fn_name = callback_fn.name
        contract = next(
            (c.name for c in [] if c.id == callback_fn.contract_id), "FlashLoanReceiver"
        )

        steps = [
            self._step(1, "Request flash loan from external provider (Aave, Balancer)",
                       "Initiate flash loan to trigger callback",
                       target_function="flashLoan"),
            self._step(2, f"Inside `{fn_name}()`, verify that msg.sender is checked",
                       "If callback trusts msg.sender without validation, anyone can call it",
                       target_function=fn_name),
            self._step(3, "Call `{fn_name}()` directly as attacker (no flash loan required)",
                       "If no msg.sender check, attacker calls the callback directly",
                       target_function=fn_name),
            self._step(4, "Callback executes privileged operations (approve, transfer, etc.)",
                       "Protocol performs sensitive operations assuming callback is from legit lender"),
        ]
        preconditions = [
            self._precondition(ConditionType.OPEN_CALL,
                               f"`{fn_name}` does not verify msg.sender is a trusted flash loan provider",
                               is_met=None),
            self._precondition(ConditionType.FLASH_LOAN_AVAILABLE,
                               "External flash loan provider accessible", is_met=True),
        ]
        profit = self._profit("Bypass flash loan repayment check or trigger privileged ops",
                               asset="ERC20")
        return self._make_hypothesis(
            invariant,
            title=f"Unvalidated flash loan callback {fn_name}() — direct call bypass",
            attack_class=AttackClass.COMPOSABILITY,
            narrative=(
                f"`{fn_name}` is a flash loan callback that may not validate `msg.sender`.  "
                f"An attacker calls it directly without actually taking a flash loan, potentially "
                f"bypassing repayment checks or triggering privileged protocol operations."
            ),
            steps=steps,
            preconditions=preconditions,
            profit=profit,
            confidence=0.65,
            historical_protocols=["Reentrancy via callback pattern"],
            suggested_fix=(
                f"In `{fn_name}`: require `msg.sender == TRUSTED_LENDER`.  "
                f"Use a transient state flag: set `_inFlashLoan = true` before initiating and "
                f"check it in the callback."
            ),
        )

    def _protocol_dependency_attack(self, invariant, graph, pattern) -> AttackHypothesis:
        dep_names = [dep.name for dep in graph.external_dependencies[:5]]
        contract = (invariant.contracts_involved or ["Protocol"])[0]

        steps = [
            self._step(1, f"Identify the most critical external dependency: {dep_names[0] if dep_names else 'ExternalProtocol'}",
                       "High composability = large attack surface"),
            self._step(2, f"Exploit a known vulnerability in {dep_names[0] if dep_names else 'ExternalProtocol'}",
                       "Or manipulate its state via flash loan"),
            self._step(3, f"The state change in the dependency propagates to {contract}",
                       "Protocol assumes dependency state is valid"),
            self._step(4, "Extract value from the cascading invariant violation",
                       "Depends on which dependency is compromised"),
        ]
        preconditions = [
            self._precondition(ConditionType.CROSS_PROTOCOL_DEPENDENCY,
                               f"Protocol has {len(graph.external_dependencies)} external dependencies",
                               is_met=True,
                               evidence=f"Dependencies: {', '.join(dep_names)}"),
            self._precondition(ConditionType.CUSTOM,
                               "At least one dependency has manipulable state",
                               is_met=None),
        ]
        profit = self._profit("Cascading failure from compromised dependency", asset="ERC20")
        return self._make_hypothesis(
            invariant,
            title=f"High composability risk — {len(graph.external_dependencies)} external dependencies",
            attack_class=AttackClass.COMPOSABILITY,
            narrative=(
                f"`{contract}` depends on {len(graph.external_dependencies)} external protocols: "
                f"{', '.join(dep_names[:3])}.  Each dependency is an attack surface.  "
                f"A vulnerability or state manipulation in any dependency can cascade."
            ),
            steps=steps,
            preconditions=preconditions,
            profit=profit,
            confidence=0.45,
            historical_protocols=_HISTORICAL[-2:],
            suggested_fix=(
                "Audit every external dependency.  Add circuit breakers for critical price feeds.  "
                "Use defensive programming: validate all return values from external calls."
            ),
        )
