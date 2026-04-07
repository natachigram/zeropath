"""
AccessControlAgent — Phase 3 adversarial agent.

Generates attack hypotheses for:
  - Unprotected initialize() → front-run to own the contract
  - Unprotected upgradeTo() → replace implementation with malicious code
  - Unprotected mint/burn → inflate/deflate supply
  - Privilege escalation via compromised owner key
  - Unprotected admin setters (setOracle, setFee, transferOwnership)
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

# Function name tiers by criticality
_CRITICAL_FNS = {"initialize", "initialise", "init", "upgradeto", "upgradetoandcall",
                  "selfdestruct", "destroy", "suicide"}
_HIGH_FNS = {"mint", "burn", "setoracle", "setpricefeed", "setrole", "grantrole",
              "revokerole", "pause", "unpause", "setfee", "setowner",
              "transferownership", "withdrawall", "emergencywithdraw"}
_MEDIUM_FNS = {"setparam", "setconfig", "setaddress", "setthreshold", "setlimit",
               "setreward", "setrate", "setslippage"}

_HISTORICAL = [
    "Parity Multisig uninitialized ($30M, 2017)",
    "Ronin Bridge compromised keys ($625M, 2022)",
    "Poly Network admin key compromise ($611M, 2021)",
    "Nomad Bridge ($190M, 2022)",
]


class AccessControlAgent(BaseAdversarialAgent):
    """Generates access control attack hypotheses."""

    name = "AccessControlAgent"
    attack_class = AttackClass.ACCESS_CONTROL
    relevant_invariant_types = [
        InvariantType.ACCESS_CONTROL,
        InvariantType.GOVERNANCE_SAFETY,
    ]

    def analyse_invariant(
        self,
        invariant: Invariant,
        graph: ProtocolGraph,
        pattern: ProtocolPattern,
    ) -> list[AttackHypothesis]:
        hypotheses: list[AttackHypothesis] = []

        for fn_name in invariant.functions_involved:
            fn_lower = fn_name.lower()
            fn_obj = next((f for f in graph.functions if f.name == fn_name), None)

            has_guard = False
            if fn_obj:
                has_guard = bool(fn_obj.access_control.modifiers) or \
                            fn_obj.access_control.only_owner or \
                            fn_obj.access_control.only_role is not None

            if has_guard:
                continue  # Protected — skip

            if fn_lower in _CRITICAL_FNS:
                if "init" in fn_lower:
                    hypotheses.append(self._frontrun_initializer(invariant, fn_obj or fn_name))
                elif "upgrade" in fn_lower:
                    hypotheses.append(self._upgrade_takeover(invariant, fn_obj or fn_name))
                else:
                    hypotheses.append(self._generic_critical(invariant, fn_name))

            elif fn_lower in _HIGH_FNS:
                if "mint" in fn_lower:
                    hypotheses.append(self._unbounded_mint(invariant, fn_name, pattern))
                elif "burn" in fn_lower:
                    hypotheses.append(self._unbounded_burn(invariant, fn_name, pattern))
                elif "oracle" in fn_lower or "feed" in fn_lower:
                    hypotheses.append(self._oracle_substitution(invariant, fn_name, pattern))
                else:
                    hypotheses.append(self._generic_high(invariant, fn_name))

            elif fn_lower in _MEDIUM_FNS:
                hypotheses.append(self._parameter_manipulation(invariant, fn_name))

        return hypotheses

    # ------------------------------------------------------------------

    def _frontrun_initializer(self, invariant, fn) -> AttackHypothesis:
        fn_name = fn.name if hasattr(fn, "name") else fn
        contract = (invariant.contracts_involved or ["TargetContract"])[0]

        steps = [
            self._step(1, "Monitor the mempool for proxy deployment transactions",
                       "Proxy is deployed, then initialize() must be called separately"),
            self._step(2, f"Front-run the legitimate initialize() call with higher gas",
                       "Submit own transaction before the deployer's",
                       target_contract=contract, target_function=fn_name),
            self._step(3, f"Call {fn_name}(attacker_address, ...) — set attacker as owner/admin",
                       "Attacker now controls the contract",
                       target_contract=contract, target_function=fn_name),
            self._step(4, "Call privileged functions: drain funds, pause protocol, upgrade implementation",
                       "Full contract control achieved",
                       target_contract=contract),
        ]
        preconditions = [
            self._precondition(ConditionType.UNGUARDED_FUNCTION,
                               f"`{fn_name}` has no initializer guard (Initializable.initializer modifier absent)",
                               is_met=True,
                               evidence="; ".join(invariant.evidence[:2])),
            self._precondition(ConditionType.UPGRADEABLE_PROXY,
                               "Contract is a proxy — initialization is separate from deployment",
                               is_met=invariant.contracts_involved is not None),
        ]
        profit = self._profit("Full contract takeover — drain all assets", asset="ETH/ERC20")
        poc = f"""// Foundry PoC
contract FrontrunInit {{
    function attack(address target) external {{
        I{contract}(target).{fn_name}(address(this), ...);
        // Now attacker is owner
        I{contract}(target).withdrawAll(address(this));
    }}
}}"""
        return self._make_hypothesis(
            invariant,
            title=f"Front-run {fn_name}() to seize contract ownership",
            attack_class=AttackClass.ACCESS_CONTROL,
            narrative=(
                f"`{fn_name}` in `{contract}` lacks an initializer guard.  Between contract "
                f"deployment and the legitimate `{fn_name}()` call, an attacker can call it first "
                f"via mempool front-running, setting themselves as owner/admin."
            ),
            steps=steps,
            preconditions=preconditions,
            profit=profit,
            confidence=0.90,
            historical_protocols=_HISTORICAL[:1],
            historical_loss=30_000_000,
            poc_sketch=poc,
            suggested_fix=(
                f"Add OpenZeppelin `Initializable` and mark `{fn_name}` with the "
                f"`initializer` modifier.  Consider calling `_disableInitializers()` in "
                f"the implementation constructor to prevent re-initialization."
            ),
        )

    def _upgrade_takeover(self, invariant, fn) -> AttackHypothesis:
        fn_name = fn.name if hasattr(fn, "name") else fn
        contract = (invariant.contracts_involved or ["TargetProxy"])[0]

        steps = [
            self._step(1, f"Call `{fn_name}(malicious_impl)` directly — no access control",
                       "Replace the proxy's implementation with attacker's contract",
                       target_contract=contract, target_function=fn_name),
            self._step(2, "New implementation's `selfdestruct()` or drain function executes in proxy context",
                       "Attacker code runs with proxy's storage and balance"),
            self._step(3, "Drain all ETH and ERC20 tokens held by proxy",
                       "Complete asset theft"),
        ]
        preconditions = [
            self._precondition(ConditionType.UNGUARDED_FUNCTION,
                               f"{fn_name} callable by anyone", is_met=True),
            self._precondition(ConditionType.UPGRADEABLE_PROXY,
                               "Contract is a UUPS or transparent proxy",
                               is_met=True),
        ]
        profit = self._profit("Full asset drain via malicious implementation", asset="ETH/ERC20")
        poc = f"""// Foundry PoC
contract MaliciousImpl {{
    function drainAll(address recipient) external {{
        payable(recipient).transfer(address(this).balance);
    }}
}}
// Attack: target.{fn_name}(address(new MaliciousImpl()));"""
        return self._make_hypothesis(
            invariant,
            title=f"Unprotected {fn_name}() — anyone can replace proxy implementation",
            attack_class=AttackClass.ACCESS_CONTROL,
            narrative=(
                f"`{fn_name}` on `{contract}` is externally callable without access control. "
                f"Any address can point the proxy to a malicious implementation and drain all assets."
            ),
            steps=steps,
            preconditions=preconditions,
            profit=profit,
            confidence=0.92,
            historical_protocols=_HISTORICAL,
            historical_loss=30_000_000,
            poc_sketch=poc,
            suggested_fix=(
                f"Guard `{fn_name}` with `onlyOwner` or `onlyRole(UPGRADER_ROLE)`.  "
                f"In UUPS, override `_authorizeUpgrade` with strict access control."
            ),
        )

    def _unbounded_mint(self, invariant, fn_name, pattern) -> AttackHypothesis:
        contract = (invariant.contracts_involved or ["Token"])[0]
        supply_var = (pattern.supply_vars or ["totalSupply"])[0]

        steps = [
            self._step(1, f"Call `{fn_name}(attacker, type(uint256).max)` — no guard",
                       "Mint maximum token supply to attacker",
                       target_contract=contract, target_function=fn_name),
            self._step(2, "Dump minted tokens on open market / DEX",
                       "Sell inflated supply for ETH or stablecoins"),
            self._step(3, "Price collapses; attacker exits with profit",
                       "Other token holders suffer total loss"),
        ]
        preconditions = [
            self._precondition(ConditionType.UNGUARDED_FUNCTION,
                               f"`{fn_name}` has no onlyOwner/onlyMinter guard",
                               is_met=True),
        ]
        profit = self._profit(f"Inflate {supply_var} → dump on market", asset="ERC20")
        return self._make_hypothesis(
            invariant,
            title=f"Unbounded mint via unprotected {fn_name}()",
            attack_class=AttackClass.ACCESS_CONTROL,
            narrative=(
                f"`{fn_name}` can be called by any address, allowing unlimited token minting.  "
                f"Attacker mints max supply and sells on open market."
            ),
            steps=steps,
            preconditions=preconditions,
            profit=profit,
            confidence=0.88,
            historical_protocols=["Cover Protocol ($3M, 2020)", "Paid Network ($180M, 2021)"],
            historical_loss=180_000_000,
            suggested_fix=f"Add `onlyOwner` or `onlyRole(MINTER_ROLE)` to `{fn_name}`.",
        )

    def _unbounded_burn(self, invariant, fn_name, pattern) -> AttackHypothesis:
        contract = (invariant.contracts_involved or ["Token"])[0]

        steps = [
            self._step(1, f"Call `{fn_name}(victim_address, amount)` for any user",
                       "Burn tokens from arbitrary addresses without approval",
                       target_contract=contract, target_function=fn_name),
            self._step(2, "Burn all LP tokens or collateral to trigger liquidations",
                       "Force other users into liquidation or halt redemptions"),
        ]
        preconditions = [
            self._precondition(ConditionType.UNGUARDED_FUNCTION,
                               f"`{fn_name}` burns from arbitrary addresses without approval",
                               is_met=True),
        ]
        profit = self._profit("Force liquidations or grief protocol users", asset="ERC20",
                               scales_with_tvl=False)
        return self._make_hypothesis(
            invariant,
            title=f"Unprotected {fn_name}() — burn tokens from any address",
            attack_class=AttackClass.ACCESS_CONTROL,
            narrative=(
                f"`{fn_name}` permits burning tokens from arbitrary addresses.  "
                f"Attacker burns LP tokens, collateral, or governance tokens to grief the protocol."
            ),
            steps=steps,
            preconditions=preconditions,
            profit=profit,
            confidence=0.80,
            suggested_fix=f"Restrict `{fn_name}` to owner or require explicit allowance from the token holder.",
        )

    def _oracle_substitution(self, invariant, fn_name, pattern) -> AttackHypothesis:
        contract = (invariant.contracts_involved or ["Contract"])[0]

        steps = [
            self._step(1, f"Call `{fn_name}(attacker_oracle)` — no access control",
                       "Replace legitimate oracle with attacker-controlled contract",
                       target_contract=contract, target_function=fn_name),
            self._step(2, "Attacker oracle returns manipulated price for any asset",
                       "Returns inflated collateral value or deflated debt value"),
            self._step(3, "Borrow maximum, drain liquidity, or force liquidations at fake price",
                       "Exploit protocol at attacker-controlled price",
                       target_contract=contract),
        ]
        preconditions = [
            self._precondition(ConditionType.UNGUARDED_FUNCTION,
                               f"`{fn_name}` sets oracle address without access control",
                               is_met=True),
        ]
        profit = self._profit("Arbitrary price manipulation → borrow/drain", asset="ERC20")
        return self._make_hypothesis(
            invariant,
            title=f"Oracle substitution via unprotected {fn_name}()",
            attack_class=AttackClass.ACCESS_CONTROL,
            narrative=(
                f"Any address can call `{fn_name}` to replace the protocol's oracle with an "
                f"attacker-controlled contract.  The attacker then reports any price, enabling "
                f"unbounded borrowing or forced liquidations."
            ),
            steps=steps,
            preconditions=preconditions,
            profit=profit,
            confidence=0.85,
            suggested_fix=f"Add `onlyOwner` + `timelock` to `{fn_name}`.  Emit events on oracle changes.",
        )

    def _parameter_manipulation(self, invariant, fn_name) -> AttackHypothesis:
        contract = (invariant.contracts_involved or ["Contract"])[0]

        steps = [
            self._step(1, f"Call `{fn_name}(extreme_value)` — no access control",
                       "Set a protocol parameter to an extreme value",
                       target_contract=contract, target_function=fn_name),
            self._step(2, "Extreme parameter causes protocol malfunction",
                       "e.g., 100% fee, 0 collateral ratio, 0 liquidation threshold"),
        ]
        preconditions = [
            self._precondition(ConditionType.UNGUARDED_FUNCTION,
                               f"`{fn_name}` has no caller validation",
                               is_met=True),
        ]
        profit = self._profit("Parameter griefing / protocol disruption", asset="N/A",
                               scales_with_tvl=False)
        return self._make_hypothesis(
            invariant,
            title=f"Unprotected parameter setter {fn_name}() — protocol manipulation",
            attack_class=AttackClass.ACCESS_CONTROL,
            narrative=(
                f"`{fn_name}` in `{contract}` modifies a protocol parameter without access control.  "
                f"Setting extreme values can break the protocol's invariants."
            ),
            steps=steps,
            preconditions=preconditions,
            profit=profit,
            confidence=0.65,
            suggested_fix=f"Add `onlyOwner` to `{fn_name}`.  Add input validation with min/max bounds.",
        )

    def _generic_critical(self, invariant, fn_name) -> AttackHypothesis:
        contract = (invariant.contracts_involved or ["Contract"])[0]

        steps = [
            self._step(1, f"Call `{fn_name}()` directly — no guard",
                       "Trigger the critical privileged function",
                       target_contract=contract, target_function=fn_name),
            self._step(2, "Protocol state permanently altered or destroyed",
                       "Depends on function semantics — selfdestruct, pause, drain, etc."),
        ]
        preconditions = [
            self._precondition(ConditionType.UNGUARDED_FUNCTION,
                               f"`{fn_name}` lacks any access control", is_met=True),
        ]
        profit = self._profit(f"Exploit via unprotected {fn_name}", asset="ETH/ERC20")
        return self._make_hypothesis(
            invariant,
            title=f"Unprotected critical function {fn_name}()",
            attack_class=AttackClass.ACCESS_CONTROL,
            narrative=(
                f"`{fn_name}` performs a critical privileged action without access control.  "
                f"Any address can trigger it."
            ),
            steps=steps,
            preconditions=preconditions,
            profit=profit,
            confidence=0.80,
            suggested_fix=f"Add `onlyOwner` or appropriate role guard to `{fn_name}`.",
        )

    def _generic_high(self, invariant, fn_name) -> AttackHypothesis:
        contract = (invariant.contracts_involved or ["Contract"])[0]

        steps = [
            self._step(1, f"Call `{fn_name}()` without required role",
                       "Execute privileged action",
                       target_contract=contract, target_function=fn_name),
            self._step(2, "Use resulting state change to extract value or disrupt protocol",
                       "Depends on specific function"),
        ]
        preconditions = [
            self._precondition(ConditionType.UNGUARDED_FUNCTION,
                               f"No access control on `{fn_name}`", is_met=True),
        ]
        profit = self._profit(f"Exploit via {fn_name}", asset="ERC20")
        return self._make_hypothesis(
            invariant,
            title=f"Unprotected high-privilege function {fn_name}()",
            attack_class=AttackClass.ACCESS_CONTROL,
            narrative=f"`{fn_name}` is publicly callable without role check.",
            steps=steps,
            preconditions=preconditions,
            profit=profit,
            confidence=0.70,
            suggested_fix=f"Add appropriate role guard to `{fn_name}`.",
        )
