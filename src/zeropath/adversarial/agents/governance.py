"""
GovernanceAttackAgent — Phase 3 adversarial agent.

Generates attack hypotheses for:
  - Missing timelock — instant proposal execution
  - Flash loan governance capture (Beanstalk-style)
  - Proposal front-running / hijacking
  - Malicious proposal via compromised multisig
  - Vote buying / bribe market exploitation
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

_HISTORICAL = [
    "Beanstalk ($182M, 2022) — flash loan governance",
    "Build Finance ($470K, 2022) — hostile takeover vote",
    "Tornado Cash governance attack (2023) — malicious proposal",
    "Compound proposal 64 — near governance attack",
]


class GovernanceAttackAgent(BaseAdversarialAgent):
    """Generates governance attack hypotheses."""

    name = "GovernanceAttackAgent"
    attack_class = AttackClass.GOVERNANCE
    relevant_invariant_types = [
        InvariantType.GOVERNANCE_SAFETY,
        InvariantType.ACCESS_CONTROL,
        InvariantType.FLASH_LOAN_SAFETY,
    ]

    def analyse_invariant(
        self,
        invariant: Invariant,
        graph: ProtocolGraph,
        pattern: ProtocolPattern,
    ) -> list[AttackHypothesis]:
        hypotheses: list[AttackHypothesis] = []

        if not pattern.governance_functions:
            return hypotheses

        propose_fn = next(
            (f for f in pattern.governance_functions if "propose" in f.lower()), None
        )
        vote_fn = next(
            (f for f in pattern.governance_functions if "vote" in f.lower()), None
        )
        execute_fn = next(
            (f for f in pattern.governance_functions if "execute" in f.lower()), None
        )

        if not pattern.has_timelock:
            hypotheses.append(
                self._instant_execution(invariant, propose_fn, vote_fn, execute_fn, pattern)
            )

        if not pattern.has_timelock or pattern.has_flash_loan:
            hypotheses.append(
                self._flash_loan_capture(invariant, vote_fn, execute_fn, pattern)
            )

        if propose_fn:
            hypotheses.append(self._malicious_proposal(invariant, propose_fn, execute_fn, pattern))

        if execute_fn:
            hypotheses.append(self._proposal_frontrun(invariant, execute_fn))

        return hypotheses

    # ------------------------------------------------------------------

    def _instant_execution(self, invariant, propose_fn, vote_fn, execute_fn, pattern):
        contract = (invariant.contracts_involved or ["Governance"])[0]
        p = propose_fn or "propose"
        v = vote_fn or "vote"
        e = execute_fn or "execute"

        steps = [
            self._step(1, f"Create malicious proposal via `{p}()` that drains treasury",
                       "Proposal created with any quorum threshold",
                       target_contract=contract, target_function=p),
            self._step(2, f"Vote to pass via `{v}()` with majority stake",
                       "If attacker holds enough tokens, passes immediately",
                       target_contract=contract, target_function=v),
            self._step(3, f"Execute immediately via `{e}()` — no timelock delay",
                       "Treasury drain executes in same block as vote",
                       target_contract=contract, target_function=e),
            self._step(4, "Treasury assets transferred to attacker",
                       "No opportunity for community to intervene"),
        ]
        preconditions = [
            self._precondition(ConditionType.NO_TIMELOCK,
                               "No timelock between proposal passing and execution",
                               is_met=not pattern.has_timelock,
                               evidence="has_timelock=False detected by ZeroPath"),
            self._precondition(ConditionType.GOVERNANCE_TOKEN_AVAILABLE,
                               "Attacker can acquire voting majority (market or flash loan)",
                               is_met=None),
        ]
        profit = self._profit("Full treasury drain via malicious governance execution",
                               asset="ERC20/ETH", scales_with_tvl=True)
        return self._make_hypothesis(
            invariant,
            title=f"Instant governance execution without timelock — treasury drain via {e}()",
            attack_class=AttackClass.GOVERNANCE,
            narrative=(
                f"`{contract}` has no timelock between proposal passing and execution.  "
                f"An attacker with governance majority can propose and execute a malicious "
                f"proposal (treasury drain, protocol pause, supply inflation) in a single transaction."
            ),
            steps=steps,
            preconditions=preconditions,
            profit=profit,
            confidence=0.82 if not pattern.has_timelock else 0.30,
            historical_protocols=_HISTORICAL,
            historical_loss=182_000_000,
            suggested_fix=(
                f"Add TimelockController with >= 48 hour delay between `{v}` and `{e}`.  "
                f"Use OpenZeppelin Governor + TimelockController.  "
                f"Emit events at proposal creation for community monitoring."
            ),
        )

    def _flash_loan_capture(self, invariant, vote_fn, execute_fn, pattern):
        contract = (invariant.contracts_involved or ["Governance"])[0]
        v = vote_fn or "vote"
        e = execute_fn or "execute"

        steps = [
            self._step(1, "Flash loan maximum governance tokens from Aave or Balancer",
                       "Acquire supermajority voting power atomically",
                       target_function="flashLoan"),
            self._step(2, f"Call `{v}()` with flash-loaned tokens to pass malicious proposal",
                       "Instant vote — snapshot protection absent",
                       target_contract=contract, target_function=v),
            self._step(3, f"Execute proposal via `{e}()` in same transaction",
                       "No delay = no chance for community intervention",
                       target_contract=contract, target_function=e),
            self._step(4, "Return governance tokens via flash loan repayment",
                       "Attacker repays loan; keeps stolen treasury funds",
                       target_function="repay"),
        ]
        preconditions = [
            self._precondition(ConditionType.FLASH_LOAN_AVAILABLE,
                               "Governance tokens flash-loanable or purchasable in one block",
                               is_met=True),
            self._precondition(ConditionType.NO_TIMELOCK,
                               "No snapshot-based voting (current balance instead of historical)",
                               is_met=None),
        ]
        profit = self._profit("Instant protocol takeover via atomic flash loan vote",
                               asset="ERC20/ETH", scales_with_tvl=True)
        return self._make_hypothesis(
            invariant,
            title=f"Flash loan governance capture — atomic vote+execute via {v}()",
            attack_class=AttackClass.GOVERNANCE,
            narrative=(
                f"Governance tokens flash-loaned in one block, used to vote and execute a "
                f"malicious proposal atomically.  Beanstalk lost $182M via this exact vector."
            ),
            steps=steps,
            preconditions=preconditions,
            profit=profit,
            confidence=0.88,
            historical_protocols=_HISTORICAL[:1],
            historical_loss=182_000_000,
            suggested_fix=(
                "Use `getPastVotes` (ERC20Votes) to count votes at proposal creation block.  "
                "Flash-loaned tokens acquired AFTER proposal creation cannot vote.  "
                "Add >= 48 hour timelock."
            ),
        )

    def _malicious_proposal(self, invariant, propose_fn, execute_fn, pattern):
        contract = (invariant.contracts_involved or ["Governance"])[0]
        p = propose_fn or "propose"
        e = execute_fn or "execute"

        steps = [
            self._step(1, f"Submit proposal via `{p}()` with malicious calldata",
                       "Proposal appears legitimate in title but calldata drains treasury",
                       target_contract=contract, target_function=p),
            self._step(2, "Accumulate votes using bribe market or sybil accounts",
                       "Vote buying is legal in many DAOs"),
            self._step(3, f"Execute proposal after voting period via `{e}()`",
                       "Malicious calldata executes treasury drain",
                       target_contract=contract, target_function=e),
        ]
        preconditions = [
            self._precondition(ConditionType.GOVERNANCE_TOKEN_AVAILABLE,
                               "Attacker has enough tokens to meet proposal threshold",
                               is_met=None),
            self._precondition(ConditionType.CUSTOM,
                               "No human review of proposal calldata before execution",
                               is_met=None),
        ]
        profit = self._profit("Treasury drain or protocol takeover via accepted malicious proposal",
                               asset="ERC20", scales_with_tvl=True)
        return self._make_hypothesis(
            invariant,
            title=f"Malicious governance proposal via {p}() — obfuscated calldata",
            attack_class=AttackClass.GOVERNANCE,
            narrative=(
                f"Attacker submits a proposal with deceptive description but malicious calldata.  "
                f"Voters may approve without decoding the raw calldata.  "
                f"Upon execution, treasury is drained."
            ),
            steps=steps,
            preconditions=preconditions,
            profit=profit,
            confidence=0.55,
            historical_protocols=["Tornado Cash governance (2023)", "Build Finance ($470K, 2022)"],
            suggested_fix=(
                "Add proposal calldata simulation in frontend.  Require calldataDecoder on-chain.  "
                "Use human-readable proposal descriptions verified by a multisig security committee."
            ),
        )

    def _proposal_frontrun(self, invariant, execute_fn) -> AttackHypothesis:
        contract = (invariant.contracts_involved or ["Governance"])[0]

        steps = [
            self._step(1, "Monitor mempool for the legitimate proposal execution transaction",
                       "The executor broadcasts `execute()` — it's visible in mempool"),
            self._step(2, "Front-run with a cancellation or duplicate proposal",
                       "Submit competing transaction with higher gas",
                       target_contract=contract),
            self._step(3, "Legitimate execution fails (wrong state) or duplicate passes",
                       "MEV-based governance disruption or double-execution"),
        ]
        preconditions = [
            self._precondition(ConditionType.CUSTOM,
                               "Execution transaction not protected against MEV (no private mempool)",
                               is_met=None),
        ]
        profit = self._profit("MEV extraction from governance execution or proposal griefing",
                               asset="ETH", scales_with_tvl=False)
        return self._make_hypothesis(
            invariant,
            title=f"MEV front-run of governance {execute_fn}() — proposal griefing",
            attack_class=AttackClass.GOVERNANCE,
            narrative=(
                f"The `{execute_fn}` call is visible in the public mempool.  "
                f"An MEV bot can front-run it to grief the execution or extract value."
            ),
            steps=steps,
            preconditions=preconditions,
            profit=profit,
            confidence=0.40,
            suggested_fix="Use commit-reveal scheme or private mempool (Flashbots Protect) for governance execution.",
        )
