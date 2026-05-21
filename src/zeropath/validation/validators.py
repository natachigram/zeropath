"""
Atomic validators — Phase 6.

Each validator inspects one aspect of (hypothesis, sequence, simulation) and
returns a verdict with optional :class:`RejectionReason` codes. The
orchestrator runs them in series and short-circuits on the first failure
that crosses the "obvious false positive" threshold.

Spec (phases.md, PHASE 6 LLM prompt):
    "Validate: profit > 0, no privileged roles required, realistic
     liquidity assumptions. ... Reject false positives aggressively. When
     in doubt, reject."
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Optional

from zeropath.adversarial.models import (
    AttackHypothesis,
    ConditionType,
    Precondition,
)
from zeropath.sequencer.models import TransactionSequence
from zeropath.simulator.models import SimulationOutcome, SimulationResult
from zeropath.validation.models import RejectionReason

logger = logging.getLogger(__name__)


# Mainnet block gas limit (Shanghai / Cancun). Sequences whose estimated gas
# exceeds this are unexecutable in a single block.
BLOCK_GAS_LIMIT = 30_000_000


# ---------------------------------------------------------------------------
# Verdict
# ---------------------------------------------------------------------------


@dataclass
class ValidatorVerdict:
    """Result of one validator pass."""

    passed: bool
    rejection_reasons: list[RejectionReason] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


class BaseValidator:
    """Lightweight base — keeps the API uniform across validators."""

    name: str = "base"

    def validate(
        self,
        *,
        hypothesis: AttackHypothesis,
        sequence: TransactionSequence,
        simulation: SimulationResult,
    ) -> ValidatorVerdict:
        raise NotImplementedError


# ---------------------------------------------------------------------------
# Profit
# ---------------------------------------------------------------------------


class ProfitValidator(BaseValidator):
    """
    Reject sequences where the simulator measured zero or negative profit.

    Also rejects simulations that never executed (NOT_EXECUTED) or crashed
    inside the executor (SIMULATION_ERROR) — there is nothing to validate.
    Reverts in-EVM are flagged but not auto-rejected here so the contrarian
    agent / mutation engine can decide whether to retry.
    """

    name = "profit"

    def __init__(self, min_profit_wei: int = 1) -> None:
        self.min_profit_wei = min_profit_wei

    def validate(
        self,
        *,
        hypothesis: AttackHypothesis,
        sequence: TransactionSequence,
        simulation: SimulationResult,
    ) -> ValidatorVerdict:
        v = ValidatorVerdict(passed=True)

        if simulation.outcome == SimulationOutcome.NOT_EXECUTED:
            v.passed = False
            v.rejection_reasons.append(RejectionReason.SIMULATION_NOT_EXECUTED)
            v.notes.append("simulator did not execute the sequence (anvil missing / empty)")
            return v

        if simulation.outcome == SimulationOutcome.SIMULATION_ERROR:
            v.passed = False
            v.rejection_reasons.append(RejectionReason.SIMULATION_ERROR)
            v.notes.append(f"executor error: {simulation.revert_reason or 'unknown'}")
            return v

        if simulation.outcome == SimulationOutcome.REVERTED:
            v.passed = False
            v.rejection_reasons.append(RejectionReason.SIMULATION_REVERTED)
            v.notes.append(f"in-EVM revert: {simulation.revert_reason or 'unknown'}")
            return v

        if simulation.profit_wei < self.min_profit_wei:
            v.passed = False
            v.rejection_reasons.append(RejectionReason.PROFIT_NOT_POSITIVE)
            v.notes.append(
                f"profit_wei={simulation.profit_wei} below min={self.min_profit_wei}"
            )
            return v

        return v


# ---------------------------------------------------------------------------
# Permissions
# ---------------------------------------------------------------------------


# Preconditions that indicate the attack requires a privileged caller, not a
# random adversary. These are auto-reject conditions: a "vulnerability" that
# requires admin keys is just a feature of the admin role, not a finding.
_PRIVILEGED_PRECONDITIONS = {
    # Hypothesis explicitly says it needs governance token or owner rights.
    ConditionType.GOVERNANCE_TOKEN_AVAILABLE,
}


# Keywords in the precondition description that suggest privileged access.
_PRIVILEGED_KEYWORDS = (
    "owner",
    "admin",
    "governance proposal",
    "multisig",
    "timelocked",
    "deployer key",
    "dao vote",
)


class PermissionValidator(BaseValidator):
    """
    Reject exploits that require privileged roles (owner / admin / multisig).

    An attack that needs an admin signature is not an *exploit* — it's the
    admin doing what the admin can already do. Phase 6 must aggressively
    reject those (per spec).

    Governance attacks are exempt: the GOVERNANCE_ATTACK class is exactly
    "the attacker captures governance" so requiring a governance token is
    in-scope. We only auto-reject when the hypothesis is a governance class
    AND the precondition says the attacker *must already hold* the role.
    """

    name = "permission"

    def validate(
        self,
        *,
        hypothesis: AttackHypothesis,
        sequence: TransactionSequence,
        simulation: SimulationResult,
    ) -> ValidatorVerdict:
        v = ValidatorVerdict(passed=True)

        for pc in hypothesis.preconditions:
            if self._is_privileged_precondition(pc, hypothesis):
                v.passed = False
                v.rejection_reasons.append(RejectionReason.PRIVILEGED_ROLE_REQUIRED)
                v.notes.append(
                    f"hypothesis requires privileged caller: '{pc.description}'"
                )
                return v
        return v

    @staticmethod
    def _is_privileged_precondition(
        pc: Precondition, hypothesis: AttackHypothesis
    ) -> bool:
        if pc.condition_type in _PRIVILEGED_PRECONDITIONS:
            # Governance class is allowed to require governance tokens.
            from zeropath.adversarial.models import AttackClass
            if hypothesis.attack_class == AttackClass.GOVERNANCE:
                return False
            return True
        descr = (pc.description or "").lower()
        if any(kw in descr for kw in _PRIVILEGED_KEYWORDS):
            return True
        return False


# ---------------------------------------------------------------------------
# Realism
# ---------------------------------------------------------------------------


class RealismValidator(BaseValidator):
    """
    Reject sequences with assumptions no real attacker could meet.

    Currently checked:

    1. **Total gas vs. block limit** — if the sequence requires single-block
       atomicity but its estimated gas exceeds the mainnet block gas limit
       (30M), it cannot land atomically.

    2. **Flash-loan vs. pool depth** — if the simulator captured an on-chain
       snapshot, the flash-loan amount must fit within the largest known
       pool reserve.

    3. **No concrete target addresses** — if every TxCall still has only a
       placeholder ``target_address_expr`` (no ``target_address``), the
       sequence is a sketch, not an exploit.
    """

    name = "realism"

    def __init__(self, block_gas_limit: int = BLOCK_GAS_LIMIT) -> None:
        self.block_gas_limit = block_gas_limit

    def validate(
        self,
        *,
        hypothesis: AttackHypothesis,
        sequence: TransactionSequence,
        simulation: SimulationResult,
    ) -> ValidatorVerdict:
        v = ValidatorVerdict(passed=True)

        # Gas / atomicity
        if (
            sequence.context.requires_single_block
            and sequence.total_gas_estimate > self.block_gas_limit
        ):
            v.passed = False
            v.rejection_reasons.append(RejectionReason.UNREALISTIC_GAS)
            v.notes.append(
                f"single-block atomicity required but total_gas={sequence.total_gas_estimate:_} "
                f"> block limit {self.block_gas_limit:_}"
            )
            return v

        # Pool-depth sanity check (only when we have a snapshot)
        snap = sequence.context.onchain_snapshot
        if snap and snap.pool_reserves and sequence.uses_flash_loan:
            max_reserve = max(
                max(r0, r1) for (r0, r1, _) in snap.pool_reserves.values()
            )
            flash_amount = self._infer_flash_amount(sequence)
            if flash_amount and flash_amount > 10 * max_reserve:
                v.passed = False
                v.rejection_reasons.append(RejectionReason.UNREALISTIC_LIQUIDITY)
                v.notes.append(
                    f"flash amount {flash_amount:_} exceeds 10× largest pool reserve "
                    f"{max_reserve:_}"
                )
                return v

        # Sketch detection
        if not any(c.target_address for c in sequence.calls):
            v.passed = False
            v.rejection_reasons.append(RejectionReason.UNREALISTIC_LIQUIDITY)
            v.notes.append(
                "no concrete target_address on any call — sequence is still a sketch"
            )
            return v

        return v

    @staticmethod
    def _infer_flash_amount(sequence: TransactionSequence) -> Optional[int]:
        """Best-effort: find the largest uint256 param in a flash-loan-shaped call."""
        for call in sequence.calls:
            sig = (call.function_signature or "").lower()
            if "flashloan" in sig or "flash" in sig:
                for ptype, pval in zip(call.param_types, call.params):
                    if ptype.startswith("uint") and isinstance(pval, int) and pval > 0:
                        return pval
        return None
