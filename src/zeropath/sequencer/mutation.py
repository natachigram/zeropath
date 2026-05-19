"""
Sequence mutation engine — Phase 4.

Spec (phases.md, PHASE 4):
    "Include mutation strategies: reorder calls, vary amounts, repeat actions,
     substitute protocols."

The mutation engine takes a single :class:`TransactionSequence` and produces
deterministic variants by applying parameterised mutation operators. Each
variant carries ``is_mutation_of=parent.id`` and ``mutation_strategy=<op>``
so Phase 5 / Phase 6 can keep track of which parent the variant came from
when reporting results.

Mutation operators:

* ``scale_amount_<k>x`` — multiply every numeric ``uint*`` param by ``k``
* ``reorder_inner_steps`` — swap the order of the inner manipulation steps
  (preserving flash-loan begin/repay pair, asserts, approvals)
* ``substitute_flash_provider_<name>`` — switch flash loan provider
  (Aave V3 ↔ Balancer ↔ Uniswap V3)
* ``repeat_manipulation`` — duplicate the manipulation step to drive the
  price farther before exploiting
* ``inject_pre_drain`` — add a tiny opening swap that signals MEV bots and
  forces them to commit before the real attack (white-hat reorg test)
"""

from __future__ import annotations

import copy
import logging
import re
from typing import Callable

from zeropath.sequencer.models import (
    CallEncoding,
    SequenceStatus,
    TransactionSequence,
    TxCall,
)

logger = logging.getLogger(__name__)


# Alternative flash-loan providers for substitute mutations
_FLASH_PROVIDERS = {
    "aave_v3":  "0x87870Bca3F3fD6335C3F4ce8392D69350B4fA4E2",
    "balancer": "0xBA12222222228d8Ba445958a75a0704d566BF2C8",
    "maker":    "0x60744434d6339a6B27d73d9Eda62b6F66a0a04FA",
}


_AMOUNT_NAME_PATTERN = re.compile(
    r"amount|flashAmount|borrow|loan|wad|qty|value|reserve|swap",
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _clone(seq: TransactionSequence, strategy: str) -> TransactionSequence:
    """Deep-clone a sequence and mark it as a mutation variant."""
    clone = seq.model_copy(deep=True)
    # Fresh ID, link to parent.
    from uuid import uuid4
    clone.id = str(uuid4())
    clone.is_mutation_of = seq.id
    clone.mutation_strategy = strategy
    clone.status = SequenceStatus.GENERATED
    # Mutations invalidate any prior gas estimate.
    clone.total_gas_estimate = 0
    # Invalidate previously generated test files (will need regen for new args).
    clone.foundry_test = None
    clone.hardhat_test = None
    # Drop pre-encoded calldata since params may change.
    for c in clone.calls:
        c.calldata_hex = None
        c.function_selector = None
    return clone


def _is_uint_type(t: str) -> bool:
    return t.startswith("uint") or t == "uint"


def _is_int_type(t: str) -> bool:
    return t.startswith("int") or t == "int"


# ---------------------------------------------------------------------------
# Mutation operators
# ---------------------------------------------------------------------------


def _scale_amounts(seq: TransactionSequence, factor: int) -> TransactionSequence | None:
    """
    Multiply every uint/int param that *looks like* an amount by ``factor``.

    Heuristic: scale params where the corresponding type is uint/int AND
    either the description or a sibling expr contains an amount-ish word.
    """
    if factor in (0, 1):
        return None
    clone = _clone(seq, f"scale_amount_{factor}x")
    touched = False
    for call in clone.calls:
        scale_this_call = bool(
            _AMOUNT_NAME_PATTERN.search(call.description or "")
            or _AMOUNT_NAME_PATTERN.search(call.calldata_expr or "")
            or _AMOUNT_NAME_PATTERN.search(call.value_expr or "")
        )
        # Always scale concrete value_wei if present.
        if call.value_wei > 0:
            call.value_wei *= factor
            touched = True
        # Scale numeric uint/int params.
        new_params = list(call.params)
        for i, (ptype, pval) in enumerate(zip(call.param_types, new_params)):
            if (_is_uint_type(ptype) or _is_int_type(ptype)) and isinstance(pval, int):
                if scale_this_call or len(call.params) == 1:
                    new_params[i] = pval * factor
                    touched = True
        call.params = new_params
    if not touched:
        return None
    clone.auditor_notes.append(f"Mutation: scaled amounts by {factor}× from parent.")
    return clone


def _reorder_inner(seq: TransactionSequence) -> TransactionSequence | None:
    """
    Swap the two innermost manipulation steps.

    Skips the first call (typically setup/approval/flash-loan trigger) and
    the last call (assertion / repayment). With < 4 steps there's nothing
    to reorder.
    """
    if len(seq.calls) < 4:
        return None
    clone = _clone(seq, "reorder_inner_steps")
    inner = clone.calls[1:-1]
    if len(inner) < 2:
        return None
    # Swap the middle pair.
    mid = len(inner) // 2
    inner[mid - 1], inner[mid] = inner[mid], inner[mid - 1]
    # Re-number all steps so 1..N stays contiguous.
    reordered = [clone.calls[0]] + inner + [clone.calls[-1]]
    for i, c in enumerate(reordered, start=1):
        c.step = i
    clone.calls = reordered
    clone.auditor_notes.append(
        "Mutation: swapped order of innermost manipulation steps — "
        "tests whether the attack survives a different call ordering."
    )
    return clone


def _substitute_flash_provider(
    seq: TransactionSequence, provider_name: str
) -> TransactionSequence | None:
    """Replace the flash-loan provider address in the first matching call."""
    new_addr = _FLASH_PROVIDERS.get(provider_name)
    if not new_addr:
        return None
    if seq.context.flash_loan_provider is None:
        return None
    if seq.context.flash_loan_provider.lower() == new_addr.lower():
        return None
    clone = _clone(seq, f"substitute_flash_provider_{provider_name}")
    old_addr = seq.context.flash_loan_provider
    clone.context.flash_loan_provider = new_addr
    # Patch target addresses + expressions.
    for call in clone.calls:
        if old_addr in call.target_address_expr:
            call.target_address_expr = call.target_address_expr.replace(old_addr, new_addr)
        if call.target_address and call.target_address.lower() == old_addr.lower():
            call.target_address = new_addr
    clone.auditor_notes.append(
        f"Mutation: switched flash-loan provider {old_addr} → {new_addr} "
        f"({provider_name}). Verifies the attack isn't provider-specific."
    )
    return clone


def _repeat_manipulation(seq: TransactionSequence) -> TransactionSequence | None:
    """
    Duplicate the manipulation step to drive price farther.

    Identifies the manipulation step as the inner step whose description or
    function name suggests a swap/price move.
    """
    if len(seq.calls) < 3:
        return None
    manip_idx = None
    for i in range(1, len(seq.calls) - 1):
        call = seq.calls[i]
        if any(kw in (call.description or "").lower() for kw in ("swap", "manipul", "skew", "drive")):
            manip_idx = i
            break
        if call.function_signature and any(
            kw in call.function_signature.lower() for kw in ("swap", "exchange")
        ):
            manip_idx = i
            break
    if manip_idx is None:
        return None
    clone = _clone(seq, "repeat_manipulation")
    dup = clone.calls[manip_idx].model_copy(deep=True)
    dup.step = clone.calls[manip_idx].step + 1
    dup.description = f"[REPEATED] {dup.description}"
    dup.pre_assertions = []  # Don't re-check the same precondition
    new_calls = clone.calls[:manip_idx + 1] + [dup] + clone.calls[manip_idx + 1:]
    # Re-number trailing steps.
    for i, c in enumerate(new_calls, start=1):
        c.step = i
    clone.calls = new_calls
    clone.auditor_notes.append(
        "Mutation: duplicated manipulation step to test whether a stronger "
        "price push surfaces a larger profit (or trips a circuit breaker)."
    )
    return clone


# ---------------------------------------------------------------------------
# Public engine
# ---------------------------------------------------------------------------


# Catalogue: name → builder. Order matters — caller can request first-N.
_OPERATORS: list[tuple[str, Callable[[TransactionSequence], TransactionSequence | None]]] = [
    ("scale_amount_10x",          lambda s: _scale_amounts(s, 10)),
    ("scale_amount_100x",         lambda s: _scale_amounts(s, 100)),
    ("scale_amount_1000x",        lambda s: _scale_amounts(s, 1000)),
    ("reorder_inner_steps",       _reorder_inner),
    ("substitute_balancer",       lambda s: _substitute_flash_provider(s, "balancer")),
    ("substitute_maker",          lambda s: _substitute_flash_provider(s, "maker")),
    ("repeat_manipulation",       _repeat_manipulation),
]


class MutationEngine:
    """
    Produce parametric variants of a transaction sequence.

    Parameters
    ----------
    max_per_sequence : int
        Cap on variants emitted per input sequence. Default 4 — high enough
        to surface meaningful diversity, low enough to keep Phase 5 sim
        compute under control.
    enabled_operators : list[str] | None
        Allowlist of operator names. None = run all available.
    """

    def __init__(
        self,
        max_per_sequence: int = 4,
        enabled_operators: list[str] | None = None,
    ) -> None:
        self.max_per_sequence = max_per_sequence
        if enabled_operators is not None:
            allowed = set(enabled_operators)
            self._ops = [op for op in _OPERATORS if op[0] in allowed]
        else:
            self._ops = list(_OPERATORS)

    def mutate(self, sequence: TransactionSequence) -> list[TransactionSequence]:
        """Return up to ``max_per_sequence`` variants of ``sequence``."""
        out: list[TransactionSequence] = []
        for name, op in self._ops:
            if len(out) >= self.max_per_sequence:
                break
            try:
                variant = op(sequence)
            except Exception:
                logger.exception("Mutation operator %s failed", name)
                continue
            if variant is None:
                continue
            out.append(variant)
        return out

    def expand(
        self, sequences: list[TransactionSequence]
    ) -> list[TransactionSequence]:
        """Return parents + mutations in one flat list."""
        out: list[TransactionSequence] = []
        for seq in sequences:
            out.append(seq)
            out.extend(self.mutate(seq))
        return out
