"""Deterministic stateful corpus helpers.

These helpers are intentionally backend-neutral.  An EVM adapter can map a
``CorpusAction`` to ABI calldata, while a future Cairo/Move adapter can map the
same durable sequence to its own executor.  The sequence itself remains the
portable replay artifact.
"""

from __future__ import annotations

import copy
import hashlib
import random
from collections.abc import Callable, Sequence
from typing import Any

from zeropath.harness.digests import canonical_json
from zeropath.harness.models import CorpusAction, CorpusCase


def generate_cases(
    operation_ids: Sequence[str],
    *,
    seed: int,
    count: int = 8,
    depth: int = 8,
) -> list[CorpusCase]:
    """Generate a reproducible family of abstract stateful sequences."""

    if count < 0 or depth < 0:
        raise ValueError("count and depth must be non-negative")
    operations = [str(item) for item in operation_ids if str(item)]
    if not operations or count == 0 or depth == 0:
        return []
    rng = random.Random(seed)
    cases: list[CorpusCase] = []
    for index in range(count):
        length = rng.randint(1, depth)
        actions = [
            CorpusAction(operation_id=(operation := rng.choice(operations)), name=operation)
            for _ in range(length)
        ]
        case_seed = rng.randrange(0, 2**63)
        case_id = case_fingerprint(case_seed, actions)[:16]
        cases.append(
            CorpusCase(
                case_id=f"CASE-{case_id}",
                seed=case_seed,
                depth=length,
                actions=actions,
            )
        )
    return cases


def case_fingerprint(seed: int, actions: Sequence[CorpusAction]) -> str:
    """Hash a sequence using stable JSON rather than Python object reprs."""

    payload = {
        "seed": seed,
        "actions": [action.model_dump(mode="json") for action in actions],
    }
    encoded = canonical_json(payload).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def shrink_case(
    case: CorpusCase,
    fails: Callable[[CorpusCase], bool],
) -> CorpusCase:
    """Greedily minimize a failing sequence while preserving its failure.

    The predicate is supplied by the backend adapter and must be deterministic
    for a fixed case.  We try action deletion first, then shrink integer
    arguments toward zero.  If the original case does not fail, it is returned
    unchanged rather than manufacturing a failure.
    """

    current = copy.deepcopy(case)
    if not fails(current):
        return current

    changed = True
    while changed and len(current.actions) > 1:
        changed = False
        for index in range(len(current.actions)):
            candidate = copy.deepcopy(current)
            del candidate.actions[index]
            candidate.depth = len(candidate.actions)
            if fails(candidate):
                current = candidate
                changed = True
                break

    for action_index, action in enumerate(current.actions):
        for argument_index, value in enumerate(list(action.arguments)):
            if not isinstance(value, int) or value == 0:
                continue
            for replacement in _integer_shrinks(value):
                candidate = copy.deepcopy(current)
                candidate.actions[action_index].arguments[argument_index] = replacement
                if fails(candidate):
                    current = candidate
                    break

    current.status = "shrunk"
    current.case_id = f"CASE-{case_fingerprint(current.seed, current.actions)[:16]}"
    current.depth = len(current.actions)
    return current


def _integer_shrinks(value: int) -> list[int]:
    candidates = [0, 1, value // 2, -1 if value < 0 else 2]
    return list(dict.fromkeys(item for item in candidates if item != value))


__all__ = ["case_fingerprint", "generate_cases", "shrink_case"]
