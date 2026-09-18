"""Registry of concrete Foundry proof generators, keyed by bug class.

Each :class:`ProofGenerator` turns a candidate of its bug class into an
executable Foundry PoC that emits ``Measured(name, value)`` events, plus the
logic to interpret those measurements into candidate evidence. This is the
bug-class-agnostic spine the adapter and CLI dispatch through: adding support
for a new class is adding one ``ProofGenerator`` here -- no changes to
``adapter.generate_poc`` or the ``prove`` command.

Scope: ERC4626 share inflation and initializer takeover today. Both are
fixture-shaped templates (see each module's docstring), not general analyzers.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from zeropath.adapters.evm.inflation_poc import (
    apply_inflation_proof_evidence,
    detect_inflation_targets,
    render_inflation_poc,
)
from zeropath.adapters.evm.initializer_poc import (
    apply_initializer_proof_evidence,
    detect_initializer_targets,
    render_initializer_poc,
)
from zeropath.core.inflation_guards import INFLATION_BUG_CLASSES
from zeropath.core.initializer_guards import INITIALIZER_BUG_CLASSES
from zeropath.core.schemas import CandidateFinding


class ProofTargets(Protocol):
    """The per-class target bundle. Must describe itself for evidence notes."""

    def describe(self) -> str: ...
    def import_path_for(self, poc_location: str) -> str: ...


TargetDetector = Callable[[CandidateFinding, "dict[str, Any] | None", "Path | None"], "ProofTargets | None"]
PocRenderer = Callable[..., str]
Interpreter = Callable[[CandidateFinding, "dict[str, Any]", "dict[str, int]"], "list[str]"]


@dataclass(frozen=True)
class ProofGenerator:
    """A concrete proof generator for one or more bug classes."""

    bug_classes: frozenset[str]
    detect_targets: TargetDetector
    render_poc: PocRenderer
    interpret: Interpreter
    verbosity: int = 4


_GENERATORS: list[ProofGenerator] = [
    ProofGenerator(
        bug_classes=frozenset(c.lower() for c in INFLATION_BUG_CLASSES),
        detect_targets=detect_inflation_targets,
        render_poc=render_inflation_poc,
        interpret=apply_inflation_proof_evidence,
    ),
    ProofGenerator(
        bug_classes=frozenset(c.lower() for c in INITIALIZER_BUG_CLASSES),
        detect_targets=detect_initializer_targets,
        render_poc=render_initializer_poc,
        interpret=apply_initializer_proof_evidence,
    ),
]


def get_proof_generator(bug_class: str | None) -> ProofGenerator | None:
    """Return the proof generator registered for ``bug_class`` (or None)."""

    key = (bug_class or "").lower()
    for generator in _GENERATORS:
        if key in generator.bug_classes:
            return generator
    return None


__all__ = ["ProofGenerator", "ProofTargets", "get_proof_generator"]
