"""Per-bug-class anti-condition + mitigation dispatch.

An *anti-condition* is a source-level pattern that makes a candidate's exploit
unlikely to be real (e.g. an ERC4626 vault using virtual shares defeats donation
inflation). The judge uses these to block or downgrade a candidate unless a
passing PoC overrides the heuristic.

This module is the bug-class-agnostic spine: the judge and report layer call
``detect_anti_conditions``/``mitigations_for`` with a ``bug_class`` and never need
to know which detector handles it. Each class registers its detector + mitigation
text in its own module (e.g. ``inflation_guards``, ``initializer_guards``); the
imports at the bottom wire them in. Detection is heuristic (regex over source).
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

GuardDetector = Callable[[str], "list[GuardHit]"]


@dataclass(frozen=True)
class GuardHit:
    """One detected anti-condition."""

    name: str
    detail: str
    confidence: str = "heuristic"


_DETECTORS: dict[str, GuardDetector] = {}
_MITIGATIONS: dict[str, list[str]] = {}


def register_anti_conditions(
    bug_classes: set[str] | frozenset[str],
    detector: GuardDetector,
    mitigations: list[str],
) -> None:
    """Register a class's anti-condition detector and report mitigations."""

    for bug_class in bug_classes:
        key = bug_class.lower()
        _DETECTORS[key] = detector
        _MITIGATIONS[key] = list(mitigations)


def detect_anti_conditions(bug_class: str | None, source: str) -> list[GuardHit]:
    """Run the registered detector for ``bug_class`` (empty if none/unknown)."""

    detector = _DETECTORS.get((bug_class or "").lower())
    if detector is None or not source:
        return []
    return detector(source)


def mitigations_for(bug_class: str | None) -> list[str]:
    """Return class-specific report mitigation lines (empty if none/unknown)."""

    return list(_MITIGATIONS.get((bug_class or "").lower(), []))


def summarize_guards(hits: list[GuardHit]) -> str:
    """One-line, human-readable summary of detected guards."""

    if not hits:
        return "none detected"
    return ", ".join(f"{hit.name} ({hit.confidence})" for hit in hits)


# Import class modules for their registration side effects. Placed at the bottom
# so GuardHit + register_anti_conditions are defined before the modules import
# them back (avoids a circular import at load time).
from zeropath.core import inflation_guards as _inflation_guards  # noqa: E402,F401
from zeropath.core import initializer_guards as _initializer_guards  # noqa: E402,F401

__all__ = [
    "GuardHit",
    "detect_anti_conditions",
    "mitigations_for",
    "register_anti_conditions",
    "summarize_guards",
]
