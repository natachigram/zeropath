"""
Base class for all invariant detectors.

Each detector:
  1. Receives a ProtocolGraph and a ProtocolPattern.
  2. Applies its domain-specific analysis.
  3. Returns a list of Invariant objects.
  4. Is responsible for attaching formal specs and historical precedents.

The engine (engine.py) orchestrates detectors and deduplicates output.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from zeropath.models import ProtocolGraph
    from zeropath.invariants.models import Invariant, ProtocolPattern


class BaseDetector(ABC):
    """Abstract base for all invariant detectors."""

    #: Set by each subclass — used for the `detector` field on Invariant.
    name: str = "base"

    @abstractmethod
    def detect(
        self,
        graph: "ProtocolGraph",
        pattern: "ProtocolPattern",
    ) -> "list[Invariant]":
        """Run detection and return zero or more Invariant objects."""
        ...
