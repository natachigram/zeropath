"""
Base platform formatter — Contest mode.

Each contest platform (Cantina, Code4rena, Sherlock, Immunefi) accepts
findings in its own structured shape. Subclasses implement
:meth:`render` to produce the exact payload that can be POSTed to the
platform's submission API or pasted into their web form.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from zeropath.contest.models import ContestPlatform, Submission


_SEVERITY_NORM = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "info": "informational",
    "informational": "informational",
}


class BasePlatformFormatter(ABC):
    """One concrete platform's submission schema."""

    platform: ContestPlatform = ContestPlatform.GENERIC

    @abstractmethod
    def render(self, submission: Submission) -> dict[str, Any]: ...

    def render_many(self, submissions: list[Submission]) -> list[dict[str, Any]]:
        return [self.render(s) for s in submissions]

    # Helpers shared across platforms ----------------------------------

    @staticmethod
    def _norm_severity(raw: str) -> str:
        return _SEVERITY_NORM.get((raw or "").lower(), "medium")

    @staticmethod
    def _join_loc_refs(refs: list[str]) -> str:
        return "\n".join(f"- {r}" for r in refs) if refs else "- (n/a)"
