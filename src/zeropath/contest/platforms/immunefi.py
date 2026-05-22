"""
Immunefi submission formatter.

Immunefi expects: project ID, bug title, severity (Immunefi v2 severity:
``critical|high|medium|low``), description with reproduction steps, and a
*runnable* PoC attached. They emphasise root cause + impact + reproduction.

Reference: https://immunefi.com/learn — schema mirrors their submission UI
as of mid-2026.
"""

from __future__ import annotations

from typing import Any

from zeropath.contest.models import ContestPlatform, Submission
from zeropath.contest.platforms.base import BasePlatformFormatter


_IMMUNEFI_SEVERITY = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "informational": "low",
}


class ImmunefiFormatter(BasePlatformFormatter):
    platform = ContestPlatform.IMMUNEFI

    def render(self, submission: Submission) -> dict[str, Any]:
        f = submission.finding
        severity = _IMMUNEFI_SEVERITY.get(self._norm_severity(f.severity), "medium")
        return {
            "title": f.title,
            "severity": severity,
            "vulnerability_type": f.attack_class,
            "description": self._description(f),
            "impact": f.impact or "(see attack path)",
            "reproduction_steps": list(f.attack_path),
            "preconditions": list(f.preconditions),
            "poc_code": f.proof_of_concept_code,
            "poc_run_log": f.proof_of_concept_run_log,
            "recommendation": f.recommendation,
            "affected_files": list(f.lines_of_code),
            "_zeropath": {
                "confidence": round(f.confidence, 3),
                "duplicate_likelihood": round(f.duplicate_likelihood, 3),
                "historical_precedents": f.historical_precedents,
            },
        }

    @staticmethod
    def _description(f) -> str:
        parts = []
        if f.description:
            parts.append(f.description)
        if f.preconditions:
            parts.append("\nPreconditions:")
            parts.extend(f"- {p}" for p in f.preconditions)
        return "\n".join(parts).strip()
