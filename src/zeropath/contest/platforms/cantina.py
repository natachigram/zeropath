"""
Cantina submission formatter.

Cantina expects a structured JSON-ish payload with: ``title``, ``severity``,
``description``, ``impact``, ``proof_of_concept``, ``recommendation``,
``lines_of_code``. Severity maps to their ``critical|high|medium|low|gas``
rubric.

Reference: https://cantina.xyz — competition submission schema observed
from public reports as of mid-2026.
"""

from __future__ import annotations

from typing import Any

from zeropath.contest.models import ContestPlatform, Submission
from zeropath.contest.platforms.base import BasePlatformFormatter


_CANTINA_SEVERITY = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "informational": "low",   # Cantina collapses info into low / gas
}


class CantinaFormatter(BasePlatformFormatter):
    platform = ContestPlatform.CANTINA

    def render(self, submission: Submission) -> dict[str, Any]:
        f = submission.finding
        severity = _CANTINA_SEVERITY.get(self._norm_severity(f.severity), "medium")
        return {
            "title": f.title,
            "severity": severity,
            "lines_of_code": list(f.lines_of_code),
            "description": self._description(f),
            "impact": f.impact or "(see attack path)",
            "proof_of_concept": (
                f.proof_of_concept_code
                or "_See attack path; no executable PoC attached._"
            ),
            "recommendation": f.recommendation or "(no automated recommendation)",
            "attack_class": f.attack_class,
            "confidence": round(f.confidence, 3),
            "_zeropath": {
                "duplicate_likelihood": round(f.duplicate_likelihood, 3),
                "hypothesis_id": f.hypothesis_id,
                "validation_result_id": f.validation_result_id,
                "novelty_assessment": f.novelty_assessment,
            },
        }

    @staticmethod
    def _description(f) -> str:
        parts = []
        if f.description:
            parts.append(f.description)
        if f.attack_path:
            parts.append("\n**Attack path:**")
            parts.extend(f"{i + 1}. {step}" for i, step in enumerate(f.attack_path))
        if f.preconditions:
            parts.append("\n**Preconditions:**")
            parts.extend(f"- {p}" for p in f.preconditions)
        if f.historical_precedents:
            parts.append("\n**Historical precedents:**")
            for ref in f.historical_precedents[:3]:
                parts.append(
                    f"- {ref.get('protocol', 'unknown')} "
                    f"({ref.get('incident_date', 'n/a')}) — "
                    f"${ref.get('loss_usd', 0):,}"
                )
        return "\n".join(parts).strip()
