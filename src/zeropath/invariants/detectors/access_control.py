"""
Access control invariant detector.

Detection strategy:
  1. Find admin/privileged functions (upgrade, pause, mint, setOracle, etc.).
  2. Check whether each privileged function has access control modifiers
     or onlyOwner / onlyRole patterns.
  3. Detect missing access control on upgrade functions (CRITICAL).
  4. Detect missing access control on mint/burn functions (HIGH).
  5. Check proxy contracts: upgradeTo/upgradeToAndCall unprotected is CRITICAL.
"""

from __future__ import annotations

from zeropath.invariants.detectors.base import BaseDetector
from zeropath.invariants.formal_spec import FormalSpecGenerator
from zeropath.invariants.models import (
    Invariant,
    InvariantSeverity,
    InvariantType,
    ProtocolPattern,
)
from zeropath.invariants.rag import get_rag
from zeropath.logging_config import get_logger
from zeropath.models import Function, ProtocolGraph, Visibility

logger = get_logger(__name__)

# Function name keywords by risk tier
_CRITICAL_FUNC_KW = {"upgrade", "upgradeto", "initialize", "selfdestruct", "destroy"}
_HIGH_FUNC_KW = {
    "mint", "burn", "setoracle", "setrole", "grant", "revoke",
    "pause", "unpause", "setfee", "setowner", "transferownership",
    "withdrawall", "emergencywithdraw",
}
_MEDIUM_FUNC_KW = {"setparam", "setconfig", "setaddress", "setthreshold", "setlimit"}

# Modifiers that imply access control
_AC_MODIFIER_KW = {
    "onlyowner", "onlyrole", "restricted", "auth", "admin",
    "onlygovernance", "onlymultisig", "onlyguardian",
}

_spec_gen = FormalSpecGenerator()
_rag = get_rag()


class AccessControlDetector(BaseDetector):
    """Detect missing or insufficient access control on privileged functions."""

    name = "access_control"

    def detect(
        self,
        graph: ProtocolGraph,
        pattern: ProtocolPattern,
    ) -> list[Invariant]:
        results: list[Invariant] = []

        for func in graph.functions:
            if func.visibility not in (Visibility.PUBLIC, Visibility.EXTERNAL):
                continue
            if func.is_view or func.is_pure:
                continue

            name_lower = func.name.lower()
            tier = _classify_tier(name_lower)
            if tier is None:
                continue

            has_ac = _has_access_control(func)
            if has_ac:
                continue  # Protected — no finding

            severity, confidence = _risk_for_tier(tier)

            from zeropath.invariants.oracle_mapper import _contract_name_for_function
            contract_name = _contract_name_for_function(func, graph)

            precedents = _rag.query(
                InvariantType.ACCESS_CONTROL,
                tags={"access_control"},
            )
            boost = _rag.confidence_boost(precedents)
            evidence_str = _rag.evidence_summary(precedents)

            evidence = [
                f"{contract_name}.{func.name}() is a {tier}-risk privileged function "
                f"with visibility={func.visibility.value} and NO access control modifier."
            ]
            if evidence_str:
                evidence.append(evidence_str)

            results.append(
                Invariant(
                    type=InvariantType.ACCESS_CONTROL,
                    severity=severity,
                    description=(
                        f"{contract_name}.{func.name}() appears to be a privileged "
                        f"function but has no access control. Any caller can invoke it."
                    ),
                    formal_spec=_spec_gen.generate(InvariantType.ACCESS_CONTROL, pattern),
                    confidence=min(confidence + boost, 0.95),
                    contracts_involved=[contract_name],
                    functions_involved=[func.name],
                    historical_precedent=precedents,
                    evidence=evidence,
                    detector=self.name,
                )
            )

        logger.debug("access_control_detector", findings=len(results))
        return results


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _classify_tier(name_lower: str) -> str | None:
    if any(kw in name_lower for kw in _CRITICAL_FUNC_KW):
        return "critical"
    if any(kw in name_lower for kw in _HIGH_FUNC_KW):
        return "high"
    if any(kw in name_lower for kw in _MEDIUM_FUNC_KW):
        return "medium"
    return None


def _has_access_control(func: Function) -> bool:
    """Return True if the function has any access control protection."""
    # Explicit access control via Slither analysis
    if func.access_control.only_owner or func.access_control.only_role:
        return True
    if func.access_control.requires_auth:
        return True
    # Modifier-based detection
    modifiers_lower = [m.lower() for m in func.modifiers]
    return any(
        any(kw in m for kw in _AC_MODIFIER_KW)
        for m in modifiers_lower
    )


def _risk_for_tier(tier: str) -> tuple[InvariantSeverity, float]:
    if tier == "critical":
        return InvariantSeverity.CRITICAL, 0.80
    if tier == "high":
        return InvariantSeverity.HIGH, 0.70
    return InvariantSeverity.MEDIUM, 0.50
