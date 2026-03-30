"""
Oracle dependency mapper.

Scans a ProtocolGraph for external price oracle references and classifies
each one by:
  - Oracle type (Chainlink, Uniswap spot, TWAP, Band, custom)
  - Whether the read happens in a single block (manipulation risk)
  - Whether the result is used in a state-changing function

Price oracle manipulation is the root cause of billions in DeFi losses.
Detecting it at the static analysis stage is critical for Phase 3 attack
hypothesis generation.

Detection strategy:
  1. External dependencies with known oracle interfaces
  2. State variables typed as oracle interfaces
  3. Function call patterns to known oracle read functions
  4. Cross-reference: is the oracle-reading function state-mutating?
"""

from typing import Optional

from zeropath.invariants.models import (
    OracleDependency,
    OracleManipulationRisk,
    OracleType,
)
from zeropath.logging_config import get_logger
from zeropath.models import ExternalDependency, Function, ProtocolGraph, StateVariable

logger = get_logger(__name__)


# ---------------------------------------------------------------------------
# Oracle interface registry
# ---------------------------------------------------------------------------

#: Maps interface name (lower) → (OracleType, is_single_block)
_INTERFACE_MAP: dict[str, tuple[OracleType, bool]] = {
    # Chainlink — aggregator, not single-block manipulable
    "aggregatorv3interface":       (OracleType.CHAINLINK, False),
    "aggregatorinterface":         (OracleType.CHAINLINK, False),
    "iaggregatortransmitter":      (OracleType.CHAINLINK, False),
    "chainlinkoracle":             (OracleType.CHAINLINK, False),
    "keepercompatibleinterface":   (OracleType.CHAINLINK, False),
    "iaccess_control_chain_link":  (OracleType.CHAINLINK, False),

    # Uniswap V2 — getReserves() is a single-block spot price
    "iuniswapv2pair":              (OracleType.UNISWAP_SPOT, True),
    "iuniswapv2factory":           (OracleType.UNISWAP_SPOT, True),
    "iuniswapv2router":            (OracleType.UNISWAP_SPOT, True),
    "iuniswapv2router02":          (OracleType.UNISWAP_SPOT, True),

    # Uniswap V2 TWAP oracle libraries
    "uniswaporaclev2":             (OracleType.UNISWAP_TWAP, False),
    "iuniswaporacle":              (OracleType.UNISWAP_TWAP, False),

    # Uniswap V3 — slot0 is single-block; observe() is TWAP
    "iuniswapv3pool":              (OracleType.UNISWAP_SPOT, True),  # conservative
    "iuniswapv3factory":           (OracleType.UNISWAP_SPOT, True),

    # Band Protocol — decentralised, not single-block
    "istdreference":               (OracleType.BAND_PROTOCOL, False),
    "ibridgeaggregator":           (OracleType.BAND_PROTOCOL, False),

    # Balancer TWAP
    "iweightedpool":               (OracleType.BALANCER_TWAP, False),
    "ibalancervault":              (OracleType.BALANCER_TWAP, False),
}

#: Oracle read function names → (OracleType, is_single_block)
_READ_FUNCTION_MAP: dict[str, tuple[OracleType, bool]] = {
    # Chainlink
    "latestrounddata":     (OracleType.CHAINLINK, False),
    "latesttimestamp":     (OracleType.CHAINLINK, False),
    "latestanswer":        (OracleType.CHAINLINK, False),
    "getrounddata":        (OracleType.CHAINLINK, False),

    # Uniswap V2 spot
    "getreserves":         (OracleType.UNISWAP_SPOT, True),   # HIGH RISK
    "price0cumulativelast": (OracleType.UNISWAP_TWAP, False),
    "price1cumulativelast": (OracleType.UNISWAP_TWAP, False),

    # Uniswap V3
    "slot0":               (OracleType.UNISWAP_SPOT, True),   # HIGH RISK (sqrtPriceX96)
    "observe":             (OracleType.UNISWAP_TWAP, False),  # TWAP
    "observations":        (OracleType.UNISWAP_TWAP, False),

    # Band Protocol
    "getreferencedata":    (OracleType.BAND_PROTOCOL, False),

    # Generic patterns
    "getprice":            (OracleType.UNKNOWN, True),         # assume single-block unless proven
    "currentprice":        (OracleType.UNKNOWN, True),
    "price":               (OracleType.UNKNOWN, True),
    "consult":             (OracleType.UNISWAP_TWAP, False),  # Uniswap TWAP library
    "update":              (OracleType.UNISWAP_TWAP, False),  # TWAP update
}

_RISK_MAP: dict[tuple[OracleType, bool], OracleManipulationRisk] = {
    (OracleType.CHAINLINK, False):       OracleManipulationRisk.LOW,
    (OracleType.UNISWAP_SPOT, True):     OracleManipulationRisk.HIGH,
    (OracleType.UNISWAP_TWAP, False):    OracleManipulationRisk.MEDIUM,
    (OracleType.BALANCER_TWAP, False):   OracleManipulationRisk.MEDIUM,
    (OracleType.BAND_PROTOCOL, False):   OracleManipulationRisk.LOW,
    (OracleType.UNKNOWN, True):          OracleManipulationRisk.HIGH,
    (OracleType.UNKNOWN, False):         OracleManipulationRisk.MEDIUM,
}

# Functions considered "state-changing" (not view/pure)
_VIEW_LIKE_MODIFIERS = {"view", "pure"}


# ---------------------------------------------------------------------------
# Oracle mapper
# ---------------------------------------------------------------------------


class OracleMapper:
    """
    Map all oracle dependencies in a ProtocolGraph.

    Usage::

        mapper = OracleMapper()
        deps = mapper.map(graph)
    """

    def map(self, graph: ProtocolGraph) -> list[OracleDependency]:
        """
        Scan the graph and return every detected oracle dependency.

        Returns:
            List of OracleDependency, deduplicated by (contract, function, oracle).
        """
        results: list[OracleDependency] = []
        seen: set[tuple[str, str, str]] = set()

        # 1. Scan external dependencies for known oracle interfaces
        for dep in graph.external_dependencies:
            deps_from_interface = self._from_external_dep(dep, graph.functions)
            for od in deps_from_interface:
                key = (od.contract_name, od.function_name, od.oracle_contract)
                if key not in seen:
                    seen.add(key)
                    results.append(od)

        # 2. Scan state variables for oracle-typed variables
        for var in graph.state_variables:
            deps_from_var = self._from_state_variable(var, graph)
            for od in deps_from_var:
                key = (od.contract_name, od.function_name, od.oracle_contract)
                if key not in seen:
                    seen.add(key)
                    results.append(od)

        # 3. Scan function calls for oracle read patterns
        for func in graph.functions:
            deps_from_calls = self._from_function_calls(func, graph)
            for od in deps_from_calls:
                key = (od.contract_name, od.function_name, od.oracle_contract)
                if key not in seen:
                    seen.add(key)
                    results.append(od)

        logger.info(
            "oracle_dependencies_mapped",
            count=len(results),
            high_risk=sum(1 for d in results if d.manipulation_risk == OracleManipulationRisk.HIGH),
        )
        return results

    # ------------------------------------------------------------------
    # Strategy 1: External dependencies with oracle interfaces
    # ------------------------------------------------------------------

    def _from_external_dep(
        self,
        dep: ExternalDependency,
        functions: list[Function],
    ) -> list[OracleDependency]:
        """Detect oracle usage from an external dependency's interface."""
        iface = (dep.interface or "").lower()
        name_lower = dep.name.lower()

        oracle_type, is_single_block = _INTERFACE_MAP.get(
            iface,
            (None, None),  # type: ignore
        )

        # Heuristic: if interface not in map, check name
        if oracle_type is None:
            if any(kw in name_lower for kw in {"oracle", "price", "feed", "aggregator", "twap"}):
                oracle_type = OracleType.UNKNOWN
                is_single_block = True  # pessimistic
            else:
                return []

        results: list[OracleDependency] = []
        risk = _RISK_MAP.get(
            (oracle_type, bool(is_single_block)),
            OracleManipulationRisk.MEDIUM,
        )

        # Find caller functions
        caller_names = dep.call_sites  # "ContractName.functionName"
        for caller_str in caller_names:
            parts = caller_str.split(".")
            contract_name = parts[0] if parts else "Unknown"
            func_name = parts[1] if len(parts) > 1 else "unknown"

            # Is it a state-changing call?
            is_mutating = _is_state_changing_function(func_name, functions)

            results.append(
                OracleDependency(
                    contract_name=contract_name,
                    function_name=func_name,
                    oracle_contract=dep.name,
                    oracle_type=oracle_type,
                    read_function=dep.name,
                    is_single_block=bool(is_single_block),
                    manipulation_risk=risk,
                    used_in_state_changing_function=is_mutating,
                    evidence=f"ExternalDependency({dep.name}) has interface={dep.interface}",
                )
            )

        # If no call sites found, create a generic entry
        if not caller_names:
            results.append(
                OracleDependency(
                    contract_name="Unknown",
                    function_name="unknown",
                    oracle_contract=dep.name,
                    oracle_type=oracle_type,
                    read_function=dep.name,
                    is_single_block=bool(is_single_block),
                    manipulation_risk=risk,
                    evidence=f"ExternalDependency({dep.name}) has oracle interface",
                )
            )

        return results

    # ------------------------------------------------------------------
    # Strategy 2: State variables typed as oracle interfaces
    # ------------------------------------------------------------------

    def _from_state_variable(
        self,
        var: StateVariable,
        graph: ProtocolGraph,
    ) -> list[OracleDependency]:
        """Detect oracle variables and find functions that read them."""
        type_lower = var.type_.lower()
        oracle_type, is_single_block = _INTERFACE_MAP.get(type_lower, (None, None))  # type: ignore

        if oracle_type is None:
            # Check if variable name or type suggests an oracle
            name_lower = var.name.lower()
            if not any(kw in name_lower or kw in type_lower
                       for kw in {"oracle", "feed", "price", "aggregator"}):
                return []
            oracle_type = OracleType.UNKNOWN
            is_single_block = True

        risk = _RISK_MAP.get(
            (oracle_type, bool(is_single_block)),
            OracleManipulationRisk.MEDIUM,
        )

        results: list[OracleDependency] = []

        # Find functions that read this oracle variable
        for func in graph.functions:
            if var.name in func.state_vars_read:
                # Get contract name
                contract_name = _contract_name_for_function(func, graph)
                is_mutating = not (func.is_view or func.is_pure)

                results.append(
                    OracleDependency(
                        contract_name=contract_name,
                        function_name=func.name,
                        oracle_contract=var.name,
                        oracle_type=oracle_type,
                        read_function=var.name,
                        is_single_block=bool(is_single_block),
                        manipulation_risk=risk,
                        used_in_state_changing_function=is_mutating,
                        evidence=f"StateVariable({var.name}: {var.type_}) read in {func.name}()",
                    )
                )

        return results

    # ------------------------------------------------------------------
    # Strategy 3: Function calls matching oracle read function names
    # ------------------------------------------------------------------

    def _from_function_calls(
        self,
        func: Function,
        graph: ProtocolGraph,
    ) -> list[OracleDependency]:
        """Detect oracle reads from function call names."""
        from zeropath.models import FunctionCall, CallType

        results: list[OracleDependency] = []

        # Find all external calls made by this function
        external_calls = [
            fc for fc in graph.function_calls
            if fc.caller_id == func.id and fc.call_type in (
                CallType.EXTERNAL, CallType.STATICCALL, CallType.LOW_LEVEL
            )
        ]

        for call in external_calls:
            callee_lower = call.callee_name.lower()
            oracle_type, is_single_block = _READ_FUNCTION_MAP.get(
                callee_lower, (None, None)  # type: ignore
            )

            if oracle_type is None:
                continue

            risk = _RISK_MAP.get(
                (oracle_type, bool(is_single_block)),
                OracleManipulationRisk.MEDIUM,
            )

            contract_name = _contract_name_for_function(func, graph)
            is_mutating = not (func.is_view or func.is_pure)

            results.append(
                OracleDependency(
                    contract_name=contract_name,
                    function_name=func.name,
                    oracle_contract=call.callee_contract or "Unknown",
                    oracle_type=oracle_type,
                    read_function=call.callee_name,
                    is_single_block=bool(is_single_block),
                    manipulation_risk=risk,
                    used_in_state_changing_function=is_mutating,
                    evidence=(
                        f"{func.name}() calls {call.callee_name}() "
                        f"on {call.callee_contract or 'external contract'}"
                    ),
                )
            )

        return results


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _is_state_changing_function(func_name: str, functions: list[Function]) -> bool:
    """Return True if the named function is not view/pure."""
    for func in functions:
        if func.name == func_name:
            return not (func.is_view or func.is_pure)
    # Unknown functions are assumed to be state-changing (pessimistic)
    return True


def _contract_name_for_function(func: Function, graph: ProtocolGraph) -> str:
    """Look up the contract name for a function."""
    for contract in graph.contracts:
        if contract.id == func.contract_id:
            return contract.name
    return "Unknown"
