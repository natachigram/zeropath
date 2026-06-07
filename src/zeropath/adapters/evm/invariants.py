"""EVM invariant suggestions."""

from __future__ import annotations

from zeropath.core.invariants import invariants_for_protocol_type
from zeropath.core.schemas import Invariant, ProtocolIntent


def suggest_evm_invariants(intent: ProtocolIntent) -> list[Invariant]:
    contracts = [contract for inv in intent.critical_invariants for contract in inv.affected_contracts]
    return invariants_for_protocol_type(intent.protocol_type, sorted(set(contracts)))
