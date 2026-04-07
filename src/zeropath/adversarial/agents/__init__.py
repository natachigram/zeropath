"""Adversarial agent implementations."""

from zeropath.adversarial.agents.access import AccessControlAgent
from zeropath.adversarial.agents.composability import ComposabilityAgent
from zeropath.adversarial.agents.flash_loan import FlashLoanAgent
from zeropath.adversarial.agents.governance import GovernanceAttackAgent
from zeropath.adversarial.agents.integer_math import IntegerMathAgent
from zeropath.adversarial.agents.oracle import OracleManipulatorAgent
from zeropath.adversarial.agents.reentrancy import ReentrancyAgent

__all__ = [
    "OracleManipulatorAgent",
    "ReentrancyAgent",
    "AccessControlAgent",
    "FlashLoanAgent",
    "ComposabilityAgent",
    "GovernanceAttackAgent",
    "IntegerMathAgent",
]
