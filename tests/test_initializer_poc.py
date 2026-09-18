"""Unit coverage for the initializer-takeover proof vertical."""

from __future__ import annotations

from zeropath.adapters.evm.initializer_poc import (
    apply_initializer_proof_evidence,
    detect_initializer_targets,
    render_initializer_poc,
)
from zeropath.adapters.evm.proof_generators import get_proof_generator
from zeropath.core.schemas import CandidateFinding, Impact, SourceLocation


def _index():
    return {
        "contracts": [{"name": "UpgradeableVault", "file": "src/UpgradeableVault.sol"}],
        "functions": [
            {
                "contract": "UpgradeableVault",
                "name": "initialize",
                "file": "src/UpgradeableVault.sol",
                "visibility": "external",
            },
            {
                "contract": "UpgradeableVault",
                "name": "owner",
                "file": "src/UpgradeableVault.sol",
                "visibility": "public",
            },
        ],
    }


def _candidate(**overrides):
    values = {
        "id": "ZP-001",
        "project_id": "fixture",
        "title": "Initializer access control may be reachable after deployment",
        "bug_class": "access_control_initializer",
        "affected_contracts": ["UpgradeableVault"],
        "root_cause_locations": [
            SourceLocation(
                file="src/UpgradeableVault.sol",
                contract="UpgradeableVault",
                function="initialize",
            )
        ],
        "impact": Impact(impact_type="unauthorized_mint", funds_at_risk=True),
    }
    values.update(overrides)
    return CandidateFinding(**values)


def test_initializer_targets_and_renderer_are_concrete():
    targets = detect_initializer_targets(_candidate(), _index())
    assert targets is not None
    assert targets.contract == "UpgradeableVault"
    assert targets.init_function == "initialize"
    rendered = render_initializer_poc(_candidate(), targets, poc_location="test/zeropath")
    assert 'import "../../src/UpgradeableVault.sol";' in rendered
    assert "unprotectedInitializerSeizesOwnership" in rendered
    assert 'emit Measured("attackerBecameOwner"' in rendered


def test_initializer_proof_interpreter_records_measured_impact():
    candidate = _candidate()
    notes = apply_initializer_proof_evidence(
        candidate,
        {"status": "passed"},
        {"attackerBecameOwner": 1, "seizedOwner": 123, "attacker": 123},
    )
    assert candidate.impact.measured is True
    assert candidate.evidence.profit_measured is True
    assert candidate.evidence.forge_result == "passed"
    assert any("takeover" in note.lower() for note in notes)


def test_proof_registry_dispatches_initializer_class():
    generator = get_proof_generator("ACCESS_CONTROL_INITIALIZER")
    assert generator is not None
    assert generator.verbosity >= 1
