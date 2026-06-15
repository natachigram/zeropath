"""Unit tests for the concrete ERC4626 inflation PoC generator."""

from __future__ import annotations

from zeropath.adapters.evm.inflation_poc import (
    InflationProofTargets,
    apply_inflation_proof_evidence,
    detect_inflation_targets,
    parse_measured_events,
    render_inflation_poc,
)
from zeropath.core.schemas import CandidateFinding, Impact, SourceLocation


def _index(*, vault="VulnerableVault", asset="MockERC20", source="src/VulnerableVault.sol"):
    """Build an EVM index shaped like the parser's real output."""

    def fn(contract, name):
        return {"contract": contract, "name": name, "file": source}

    functions = [
        fn(vault, "deposit"),
        fn(vault, "redeem"),
        fn(vault, "withdraw"),
        fn(vault, "totalAssets"),
        fn(asset, "mint"),
        fn(asset, "transfer"),
        fn(asset, "transferFrom"),
        fn(asset, "approve"),
    ]
    contracts = [{"name": asset, "file": source}, {"name": vault, "file": source}]
    return {"functions": functions, "contracts": contracts}


def _candidate(**overrides) -> CandidateFinding:
    defaults = {
        "id": "ZP-001",
        "project_id": "demo",
        "title": "Vault share accounting may be inflation-sensitive",
        "bug_class": "erc4626_share_inflation",
        "affected_contracts": ["VulnerableVault"],
        "impact": Impact(impact_type="direct_theft", funds_at_risk=True, explanation="demo"),
    }
    defaults.update(overrides)
    return CandidateFinding(**defaults)


# ---------------------------------------------------------------------------
# InflationProofTargets.import_path_for
# ---------------------------------------------------------------------------


def test_import_path_for_root_location_has_no_prefix():
    targets = InflationProofTargets("V", "A", "src/V.sol")
    assert targets.import_path_for("") == "src/V.sol"


def test_import_path_for_adjusts_depth_per_directory_segment():
    targets = InflationProofTargets("V", "A", "src/V.sol")
    assert targets.import_path_for("test/zeropath") == "../../src/V.sol"
    assert targets.import_path_for(".zeropath/artifacts/pocs") == "../../../src/V.sol"


def test_import_path_for_normalizes_backslashes_and_trailing_slash():
    targets = InflationProofTargets("V", "A", "src/V.sol")
    assert targets.import_path_for("test\\zeropath\\") == "../../src/V.sol"


# ---------------------------------------------------------------------------
# detect_inflation_targets
# ---------------------------------------------------------------------------


def test_detect_returns_targets_for_matching_vault_and_asset():
    targets = detect_inflation_targets(_candidate(), _index())
    assert targets is not None
    assert targets.vault_contract == "VulnerableVault"
    assert targets.asset_contract == "MockERC20"
    assert targets.source_file == "src/VulnerableVault.sol"


def test_detect_returns_none_for_unrelated_bug_class():
    assert detect_inflation_targets(_candidate(bug_class="reentrancy"), _index()) is None


def test_detect_returns_none_when_bug_class_missing():
    assert detect_inflation_targets(_candidate(bug_class=None), _index()) is None


def test_detect_is_case_insensitive_on_bug_class():
    targets = detect_inflation_targets(
        _candidate(bug_class="ERC4626_Share_Inflation"), _index()
    )
    assert targets is not None


def test_detect_returns_none_without_index():
    assert detect_inflation_targets(_candidate(), None) is None
    assert detect_inflation_targets(_candidate(), {}) is None


def test_detect_returns_none_when_no_asset_contract_present():
    index = _index()
    # Drop the asset's ERC20 functions so nothing looks like a mintable asset.
    index["functions"] = [f for f in index["functions"] if f["contract"] != "MockERC20"]
    index["contracts"] = [c for c in index["contracts"] if c["name"] != "MockERC20"]
    assert detect_inflation_targets(_candidate(), index) is None


def test_detect_returns_none_when_no_vault_shape_present():
    index = _index()
    # Strip the vault entrypoints so no contract looks like a vault.
    index["functions"] = [
        f
        for f in index["functions"]
        if not (f["contract"] == "VulnerableVault" and f["name"] in {"deposit", "redeem", "withdraw", "totalAssets"})
    ]
    assert detect_inflation_targets(_candidate(), index) is None


def test_detect_uses_root_cause_location_contract_as_hint():
    index = _index(vault="Pool")
    candidate = _candidate(
        affected_contracts=[],
        root_cause_locations=[
            SourceLocation(file="src/VulnerableVault.sol", contract="Pool", function="totalAssets")
        ],
    )
    targets = detect_inflation_targets(candidate, index)
    assert targets is not None
    assert targets.vault_contract == "Pool"


def test_detect_falls_back_to_shape_when_hints_do_not_match():
    # Candidate points at a contract that is not in the index; detection should
    # still find the vault by function shape.
    candidate = _candidate(affected_contracts=["DoesNotExist"])
    targets = detect_inflation_targets(candidate, _index())
    assert targets is not None
    assert targets.vault_contract == "VulnerableVault"


# ---------------------------------------------------------------------------
# render_inflation_poc
# ---------------------------------------------------------------------------


def test_render_includes_sanitized_names_and_import():
    targets = InflationProofTargets("VulnerableVault", "MockERC20", "src/VulnerableVault.sol")
    poc = render_inflation_poc(_candidate(), targets, poc_location="test/zeropath")

    assert 'import "../../src/VulnerableVault.sol";' in poc
    assert "contract ZeroPath_ZP_001_InflationPoC" in poc
    assert "contract ZeroPath_ZP_001_Actor" in poc
    assert "function test_ZP_001_donationInflationProfitable() public" in poc
    # The vault + asset types must be instantiated in the test body.
    assert "new MockERC20()" in poc
    assert "new VulnerableVault(token)" in poc
    assert 'emit Measured("attackerProfit", attackerProfit);' in poc


def test_render_import_path_tracks_poc_location():
    targets = InflationProofTargets("V", "A", "src/V.sol")
    nested = render_inflation_poc(_candidate(), targets, poc_location=".zeropath/artifacts/pocs")
    assert 'import "../../../src/V.sol";' in nested


def test_render_includes_no_donation_baseline():
    targets = InflationProofTargets("VulnerableVault", "MockERC20", "src/VulnerableVault.sol")
    poc = render_inflation_poc(_candidate(), targets, poc_location="test/zeropath")
    # A fresh, un-donated vault quantifies the victim's expected shares.
    assert "new VulnerableVault(cleanToken)" in poc
    assert 'emit Measured("expectedVictimSharesWithoutDonation", expectedVictimSharesWithoutDonation);' in poc


# ---------------------------------------------------------------------------
# parse_measured_events
# ---------------------------------------------------------------------------


_FORGE_STDOUT = """\
Ran 1 test for test/zeropath/ZP_001.t.sol:ZeroPath_ZP_001_InflationPoC
[PASS] test_ZP_001_donationInflationProfitable() (gas: 3055643)
Traces:
    ├─ emit Measured(name: "attackerInitialBalance", value: 2000000000000000000000 [2e21])
    ├─ emit Measured(name: "vaultTotalAssetsBeforeDonation", value: 0)
    ├─ emit Measured(name: "victimShares", value: 0)
    ├─ emit Measured(name: "attackerProfit", value: 1000000000000000000000 [1e21])
Suite result: ok. 1 passed; 0 failed; 0 skipped
"""


def test_parse_measured_events_reads_named_values():
    measured = parse_measured_events(_FORGE_STDOUT)
    assert measured["attackerInitialBalance"] == 2000000000000000000000
    assert measured["attackerProfit"] == 1000000000000000000000
    # Plain zero values (no scientific-notation hint) are parsed too.
    assert measured["vaultTotalAssetsBeforeDonation"] == 0
    assert measured["victimShares"] == 0


def test_parse_measured_events_returns_empty_without_matches():
    assert parse_measured_events("") == {}
    assert parse_measured_events("no events here") == {}


# ---------------------------------------------------------------------------
# apply_inflation_proof_evidence
# ---------------------------------------------------------------------------


def _passed_result() -> dict:
    return {"ok": True, "status": "passed", "stdout": "...", "stderr": ""}


def test_apply_sets_measured_attacker_profit_on_pass():
    candidate = _candidate()
    measured = {
        "attackerProfit": 1000 * 10**18,
        "victimDeposit": 1000 * 10**18,
        "victimShares": 0,
    }
    notes = apply_inflation_proof_evidence(candidate, _passed_result(), measured)

    assert candidate.impact.measured is True
    assert "attacker profit" in candidate.impact.amount
    assert candidate.evidence.profit_measured is True
    assert candidate.evidence.root_cause_lines_present is True
    assert candidate.evidence.attacker_path_present is True
    assert candidate.evidence.state_preconditions_present is True
    assert candidate.evidence.live_config_checked is True
    # Notes are both returned and appended to the evidence bundle.
    assert any("attacker profit" in note.lower() for note in notes)
    assert any("attacker profit" in note.lower() for note in candidate.evidence.notes)


def test_apply_falls_back_to_victim_loss_when_no_profit():
    candidate = _candidate()
    measured = {"attackerProfit": 0, "victimDeposit": 1000, "victimShares": 400}
    apply_inflation_proof_evidence(candidate, _passed_result(), measured)

    assert candidate.impact.measured is True
    assert "loss" in candidate.impact.amount.lower()
    assert candidate.evidence.profit_measured is True


def test_apply_prefers_no_donation_baseline_for_victim_loss():
    candidate = _candidate()
    measured = {
        "attackerProfit": 0,
        "victimShares": 0,
        "expectedVictimSharesWithoutDonation": 1000 * 10**18,
    }
    apply_inflation_proof_evidence(candidate, _passed_result(), measured)

    assert candidate.impact.measured is True
    assert "expected without donation" in candidate.impact.amount.lower()
    assert "shortfall" in candidate.impact.amount.lower()


def test_apply_leaves_impact_unmeasured_when_no_signal():
    candidate = _candidate()
    apply_inflation_proof_evidence(candidate, _passed_result(), {})

    assert candidate.impact.measured is False
    assert candidate.evidence.profit_measured is False
    assert any("impact remains unmeasured" in note for note in candidate.evidence.notes)


def test_apply_sets_default_known_issue_and_duplicate_risk():
    candidate = _candidate()
    apply_inflation_proof_evidence(candidate, _passed_result(), {"attackerProfit": 5})

    assert candidate.known_issue_risk == "low"
    assert candidate.duplicate_risk == "medium"
    assert candidate.evidence.known_issues_checked is True
    assert candidate.evidence.duplicate_risk_checked is True


def test_apply_does_not_override_existing_risk_assessment():
    candidate = _candidate(known_issue_risk="high", duplicate_risk="low")
    apply_inflation_proof_evidence(candidate, _passed_result(), {"attackerProfit": 5})

    assert candidate.known_issue_risk == "high"
    assert candidate.duplicate_risk == "low"


def test_apply_records_failed_proof_without_measuring_impact():
    candidate = _candidate()
    notes = apply_inflation_proof_evidence(
        candidate, {"ok": False, "status": "failed"}, {}
    )

    assert candidate.impact.measured is False
    assert candidate.evidence.profit_measured is False
    assert any("failed" in note.lower() for note in notes)


def test_apply_handles_non_passing_statuses():
    for status, needle in (
        ("no_tests", "no tests"),
        ("unavailable", "unavailable"),
        ("timeout", "timed out"),
    ):
        candidate = _candidate()
        notes = apply_inflation_proof_evidence(candidate, {"status": status}, {})
        assert candidate.impact.measured is False
        assert any(needle in note.lower() for note in notes), (status, notes)
