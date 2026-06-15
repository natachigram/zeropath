import shutil
from pathlib import Path

import pytest
from click.testing import CliRunner

from zeropath.adapters.evm import EVMAdapter
from zeropath.adapters.evm.forge import forge_available
from zeropath.cli import cli
from zeropath.core.candidates import generate_candidates
from zeropath.core.intent import build_protocol_intent
from zeropath.core.schemas import ProjectConfig
from zeropath.core.storage import Storage

FIXTURE = Path(__file__).resolve().parents[1] / "examples" / "erc4626_inflation_fixture"


def _copy_fixture(tmp_path: Path) -> Path:
    target = tmp_path / "erc4626_inflation_fixture"
    shutil.copytree(
        FIXTURE,
        target,
        ignore=shutil.ignore_patterns(".zeropath", "out", "cache", "broadcast"),
    )
    return target


def test_erc4626_fixture_ingests_as_vault_and_generates_share_inflation_candidate(tmp_path):
    fixture = _copy_fixture(tmp_path)
    storage = Storage(fixture)
    config = ProjectConfig(
        project_id="erc4626-inflation-fixture",
        root_path=str(fixture),
        adapter="evm",
        build_system="foundry",
    )
    storage.initialize(config)

    index = EVMAdapter(fixture).ingest_project(config)
    storage.save_record("ingest", "evm_index", index)

    assert index["protocol_type"] == "vault"

    intent = build_protocol_intent(storage)
    invariant_ids = {item.id for item in intent.critical_invariants}
    assert "INV-VLT-001" in invariant_ids
    assert "share" in next(
        item.title.lower()
        for item in intent.critical_invariants
        if item.id == "INV-VLT-001"
    )

    candidates = generate_candidates(storage, mode="critical", limit=5)

    assert len(candidates) == 1
    candidate = candidates[0]
    assert candidate.bug_class == "erc4626_share_inflation"
    assert candidate.affected_invariant == "INV-VLT-001"
    assert candidate.affected_contracts == ["VulnerableVault"]
    assert candidate.root_cause_locations[0].contract == "VulnerableVault"
    assert candidate.root_cause_locations[0].function == "totalAssets"
    assert candidate.attacker_model
    assert candidate.required_state
    assert any("donat" in step.lower() for step in candidate.transaction_sequence)
    assert any("victim" in step.lower() for step in candidate.transaction_sequence)


@pytest.mark.skipif(not forge_available(), reason="forge is not installed on PATH")
def test_erc4626_fixture_prove_generates_passing_inflation_poc(tmp_path):
    fixture = _copy_fixture(tmp_path)
    storage = Storage(fixture)
    config = ProjectConfig(
        project_id="erc4626-inflation-fixture",
        root_path=str(fixture),
        adapter="evm",
        build_system="foundry",
    )
    storage.initialize(config)
    index = EVMAdapter(fixture).ingest_project(config)
    storage.save_record("ingest", "evm_index", index)

    candidate = generate_candidates(storage, mode="critical", limit=5)[0]

    result = CliRunner().invoke(cli, ["prove", candidate.id, "--repo", str(fixture)])
    assert result.exit_code == 0, result.output

    proven = storage.load_candidate(candidate.id)
    assert proven.status == "poc_passed"
    assert proven.evidence.forge_result == "passed"
    assert proven.evidence.profit_measured is True
    assert proven.impact.measured is True
    assert "ether" in (proven.impact.amount or "")
    # The runnable copy must be discoverable by forge under test/.
    assert (fixture / "test" / "zeropath" / f"{candidate.id.replace('-', '_')}.t.sol").exists()
    # The no-donation baseline must be measured and recorded.
    assert any("expectedVictimSharesWithoutDonation" in note for note in proven.evidence.notes)

    # judge must mark the proven candidate report-ready (no anti-condition on the
    # vulnerable vault), and report must then export a final artifact.
    judge_result = CliRunner().invoke(cli, ["judge", candidate.id, "--repo", str(fixture)])
    assert judge_result.exit_code == 0, judge_result.output
    verdict = storage.load_judge_result(candidate.id)
    assert verdict.report_ready is True
    assert verdict.severity == "critical"

    report_result = CliRunner().invoke(
        cli, ["report", candidate.id, "--repo", str(fixture), "--format", "code4rena"]
    )
    assert report_result.exit_code == 0, report_result.output
    report_path = fixture / ".zeropath" / "artifacts" / "reports" / f"{candidate.id}_code4rena_final.md"
    assert report_path.exists()
    report_text = report_path.read_text()
    assert "FINAL / REPORT READY" in report_text
    assert "virtual shares" in report_text  # ERC4626-specific mitigation rendered
