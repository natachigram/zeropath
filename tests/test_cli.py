import importlib
from pathlib import Path

from click.testing import CliRunner

from zeropath.cli import cli
from zeropath.core.memory import propose_memory
from zeropath.core.schemas import CandidateFinding, Impact, ProjectConfig
from zeropath.core.state_plan import build_candidate_state_plan
from zeropath.core.storage import Storage
from zeropath.core.utils import sha256_file


SOLIDITY = """
pragma solidity ^0.8.20;

contract Vault {
    uint256 public totalSupply;
    function totalAssets() public view returns (uint256) { return address(this).balance; }
    function deposit(uint256 assets, address receiver) public returns (uint256) { return assets; }
    function withdraw(uint256 assets, address receiver, address owner) public returns (uint256) { return assets; }
}
"""


def test_cli_init_ingest_understand_hunt_flow():
    runner = CliRunner()
    with runner.isolated_filesystem():
        import pathlib

        root = pathlib.Path(".")
        (root / "foundry.toml").write_text("[profile.default]\nsrc = 'src'\n")
        (root / "src").mkdir()
        (root / "src" / "Vault.sol").write_text(SOLIDITY)

        result = runner.invoke(cli, ["init"])
        assert result.exit_code == 0, result.output
        assert (root / ".zeropath").exists()

        result = runner.invoke(cli, ["ingest", "--repo", "."])
        assert result.exit_code == 0, result.output
        assert "contracts" in result.output

        result = runner.invoke(cli, ["understand", "--repo", "."])
        assert result.exit_code == 0, result.output
        assert "Protocol intent" in result.output

        result = runner.invoke(cli, ["hunt", "--repo", ".", "--mode", "critical", "--limit", "5"])
        assert result.exit_code == 0, result.output
        assert "Hypotheses are not findings" in result.output


def test_report_command_refuses_final_without_judge(tmp_path):
    storage = Storage(tmp_path)
    storage.initialize(ProjectConfig(project_id="demo", root_path=str(tmp_path), adapter="evm"))
    storage.save_candidate(
        CandidateFinding(
            id="ZP-001",
            project_id="demo",
            title="Draft only",
            impact=Impact(impact_type="direct_theft", funds_at_risk=True, explanation="hypothesis"),
        )
    )
    runner = CliRunner()

    result = runner.invoke(cli, ["report", "ZP-001", "--repo", str(tmp_path)])

    assert result.exit_code == 1
    assert "Report refused" in result.output
    assert "Traceback" not in result.output


def test_candidates_evidence_command_updates_candidate(tmp_path):
    storage = Storage(tmp_path)
    storage.initialize(ProjectConfig(project_id="demo", root_path=str(tmp_path), adapter="evm"))
    storage.save_candidate(
        CandidateFinding(
            id="ZP-002",
            project_id="demo",
            title="Evidence target",
            impact=Impact(impact_type="direct_theft", funds_at_risk=True, explanation="demo"),
        )
    )
    runner = CliRunner()

    result = runner.invoke(
        cli,
        [
            "candidates",
            "evidence",
            "ZP-002",
            "--repo",
            str(tmp_path),
            "--root-cause-lines",
            "--attacker-path",
            "--state-preconditions",
            "--duplicate-risk",
            "low",
            "--known-issue-risk",
            "none",
            "--chain-id",
            "1",
            "--profit-measured",
            "--amount",
            "1 ether",
            "--note",
            "manual triage complete",
        ],
    )

    assert result.exit_code == 0, result.output
    assert "Evidence updated" in result.output
    updated = storage.load_candidate("ZP-002")
    assert updated.evidence.root_cause_lines_present is True
    assert updated.evidence.attacker_path_present is True
    assert updated.evidence.state_preconditions_present is True
    assert updated.evidence.duplicate_risk_checked is True
    assert updated.evidence.known_issues_checked is True
    assert updated.evidence.chain_id == 1
    assert updated.evidence.profit_measured is True
    assert updated.impact.amount == "1 ether"
    assert "manual triage complete" in updated.evidence.notes


def test_candidates_plan_command_writes_state_plan(tmp_path):
    storage = Storage(tmp_path)
    storage.initialize(ProjectConfig(project_id="demo", root_path=str(tmp_path), adapter="evm"))
    storage.save_candidate(
        CandidateFinding(
            id="ZP-014",
            project_id="demo",
            title="Plan target",
            attacker_model="Untrusted depositor",
            required_state=["vault seeded"],
            transaction_sequence=["deposit", "redeem"],
            impact=Impact(impact_type="direct_theft", funds_at_risk=True, explanation="demo"),
        )
    )
    runner = CliRunner()

    result = runner.invoke(cli, ["candidates", "plan", "ZP-014", "--repo", str(tmp_path)])

    assert result.exit_code == 0, result.output
    assert "State plan" in result.output
    assert storage.load_candidate("ZP-014").status == "state_planned"
    assert storage.load_record("state_plan", "ZP-014")["candidate_id"] == "ZP-014"


def test_prove_uses_saved_state_plan_in_generated_poc(tmp_path):
    storage = Storage(tmp_path)
    storage.initialize(ProjectConfig(project_id="demo", root_path=str(tmp_path), adapter="evm"))
    storage.save_candidate(
        CandidateFinding(
            id="ZP-017",
            project_id="demo",
            title="Planned proof target",
            attacker_model="Untrusted depositor",
            required_state=["vault seeded"],
            transaction_sequence=["deposit", "redeem"],
            impact=Impact(impact_type="direct_theft", funds_at_risk=True, explanation="demo"),
        )
    )
    plan = build_candidate_state_plan(storage, "ZP-017")
    runner = CliRunner()

    result = runner.invoke(cli, ["prove", "ZP-017", "--repo", str(tmp_path), "--no-run"])

    assert result.exit_code == 0, result.output
    candidate = storage.load_candidate("ZP-017")
    assert candidate.evidence.poc_path
    poc = Path(candidate.evidence.poc_path).read_text()
    assert plan.artifact_path in poc
    assert "Setup steps" not in poc
    assert "TODO: Materialize required state: vault seeded" in poc


def test_prove_runs_generated_candidate_test_path(tmp_path, monkeypatch):
    storage = Storage(tmp_path)
    storage.initialize(ProjectConfig(project_id="demo", root_path=str(tmp_path), adapter="evm"))
    storage.save_candidate(
        CandidateFinding(
            id="ZP-019",
            project_id="demo",
            title="Runnable proof target",
            attacker_model="Untrusted depositor",
            required_state=["vault seeded"],
            transaction_sequence=["deposit", "redeem"],
            impact=Impact(impact_type="direct_theft", funds_at_risk=True, explanation="demo"),
        )
    )
    (tmp_path / "test").mkdir()
    calls = {}

    def fake_run_forge_test(root_path, match_path=None):
        calls["root_path"] = root_path
        calls["match_path"] = match_path
        return {"ok": True, "status": "passed", "message": "scoped forge test passed"}

    monkeypatch.setattr("zeropath.adapters.evm.forge.run_forge_test", fake_run_forge_test)
    runner = CliRunner()

    result = runner.invoke(cli, ["prove", "ZP-019", "--repo", str(tmp_path), "--write-test-dir"])

    assert result.exit_code == 0, result.output
    expected = tmp_path / "test" / "zeropath" / "ZP_019.t.sol"
    assert expected.exists()
    assert Path(calls["match_path"]) == expected
    assert storage.load_candidate("ZP-019").status == "poc_passed"


def test_memory_refresh_stale_command_marks_changed_source_memory(tmp_path):
    source = tmp_path / "contracts" / "Vault.sol"
    source.parent.mkdir()
    source.write_text("contract Vault {}\n", encoding="utf-8")
    original_hash = sha256_file(source)
    storage = Storage(tmp_path)
    storage.initialize(ProjectConfig(project_id="demo", root_path=str(tmp_path), adapter="evm"))
    _, memory = propose_memory(
        storage,
        content="Rejected because Vault.withdraw has no external call.",
        memory_type="rejected_hypothesis",
        confidence="rejected",
        source="judge",
        tags=["rejected", "vault"],
    )
    assert memory is not None
    memory.file_hashes = {"contracts/Vault.sol": original_hash}
    storage.save_memory(memory)
    source.write_text("contract Vault { function withdraw() external {} }\n", encoding="utf-8")
    runner = CliRunner()

    result = runner.invoke(cli, ["memory", "refresh-stale", "--repo", str(tmp_path)])

    assert result.exit_code == 0, result.output
    assert "Marked stale" in result.output
    assert storage.load_memory(memory.id).stale is True


def test_cli_package_layout_exports_evidence_commands():
    from zeropath.cli import cli as package_cli
    from zeropath.cli import main as package_main
    from zeropath.cli.commands import judge, report

    assert package_cli is cli
    assert callable(package_main)
    assert importlib.import_module("zeropath.cli.__main__").main is package_main

    expected = {
        "init": ("zeropath.cli.commands.init", "init"),
        "status": ("zeropath.cli.commands.status", "status"),
        "ingest": ("zeropath.cli.commands.ingest", "ingest"),
        "understand": ("zeropath.cli.commands.understand", "understand"),
        "hunt": ("zeropath.cli.commands.hunt", "hunt"),
        "candidates": ("zeropath.cli.commands.candidates", "candidates"),
        "prove": ("zeropath.cli.commands.prove", "prove"),
        "judge": ("zeropath.cli.commands.judge", "judge"),
        "report": ("zeropath.cli.commands.report", "report"),
        "memory": ("zeropath.cli.commands.memory", "memory"),
        "mcp": ("zeropath.cli.commands.mcp", "mcp"),
    }

    for command_name, (module_name, attr) in expected.items():
        command = getattr(importlib.import_module(module_name), attr)
        assert command.name == command_name
        assert package_cli.commands[command_name] is command

    assert judge is package_cli.commands["judge"]
    assert report is package_cli.commands["report"]
