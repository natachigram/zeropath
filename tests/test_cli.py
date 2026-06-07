from click.testing import CliRunner

from zeropath.cli import cli
from zeropath.core.schemas import CandidateFinding, Impact, ProjectConfig
from zeropath.core.storage import Storage


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
