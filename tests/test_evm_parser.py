from pathlib import Path

from zeropath.adapters.evm.adapter import EVMAdapter
from zeropath.adapters.evm.parser import EVMParser
from zeropath.core.schemas import ProjectConfig

SOLIDITY_WITH_EXTERNAL_CALLS = """
pragma solidity ^0.8.20;

interface IERC20 {
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function safeTransfer(address to, uint256 amount) external;
}

interface IOracle {
    function latestRoundData() external view returns (uint80, int256, uint256, uint256, uint80);
}

contract Vault {
    IERC20 public asset;
    IOracle public oracle;

    function deposit(uint256 assets) external {
        asset.transferFrom(msg.sender, address(this), assets);
    }

    function withdraw(uint256 assets, address payable receiver) external {
        oracle.latestRoundData();
        asset.safeTransfer(receiver, assets);
        (bool ok,) = receiver.call{value: assets}("");
        require(ok);
    }
}
"""


def test_evm_parser_extracts_external_calls(tmp_path: Path):
    source_dir = tmp_path / "src"
    source_dir.mkdir()
    (source_dir / "Vault.sol").write_text(SOLIDITY_WITH_EXTERNAL_CALLS, encoding="utf-8")

    index = EVMParser().parse_project(tmp_path)

    calls = index["external_calls"]
    observed = {(call["caller"], call["target"], call["callee"]) for call in calls}
    assert ("Vault.deposit", "asset", "transferFrom") in observed
    assert ("Vault.withdraw", "oracle", "latestRoundData") in observed
    assert ("Vault.withdraw", "asset", "safeTransfer") in observed
    assert ("Vault.withdraw", "receiver", "call") in observed
    low_level = next(call for call in calls if call["target"] == "receiver")
    assert low_level["call_type"] == "low_level_call"
    assert low_level["value_transfer"] is True
    assert low_level["confidence"] == "low"


def test_evm_adapter_call_graph_uses_external_call_index(tmp_path: Path):
    source_dir = tmp_path / "src"
    source_dir.mkdir()
    (source_dir / "Vault.sol").write_text(SOLIDITY_WITH_EXTERNAL_CALLS, encoding="utf-8")
    adapter = EVMAdapter(tmp_path)
    adapter.ingest_project(ProjectConfig(project_id="demo", root_path=str(tmp_path), adapter="evm"))

    graph = adapter.build_call_graph()

    edges = {(edge["from"], edge["to"]) for edge in graph["edges"]}
    assert ("Vault.deposit", "asset.transferFrom") in edges
    assert ("Vault.withdraw", "oracle.latestRoundData") in edges
    assert ("Vault.withdraw", "receiver.call") in edges
    assert graph["external_calls"]
    assert "runtime reachability" in " ".join(graph["unknowns"])
