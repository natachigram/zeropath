"""Tests for the durable, backend-neutral ZeroPath harness spine."""

from __future__ import annotations

from pathlib import Path

import pytest

from zeropath.adapters.evm.parser import EVMParser
from zeropath.core.schemas import ProjectConfig
from zeropath.core.storage import Storage
from zeropath.harness import (
    BackendContext,
    HarnessController,
    HarnessError,
    HarnessStore,
    generate_cases,
    run_named_backend,
    shrink_case,
)


VAULT_SOURCE = """
pragma solidity ^0.8.20;
contract MockERC20 {
    function mint(address to, uint256 amount) external {}
    function transfer(address to, uint256 amount) external returns (bool) { return true; }
    function transferFrom(address from, address to, uint256 amount) external returns (bool) { return true; }
    function approve(address spender, uint256 amount) external returns (bool) { return true; }
}
contract Vault {
    uint256 public totalSupply;
    function totalAssets() public view returns (uint256) { return address(this).balance; }
    function deposit(uint256 assets, address receiver) public returns (uint256) { return assets; }
    function withdraw(uint256 assets, address receiver, address owner) public returns (uint256) { return assets; }
    function redeem(uint256 shares, address receiver, address owner) public returns (uint256) { return shares; }
}
"""


def _prepared_project(tmp_path: Path) -> Storage:
    source = tmp_path / "src" / "Vault.sol"
    source.parent.mkdir(parents=True)
    source.write_text(VAULT_SOURCE, encoding="utf-8")
    storage = Storage(tmp_path)
    config = ProjectConfig(
        project_id="harness-fixture",
        root_path=str(tmp_path),
        adapter="evm",
        build_system="foundry",
        source_paths=["src/Vault.sol"],
    )
    storage.initialize(config)
    index = EVMParser().parse_project(tmp_path)
    storage.save_record("ingest", "evm_index", index)
    return storage


def test_campaign_frame_is_durable_and_integrity_checked(tmp_path: Path):
    _prepared_project(tmp_path)

    controller = HarnessController(tmp_path)
    manifest = controller.initialize(seed=19, backends=("foundry",))
    campaign_dir = tmp_path / ".zeropath" / "harness" / "campaigns" / manifest.campaign_id

    assert (campaign_dir / "run.json").exists()
    assert (campaign_dir / "coverage.json").exists()
    assert (campaign_dir / "reference-lock.json").exists()
    assert controller.check(manifest.campaign_id)["passed"] is True
    assert [event.sequence for event in HarnessStore(tmp_path).read_events(manifest.campaign_id)] == [1, 2]
    assert HarnessStore(tmp_path).list_corpus_cases(manifest.campaign_id)
    assert controller.status(manifest.campaign_id)["corpus"]["cases"] > 0


def test_integrity_check_detects_scoped_source_drift(tmp_path: Path):
    _prepared_project(tmp_path)
    controller = HarnessController(tmp_path)
    manifest = controller.initialize(seed=21)
    source = tmp_path / "src" / "Vault.sol"
    source.write_text(source.read_text(encoding="utf-8") + "\n// drift\n", encoding="utf-8")

    check = controller.check(manifest.campaign_id)
    assert check["passed"] is False
    assert check["checks"]["source_digest"] is False


def test_hunt_and_bank_preserve_a_single_active_candidate(tmp_path: Path):
    _prepared_project(tmp_path)
    controller = HarnessController(tmp_path)
    manifest = controller.initialize(seed=3)

    candidates = controller.hunt(manifest.campaign_id, limit=3)
    assert candidates
    banked = controller.bank(manifest.campaign_id, candidate_id=candidates[0].id)
    assert banked.phase == "verify"
    assert banked.active_candidate_id == candidates[0].id

    queue = HarnessStore(tmp_path).load_queue(manifest.campaign_id)
    assert [item.id for item in queue.items if item.status == "active"] == [candidates[0].id]
    assert all(item.precision_bucket in {"B", "C"} for item in queue.items)
    other = candidates[0].model_copy(deep=True)
    other.id = "ZP-OTHER"
    controller.storage.save_candidate(other)
    with pytest.raises(HarnessError, match="single active hypothesis"):
        controller.verify(
            manifest.campaign_id,
            candidate_id=other.id,
            generate_poc=False,
        )


def test_backend_rejects_target_path_escape(tmp_path: Path):
    context = BackendContext(
        campaign_id="H-test",
        root_path=tmp_path,
        target_path="../outside.t.sol",
        seed=1,
        timeout_seconds=1,
    )
    result = run_named_backend("foundry", context)
    assert result.status == "blocked"
    assert "escapes target root" in (result.error or "")


def test_backend_rejects_unknown_name_as_a_durable_observation(tmp_path: Path):
    context = BackendContext(
        campaign_id="H-test",
        root_path=tmp_path,
        target_path=None,
        seed=1,
        timeout_seconds=1,
    )
    result = run_named_backend("not-a-backend", context)
    assert result.status == "blocked"
    assert "unsupported backend" in (result.error or "")


def test_corpus_generation_is_reproducible_and_shrinks():
    first = generate_cases(["OP-deposit", "OP-redeem"], seed=7, count=4, depth=5)
    second = generate_cases(["OP-deposit", "OP-redeem"], seed=7, count=4, depth=5)
    assert [
        (case.case_id, case.seed, [action.model_dump(mode="json") for action in case.actions])
        for case in first
    ] == [
        (case.case_id, case.seed, [action.model_dump(mode="json") for action in case.actions])
        for case in second
    ]

    failing = first[0]
    failing.actions = failing.actions + failing.actions[:1]
    failing.depth = len(failing.actions)
    minimized = shrink_case(failing, lambda case: len(case.actions) >= 2)
    assert minimized.status == "shrunk"
    assert len(minimized.actions) == 2


def test_replay_requires_an_existing_campaign(tmp_path: Path):
    controller = HarnessController(tmp_path)
    with pytest.raises(HarnessError):
        controller.status("missing")


def test_canonical_mcp_exposes_harness_control_plane(tmp_path: Path):
    from zeropath.mcp.server import build_server

    server = build_server(tmp_path)
    assert "zeropath_harness_status" in server.tools
    assert "zeropath_harness_init" in server.tools
    assert "zeropath_harness_run" in server.tools
    assert "zeropath_harness_replay" in server.tools
