import shutil
from pathlib import Path

from zeropath.adapters.evm import EVMAdapter
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
