from zeropath.core.memory import mark_memory_stale, mark_stale_memories, propose_memory, rejected_memories
from zeropath.core.schemas import ProjectConfig
from zeropath.core.storage import Storage
from zeropath.core.utils import sha256_file


def test_memory_proposal_persists_rejected_hypothesis(tmp_path):
    storage = Storage(tmp_path)
    storage.initialize(ProjectConfig(project_id="demo", root_path=str(tmp_path), adapter="evm"))

    decision, memory = propose_memory(
        storage,
        content="Rejected because the candidate requires trusted admin control.",
        memory_type="rejected_hypothesis",
        confidence="rejected",
        source="judge",
        tags=["rejected"],
    )

    assert decision.save is True
    assert memory is not None
    assert len(rejected_memories(storage)) == 1


def test_memory_can_be_marked_stale(tmp_path):
    storage = Storage(tmp_path)
    storage.initialize(ProjectConfig(project_id="demo", root_path=str(tmp_path), adapter="evm"))
    _, memory = propose_memory(
        storage,
        content="Rejected because the state is unreachable.",
        memory_type="rejected_hypothesis",
        confidence="rejected",
        source="judge",
        tags=["rejected"],
    )

    assert memory is not None
    assert mark_memory_stale(storage, memory.id, "repo changed") is True
    assert storage.load_memory(memory.id).stale is True


def test_stale_automation_marks_repo_commit_changes(tmp_path):
    storage = Storage(tmp_path)
    storage.initialize(ProjectConfig(project_id="demo", root_path=str(tmp_path), adapter="evm"))
    _, memory = propose_memory(
        storage,
        content="Rejected because the invariant is already enforced.",
        memory_type="rejected_hypothesis",
        confidence="rejected",
        source="judge",
        tags=["rejected"],
        structured_data={"reason": "guard exists"},
    )
    assert memory is not None
    memory.repo_commit = "oldcommit"
    storage.save_memory(memory)

    marked = mark_stale_memories(storage, current_repo_commit="newcommit")

    assert [item.id for item in marked] == [memory.id]
    loaded = storage.load_memory(memory.id)
    assert loaded.stale is True
    assert loaded.structured_data["reason"] == "guard exists"
    assert loaded.structured_data["stale_reason"] == "repo_commit changed from oldcommit to newcommit"


def test_stale_automation_marks_source_file_hash_changes(tmp_path):
    source = tmp_path / "contracts" / "Vault.sol"
    source.parent.mkdir()
    source.write_text("contract Vault {}\n", encoding="utf-8")
    original_hash = sha256_file(source)

    storage = Storage(tmp_path)
    storage.initialize(ProjectConfig(project_id="demo", root_path=str(tmp_path), adapter="evm"))
    _, memory = propose_memory(
        storage,
        content="Rejected because the vault has no external call in withdraw.",
        memory_type="rejected_hypothesis",
        confidence="rejected",
        source="judge",
        tags=["rejected", "vault"],
    )
    assert memory is not None
    memory.file_hashes = {"contracts/Vault.sol": original_hash}
    storage.save_memory(memory)

    source.write_text("contract Vault { function withdraw() external {} }\n", encoding="utf-8")
    marked = mark_stale_memories(storage)

    assert [item.id for item in marked] == [memory.id]
    loaded = storage.load_memory(memory.id)
    assert loaded.stale is True
    assert "source file changed: contracts/Vault.sol" in loaded.structured_data["stale_reason"]
    assert original_hash in loaded.structured_data["stale_reason"]
    assert sha256_file(source) in loaded.structured_data["stale_reason"]


def test_stale_automation_skips_memories_without_changed_anchors(tmp_path):
    source = tmp_path / "contracts" / "Vault.sol"
    source.parent.mkdir()
    source.write_text("contract Vault {}\n", encoding="utf-8")
    current_hash = sha256_file(source)

    storage = Storage(tmp_path)
    storage.initialize(ProjectConfig(project_id="demo", root_path=str(tmp_path), adapter="evm"))
    _, anchored = propose_memory(
        storage,
        content="Rejected because deposits cannot reenter.",
        memory_type="rejected_hypothesis",
        confidence="rejected",
        source="judge",
        tags=["rejected", "vault"],
    )
    _, unanchored = propose_memory(
        storage,
        content="Rejected because only the owner can trigger the path.",
        memory_type="rejected_hypothesis",
        confidence="rejected",
        source="judge",
        tags=["rejected", "access-control"],
    )
    assert anchored is not None
    assert unanchored is not None
    anchored.repo_commit = "samecommit"
    anchored.file_hashes = {"contracts/Vault.sol": current_hash}
    storage.save_memory(anchored)

    marked = mark_stale_memories(storage, current_repo_commit="samecommit")

    assert marked == []
    assert storage.load_memory(anchored.id).stale is False
    assert storage.load_memory(unanchored.id).stale is False
