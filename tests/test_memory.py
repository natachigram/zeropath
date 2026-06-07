from zeropath.core.memory import mark_memory_stale, propose_memory, rejected_memories
from zeropath.core.schemas import ProjectConfig
from zeropath.core.storage import Storage


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
