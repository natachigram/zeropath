from zeropath.core.memory_router import MemoryRouter
from zeropath.core.schemas import MemoryItem


def test_memory_router_rejects_speculation():
    item = MemoryItem(
        id="MEM-1",
        memory_type="research_lesson",
        scope="global",
        content="Maybe all vaults are broken",
        confidence="speculation",
        source="llm",
        tags=["vault"],
    )

    decision = MemoryRouter().evaluate(item)

    assert decision.save is False
    assert "speculative" in decision.reason


def test_memory_router_saves_rejected_hypothesis_with_reason():
    item = MemoryItem(
        id="MEM-2",
        memory_type="rejected_hypothesis",
        scope="current_project",
        project_id="demo",
        content="Rejected because the path is admin-only.",
        confidence="rejected",
        source="judge",
        tags=["rejected", "access-control"],
    )

    decision = MemoryRouter().evaluate(item)

    assert decision.save is True
    assert "rejected hypothesis" in decision.reason
