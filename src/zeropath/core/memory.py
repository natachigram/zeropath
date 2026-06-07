"""Research ledger operations."""

from __future__ import annotations

from pathlib import Path
from uuid import uuid4

from zeropath.core.memory_router import MemoryRouter
from zeropath.core.schemas import MemoryDecision, MemoryItem
from zeropath.core.storage import Storage
from zeropath.core.utils import repo_commit, utc_now


def propose_memory(
    storage: Storage,
    *,
    content: str,
    memory_type: str,
    scope: str = "current_project",
    confidence: str = "inferred",
    source: str = "manual",
    tags: list[str] | None = None,
    structured_data: dict | None = None,
    evidence_refs: list[str] | None = None,
    context: dict | None = None,
) -> tuple[MemoryDecision, MemoryItem | None]:
    """Evaluate and persist a memory proposal if it satisfies policy."""

    config = storage.load_project_config()
    memory = MemoryItem(
        id=f"MEM-{uuid4().hex[:12]}",
        memory_type=memory_type,
        scope=scope,
        project_id=config.project_id if scope == "current_project" else None,
        content=content,
        structured_data=structured_data or {},
        confidence=confidence,
        source=source,
        evidence_refs=evidence_refs or [],
        tags=tags or [],
        repo_commit=repo_commit(Path(config.root_path)),
    )
    decision = MemoryRouter().evaluate(memory, context=context)
    if decision.save:
        storage.save_memory(memory)
        return decision, memory
    return decision, None


def search_memory(
    storage: Storage,
    query: str,
    *,
    scope: str | None = None,
    memory_type: str | None = None,
    tags: list[str] | None = None,
) -> list[MemoryItem]:
    """Simple keyword/tag/type memory retrieval."""

    terms = [term.lower() for term in query.split() if term.strip()]
    tag_set = {tag.lower() for tag in tags or []}
    matches: list[MemoryItem] = []
    for item in storage.list_memory():
        if scope and item.scope != scope:
            continue
        if memory_type and item.memory_type != memory_type:
            continue
        item_tags = {tag.lower() for tag in item.tags}
        if tag_set and not tag_set.issubset(item_tags):
            continue
        haystack = " ".join(
            [
                item.content,
                item.memory_type,
                item.scope,
                " ".join(item.tags),
                str(item.structured_data),
            ]
        ).lower()
        if not terms or all(term in haystack for term in terms):
            matches.append(item)
    return matches


def mark_memory_stale(storage: Storage, memory_id: str, reason: str) -> bool:
    item = storage.load_memory(memory_id)
    if item is None:
        return False
    item.stale = True
    item.updated_at = utc_now()
    item.structured_data["stale_reason"] = reason
    storage.save_memory(item)
    return True


def rejected_memories(storage: Storage) -> list[MemoryItem]:
    return [item for item in storage.list_memory() if item.memory_type == "rejected_hypothesis"]
