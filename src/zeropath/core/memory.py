"""Research ledger operations."""

from __future__ import annotations

from pathlib import Path
from uuid import uuid4

from zeropath.core.memory_router import MemoryRouter
from zeropath.core.schemas import MemoryDecision, MemoryItem
from zeropath.core.storage import Storage
from zeropath.core.utils import repo_commit, sha256_file, utc_now


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
    _mark_item_stale(storage, item, reason)
    return True


def mark_stale_memories(
    storage: Storage,
    *,
    root_path: str | Path | None = None,
    current_repo_commit: str | None = None,
    current_file_hashes: dict[str, str] | None = None,
) -> list[MemoryItem]:
    """Mark memories stale when stored repo/file anchors no longer match.

    This stays evidence-first: memories without recorded anchors are left alone,
    and unavailable current evidence does not make a memory stale.
    """

    config = storage.load_project_config()
    root = Path(root_path or config.root_path)
    current_commit = current_repo_commit or repo_commit(root)
    marked: list[MemoryItem] = []

    for item in storage.list_memory():
        if item.stale:
            continue

        reasons = _staleness_reasons(
            item,
            root_path=root,
            current_repo_commit=current_commit,
            current_file_hashes=current_file_hashes or {},
        )
        if not reasons:
            continue

        _mark_item_stale(storage, item, "; ".join(reasons))
        marked.append(item)

    return marked


def rejected_memories(storage: Storage) -> list[MemoryItem]:
    return [item for item in storage.list_memory() if item.memory_type == "rejected_hypothesis"]


def _mark_item_stale(storage: Storage, item: MemoryItem, reason: str) -> None:
    item.stale = True
    item.updated_at = utc_now()
    item.structured_data["stale_reason"] = reason
    storage.save_memory(item)


def _staleness_reasons(
    item: MemoryItem,
    *,
    root_path: Path,
    current_repo_commit: str | None,
    current_file_hashes: dict[str, str],
) -> list[str]:
    reasons: list[str] = []

    if item.repo_commit and current_repo_commit and item.repo_commit != current_repo_commit:
        reasons.append(f"repo_commit changed from {item.repo_commit} to {current_repo_commit}")

    for source_path, stored_hash in sorted(item.file_hashes.items()):
        if not stored_hash:
            continue

        current_hash = _current_source_hash(source_path, root_path, current_file_hashes)
        if current_hash is None:
            source = _source_path(source_path, root_path)
            if not source.exists():
                reasons.append(f"source file removed: {source_path} (stored hash {stored_hash})")
            continue
        if current_hash != stored_hash:
            reasons.append(f"source file changed: {source_path} hash {stored_hash} -> {current_hash}")

    return reasons


def _current_source_hash(
    source_path: str,
    root_path: Path,
    current_file_hashes: dict[str, str],
) -> str | None:
    if source_path in current_file_hashes:
        return current_file_hashes[source_path]

    source = _source_path(source_path, root_path)
    resolved = str(source)
    if resolved in current_file_hashes:
        return current_file_hashes[resolved]

    try:
        return sha256_file(source)
    except OSError:
        return None


def _source_path(source_path: str, root_path: Path) -> Path:
    path = Path(source_path)
    if path.is_absolute():
        return path
    return root_path / path
