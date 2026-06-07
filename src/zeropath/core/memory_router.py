"""Admission policy for ZeroPath research memory."""

from __future__ import annotations

from typing import Any

from zeropath.core.config import EVIDENCE_LEVELS, MEMORY_TYPES
from zeropath.core.schemas import MemoryDecision, MemoryItem


HIGH_CONFIDENCE = {"source_backed", "poc_passed", "fork_reproduced", "judge_confirmed"}


class MemoryRouter:
    """Decides whether proposed memories are durable research ledger entries."""

    def evaluate(self, candidate_memory: MemoryItem | dict[str, Any], context: dict[str, Any] | None = None) -> MemoryDecision:
        context = context or {}
        memory = (
            candidate_memory
            if isinstance(candidate_memory, MemoryItem)
            else MemoryItem.model_validate(candidate_memory)
        )

        if memory.memory_type not in MEMORY_TYPES:
            return MemoryDecision(save=False, reason=f"unknown memory type: {memory.memory_type}")
        if memory.confidence not in EVIDENCE_LEVELS:
            return MemoryDecision(save=False, reason=f"unknown evidence level: {memory.confidence}")
        if not memory.source:
            return MemoryDecision(save=False, reason="memory requires a source")
        if not memory.tags:
            return MemoryDecision(save=False, reason="memory requires tags")

        content = memory.content.lower()
        if memory.confidence == "speculation":
            return MemoryDecision(
                save=False,
                memory_type=memory.memory_type,
                scope=memory.scope,
                confidence=memory.confidence,
                reason="speculative memory is not persisted",
                tags=memory.tags,
            )

        if memory.scope == "global" and memory.confidence not in HIGH_CONFIDENCE:
            return MemoryDecision(
                save=False,
                memory_type=memory.memory_type,
                scope=memory.scope,
                confidence=memory.confidence,
                reason="global memory requires source-backed or stronger evidence",
                tags=memory.tags,
            )

        if memory.memory_type == "rejected_hypothesis":
            if "because" in content or "reason" in memory.structured_data or memory.evidence_refs:
                return self._save(memory, "rejected hypothesis prevents repeated work")
            return MemoryDecision(
                save=False,
                memory_type=memory.memory_type,
                scope=memory.scope,
                confidence=memory.confidence,
                reason="rejected hypotheses need a reason or evidence reference",
                tags=memory.tags,
            )

        if memory.memory_type in {"protocol_intent", "invariant", "judge_decision", "proof_result"}:
            if memory.confidence in HIGH_CONFIDENCE or memory.scope == "current_project":
                return self._save(memory, "project-local evidence-backed memory")

        if memory.memory_type in {"known_issue", "duplicate_signal", "exploit_pattern"}:
            if memory.confidence in HIGH_CONFIDENCE:
                return self._save(memory, "high-confidence reusable research memory")

        if memory.memory_type == "research_lesson" and context.get("user_approved"):
            return self._save(memory, "user-approved research lesson")

        return MemoryDecision(
            save=False,
            memory_type=memory.memory_type,
            scope=memory.scope,
            confidence=memory.confidence,
            reason="memory did not meet admission policy",
            tags=memory.tags,
        )

    @staticmethod
    def _save(memory: MemoryItem, reason: str) -> MemoryDecision:
        return MemoryDecision(
            save=True,
            memory_type=memory.memory_type,
            scope=memory.scope,
            confidence=memory.confidence,
            reason=reason,
            tags=memory.tags,
        )
