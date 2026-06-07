"""Configuration constants for the evidence-first engine."""

from __future__ import annotations

ZEROPATH_DIR = ".zeropath"

ARTIFACT_DIRS = (
    "artifacts/pocs",
    "artifacts/traces",
    "artifacts/reports",
    "artifacts/rejected",
    "artifacts/snapshots",
    "artifacts/candidates",
    "memory",
    "exports",
    "logs",
)

MEMORY_FILES = (
    "memory/global.jsonl",
    "memory/project.jsonl",
    "memory/patterns.jsonl",
    "memory/rejected.jsonl",
)

CANDIDATE_STATUSES = {
    "observation",
    "hypothesis",
    "path_identified",
    "state_planned",
    "poc_generated",
    "poc_passed",
    "judge_passed",
    "report_ready",
    "rejected",
    "stale",
    "needs_evidence",
}

REPORT_FORMATS = {"code4rena", "sherlock", "cantina", "internal"}

MEMORY_TYPES = {
    "project_fact",
    "protocol_intent",
    "invariant",
    "candidate_finding",
    "rejected_hypothesis",
    "exploit_pattern",
    "judge_decision",
    "proof_result",
    "research_lesson",
    "known_issue",
    "duplicate_signal",
}

EVIDENCE_LEVELS = {
    "speculation",
    "inferred",
    "source_backed",
    "poc_passed",
    "fork_reproduced",
    "judge_confirmed",
    "rejected",
}
