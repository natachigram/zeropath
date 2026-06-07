"""Local project storage for ZeroPath."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

from zeropath.core.config import ARTIFACT_DIRS, MEMORY_FILES, ZEROPATH_DIR
from zeropath.core.errors import ProjectNotInitializedError
from zeropath.core.schemas import (
    CandidateFinding,
    JudgeResult,
    MemoryItem,
    ProjectConfig,
    ProtocolIntent,
    RejectionCheck,
)
from zeropath.core.utils import utc_now


class Storage:
    """Persistent local state under a project's .zeropath directory."""

    def __init__(self, root_path: str | Path = ".") -> None:
        self.root_path = Path(root_path).resolve()
        self.zp_dir = self.root_path / ZEROPATH_DIR
        self.db_path = self.zp_dir / "project.sqlite"

    @property
    def initialized(self) -> bool:
        return self.zp_dir.exists() and self.db_path.exists()

    def initialize(self, config: ProjectConfig | None = None) -> None:
        self.zp_dir.mkdir(parents=True, exist_ok=True)
        for rel in ARTIFACT_DIRS:
            (self.zp_dir / rel).mkdir(parents=True, exist_ok=True)
        for rel in MEMORY_FILES:
            path = self.zp_dir / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.touch(exist_ok=True)
        self._init_db()
        if config is not None:
            self.save_project_config(config)

    def require_initialized(self) -> None:
        if not self.initialized:
            raise ProjectNotInitializedError(
                f"ZeroPath project is not initialized at {self.root_path}. Run `zeropath init`."
            )
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        self.zp_dir.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS records (
                    record_type TEXT NOT NULL,
                    record_id TEXT NOT NULL,
                    payload TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    PRIMARY KEY (record_type, record_id)
                )
                """
            )
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_records_type
                ON records(record_type)
                """
            )

    def save_record(self, record_type: str, record_id: str, payload: Any) -> None:
        self.require_initialized()
        now = utc_now().isoformat()
        encoded = json.dumps(self._coerce_json(payload), indent=2, sort_keys=True)
        with self._connect() as conn:
            existing = conn.execute(
                "SELECT created_at FROM records WHERE record_type = ? AND record_id = ?",
                (record_type, record_id),
            ).fetchone()
            created_at = existing["created_at"] if existing else now
            conn.execute(
                """
                INSERT INTO records(record_type, record_id, payload, created_at, updated_at)
                VALUES(?, ?, ?, ?, ?)
                ON CONFLICT(record_type, record_id)
                DO UPDATE SET payload = excluded.payload, updated_at = excluded.updated_at
                """,
                (record_type, record_id, encoded, created_at, now),
            )

    def load_record(self, record_type: str, record_id: str) -> dict[str, Any] | None:
        self.require_initialized()
        with self._connect() as conn:
            row = conn.execute(
                "SELECT payload FROM records WHERE record_type = ? AND record_id = ?",
                (record_type, record_id),
            ).fetchone()
        if row is None:
            return None
        return json.loads(row["payload"])

    def list_records(self, record_type: str) -> list[dict[str, Any]]:
        self.require_initialized()
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT payload FROM records WHERE record_type = ? ORDER BY record_id",
                (record_type,),
            ).fetchall()
        return [json.loads(row["payload"]) for row in rows]

    def delete_record(self, record_type: str, record_id: str) -> bool:
        self.require_initialized()
        with self._connect() as conn:
            cur = conn.execute(
                "DELETE FROM records WHERE record_type = ? AND record_id = ?",
                (record_type, record_id),
            )
        return cur.rowcount > 0

    def save_project_config(self, config: ProjectConfig) -> None:
        config.updated_at = utc_now()
        self.save_record("project_config", config.project_id, config)
        self.save_record("meta", "project_id", {"project_id": config.project_id})
        (self.zp_dir / "zeropath.toml").write_text(self._project_toml(config), encoding="utf-8")
        self._write_json(self.zp_dir / "artifacts/snapshots/project_config.json", config)

    def load_project_config(self) -> ProjectConfig:
        self.require_initialized()
        meta = self.load_record("meta", "project_id")
        if not meta:
            raise ProjectNotInitializedError("Missing project_id in .zeropath storage")
        data = self.load_record("project_config", meta["project_id"])
        if not data:
            raise ProjectNotInitializedError("Missing ProjectConfig in .zeropath storage")
        return ProjectConfig.model_validate(data)

    def save_protocol_intent(self, intent: ProtocolIntent) -> None:
        self.save_record("protocol_intent", intent.project_id, intent)
        self._write_json(self.zp_dir / "artifacts/snapshots/protocol_intent.json", intent)

    def load_protocol_intent(self) -> ProtocolIntent | None:
        config = self.load_project_config()
        data = self.load_record("protocol_intent", config.project_id)
        return ProtocolIntent.model_validate(data) if data else None

    def save_candidate(self, candidate: CandidateFinding) -> None:
        candidate.updated_at = utc_now()
        self.save_record("candidate", candidate.id, candidate)
        self._write_json(self.zp_dir / f"artifacts/candidates/{candidate.id}.json", candidate)

    def load_candidate(self, candidate_id: str) -> CandidateFinding | None:
        data = self.load_record("candidate", candidate_id)
        return CandidateFinding.model_validate(data) if data else None

    def list_candidates(self) -> list[CandidateFinding]:
        return [CandidateFinding.model_validate(item) for item in self.list_records("candidate")]

    def update_candidate_status(
        self,
        candidate_id: str,
        status: str,
        reason: str | None = None,
    ) -> CandidateFinding:
        candidate = self.load_candidate(candidate_id)
        if candidate is None:
            raise KeyError(f"Candidate not found: {candidate_id}")
        candidate.status = status
        if reason:
            candidate.rejection_checks.append(
                RejectionCheck(
                    check_name="manual_status_update",
                    passed=status != "rejected",
                    reason=reason,
                )
            )
            if candidate.notes:
                candidate.notes += "\n"
            candidate.notes += f"Status update: {reason}"
        self.save_candidate(candidate)
        return candidate

    def save_judge_result(self, result: JudgeResult) -> None:
        self.save_record("judge_result", result.candidate_id, result)
        self.save_record("judge_result_latest", "latest", result)
        self._write_json(
            self.zp_dir / f"artifacts/snapshots/judge_{result.candidate_id}.json",
            result,
        )

    def load_judge_result(self, candidate_id: str) -> JudgeResult | None:
        data = self.load_record("judge_result", candidate_id)
        return JudgeResult.model_validate(data) if data else None

    def load_last_judge_result(self) -> JudgeResult | None:
        data = self.load_record("judge_result_latest", "latest")
        return JudgeResult.model_validate(data) if data else None

    def save_memory(self, memory: MemoryItem) -> None:
        memory.updated_at = utc_now()
        self.save_record("memory", memory.id, memory)
        rel = "memory/project.jsonl"
        if memory.memory_type == "rejected_hypothesis":
            rel = "memory/rejected.jsonl"
        elif memory.memory_type == "exploit_pattern":
            rel = "memory/patterns.jsonl"
        elif memory.scope == "global":
            rel = "memory/global.jsonl"
        with (self.zp_dir / rel).open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(memory.model_dump(mode="json"), sort_keys=True) + "\n")

    def load_memory(self, memory_id: str) -> MemoryItem | None:
        data = self.load_record("memory", memory_id)
        return MemoryItem.model_validate(data) if data else None

    def list_memory(self) -> list[MemoryItem]:
        return [MemoryItem.model_validate(item) for item in self.list_records("memory")]

    def append_artifact(
        self,
        relative_path: str | Path,
        content: str,
        *,
        overwrite: bool = False,
    ) -> Path:
        self.require_initialized()
        path = (self.zp_dir / "artifacts" / relative_path).resolve()
        artifacts_root = (self.zp_dir / "artifacts").resolve()
        if artifacts_root not in path.parents and path != artifacts_root:
            raise ValueError("Artifact path escapes .zeropath/artifacts")
        if path.exists() and not overwrite:
            raise FileExistsError(f"Artifact already exists: {path}")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        return path

    def export_json_files(self) -> Path:
        self.require_initialized()
        data: dict[str, Any] = {}
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT record_type, record_id, payload FROM records ORDER BY record_type, record_id"
            ).fetchall()
        for row in rows:
            data.setdefault(row["record_type"], {})[row["record_id"]] = json.loads(row["payload"])
        out = self.zp_dir / "exports/storage.json"
        self._write_json(out, data)
        return out

    def status_summary(self) -> dict[str, Any]:
        config = self.load_project_config()
        candidates = self.list_candidates()
        memory = self.list_memory()
        by_status: dict[str, int] = {}
        for candidate in candidates:
            by_status[candidate.status] = by_status.get(candidate.status, 0) + 1
        intent = self.load_protocol_intent()
        last_judge = self.load_last_judge_result()
        evm_index = self.load_record("ingest", "evm_index") or {}
        return {
            "project_id": config.project_id,
            "root_path": config.root_path,
            "adapter": config.adapter,
            "build_system": config.build_system,
            "indexed_contracts": len(evm_index.get("contracts", [])),
            "protocol_intent": bool(intent),
            "protocol_type": intent.protocol_type if intent else None,
            "candidates_by_status": by_status,
            "memory_count": len(memory),
            "last_judge": last_judge.model_dump(mode="json") if last_judge else None,
        }

    @staticmethod
    def _coerce_json(payload: Any) -> Any:
        if hasattr(payload, "model_dump"):
            return payload.model_dump(mode="json")
        return payload

    @staticmethod
    def _project_toml(config: ProjectConfig) -> str:
        def scalar(value: Any) -> str:
            if value is None:
                return '""'
            return json.dumps(value)

        return "\n".join(
            [
                "# Generated by ZeroPath. Edit carefully.",
                "[project]",
                f"project_id = {scalar(config.project_id)}",
                f"root_path = {scalar(config.root_path)}",
                f"adapter = {scalar(config.adapter)}",
                f"created_at = {scalar(config.created_at.isoformat())}",
                f"updated_at = {scalar(config.updated_at.isoformat())}",
                f"repo_commit = {scalar(config.repo_commit)}",
                f"build_system = {scalar(config.build_system)}",
                f"scope_files = {json.dumps(config.scope_files)}",
                f"docs_paths = {json.dumps(config.docs_paths)}",
                f"source_paths = {json.dumps(config.source_paths)}",
                "",
            ]
        )

    @staticmethod
    def _write_json(path: Path, payload: Any) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        if hasattr(payload, "model_dump"):
            data = payload.model_dump(mode="json")
        else:
            data = payload
        path.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")
