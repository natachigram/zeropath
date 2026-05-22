"""
LLM Reasoner — the contest-winning brain.

Drives an LLM (Claude Opus 4.7 by default) through an agentic audit loop
against one Solidity file at a time:

  1. Build context: source code + Phase 1 graph summary + Phase 2 invariants
     + Phase 8 RAG over past findings + spec-mined claimed invariants.
  2. Call the model with a strict-JSON-output system prompt + tool use.
  3. Iterate when the model invokes tools (read_file, grep, lookup_past_finding).
  4. Validate every returned finding has a concrete attack path before
     yielding it.
  5. Hand findings to Phase 4-6 for PoC generation + Foundry verification +
     contrarian review.

Budget-aware: respects ``CostLedger`` so a contest run can cap LLM spend
(``zeropath contest --llm-budget-usd 200`` style).
"""

from __future__ import annotations

import json
import logging
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Optional
from uuid import uuid4

from zeropath.adversarial.models import (
    AttackClass,
    AttackHypothesis,
    AttackStep,
    Precondition,
    ProfitMechanism,
    ConditionType,
    HypothesisStatus,
)
from zeropath.llm.audit_corpus import AuditCorpus
from zeropath.llm.prompts import (
    SYSTEM_AUDITOR,
    SYSTEM_CONTRARIAN,
    file_audit_prompt,
    contrarian_prompt,
)
from zeropath.llm.provider import (
    CostLedger,
    LLMProvider,
    LLMProviderUnavailable,
    LLMResponse,
    ToolCall,
    ToolDescriptor,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Tool descriptors the model can invoke
# ---------------------------------------------------------------------------


def _default_tools() -> list[ToolDescriptor]:
    return [
        ToolDescriptor(
            name="read_file",
            description="Read a Solidity / Markdown / text file from the audit scope.",
            input_schema={
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "File path relative to the audit root."},
                    "start_line": {"type": "integer", "description": "Optional 1-indexed start line."},
                    "end_line": {"type": "integer", "description": "Optional 1-indexed end line."},
                },
                "required": ["path"],
            },
        ),
        ToolDescriptor(
            name="grep_codebase",
            description="Search the audit scope for a regex / substring; returns matching file:line pairs.",
            input_schema={
                "type": "object",
                "properties": {
                    "pattern": {"type": "string"},
                    "path_glob": {"type": "string", "description": "Optional restrict to e.g. 'src/**/*.sol'."},
                    "max_results": {"type": "integer", "default": 50},
                },
                "required": ["pattern"],
            },
        ),
        ToolDescriptor(
            name="lookup_past_finding",
            description="Return past contest findings on structurally similar contracts.",
            input_schema={
                "type": "object",
                "properties": {
                    "contract_name": {"type": "string"},
                    "attack_class_hint": {"type": "string"},
                    "top_k": {"type": "integer", "default": 5},
                },
                "required": ["contract_name"],
            },
        ),
    ]


# ---------------------------------------------------------------------------
# Records
# ---------------------------------------------------------------------------


@dataclass
class LLMFinding:
    """One raw finding emitted by the model, before Phase 4-6 validation."""

    title: str
    severity: str = "medium"
    attack_class: str = "other"
    contracts_involved: list[str] = field(default_factory=list)
    functions_involved: list[str] = field(default_factory=list)
    lines_of_code: list[str] = field(default_factory=list)
    root_cause: str = ""
    attack_path: list[str] = field(default_factory=list)
    preconditions: list[str] = field(default_factory=list)
    impact: str = ""
    proof_of_concept: str = ""
    recommendation: str = ""
    confidence: float = 0.5
    novelty_assessment: str = ""

    # Provenance — set by the reasoner, not the model.
    file_path: str = ""
    raw_payload: dict[str, Any] = field(default_factory=dict)

    def is_actionable(self) -> bool:
        """Spec-compliance gate: drop vague findings."""
        if not self.title or not self.root_cause:
            return False
        if len(self.attack_path) < 2:
            return False
        if not self.impact:
            return False
        return True


# ---------------------------------------------------------------------------
# Tool runner
# ---------------------------------------------------------------------------


class _ToolRunner:
    """Dispatcher for tool calls the model makes during the audit loop."""

    def __init__(
        self,
        *,
        repo_root: Path,
        corpus: Optional[AuditCorpus],
        max_file_bytes: int = 60_000,
    ) -> None:
        self.repo_root = repo_root
        self.corpus = corpus
        self.max_file_bytes = max_file_bytes

    def run(self, call: ToolCall) -> str:
        try:
            if call.name == "read_file":
                return self._read_file(**call.arguments)
            if call.name == "grep_codebase":
                return self._grep(**call.arguments)
            if call.name == "lookup_past_finding":
                return self._lookup(**call.arguments)
        except Exception as exc:
            return f"<tool error: {exc}>"
        return f"<unknown tool: {call.name}>"

    # ------------------------------------------------------------------

    def _read_file(
        self, path: str, start_line: Optional[int] = None,
        end_line: Optional[int] = None,
    ) -> str:
        full = (self.repo_root / path).resolve()
        if not str(full).startswith(str(self.repo_root.resolve())):
            return "<error: path escapes audit root>"
        if not full.exists() or not full.is_file():
            return f"<error: {path} not found>"
        text = full.read_text(encoding="utf-8", errors="replace")
        if start_line or end_line:
            lines = text.splitlines()
            lo = max((start_line or 1) - 1, 0)
            hi = min(end_line or len(lines), len(lines))
            text = "\n".join(lines[lo:hi])
        if len(text) > self.max_file_bytes:
            text = text[: self.max_file_bytes] + "\n<...truncated...>"
        return text

    def _grep(
        self, pattern: str, path_glob: Optional[str] = None,
        max_results: int = 50,
    ) -> str:
        try:
            regex = re.compile(pattern)
        except re.error as exc:
            return f"<invalid regex: {exc}>"
        matches: list[str] = []
        glob = path_glob or "**/*.sol"
        for f in self.repo_root.rglob(glob):
            if not f.is_file():
                continue
            try:
                lines = f.read_text(encoding="utf-8", errors="replace").splitlines()
            except Exception:
                continue
            for i, line in enumerate(lines, 1):
                if regex.search(line):
                    matches.append(f"{f.relative_to(self.repo_root)}:{i}: {line.strip()[:200]}")
                    if len(matches) >= max_results:
                        return "\n".join(matches) + "\n<truncated>"
        return "\n".join(matches) or "<no matches>"

    def _lookup(
        self, contract_name: str, attack_class_hint: Optional[str] = None,
        top_k: int = 5,
    ) -> str:
        if self.corpus is None:
            return "<knowledge graph not configured>"
        return self.corpus.context_for_file(
            file_path=contract_name,
            contract_names=[contract_name],
            attack_class_hint=attack_class_hint,
            top_k=top_k,
        ) or "<no past findings matched>"


# ---------------------------------------------------------------------------
# Reasoner
# ---------------------------------------------------------------------------


# Map raw model string → Phase 3 AttackClass enum value.
_ATTACK_CLASS_NORM: dict[str, str] = {
    "oracle_manipulation": AttackClass.ORACLE_MANIPULATION.value,
    "price_manipulation": AttackClass.PRICE_MANIPULATION.value,
    "reentrancy": AttackClass.REENTRANCY.value,
    "access_control": AttackClass.ACCESS_CONTROL.value,
    "flash_loan": AttackClass.FLASH_LOAN.value,
    "composability": AttackClass.COMPOSABILITY.value,
    "governance": AttackClass.GOVERNANCE.value,
    "integer_math": AttackClass.INTEGER_MATH.value,
    "spec_violation": "other",
    "other": "unknown",
}


_JSON_BLOCK_RE = re.compile(r"```(?:json)?\s*([\s\S]*?)```", re.MULTILINE)


def _extract_json_array(text: str) -> list[dict]:
    """
    Robust JSON-array extraction. Tries direct parse first, then peels off
    Markdown code fences, then falls back to a bracket-scan.
    """
    if not text:
        return []
    text = text.strip()
    # Direct parse
    try:
        parsed = json.loads(text)
        if isinstance(parsed, list):
            return parsed
        if isinstance(parsed, dict):
            return [parsed]
    except json.JSONDecodeError:
        pass
    # Markdown code fences
    for m in _JSON_BLOCK_RE.finditer(text):
        candidate = m.group(1).strip()
        try:
            parsed = json.loads(candidate)
            if isinstance(parsed, list):
                return parsed
            if isinstance(parsed, dict):
                return [parsed]
        except json.JSONDecodeError:
            continue
    # Bracket scan
    start = text.find("[")
    if start == -1:
        return []
    depth = 0
    for i in range(start, len(text)):
        if text[i] == "[":
            depth += 1
        elif text[i] == "]":
            depth -= 1
            if depth == 0:
                try:
                    parsed = json.loads(text[start:i + 1])
                    if isinstance(parsed, list):
                        return parsed
                except json.JSONDecodeError:
                    return []
    return []


class LLMReasoner:
    """
    Tool-using audit loop driven by an LLM.

    Parameters
    ----------
    provider : LLMProvider
        The configured backend (Anthropic / OpenAI / Local).
    corpus : AuditCorpus | None
        RAG over Phase 8 KG findings. Strongly recommended in contest mode.
    repo_root : Path
        Audit scope root — every tool call is sandboxed to this directory.
    cost_ledger : CostLedger | None
        Budget enforcement.
    max_tool_turns : int
        Cap the agent loop. Default 6 — empirically enough for one file.
    max_findings_per_file : int
        Truncate the JSON array if the model emits too many.
    """

    def __init__(
        self,
        *,
        provider: LLMProvider,
        corpus: Optional[AuditCorpus] = None,
        repo_root: Path,
        cost_ledger: Optional[CostLedger] = None,
        max_tool_turns: int = 6,
        max_findings_per_file: int = 10,
        max_input_tokens_budget: int = 80_000,
    ) -> None:
        self.provider = provider
        self.corpus = corpus
        self.repo_root = Path(repo_root)
        self.ledger = cost_ledger or CostLedger()
        self.max_tool_turns = max_tool_turns
        self.max_findings_per_file = max_findings_per_file
        self.max_input_tokens_budget = max_input_tokens_budget
        self._tools = _default_tools()
        self._runner = _ToolRunner(repo_root=self.repo_root, corpus=corpus)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def audit_file(
        self,
        *,
        file_path: str,
        source_code: str,
        graph_summary: str = "",
        invariant_summary: str = "",
        spec_claims_summary: str = "",
    ) -> list[LLMFinding]:
        """
        Drive the agent loop on one file. Returns the validated findings
        (vague / non-actionable ones are filtered out).
        """
        if not self.provider.is_available:
            raise LLMProviderUnavailable(
                f"provider {self.provider.name} is not configured"
            )
        if self.ledger.would_exceed_budget(projected_usd=0.5):
            logger.warning("LLMReasoner: budget exhausted before %s", file_path)
            return []

        past_findings_summary = ""
        if self.corpus:
            past_findings_summary = self.corpus.context_for_file(
                file_path=file_path,
                contract_names=self._contract_names_from_source(source_code),
            )

        user_prompt = file_audit_prompt(
            file_path=file_path,
            source_code=source_code,
            graph_summary=graph_summary,
            invariant_summary=invariant_summary,
            past_findings_summary=past_findings_summary,
            spec_claims_summary=spec_claims_summary,
        )

        messages: list[dict[str, Any]] = [{"role": "user", "content": user_prompt}]
        final_text = ""
        for turn in range(self.max_tool_turns):
            if self.ledger.would_exceed_budget(projected_usd=0.5):
                logger.warning("LLMReasoner: budget hit during %s on turn %d", file_path, turn)
                break
            try:
                resp: LLMResponse = self.provider.complete(
                    system=SYSTEM_AUDITOR,
                    messages=messages,
                    tools=self._tools,
                    max_tokens=4096,
                    temperature=0.2,
                )
            except Exception as exc:
                logger.exception("LLM call failed for %s: %s", file_path, exc)
                return []
            if resp.usage:
                self.ledger.record(resp.usage)

            if resp.stop_reason == "tool_use" and resp.tool_calls:
                messages.append({"role": "assistant", "content": resp.content or ""})
                for call in resp.tool_calls:
                    output = self._runner.run(call)
                    messages.append({
                        "role": "user",
                        "content": (
                            f"<tool_result name=\"{call.name}\">\n{output}\n</tool_result>"
                        ),
                    })
                continue

            final_text = resp.content
            break

        return self._parse_and_validate(file_path, final_text)

    # ------------------------------------------------------------------
    # Contrarian pass
    # ------------------------------------------------------------------

    def contrarian_verdict(
        self,
        *,
        finding_json: str,
        poc_run_log: str = "",
    ) -> dict[str, Any]:
        """Run a second LLM call playing the role of a contest judge."""
        if not self.provider.is_available:
            return {"verdict": "accept", "objections": [], "recommendation": "submit"}
        if self.ledger.would_exceed_budget(projected_usd=0.2):
            return {"verdict": "accept", "objections": ["budget exhausted"], "recommendation": "submit"}
        resp = self.provider.complete(
            system=SYSTEM_CONTRARIAN,
            messages=[{"role": "user", "content": contrarian_prompt(finding_json, poc_run_log)}],
            tools=None,
            max_tokens=1024,
            temperature=0.0,
        )
        if resp.usage:
            self.ledger.record(resp.usage)
        try:
            parsed = json.loads(resp.content.strip())
            if isinstance(parsed, dict):
                return parsed
        except json.JSONDecodeError:
            pass
        return {"verdict": "accept", "objections": ["unparseable contrarian response"], "recommendation": "submit"}

    # ------------------------------------------------------------------
    # Bridge into Phase 3 AttackHypothesis
    # ------------------------------------------------------------------

    def to_hypothesis(self, finding: LLMFinding, *, invariant_id: str = "") -> AttackHypothesis:
        """Convert an LLMFinding into a Phase-3 AttackHypothesis."""
        cls = _ATTACK_CLASS_NORM.get(finding.attack_class, "unknown")
        try:
            attack_class = AttackClass(cls)
        except ValueError:
            attack_class = AttackClass.UNKNOWN

        steps = [
            AttackStep(step=i + 1, action=text, purpose="LLM-derived step")
            for i, text in enumerate(finding.attack_path)
        ]
        preconditions = [
            Precondition(
                condition_type=ConditionType.CUSTOM,
                description=p,
                is_met_by_protocol=None,
            )
            for p in finding.preconditions
        ]
        return AttackHypothesis(
            invariant_id=invariant_id or str(uuid4()),
            invariant_description=finding.root_cause,
            attack_class=attack_class,
            title=finding.title[:80],
            proposed_by="LLMReasoner",
            attack_narrative=finding.root_cause + "\n\n" + " ".join(finding.attack_path),
            exploit_steps=steps,
            preconditions=preconditions,
            contracts_involved=list(finding.contracts_involved),
            functions_involved=list(finding.functions_involved),
            profit_mechanism=ProfitMechanism(
                description=finding.impact, asset="unknown",
            ),
            confidence=float(finding.confidence or 0.5),
            specificity_score=0.8 if finding.is_actionable() else 0.5,
            status=HypothesisStatus.PROPOSED,
            poc_sketch=finding.proof_of_concept,
            suggested_fix=finding.recommendation,
        )

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _parse_and_validate(self, file_path: str, text: str) -> list[LLMFinding]:
        raw_findings = _extract_json_array(text)
        if not raw_findings:
            logger.debug("LLMReasoner: no JSON findings parsed from %s", file_path)
            return []
        out: list[LLMFinding] = []
        for raw in raw_findings[: self.max_findings_per_file]:
            try:
                f = LLMFinding(
                    title=str(raw.get("title", "")).strip()[:200],
                    severity=str(raw.get("severity", "medium")).lower(),
                    attack_class=str(raw.get("attack_class", "other")).lower(),
                    contracts_involved=list(raw.get("contracts_involved", []) or []),
                    functions_involved=list(raw.get("functions_involved", []) or []),
                    lines_of_code=list(raw.get("lines_of_code", []) or []),
                    root_cause=str(raw.get("root_cause", "")),
                    attack_path=list(raw.get("attack_path", []) or []),
                    preconditions=list(raw.get("preconditions", []) or []),
                    impact=str(raw.get("impact", "")),
                    proof_of_concept=str(raw.get("proof_of_concept", "")),
                    recommendation=str(raw.get("recommendation", "")),
                    confidence=float(raw.get("confidence", 0.5) or 0.5),
                    novelty_assessment=str(raw.get("novelty_assessment", "")),
                    file_path=file_path,
                    raw_payload=raw,
                )
            except Exception as exc:
                logger.debug("LLMReasoner: skipped malformed finding: %s", exc)
                continue
            if not f.is_actionable():
                continue
            out.append(f)
        return out

    @staticmethod
    def _contract_names_from_source(source: str) -> list[str]:
        return re.findall(
            r"contract\s+([A-Za-z_][A-Za-z0-9_]*)", source or "",
        )[:10]
