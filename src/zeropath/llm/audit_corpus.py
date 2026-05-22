"""
Audit corpus loader / RAG over the Phase 8 KG — Contest mode.

Pulls structurally similar past findings out of the knowledge graph and
shapes them into compact context blocks for the LLM Reasoner. This is
how Phase 3's swarm + the LLM agent benefit from compounding institutional
memory across runs.

Stateless wrapper over the KG — every call hits the store at query time so
new ingestions (e.g. fresh Cantina disclosures) show up immediately.
"""

from __future__ import annotations

import logging
import re
from collections import Counter
from typing import Iterable, Optional

from zeropath.knowledge.knowledge import KnowledgeGraphOrchestrator
from zeropath.knowledge.models import (
    ExploitRecord,
    ExternalIncidentRecord,
)
from zeropath.knowledge.schema import NodeLabel

logger = logging.getLogger(__name__)


_TOKEN_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]+")

_DEFAULT_TOP_K = 6
_MAX_PER_FINDING_CHARS = 400


def _tokens(text: str) -> Counter:
    return Counter(t.lower() for t in _TOKEN_RE.findall(text or ""))


def _truncate(text: str, n: int) -> str:
    if not text:
        return ""
    return text[: n - 1].rstrip() + "…" if len(text) > n else text


class AuditCorpus:
    """
    Compose RAG context strings for the LLM Reasoner from the Phase 8 KG.

    Parameters
    ----------
    knowledge : KnowledgeGraphOrchestrator
        The KG to read from.
    top_k : int
        How many past findings to include per query. 6 keeps prompts under
        ~3k tokens; raise for deeper contexts at higher cost.
    """

    def __init__(
        self,
        knowledge: KnowledgeGraphOrchestrator,
        *,
        top_k: int = _DEFAULT_TOP_K,
    ) -> None:
        self.knowledge = knowledge
        self.top_k = top_k

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def context_for_file(
        self,
        *,
        file_path: str,
        contract_names: Iterable[str] = (),
        function_names: Iterable[str] = (),
        attack_class_hint: Optional[str] = None,
        top_k: Optional[int] = None,
    ) -> str:
        """
        Build a Markdown block of the top-K most relevant past findings.

        Relevance scoring blends:
          * attack-class match (weight 3)
          * contract / function name token overlap (weight 2)
          * file-path token overlap (weight 1)
        """
        top_k = top_k or self.top_k
        query_tokens = (
            _tokens(file_path)
            + _tokens(" ".join(contract_names))
            + _tokens(" ".join(function_names))
        )
        candidates: list[tuple[float, str]] = []

        # Score every validated exploit + external incident in the KG.
        for node in self.knowledge.store.find_by_label(NodeLabel.VALIDATED_EXPLOIT):
            block = self._validated_exploit_block(node.properties)
            score = self._score(
                node.properties, query_tokens, attack_class_hint,
                node_kind="validated",
            )
            if score > 0:
                candidates.append((score, block))
        for node in self.knowledge.store.find_by_label(NodeLabel.EXTERNAL_INCIDENT):
            block = self._external_incident_block(node.properties)
            score = self._score(
                node.properties, query_tokens, attack_class_hint,
                node_kind="incident",
            )
            if score > 0:
                candidates.append((score, block))

        candidates.sort(key=lambda kv: kv[0], reverse=True)
        if not candidates:
            return ""
        top = [block for _score, block in candidates[:top_k]]
        return "\n\n".join(top)

    # ------------------------------------------------------------------
    # Block renderers
    # ------------------------------------------------------------------

    @staticmethod
    def _validated_exploit_block(props: dict) -> str:
        lines = [
            f"- **{props.get('protocol_name', 'unknown')}** "
            f"[{props.get('attack_class', 'unknown')}, "
            f"{props.get('severity_tier', 'unknown')}]",
        ]
        functions = props.get("functions_involved") or []
        if functions:
            lines.append(f"  - Functions: `{', '.join(functions[:4])}`")
        contracts = props.get("contracts_involved") or []
        if contracts:
            lines.append(f"  - Contracts: `{', '.join(contracts[:4])}`")
        loss = props.get("profit_usd") or 0
        if loss:
            lines.append(f"  - Validated profit: ${int(loss):,}")
        return "\n".join(lines)

    @staticmethod
    def _external_incident_block(props: dict) -> str:
        lines = [
            f"- **{props.get('protocol', 'unknown')}** "
            f"({props.get('incident_date') or 'n/a'}) "
            f"[{props.get('attack_class', 'unknown')}]",
        ]
        loss = int(props.get("loss_usd") or 0)
        if loss:
            lines.append(f"  - Historical loss: ${loss:,}")
        root_cause = _truncate(props.get("root_cause", ""), _MAX_PER_FINDING_CHARS)
        if root_cause:
            lines.append(f"  - Root cause: {root_cause}")
        url = props.get("source_url")
        if url:
            lines.append(f"  - Source: {url}")
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Scoring
    # ------------------------------------------------------------------

    @staticmethod
    def _score(
        props: dict,
        query_tokens: Counter,
        attack_class_hint: Optional[str],
        *,
        node_kind: str,
    ) -> float:
        score = 0.0
        node_class = props.get("attack_class") or ""
        if attack_class_hint and node_class == attack_class_hint:
            score += 3.0
        # Name / function overlap.
        node_text = " ".join([
            str(props.get("protocol_name") or props.get("protocol") or ""),
            " ".join(props.get("functions_involved") or []),
            " ".join(props.get("contracts_involved") or []),
            str(props.get("root_cause") or ""),
        ])
        node_tokens = _tokens(node_text)
        overlap = sum(min(query_tokens[k], node_tokens[k]) for k in query_tokens.keys() & node_tokens.keys())
        score += overlap * 0.5
        # Bias incidents with large historical loss — they're more likely
        # to recur in similar forms.
        loss = int(props.get("loss_usd") or props.get("profit_usd") or 0)
        if loss >= 100_000_000:
            score += 1.0
        elif loss >= 10_000_000:
            score += 0.5
        # Slightly prefer validated (our own) findings over external — they
        # carry our exact PoC patterns.
        if node_kind == "validated":
            score *= 1.1
        return score

    # ------------------------------------------------------------------
    # Bulk summary for the executive context block
    # ------------------------------------------------------------------

    def attack_class_distribution(self) -> dict[str, int]:
        """Aggregate counts of past findings by attack class."""
        counts: Counter = Counter()
        for node in self.knowledge.store.find_by_label(NodeLabel.VALIDATED_EXPLOIT):
            counts[node.properties.get("attack_class", "unknown")] += 1
        for node in self.knowledge.store.find_by_label(NodeLabel.EXTERNAL_INCIDENT):
            counts[node.properties.get("attack_class", "unknown")] += 1
        return dict(counts)
