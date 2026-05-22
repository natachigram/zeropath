"""
LLM augmentation layer — Contest mode.

Pluggable LLM provider + RAG-aware audit reasoner. Used by the Contest
orchestrator to drive an agentic audit loop against each in-scope file.

Public API::

    from zeropath.llm import build_default_provider, LLMReasoner, AuditCorpus

    provider = build_default_provider()           # reads ANTHROPIC_API_KEY etc.
    corpus   = AuditCorpus(knowledge=kg)
    reasoner = LLMReasoner(provider=provider, corpus=corpus, repo_root=Path("./contracts"))
    findings = reasoner.audit_file(file_path="src/Vault.sol", source_code=...)
"""

from zeropath.llm.audit_corpus import AuditCorpus
from zeropath.llm.prompts import (
    PROMPT_VERSION,
    SYSTEM_AUDITOR,
    SYSTEM_CONTRARIAN,
    SYSTEM_SPEC_EXTRACTOR,
    contrarian_prompt,
    file_audit_prompt,
    spec_extraction_prompt,
)
from zeropath.llm.provider import (
    AnthropicProvider,
    CostLedger,
    LLMProvider,
    LLMProviderUnavailable,
    LLMResponse,
    LLMUsage,
    LocalProvider,
    OpenAIProvider,
    ToolCall,
    ToolDescriptor,
    build_default_provider,
)
from zeropath.llm.reasoner import LLMFinding, LLMReasoner

__all__ = [
    # Provider
    "LLMProvider", "AnthropicProvider", "OpenAIProvider", "LocalProvider",
    "LLMResponse", "LLMUsage", "ToolDescriptor", "ToolCall",
    "CostLedger", "LLMProviderUnavailable",
    "build_default_provider",
    # Reasoner
    "LLMReasoner", "LLMFinding",
    "AuditCorpus",
    # Prompts
    "PROMPT_VERSION",
    "SYSTEM_AUDITOR", "SYSTEM_SPEC_EXTRACTOR", "SYSTEM_CONTRARIAN",
    "file_audit_prompt", "spec_extraction_prompt", "contrarian_prompt",
]
