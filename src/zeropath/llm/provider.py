"""
LLM provider abstraction — Contest mode.

Defines a uniform interface so the LLM Reasoner can call Anthropic Claude,
OpenAI GPT/o1, or a local Llama-class model without code changes.

No hard dependency on any vendor SDK at import time — each provider checks
for its SDK lazily so the package imports clean in environments missing
``anthropic`` / ``openai`` / ``llama-cpp-python``.

Cost tracking
-------------
Every call records ``input_tokens`` + ``output_tokens`` + ``estimated_usd``
into a per-provider ledger so :class:`LLMReasoner` can enforce the contest
budget (``--llm-budget-usd``).
"""

from __future__ import annotations

import json
import logging
import os
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Iterable, Optional, Protocol


logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Per-provider price table (USD per 1M tokens). Update as vendors change rates.
# Conservative defaults — real users should set their own.
# ---------------------------------------------------------------------------
_PRICE_USD_PER_MTOK: dict[str, dict[str, float]] = {
    "anthropic:claude-opus-4-7":    {"input": 15.0, "output": 75.0},
    "anthropic:claude-sonnet-4-6":  {"input": 3.0,  "output": 15.0},
    "anthropic:claude-haiku-4-5":   {"input": 0.80, "output": 4.0},
    "openai:gpt-4o":                {"input": 2.5,  "output": 10.0},
    "openai:o1-preview":            {"input": 15.0, "output": 60.0},
    "openai:gpt-4-turbo":           {"input": 10.0, "output": 30.0},
    "local:llama":                  {"input": 0.0,  "output": 0.0},
}


# ---------------------------------------------------------------------------
# Records
# ---------------------------------------------------------------------------


@dataclass
class LLMUsage:
    """Token + cost record for one call."""

    provider: str
    model: str
    input_tokens: int = 0
    output_tokens: int = 0
    estimated_usd: float = 0.0
    elapsed_seconds: float = 0.0


@dataclass
class ToolDescriptor:
    """One tool the reasoner can call via the model's tool-use API."""

    name: str
    description: str
    input_schema: dict[str, Any]


@dataclass
class ToolCall:
    """Model's request to invoke a tool."""

    id: str
    name: str
    arguments: dict[str, Any]


@dataclass
class LLMResponse:
    """Uniform response shape across providers."""

    content: str = ""
    tool_calls: list[ToolCall] = field(default_factory=list)
    stop_reason: str = "end_turn"      # end_turn | tool_use | max_tokens | error
    usage: Optional[LLMUsage] = None
    raw: dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Provider protocol
# ---------------------------------------------------------------------------


class LLMProvider(Protocol):
    """Minimal interface every backend implements."""

    name: str
    model: str

    @property
    def is_available(self) -> bool: ...

    def complete(
        self,
        *,
        system: str,
        messages: list[dict[str, Any]],
        tools: Optional[list[ToolDescriptor]] = None,
        max_tokens: int = 4096,
        temperature: float = 0.2,
    ) -> LLMResponse: ...


# ---------------------------------------------------------------------------
# Anthropic Claude
# ---------------------------------------------------------------------------


class AnthropicProvider:
    """
    Claude family via the official ``anthropic`` SDK.

    Default model: Claude Opus 4.7 — currently the strongest model for
    code reasoning in 2026. Cheaper models (Sonnet 4.6, Haiku 4.5) work
    via the ``model`` kwarg.

    Auth: reads ``ANTHROPIC_API_KEY`` from environment unless ``api_key``
    is passed explicitly.
    """

    name = "anthropic"

    def __init__(
        self,
        *,
        model: str = "claude-opus-4-7",
        api_key: Optional[str] = None,
        timeout: int = 120,
    ) -> None:
        self.model = model
        self.timeout = timeout
        self.api_key = api_key or os.environ.get("ANTHROPIC_API_KEY")
        self._client: Any = None

    @property
    def is_available(self) -> bool:
        if not self.api_key:
            return False
        try:
            import anthropic  # type: ignore # noqa: F401
            return True
        except ImportError:
            return False

    def _get_client(self) -> Any:
        if self._client is not None:
            return self._client
        import anthropic  # type: ignore
        self._client = anthropic.Anthropic(api_key=self.api_key, timeout=self.timeout)
        return self._client

    def complete(
        self,
        *,
        system: str,
        messages: list[dict[str, Any]],
        tools: Optional[list[ToolDescriptor]] = None,
        max_tokens: int = 4096,
        temperature: float = 0.2,
    ) -> LLMResponse:
        if not self.is_available:
            raise LLMProviderUnavailable(
                "anthropic provider unavailable — install `anthropic` and set ANTHROPIC_API_KEY"
            )
        client = self._get_client()
        start = time.monotonic()
        tool_payload = None
        if tools:
            tool_payload = [
                {"name": t.name, "description": t.description, "input_schema": t.input_schema}
                for t in tools
            ]
        kwargs: dict[str, Any] = {
            "model": self.model,
            "max_tokens": max_tokens,
            "temperature": temperature,
            "system": system,
            "messages": messages,
        }
        if tool_payload:
            kwargs["tools"] = tool_payload
        raw = client.messages.create(**kwargs)
        elapsed = time.monotonic() - start

        # Walk the response content blocks for text + tool_use.
        content_text: list[str] = []
        tool_calls: list[ToolCall] = []
        for block in getattr(raw, "content", []) or []:
            block_type = getattr(block, "type", None)
            if block_type == "text":
                content_text.append(getattr(block, "text", ""))
            elif block_type == "tool_use":
                tool_calls.append(ToolCall(
                    id=getattr(block, "id", ""),
                    name=getattr(block, "name", ""),
                    arguments=getattr(block, "input", {}) or {},
                ))

        usage = self._build_usage(raw, elapsed)
        return LLMResponse(
            content="\n".join(content_text).strip(),
            tool_calls=tool_calls,
            stop_reason=getattr(raw, "stop_reason", "end_turn"),
            usage=usage,
            raw={"id": getattr(raw, "id", "")},
        )

    def _build_usage(self, raw: Any, elapsed: float) -> LLMUsage:
        u = getattr(raw, "usage", None)
        in_tok = getattr(u, "input_tokens", 0) if u else 0
        out_tok = getattr(u, "output_tokens", 0) if u else 0
        price = _PRICE_USD_PER_MTOK.get(f"anthropic:{self.model}", {})
        cost = (
            (in_tok / 1_000_000) * price.get("input", 0)
            + (out_tok / 1_000_000) * price.get("output", 0)
        )
        return LLMUsage(
            provider=self.name, model=self.model,
            input_tokens=in_tok, output_tokens=out_tok,
            estimated_usd=round(cost, 6), elapsed_seconds=round(elapsed, 3),
        )


# ---------------------------------------------------------------------------
# OpenAI GPT / o1
# ---------------------------------------------------------------------------


class OpenAIProvider:
    """
    OpenAI Chat Completions / Responses API via the official ``openai`` SDK.

    Default: ``gpt-4o``. Use ``o1-preview`` for deep reasoning at higher cost.

    Auth: ``OPENAI_API_KEY``.
    """

    name = "openai"

    def __init__(
        self,
        *,
        model: str = "gpt-4o",
        api_key: Optional[str] = None,
        timeout: int = 120,
    ) -> None:
        self.model = model
        self.timeout = timeout
        self.api_key = api_key or os.environ.get("OPENAI_API_KEY")
        self._client: Any = None

    @property
    def is_available(self) -> bool:
        if not self.api_key:
            return False
        try:
            import openai  # type: ignore # noqa: F401
            return True
        except ImportError:
            return False

    def _get_client(self) -> Any:
        if self._client is not None:
            return self._client
        import openai  # type: ignore
        self._client = openai.OpenAI(api_key=self.api_key, timeout=self.timeout)
        return self._client

    def complete(
        self,
        *,
        system: str,
        messages: list[dict[str, Any]],
        tools: Optional[list[ToolDescriptor]] = None,
        max_tokens: int = 4096,
        temperature: float = 0.2,
    ) -> LLMResponse:
        if not self.is_available:
            raise LLMProviderUnavailable(
                "openai provider unavailable — install `openai` and set OPENAI_API_KEY"
            )
        client = self._get_client()

        # Convert Anthropic-style messages to OpenAI chat format.
        oa_messages: list[dict[str, Any]] = [{"role": "system", "content": system}]
        for m in messages:
            oa_messages.append({
                "role": m.get("role", "user"),
                "content": m.get("content", ""),
            })

        tool_payload = None
        if tools:
            tool_payload = [{
                "type": "function",
                "function": {
                    "name": t.name,
                    "description": t.description,
                    "parameters": t.input_schema,
                },
            } for t in tools]

        start = time.monotonic()
        kwargs: dict[str, Any] = {
            "model": self.model,
            "messages": oa_messages,
            "max_tokens": max_tokens,
            "temperature": temperature,
        }
        if tool_payload:
            kwargs["tools"] = tool_payload
        raw = client.chat.completions.create(**kwargs)
        elapsed = time.monotonic() - start

        msg = raw.choices[0].message
        text = (msg.content or "").strip()
        tool_calls: list[ToolCall] = []
        for tc in (msg.tool_calls or []):
            try:
                args = json.loads(tc.function.arguments or "{}")
            except json.JSONDecodeError:
                args = {}
            tool_calls.append(ToolCall(
                id=tc.id, name=tc.function.name, arguments=args,
            ))

        stop_reason = raw.choices[0].finish_reason or "stop"
        usage = self._build_usage(raw, elapsed)
        return LLMResponse(
            content=text, tool_calls=tool_calls, stop_reason=stop_reason,
            usage=usage, raw={"id": raw.id},
        )

    def _build_usage(self, raw: Any, elapsed: float) -> LLMUsage:
        u = getattr(raw, "usage", None)
        in_tok = getattr(u, "prompt_tokens", 0) if u else 0
        out_tok = getattr(u, "completion_tokens", 0) if u else 0
        price = _PRICE_USD_PER_MTOK.get(f"openai:{self.model}", {})
        cost = (
            (in_tok / 1_000_000) * price.get("input", 0)
            + (out_tok / 1_000_000) * price.get("output", 0)
        )
        return LLMUsage(
            provider=self.name, model=self.model,
            input_tokens=in_tok, output_tokens=out_tok,
            estimated_usd=round(cost, 6), elapsed_seconds=round(elapsed, 3),
        )


# ---------------------------------------------------------------------------
# Local Llama / OpenAI-compatible HTTP endpoint
# ---------------------------------------------------------------------------


class LocalProvider:
    """
    Hit any OpenAI-compatible local endpoint (llama.cpp server, vLLM,
    Ollama with the OpenAI-compatible API). Used when air-gapped or
    cost-bounded.
    """

    name = "local"

    def __init__(
        self,
        *,
        base_url: str = "http://127.0.0.1:8080/v1",
        model: str = "llama",
        api_key: str = "not-needed",
        timeout: int = 120,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.api_key = api_key
        self.timeout = timeout
        self._client: Any = None

    @property
    def is_available(self) -> bool:
        try:
            import openai  # type: ignore # noqa: F401
        except ImportError:
            return False
        # A quick TCP-level liveness check would block; defer to the call.
        return True

    def _get_client(self) -> Any:
        if self._client is not None:
            return self._client
        import openai  # type: ignore
        self._client = openai.OpenAI(
            api_key=self.api_key, base_url=self.base_url, timeout=self.timeout,
        )
        return self._client

    def complete(self, **kw: Any) -> LLMResponse:
        # Reuse OpenAIProvider's logic by delegating; this gives us tool
        # schemas + token tracking for free.
        delegate = OpenAIProvider.__new__(OpenAIProvider)
        delegate.name = "local"  # type: ignore[assignment]
        delegate.model = self.model
        delegate.api_key = self.api_key
        delegate.timeout = self.timeout
        delegate._client = self._get_client()
        return delegate.complete(**kw)


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class LLMProviderUnavailable(RuntimeError):
    """No usable provider configured."""


# ---------------------------------------------------------------------------
# Cost ledger
# ---------------------------------------------------------------------------


class CostLedger:
    """Thread-safe rolling spend tracker used by the LLM Reasoner."""

    def __init__(self, *, budget_usd: Optional[float] = None) -> None:
        self._lock = threading.Lock()
        self._budget_usd = budget_usd
        self._spent_usd = 0.0
        self._calls: list[LLMUsage] = []

    @property
    def budget_usd(self) -> Optional[float]:
        return self._budget_usd

    @property
    def spent_usd(self) -> float:
        with self._lock:
            return self._spent_usd

    @property
    def remaining_usd(self) -> Optional[float]:
        if self._budget_usd is None:
            return None
        with self._lock:
            return max(0.0, self._budget_usd - self._spent_usd)

    @property
    def call_count(self) -> int:
        return len(self._calls)

    def record(self, usage: LLMUsage) -> None:
        with self._lock:
            self._calls.append(usage)
            self._spent_usd += usage.estimated_usd

    def would_exceed_budget(self, projected_usd: float = 0.0) -> bool:
        if self._budget_usd is None:
            return False
        with self._lock:
            return (self._spent_usd + projected_usd) > self._budget_usd

    def summary(self) -> dict[str, Any]:
        with self._lock:
            in_tok = sum(c.input_tokens for c in self._calls)
            out_tok = sum(c.output_tokens for c in self._calls)
            return {
                "calls": len(self._calls),
                "input_tokens": in_tok,
                "output_tokens": out_tok,
                "spent_usd": round(self._spent_usd, 4),
                "budget_usd": self._budget_usd,
                "remaining_usd": (
                    None if self._budget_usd is None
                    else round(self._budget_usd - self._spent_usd, 4)
                ),
            }


# ---------------------------------------------------------------------------
# Env-driven factory
# ---------------------------------------------------------------------------


def build_default_provider() -> Optional[LLMProvider]:
    """
    Pick the first available provider from env. Order of preference:
        Anthropic → OpenAI → Local. Returns None if none are configured.

    Env vars:
      * ANTHROPIC_API_KEY (+ optional ZEROPATH_LLM_MODEL_ANTHROPIC)
      * OPENAI_API_KEY    (+ optional ZEROPATH_LLM_MODEL_OPENAI)
      * ZEROPATH_LLM_LOCAL_BASE_URL  (+ optional ZEROPATH_LLM_MODEL_LOCAL)
    """
    if os.environ.get("ANTHROPIC_API_KEY"):
        return AnthropicProvider(
            model=os.environ.get("ZEROPATH_LLM_MODEL_ANTHROPIC", "claude-opus-4-7"),
        )
    if os.environ.get("OPENAI_API_KEY"):
        return OpenAIProvider(
            model=os.environ.get("ZEROPATH_LLM_MODEL_OPENAI", "gpt-4o"),
        )
    if os.environ.get("ZEROPATH_LLM_LOCAL_BASE_URL"):
        return LocalProvider(
            base_url=os.environ["ZEROPATH_LLM_LOCAL_BASE_URL"],
            model=os.environ.get("ZEROPATH_LLM_MODEL_LOCAL", "llama"),
        )
    return None
