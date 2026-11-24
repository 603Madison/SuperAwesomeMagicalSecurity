"""LLM provider adapters.

One provider-neutral conversation format (``ChatMessage`` / ``ToolCall`` /
``ToolResult``) and one call (``LLMProvider.chat``) so the analyst loop, the
OpenAI-compatible endpoint and anything else in SAMS can run against:

* ``anthropic``          - Claude via the official ``anthropic`` SDK (optionally through a gateway ``base_url``)
* ``openai``             - OpenAI via the official ``openai`` SDK
* ``openai_compatible``  - any OpenAI-compatible server: vLLM, LM Studio, LocalAI, llama.cpp server,
                           OpenRouter, Together, Groq, LiteLLM, Gemini's OpenAI endpoint, Ollama's ``/v1``
* ``azure_openai``       - Azure OpenAI deployments (``openai.AzureOpenAI``)
* ``ollama``             - Ollama's native ``/api/chat`` (supports tools) over httpx

API keys are read from the environment variable *named* in the provider settings
(``api_key_env``) at construction time. They are never logged or returned.
"""
from __future__ import annotations

import json
import logging
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

import httpx

from ..config import AIProviderSettings, AISettings

log = logging.getLogger("sams.ai")


# --------------------------------------------------------------------------- #
# Provider-neutral conversation types
# --------------------------------------------------------------------------- #
@dataclass
class ToolSpec:
    name: str
    description: str
    input_schema: dict[str, Any]


@dataclass
class ToolCall:
    id: str
    name: str
    arguments: dict[str, Any]


@dataclass
class ToolResult:
    tool_call_id: str
    name: str
    content: str
    is_error: bool = False


@dataclass
class ChatMessage:
    """One conversation entry.

    * ``role="user"``: ``content`` is the user text.
    * ``role="assistant"``: ``content`` text plus optional ``tool_calls``. ``raw`` holds the
      provider-native assistant content (e.g. Anthropic content blocks incl. thinking) which
      is replayed *unchanged* when the same provider sees the conversation again.
    * ``role="tool"``: ``tool_results`` answers every tool call of the previous assistant turn.
    """
    role: str
    content: str = ""
    tool_calls: list[ToolCall] = field(default_factory=list)
    tool_results: list[ToolResult] = field(default_factory=list)
    raw: Any = None
    raw_provider: Optional[str] = None   # provider key (type:model) that produced ``raw``


@dataclass
class ChatTurn:
    text: str
    tool_calls: list[ToolCall]
    # normalized: end_turn | tool_use | max_tokens | refusal | pause_turn | other
    stop_reason: str
    usage: dict[str, int] = field(default_factory=dict)
    raw: Any = None
    refusal: Optional[dict[str, Any]] = None
    model: str = ""


class ProviderError(RuntimeError):
    """A provider call failed. ``retryable`` marks rate limits / overloads / network errors."""

    def __init__(self, message: str, retryable: bool = False):
        super().__init__(message)
        self.retryable = retryable


def _add_usage(total: dict[str, int], usage: dict[str, int]) -> dict[str, int]:
    for k, v in (usage or {}).items():
        if isinstance(v, int):
            total[k] = total.get(k, 0) + v
    return total


# --------------------------------------------------------------------------- #
# Base class
# --------------------------------------------------------------------------- #
class LLMProvider:
    type: str = "base"

    def __init__(self, settings: AIProviderSettings):
        self.settings = settings

    @property
    def name(self) -> str:
        return self.settings.name

    @property
    def model(self) -> str:
        return self.settings.model

    @property
    def locality(self) -> str:
        return self.settings.locality

    @property
    def key(self) -> str:
        """Identity used to decide whether ``ChatMessage.raw`` can be replayed verbatim."""
        return f"{self.type}:{self.settings.base_url or ''}:{self.model}"

    def chat(self, system: str, messages: list[ChatMessage], tools: list[ToolSpec]) -> ChatTurn:
        raise NotImplementedError


# --------------------------------------------------------------------------- #
# Anthropic (Claude)
# --------------------------------------------------------------------------- #
# Models on which adaptive thinking is the right setting (it is the only thinking mode,
# or the recommended one). Older models (e.g. claude-haiku-4-5) get no thinking param.
_ADAPTIVE_PREFIXES = (
    "claude-fable-", "claude-mythos-", "claude-opus-5", "claude-sonnet-5", "claude-haiku-5",
    "claude-opus-4-6", "claude-opus-4-7", "claude-opus-4-8", "claude-sonnet-4-6",
)
# Models that accept output_config.effort.
_EFFORT_PREFIXES = _ADAPTIVE_PREFIXES + ("claude-opus-4-5",)
# Models that support the server-side refusal fallback parameter.
_FALLBACK_MODELS = {
    "claude-fable-5-2", "claude-fable-5-1", "claude-opus-5-5", "claude-opus-5", "claude-sonnet-5-5",
}
FALLBACK_BETA = "server-side-fallback-2026-07-01"
DEFAULT_ANTHROPIC_MODEL = "claude-opus-5-5"


class AnthropicProvider(LLMProvider):
    """Claude through the official SDK.

    * adaptive thinking + ``output_config.effort`` (default ``high``; Opus 5.5 would
      otherwise default to ``medium``)
    * streamed requests, read with ``get_final_message()`` (protects against HTTP timeouts)
    * assistant content (incl. thinking blocks) is replayed unchanged on later turns
    * the stable prefix (tools + system prompt) is cached with a ``cache_control`` breakpoint
    * server-side refusal fallbacks (``fallbacks="default"``) on models that support it, unless
      a custom ``base_url`` is set (gateways may reject beta params) or ``extra.fallbacks`` is false
    """

    type = "anthropic"

    def __init__(self, settings: AIProviderSettings, http_client: Any = None, client: Any = None):
        super().__init__(settings)
        import anthropic

        self._anthropic = anthropic
        if client is not None:
            self.client = client
        else:
            kwargs: dict[str, Any] = {}
            key = settings.api_key()
            if key:
                kwargs["api_key"] = key
            if settings.base_url:
                kwargs["base_url"] = settings.base_url
            if http_client is not None:
                kwargs["http_client"] = http_client
            # With no key configured the SDK resolves ANTHROPIC_API_KEY / auth token / `ant` profile.
            self.client = anthropic.Anthropic(**kwargs)

    # -- request building ------------------------------------------------- #
    def _fallbacks(self) -> Any:
        extra = self.settings.extra or {}
        if "fallbacks" in extra:
            fb = extra["fallbacks"]
            return fb if fb not in (False, None, "off", "none") else None
        if self.settings.base_url:
            return None
        return "default" if self.model in _FALLBACK_MODELS else None

    def _eager(self) -> bool:
        extra = self.settings.extra or {}
        if "eager_input_streaming" in extra:
            return bool(extra["eager_input_streaming"])
        # proxies / gateways in front of the API may reject the field
        return not self.settings.base_url

    def _tools(self, tools: list[ToolSpec]) -> list[dict[str, Any]]:
        eager = self._eager()
        out = []
        for t in tools:
            d: dict[str, Any] = {"name": t.name, "description": t.description, "input_schema": t.input_schema}
            if eager:
                d["eager_input_streaming"] = True
            out.append(d)
        return out

    def _messages(self, messages: list[ChatMessage]) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for m in messages:
            if m.role == "user":
                out.append({"role": "user", "content": m.content})
            elif m.role == "assistant":
                if m.raw is not None and m.raw_provider == self.key:
                    # replay unchanged (thinking blocks, fallback blocks, tool_use ids...)
                    out.append({"role": "assistant", "content": m.raw})
                    continue
                blocks: list[dict[str, Any]] = []
                if m.content:
                    blocks.append({"type": "text", "text": m.content})
                for tc in m.tool_calls:
                    blocks.append({"type": "tool_use", "id": tc.id, "name": tc.name, "input": tc.arguments})
                out.append({"role": "assistant", "content": blocks or [{"type": "text", "text": "(no content)"}]})
            elif m.role == "tool":
                # every result of the turn goes back in ONE user message
                out.append({"role": "user", "content": [
                    {"type": "tool_result", "tool_use_id": r.tool_call_id, "content": r.content,
                     **({"is_error": True} if r.is_error else {})}
                    for r in m.tool_results
                ]})
        return out

    def build_params(self, system: str, messages: list[ChatMessage], tools: list[ToolSpec]) -> dict[str, Any]:
        model = self.model or DEFAULT_ANTHROPIC_MODEL
        params: dict[str, Any] = {
            "model": model,
            "max_tokens": self.settings.max_tokens,
            # stable prefix: tools render before system, so this breakpoint caches both
            "system": [{"type": "text", "text": system, "cache_control": {"type": "ephemeral"}}],
            "messages": self._messages(messages),
        }
        if (self.settings.extra or {}).get("auto_cache", True):
            # automatic breakpoint on the growing conversation (tool results are re-read every turn)
            params["cache_control"] = {"type": "ephemeral"}
        if tools:
            params["tools"] = self._tools(tools)
        if model.startswith(_ADAPTIVE_PREFIXES):
            params["thinking"] = {"type": "adaptive"}
        if model.startswith(_EFFORT_PREFIXES):
            params["output_config"] = {"effort": self.settings.effort or "high"}
        betas: list[str] = []
        fb = self._fallbacks()
        if fb is not None:
            betas.append(FALLBACK_BETA)
            params["fallbacks"] = fb
        if betas:
            params["betas"] = betas
        return params

    # -- call ------------------------------------------------------------- #
    def chat(self, system: str, messages: list[ChatMessage], tools: list[ToolSpec]) -> ChatTurn:
        a = self._anthropic
        params = self.build_params(system, messages, tools)
        attempts = 0
        while True:
            try:
                with self.client.beta.messages.stream(**params) as stream:
                    final = stream.get_final_message()
                break
            except ValueError as exc:
                # Eager input streaming: the SDK could not parse a tool input at all. There is no
                # tool_use id to answer, so re-issue the turn (bounded). API errors are not ValueError.
                attempts += 1
                if attempts > 2:
                    raise ProviderError(f"Claude returned unparseable tool input: {exc}") from exc
                continue
            except a.AuthenticationError as exc:
                raise ProviderError("Anthropic authentication failed - check the configured API key") from exc
            except a.PermissionDeniedError as exc:
                raise ProviderError(f"Anthropic permission denied: {exc.message}") from exc
            except a.NotFoundError as exc:
                raise ProviderError(f"Anthropic model or endpoint not found ({params['model']})") from exc
            except a.RateLimitError as exc:
                raise ProviderError("Anthropic rate limit reached; retry later", retryable=True) from exc
            except a.BadRequestError as exc:
                raise ProviderError(f"Anthropic rejected the request: {exc.message}") from exc
            except a.APIStatusError as exc:
                raise ProviderError(f"Anthropic API error {exc.status_code}", retryable=exc.status_code >= 500) from exc
            except a.APIConnectionError as exc:
                raise ProviderError("Could not reach the Anthropic API", retryable=True) from exc

        text_parts: list[str] = []
        calls: list[ToolCall] = []
        for block in final.content:
            btype = getattr(block, "type", "")
            if btype == "text":
                text_parts.append(block.text)
            elif btype == "tool_use":
                inp = block.input if isinstance(block.input, dict) else {"__invalid_input__": block.input}
                calls.append(ToolCall(id=block.id, name=block.name, arguments=inp))
        usage = {}
        if final.usage is not None:
            for k in ("input_tokens", "output_tokens", "cache_read_input_tokens", "cache_creation_input_tokens"):
                v = getattr(final.usage, k, None)
                if isinstance(v, int):
                    usage[k] = v
        refusal = None
        stop = final.stop_reason or "other"
        if stop == "refusal":
            details = getattr(final, "stop_details", None)
            refusal = {"category": getattr(details, "category", None),
                       "explanation": getattr(details, "explanation", None)}
        if stop not in ("end_turn", "tool_use", "max_tokens", "refusal", "pause_turn"):
            stop = "end_turn" if not calls else "tool_use"
        return ChatTurn(text="".join(text_parts), tool_calls=calls, stop_reason=stop, usage=usage,
                        raw=list(final.content), refusal=refusal, model=getattr(final, "model", "") or "")


# --------------------------------------------------------------------------- #
# OpenAI and OpenAI-compatible servers
# --------------------------------------------------------------------------- #
class OpenAIProvider(LLMProvider):
    """OpenAI chat.completions with function tools. With ``base_url`` it talks to any
    OpenAI-compatible server (vLLM, LM Studio, LocalAI, OpenRouter, Groq, LiteLLM, Ollama /v1,
    Gemini's OpenAI endpoint...)."""

    type = "openai"

    def __init__(self, settings: AIProviderSettings, http_client: Any = None, client: Any = None):
        super().__init__(settings)
        import openai

        self._openai = openai
        if client is not None:
            self.client = client
            return
        key = settings.api_key()
        kwargs: dict[str, Any] = {}
        if http_client is not None:
            kwargs["http_client"] = http_client
        extra = settings.extra or {}
        if settings.type == "azure_openai":
            self.client = openai.AzureOpenAI(
                azure_endpoint=settings.base_url, api_key=key,
                api_version=extra.get("api_version", "2024-10-21"), **kwargs)
            return
        if settings.base_url:
            kwargs["base_url"] = settings.base_url
        if key:
            kwargs["api_key"] = key
        elif settings.base_url:
            kwargs["api_key"] = "not-needed"     # local servers usually ignore the key
        if extra.get("default_headers"):
            kwargs["default_headers"] = dict(extra["default_headers"])
        self.client = openai.OpenAI(**kwargs)

    @property
    def key(self) -> str:
        return f"{self.settings.type}:{self.settings.base_url or ''}:{self.model}"

    @staticmethod
    def _tools(tools: list[ToolSpec]) -> list[dict[str, Any]]:
        return [{"type": "function", "function": {"name": t.name, "description": t.description,
                                                  "parameters": t.input_schema}} for t in tools]

    def _messages(self, system: str, messages: list[ChatMessage]) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = [{"role": "system", "content": system}]
        for m in messages:
            if m.role == "user":
                out.append({"role": "user", "content": m.content})
            elif m.role == "assistant":
                if m.raw is not None and m.raw_provider == self.key and isinstance(m.raw, dict):
                    out.append(m.raw)
                    continue
                msg: dict[str, Any] = {"role": "assistant", "content": m.content or None}
                if m.tool_calls:
                    msg["tool_calls"] = [{"id": tc.id, "type": "function",
                                          "function": {"name": tc.name, "arguments": json.dumps(tc.arguments)}}
                                         for tc in m.tool_calls]
                out.append(msg)
            elif m.role == "tool":
                for r in m.tool_results:   # OpenAI wants one tool message per call
                    out.append({"role": "tool", "tool_call_id": r.tool_call_id,
                                "content": ("ERROR: " + r.content) if r.is_error else r.content})
        return out

    def build_params(self, system: str, messages: list[ChatMessage], tools: list[ToolSpec]) -> dict[str, Any]:
        extra = self.settings.extra or {}
        params: dict[str, Any] = {"model": self.model, "messages": self._messages(system, messages)}
        if tools:
            params["tools"] = self._tools(tools)
        token_param = extra.get("max_tokens_param") or (
            "max_completion_tokens" if self.settings.type in ("openai", "azure_openai") else "max_tokens")
        params[token_param] = self.settings.max_tokens
        if extra.get("reasoning_effort"):
            params["reasoning_effort"] = extra["reasoning_effort"]
        return params

    def chat(self, system: str, messages: list[ChatMessage], tools: list[ToolSpec]) -> ChatTurn:
        o = self._openai
        params = self.build_params(system, messages, tools)
        try:
            resp = self.client.chat.completions.create(**params)
        except o.AuthenticationError as exc:
            raise ProviderError(f"{self.settings.type} authentication failed - check the configured API key") from exc
        except o.NotFoundError as exc:
            raise ProviderError(f"model or endpoint not found ({self.model})") from exc
        except o.RateLimitError as exc:
            raise ProviderError("rate limit reached; retry later", retryable=True) from exc
        except o.BadRequestError as exc:
            raise ProviderError(f"request rejected: {exc.message}") from exc
        except o.APIStatusError as exc:
            raise ProviderError(f"API error {exc.status_code}", retryable=exc.status_code >= 500) from exc
        except o.APIConnectionError as exc:
            raise ProviderError(f"could not reach {self.settings.base_url or 'the OpenAI API'}", retryable=True) from exc

        if not resp.choices:
            raise ProviderError("provider returned no choices")
        choice = resp.choices[0]
        msg = choice.message
        calls: list[ToolCall] = []
        for tc in (msg.tool_calls or []):
            fn = getattr(tc, "function", None)
            if fn is None:
                continue
            try:
                args = json.loads(fn.arguments or "{}")
                if not isinstance(args, dict):
                    args = {"__invalid_input__": fn.arguments}
            except json.JSONDecodeError:
                args = {"__invalid_input__": fn.arguments}
            calls.append(ToolCall(id=tc.id or f"call_{uuid.uuid4().hex[:12]}", name=fn.name, arguments=args))
        raw: dict[str, Any] = {"role": "assistant", "content": msg.content}
        if msg.tool_calls:
            raw["tool_calls"] = [{"id": c.id, "type": "function",
                                  "function": {"name": c.name, "arguments": json.dumps(c.arguments)}} for c in calls]
        finish = choice.finish_reason or ""
        stop = {"stop": "end_turn", "tool_calls": "tool_use", "function_call": "tool_use",
                "length": "max_tokens", "content_filter": "refusal"}.get(finish, "tool_use" if calls else "end_turn")
        if calls and stop == "end_turn":
            stop = "tool_use"     # some compatible servers report "stop" alongside tool calls
        usage = {}
        if resp.usage is not None:
            usage = {"input_tokens": resp.usage.prompt_tokens or 0, "output_tokens": resp.usage.completion_tokens or 0}
        refusal = {"category": "content_filter", "explanation": getattr(msg, "refusal", None)} if stop == "refusal" else None
        if getattr(msg, "refusal", None) and not msg.content:
            stop, refusal = "refusal", {"category": None, "explanation": msg.refusal}
        return ChatTurn(text=msg.content or "", tool_calls=calls, stop_reason=stop, usage=usage, raw=raw,
                        refusal=refusal, model=resp.model or self.model)


# --------------------------------------------------------------------------- #
# Ollama native API
# --------------------------------------------------------------------------- #
class OllamaProvider(LLMProvider):
    """Ollama ``/api/chat`` with tools (Llama 3.1+, Qwen 2.5+, Mistral, ...). Everything stays on
    the local network, so Ollama providers default to ``locality: local`` in the docs."""

    type = "ollama"

    def __init__(self, settings: AIProviderSettings, transport: Optional[httpx.BaseTransport] = None):
        super().__init__(settings)
        base = (settings.base_url or "http://localhost:11434").rstrip("/")
        if base.endswith("/v1"):
            base = base[:-3]
        headers = {}
        key = settings.api_key()
        if key:   # Ollama behind an authenticating reverse proxy / Open WebUI
            headers["Authorization"] = f"Bearer {key}"
        timeout = float((settings.extra or {}).get("timeout", 600))
        self.http = httpx.Client(base_url=base, headers=headers, timeout=timeout, transport=transport)

    def _messages(self, system: str, messages: list[ChatMessage]) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = [{"role": "system", "content": system}]
        for m in messages:
            if m.role == "user":
                out.append({"role": "user", "content": m.content})
            elif m.role == "assistant":
                msg: dict[str, Any] = {"role": "assistant", "content": m.content or ""}
                if m.tool_calls:
                    msg["tool_calls"] = [{"function": {"name": tc.name, "arguments": tc.arguments}}
                                         for tc in m.tool_calls]
                out.append(msg)
            elif m.role == "tool":
                for r in m.tool_results:
                    out.append({"role": "tool", "tool_name": r.name,
                                "content": ("ERROR: " + r.content) if r.is_error else r.content})
        return out

    def build_payload(self, system: str, messages: list[ChatMessage], tools: list[ToolSpec]) -> dict[str, Any]:
        extra = self.settings.extra or {}
        payload: dict[str, Any] = {
            "model": self.model,
            "messages": self._messages(system, messages),
            "stream": False,
            "options": {"num_predict": self.settings.max_tokens, **(extra.get("options") or {})},
        }
        if tools:
            payload["tools"] = [{"type": "function", "function": {"name": t.name, "description": t.description,
                                                                 "parameters": t.input_schema}} for t in tools]
        if extra.get("keep_alive"):
            payload["keep_alive"] = extra["keep_alive"]
        return payload

    def chat(self, system: str, messages: list[ChatMessage], tools: list[ToolSpec]) -> ChatTurn:
        payload = self.build_payload(system, messages, tools)
        try:
            r = self.http.post("/api/chat", json=payload)
        except httpx.HTTPError as exc:
            raise ProviderError(f"could not reach Ollama at {self.http.base_url}", retryable=True) from exc
        if r.status_code == 404:
            raise ProviderError(f"Ollama model not found: {self.model} (run `ollama pull {self.model}`)")
        if r.status_code >= 400:
            raise ProviderError(f"Ollama error {r.status_code}: {r.text[:300]}", retryable=r.status_code >= 500)
        data = r.json()
        msg = data.get("message") or {}
        calls = []
        for tc in msg.get("tool_calls") or []:
            fn = tc.get("function") or {}
            args = fn.get("arguments") or {}
            if isinstance(args, str):
                try:
                    args = json.loads(args)
                except json.JSONDecodeError:
                    args = {"__invalid_input__": args}
            calls.append(ToolCall(id=tc.get("id") or f"call_{uuid.uuid4().hex[:12]}", name=fn.get("name", ""),
                                  arguments=args if isinstance(args, dict) else {"__invalid_input__": args}))
        done = data.get("done_reason") or "stop"
        stop = "tool_use" if calls else ("max_tokens" if done == "length" else "end_turn")
        usage = {"input_tokens": int(data.get("prompt_eval_count") or 0),
                 "output_tokens": int(data.get("eval_count") or 0)}
        return ChatTurn(text=msg.get("content") or "", tool_calls=calls, stop_reason=stop, usage=usage,
                        raw=None, model=data.get("model") or self.model)


# --------------------------------------------------------------------------- #
# Factory
# --------------------------------------------------------------------------- #
PROVIDER_TYPES: dict[str, Callable[..., LLMProvider]] = {
    "anthropic": AnthropicProvider,
    "claude": AnthropicProvider,
    "openai": OpenAIProvider,
    "openai_compatible": OpenAIProvider,
    "azure_openai": OpenAIProvider,
    "ollama": OllamaProvider,
}


def get_provider(settings: AIProviderSettings, **kwargs: Any) -> LLMProvider:
    """Instantiate a provider from settings. ``kwargs`` pass through to the adapter
    (``http_client=`` for the SDK-based ones, ``transport=`` for Ollama; used by tests)."""
    cls = PROVIDER_TYPES.get(settings.type.lower())
    if cls is None:
        raise ValueError(f"unknown AI provider type {settings.type!r}; expected one of {sorted(PROVIDER_TYPES)}")
    return cls(settings, **kwargs)


def find_provider_settings(ai: AISettings, name: Optional[str] = None) -> AIProviderSettings:
    if not ai.providers:
        raise LookupError("no AI providers configured (add ai.providers to sams.yaml)")
    wanted = name or ai.default_provider
    if wanted:
        for p in ai.providers:
            if p.name == wanted:
                return p
        raise LookupError(f"AI provider {wanted!r} is not configured")
    return ai.providers[0]


def available_providers(ai: AISettings) -> list[dict[str, Any]]:
    """Describe configured providers without revealing secrets."""
    default = ai.default_provider or (ai.providers[0].name if ai.providers else None)
    out = []
    for p in ai.providers:
        needs_key = p.type in ("anthropic", "claude", "openai", "azure_openai")
        out.append({
            "name": p.name, "type": p.type, "model": p.model, "base_url": p.base_url,
            "locality": p.locality, "redacted": p.locality == "cloud" and not p.allow_sensitive,
            "key_configured": bool(p.api_key()) if p.api_key_env else (not needs_key or p.type in ("anthropic", "claude")),
            "default": p.name == default,
        })
    return out
