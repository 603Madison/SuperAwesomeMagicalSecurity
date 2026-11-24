"""AI integration: LLM providers, tool registry, analyst loop, MCP server and an
OpenAI-compatible endpoint. Heavy SDK imports (anthropic, openai, mcp) are deferred to
the modules that need them so ``import sams.ai`` works without the ``ai`` extra."""
from __future__ import annotations

from typing import Any, Optional

from .providers import (ChatMessage, ChatTurn, LLMProvider, ProviderError, ToolCall, ToolResult, ToolSpec,
                        available_providers, find_provider_settings, get_provider)
from .redact import Redactor


def make_analyst(ctx: Any, provider_name: Optional[str] = None, **kwargs: Any):
    """Convenience: SecurityAnalyst for the named (or default) configured provider."""
    from .analyst import SecurityAnalyst
    provider = get_provider(find_provider_settings(ctx.settings.ai, provider_name))
    return SecurityAnalyst(ctx, provider, **kwargs)


__all__ = ["ChatMessage", "ChatTurn", "LLMProvider", "ProviderError", "ToolCall", "ToolResult", "ToolSpec",
           "available_providers", "find_provider_settings", "get_provider", "Redactor", "make_analyst"]
