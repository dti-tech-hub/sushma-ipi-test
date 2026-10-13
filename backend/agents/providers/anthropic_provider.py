"""Anthropic-compatible chat provider.

Credentials come from ``ANTHROPIC_API_KEY`` only. The provider is imported
lazily so demo mode never touches it, and any Anthropic-compatible endpoint can
be used by setting ``base_url`` (or ``ANTHROPIC_BASE_URL``).
"""

from __future__ import annotations

import os
from typing import Any

from backend.agents.base import LLMProvider, LLMRequest, LLMResponse, ToolCallRequest
from backend.models.enums import ProviderKind
from backend.models.errors import (
    ProviderError,
    ProviderTimeoutError,
    ProviderUnavailableError,
)

ENV_API_KEY = "ANTHROPIC_API_KEY"
ENV_BASE_URL = "ANTHROPIC_BASE_URL"


class AnthropicProvider(LLMProvider):
    """Messages-API provider for Anthropic (and compatible gateways)."""

    kind = ProviderKind.ANTHROPIC
    is_simulation = False

    def __init__(
        self,
        model: str = "claude-3-5-haiku-20241022",
        *,
        api_key: str | None = None,
        base_url: str | None = None,
        temperature: float = 0.0,
        max_tokens: int = 1024,
        timeout: float = 60.0,
        max_retries: int = 2,
    ) -> None:
        self.default_model = model
        self.model_name = model
        self.temperature = temperature
        self.max_tokens = max_tokens
        self.timeout = timeout
        self.max_retries = max_retries
        self.api_key = api_key or os.getenv(ENV_API_KEY)
        self.base_url = base_url or os.getenv(ENV_BASE_URL) or None
        if not self.api_key:
            raise ProviderUnavailableError(
                f"{self.kind.value} provider requires {ENV_API_KEY} in the environment.",
                details={"env_var": ENV_API_KEY},
            )
        try:
            from anthropic import Anthropic  # type: ignore import-not-found
        except ImportError as exc:  # pragma: no cover - depends on env
            raise ProviderUnavailableError(
                "The 'anthropic' package is not installed. Install requirements.txt "
                "or run in demo mode."
            ) from exc
        kwargs: dict[str, Any] = {"api_key": self.api_key, "timeout": self.timeout, "max_retries": self.max_retries}
        if self.base_url:
            kwargs["base_url"] = self.base_url
        self._client = Anthropic(**kwargs)

    def complete(self, request: LLMRequest) -> LLMResponse:
        from backend.agents.base import parse_action_response

        # Anthropic takes the system prompt out of band.
        transcript = [m for m in request.messages if m.role != "system"]
        messages = [
            {"role": "user" if m.role in {"human", "tool"} else "assistant", "content": m.content}
            for m in transcript
        ] or [{"role": "user", "content": request.system_prompt}]

        last_error: Exception | None = None
        for _ in range(max(1, self.max_retries)):
            try:
                response = self._client.messages.create(
                    model=self.model_name,
                    system=request.system_prompt,
                    messages=messages,
                    temperature=self.temperature,
                    max_tokens=self.max_tokens,
                )
                blocks = [b for b in getattr(response, "content", []) if getattr(b, "type", "") == "text"]
                text = "".join(getattr(b, "text", "") for b in blocks)
                try:
                    parsed = parse_action_response(text)
                except Exception as exc:  # noqa: BLE001
                    raise ProviderError(
                        f"Could not parse model action: {exc}", details={"excerpt": text[:400]}
                    ) from exc
                if isinstance(parsed, str):
                    return LLMResponse(
                        text=text, final_answer=parsed, finish_reason="final_answer",
                        model=self.model_name, provider=self.kind.value,
                        raw={"stop_reason": getattr(response, "stop_reason", None)},
                    )
                return LLMResponse(
                    text=text, tool_call=parsed, finish_reason="tool_call",
                    model=self.model_name, provider=self.kind.value,
                    raw={"stop_reason": getattr(response, "stop_reason", None)},
                )
            except ProviderError:
                raise
            except Exception as exc:  # noqa: BLE001
                name = type(exc).__name__
                if "Timeout" in name or "timeout" in str(exc).lower():
                    last_error = ProviderTimeoutError(f"Anthropic request timed out: {exc}")
                else:
                    last_error = ProviderError(f"Anthropic request failed ({name}): {exc}")
        raise last_error or ProviderError("Anthropic request failed for an unknown reason.")

    def health(self) -> dict[str, Any]:
        return {
            "provider": self.kind.value,
            "model": self.model_name,
            "is_simulation": False,
            "available": bool(self.api_key),
            "base_url": self.base_url,
            "requires_api_key": True,
        }


__all__ = ["AnthropicProvider", "ENV_API_KEY", "ENV_BASE_URL"]