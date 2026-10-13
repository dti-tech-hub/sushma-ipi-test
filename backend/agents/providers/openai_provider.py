"""OpenAI-compatible chat provider.

Works with the official OpenAI endpoint and with anything that speaks the same
API (Azure OpenAI, vLLM, LM Studio, OpenRouter, Groq, Together) by setting
``base_url``. Credentials are read from the environment only.

The provider is imported lazily: ``import openai`` happens inside
:meth:`OpenAIProvider.__init__`, so demo mode never touches it.
"""

from __future__ import annotations

import json
import os
from typing import Any

from backend.agents.base import LLMProvider, LLMRequest, LLMResponse, ToolCallRequest
from backend.models.enums import ProviderKind
from backend.models.errors import (
    ProviderError,
    ProviderTimeoutError,
    ProviderUnavailableError,
)

ENV_API_KEY = "OPENAI_API_KEY"
ENV_BASE_URL = "OPENAI_BASE_URL"


class OpenAIProvider(LLMProvider):
    """Chat-completions provider for any OpenAI-compatible endpoint."""

    kind = ProviderKind.OPENAI
    is_simulation = False

    def __init__(
        self,
        model: str = "gpt-4o-mini",
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
        # Resolve key/base_url from explicit args or env; never from config files.
        self.api_key = api_key or os.getenv(ENV_API_KEY)
        self.base_url = base_url or os.getenv(ENV_BASE_URL) or None
        if not self.api_key:
            raise ProviderUnavailableError(
                f"{self.kind.value} provider requires {ENV_API_KEY} in the environment.",
                details={"env_var": ENV_API_KEY},
            )
        try:
            from openai import OpenAI  # type: ignore import-not-found
        except ImportError as exc:  # pragma: no cover - depends on env
            raise ProviderUnavailableError(
                "The 'openai' package is not installed. Install requirements.txt "
                "or run in demo mode."
            ) from exc
        kwargs: dict[str, Any] = {"api_key": self.api_key, "timeout": self.timeout, "max_retries": self.max_retries}
        if self.base_url:
            kwargs["base_url"] = self.base_url
        self._client = OpenAI(**kwargs)

    def complete(self, request: LLMRequest) -> LLMResponse:
        from backend.agents.base import parse_action_response  # local, avoids cycle

        payload_messages = [{"role": "system", "content": request.system_prompt}] + request.transcript()
        last_error: Exception | None = None
        for _ in range(max(1, self.max_retries)):
            try:
                completion = self._client.chat.completions.create(
                    model=self.model_name,
                    messages=payload_messages,
                    temperature=self.temperature,
                    max_tokens=self.max_tokens,
                )
                text = completion.choices[0].message.content or ""
                tool_call: ToolCallRequest | None = None
                final: str | None = None
                thought = ""
                try:
                    parsed = parse_action_response(text)
                except Exception as exc:  # noqa: BLE001 - provider-specific parse
                    raise ProviderError(
                        f"Could not parse model action: {exc}",
                        details={"excerpt": text[:400]},
                    ) from exc
                if isinstance(parsed, str):
                    final = parsed
                else:
                    tool_call = parsed
                return LLMResponse(
                    text=text,
                    tool_call=tool_call,
                    final_answer=final,
                    thought=thought,
                    finish_reason="tool_call" if tool_call else "final_answer",
                    model=self.model_name,
                    provider=self.kind.value,
                    raw={"usage": getattr(completion, "usage", None) and completion.usage.model_dump()},
                )
            except ProviderError:
                raise
            except Exception as exc:  # noqa: BLE001 - network/provider errors
                name = type(exc).__name__
                if "Timeout" in name or "timeout" in str(exc).lower():
                    last_error = ProviderTimeoutError(f"OpenAI request timed out: {exc}")
                else:
                    last_error = ProviderError(f"OpenAI request failed ({name}): {exc}")
        raise last_error or ProviderError("OpenAI request failed for an unknown reason.")

    def health(self) -> dict[str, Any]:
        return {
            "provider": self.kind.value,
            "model": self.model_name,
            "is_simulation": False,
            "available": bool(self.api_key),
            "base_url": self.base_url,
            "requires_api_key": True,
        }


class OpenAIJSONEchoProvider(LLMProvider):
    """Offline stand-in that returns a well-formed action object.

    Registered under ``mock-json`` so the action protocol can be exercised
    end-to-end without any model. Clearly a simulation.
    """

    kind = ProviderKind.MOCK
    is_simulation = True
    default_model = "mock-json"

    def complete(self, request: LLMRequest) -> LLMResponse:
        from backend.agents.base import parse_action_response

        plan = list(request.context.get("plan") or [])
        cursor = int(request.context.get("plan_cursor", 0))
        if cursor < len(plan):
            step = plan[cursor]
            text = json.dumps(
                {
                    "thought": "json-echo provider",
                    "action": f"{step['tool']}.{step['action']}",
                    "arguments": step.get("arguments") or {},
                }
            )
        else:
            text = json.dumps({"final": request.context.get("legit_answer") or "done"})
        parsed = parse_action_response(text)
        if isinstance(parsed, str):
            return LLMResponse(
                text=text, final_answer=parsed, finish_reason="final_answer",
                model=self.default_model, provider=self.kind.value,
            )
        return LLMResponse(
            text=text, tool_call=parsed, finish_reason="tool_call",
            model=self.default_model, provider=self.kind.value,
        )


__all__ = ["OpenAIProvider", "OpenAIJSONEchoProvider", "ENV_API_KEY", "ENV_BASE_URL"]