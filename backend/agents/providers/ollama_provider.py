"""Ollama / local model provider.

Uses the plain ``/api/chat`` HTTP endpoint via ``httpx`` so no extra SDK is
needed. Point ``OLLAMA_BASE_URL`` at a local ``ollama serve`` instance; nothing
in this project ever requires it (demo mode uses the mock provider instead).
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

ENV_BASE_URL = "OLLAMA_BASE_URL"
DEFAULT_BASE_URL = "http://localhost:11434"


class OllamaProvider(LLMProvider):
    """Local-model provider backed by an Ollama-compatible HTTP server."""

    kind = ProviderKind.OLLAMA
    is_simulation = False

    def __init__(
        self,
        model: str = "llama3.1:8b",
        *,
        base_url: str | None = None,
        temperature: float = 0.0,
        max_tokens: int = 1024,
        timeout: float = 120.0,
        max_retries: int = 2,
    ) -> None:
        self.default_model = model
        self.model_name = model
        self.temperature = temperature
        self.max_tokens = max_tokens
        self.timeout = timeout
        self.max_retries = max_retries
        self.base_url = (base_url or os.getenv(ENV_BASE_URL) or DEFAULT_BASE_URL).rstrip("/")
        try:
            import httpx  # type: ignore import-not-found
        except ImportError as exc:  # pragma: no cover - depends on env
            raise ProviderUnavailableError(
                "httpx is required for the Ollama provider. Install requirements.txt."
            ) from exc
        self._httpx = httpx

    def complete(self, request: LLMRequest) -> LLMResponse:
        from backend.agents.base import parse_action_response

        payload = {
            "model": self.model_name,
            "stream": False,
            "format": "json",
            "options": {
                "temperature": self.temperature,
                "num_predict": self.max_tokens,
                "seed": request.seed,
            },
            "messages": [
                {"role": "system", "content": request.system_prompt},
                *request.transcript(),
            ],
        }
        last_error: Exception | None = None
        for _ in range(max(1, self.max_retries)):
            try:
                response = self._httpx.post(
                    f"{self.base_url}/api/chat", json=payload, timeout=self.timeout
                )
                response.raise_for_status()
                data = response.json()
                text = (data.get("message") or {}).get("content", "")
                try:
                    parsed = parse_action_response(text)
                except Exception as exc:  # noqa: BLE001
                    raise ProviderError(
                        f"Could not parse model action: {exc}", details={"excerpt": text[:400]}
                    ) from exc
                if isinstance(parsed, str):
                    return LLMResponse(
                        text=text, final_answer=parsed, finish_reason="final_answer",
                        model=self.model_name, provider=self.kind.value, raw=data,
                    )
                return LLMResponse(
                    text=text, tool_call=parsed, finish_reason="tool_call",
                    model=self.model_name, provider=self.kind.value, raw=data,
                )
            except ProviderError:
                raise
            except Exception as exc:  # noqa: BLE001
                name = type(exc).__name__
                if "Timeout" in name or "timeout" in str(exc).lower():
                    last_error = ProviderTimeoutError(f"Ollama request timed out: {exc}")
                else:
                    last_error = ProviderError(f"Ollama request failed ({name}): {exc}")
        raise last_error or ProviderError("Ollama request failed for an unknown reason.")

    def health(self) -> dict[str, Any]:
        available = False
        detail = ""
        try:
            response = self._httpx.get(f"{self.base_url}/api/tags", timeout=5.0)
            available = response.status_code == 200
            detail = "reachable" if available else f"status {response.status_code}"
        except Exception as exc:  # noqa: BLE001
            detail = f"unreachable ({type(exc).__name__})"
        return {
            "provider": self.kind.value,
            "model": self.model_name,
            "is_simulation": False,
            "available": available,
            "base_url": self.base_url,
            "requires_api_key": False,
            "detail": detail,
        }


__all__ = ["OllamaProvider", "ENV_BASE_URL", "DEFAULT_BASE_URL"]