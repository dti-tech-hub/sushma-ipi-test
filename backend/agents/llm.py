"""LLM provider factory.

``get_provider`` is the single entry point used by the experiment runner, the
API and the CLI. It applies three rules:

1. **Demo mode wins.** If ``settings.demo_mode`` is true the deterministic mock
   provider is returned regardless of configuration, so the project always runs
   with zero API keys.
2. **No key -> mock.** If the configured provider needs a credential that is not
   present, fall back to the mock provider and say so, rather than crashing the
   experiment. Set ``strict=True`` to raise instead (used by the API).
3. **Never reads secrets from config files.** Credentials come from the
   environment only.
"""

from __future__ import annotations

import os
from typing import Any

from backend.agents.base import LLMProvider
from backend.agents.providers.anthropic_provider import AnthropicProvider
from backend.agents.providers.mock import (
    ARCHETYPES,
    MOCK_MODELS,
    MOCK_MODEL_DESCRIPTIONS,
    MockLLMProvider,
)
from backend.agents.providers.ollama_provider import OllamaProvider
from backend.agents.providers.openai_provider import OpenAIJSONEchoProvider, OpenAIProvider
from backend.models.enums import ProviderKind
from backend.models.errors import ProviderUnavailableError
from backend.services.config import Settings, get_settings

#: env var holding the credential per provider.
API_KEY_ENV: dict[ProviderKind, str] = {
    ProviderKind.OPENAI: "OPENAI_API_KEY",
    ProviderKind.ANTHROPIC: "ANTHROPIC_API_KEY",
}

FALLBACK_NOTE = (
    "Fell back to the deterministic mock provider because {reason}. "
    "Results produced this way are DEMO / MOCK results."
)


def available_models() -> list[dict[str, Any]]:
    """Catalogue of every model the runner can select, with availability."""
    catalog: list[dict[str, Any]] = []
    for name, arch in ARCHETYPES.items():
        catalog.append(
            {
                "id": name,
                "display_name": f"{name} (simulated)",
                "provider": ProviderKind.MOCK.value,
                "provider_kind": ProviderKind.MOCK.value,
                "is_simulation": True,
                "available": True,
                "requires_api_key": False,
                "description": arch.description,
                "vulnerability": arch.vulnerability,
                "decoding_ability": arch.decoding_ability,
                "source": "builtin",
            }
        )
    catalog.append(
        {
            "id": "mock-json",
            "display_name": "mock-json (protocol echo, offline)",
            "provider": ProviderKind.MOCK.value,
            "provider_kind": ProviderKind.MOCK.value,
            "is_simulation": True,
            "available": True,
            "requires_api_key": False,
            "description": "Offline provider that emits well-formed action objects; used for protocol tests.",
            "source": "builtin",
        }
    )
    for provider, default_model, env_var in (
        (ProviderKind.OPENAI, os.getenv("TESTRANGE_OPENAI__MODEL", "gpt-4o-mini"), "OPENAI_API_KEY"),
        (ProviderKind.ANTHROPIC, os.getenv("TESTRANGE_ANTHROPIC__MODEL", "claude-3-5-haiku-20241022"), "ANTHROPIC_API_KEY"),
        (ProviderKind.OLLAMA, os.getenv("TESTRANGE_OLLAMA__MODEL", "llama3.1:8b"), "OLLAMA_BASE_URL"),
    ):
        catalog.append(
            {
                "id": default_model,
                "display_name": default_model,
                "provider": provider.value,
                "provider_kind": provider.value,
                "is_simulation": False,
                "available": bool(os.getenv(env_var)),
                "requires_api_key": provider is not ProviderKind.OLLAMA,
                "env_var": env_var,
                "description": f"{provider.value} provider. Selected via configs/default.yaml model.provider.",
                "source": "external",
            }
        )
    return catalog


def has_credentials(provider: ProviderKind) -> bool:
    env_var = API_KEY_ENV.get(provider)
    return bool(env_var and os.getenv(env_var))


def get_provider(
    provider: str | ProviderKind | None = None,
    model: str | None = None,
    settings: Settings | None = None,
    *,
    strict: bool = False,
) -> LLMProvider:
    """Build a provider instance.

    Returns the concrete provider object; callers inspect ``is_simulation`` to
    label results correctly.
    """
    settings = settings or get_settings()

    if settings.demo_mode:
        return MockLLMProvider(model or settings.model_name)

    try:
        kind = ProviderKind.coerce(provider or settings.provider)
    except ValueError as exc:
        if strict:
            raise ProviderUnavailableError(str(exc)) from exc
        return MockLLMProvider(model or settings.model_name)

    model_name = model or (
        MOCK_DEFAULT_NAME
        if kind is ProviderKind.MOCK
        else os.getenv(f"TESTRANGE_{kind.value.upper()}__MODEL", settings.model_name)
    )

    try:
        if kind is ProviderKind.MOCK:
            if model_name == "mock-json":
                return OpenAIJSONEchoProvider()
            return MockLLMProvider(model_name)
        if kind is ProviderKind.OPENAI:
            return OpenAIProvider(
                model_name,
                temperature=settings.temperature,
                max_tokens=settings.max_tokens,
                timeout=settings.timeout_seconds,
                max_retries=settings.max_retries,
                base_url=settings.get("model.base_url"),
            )
        if kind is ProviderKind.ANTHROPIC:
            return AnthropicProvider(
                model_name,
                temperature=settings.temperature,
                max_tokens=settings.max_tokens,
                timeout=settings.timeout_seconds,
                max_retries=settings.max_retries,
                base_url=settings.get("model.base_url"),
            )
        if kind is ProviderKind.OLLAMA:
            return OllamaProvider(
                model_name,
                base_url=settings.get("model.base_url"),
                temperature=settings.temperature,
                max_tokens=settings.max_tokens,
                timeout=settings.timeout_seconds,
                max_retries=settings.max_retries,
            )
    except ProviderUnavailableError:
        if strict:
            raise
        return MockLLMProvider(model or settings.model_name)

    if strict:  # pragma: no cover - enum is exhaustive
        raise ProviderUnavailableError(f"Unsupported provider: {kind}")
    return MockLLMProvider(model or settings.model_name)


MOCK_DEFAULT_NAME = "mock-vulnerable"


def provider_note(provider: LLMProvider) -> str:
    """Human readable provenance note stored with every experiment."""
    if getattr(provider, "is_simulation", False):
        return "SIMULATED / DEMO RESULT - produced by the deterministic mock provider, not a real language model."
    return f"LIVE MODEL RESULT - provider={provider.kind.value}, model={getattr(provider, 'model_name', '?')}"


__all__ = [
    "get_provider",
    "available_models",
    "has_credentials",
    "provider_note",
    "API_KEY_ENV",
    "MOCK_MODELS",
    "MOCK_MODEL_DESCRIPTIONS",
    "MockLLMProvider",
    "OpenAIProvider",
    "AnthropicProvider",
    "OllamaProvider",
    "OpenAIJSONEchoProvider",
]