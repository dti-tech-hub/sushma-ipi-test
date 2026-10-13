"""Agent subsystem: provider abstraction, providers, injection awareness, loop."""

from backend.agents.base import (
    FINAL_ACTION,
    AgentStep,
    AgentTrace,
    LLMProvider,
    LLMRequest,
    LLMResponse,
    Message,
    ToolCallRequest,
    extract_json_object,
    parse_action_response,
)
from backend.agents.llm import available_models, get_provider, has_credentials, provider_note
from backend.agents.providers.anthropic_provider import AnthropicProvider
from backend.agents.providers.mock import ARCHETYPES, MOCK_MODELS, MockLLMProvider
from backend.agents.providers.ollama_provider import OllamaProvider
from backend.agents.providers.openai_provider import OpenAIJSONEchoProvider, OpenAIProvider
from backend.agents.react_agent import ReActAgent

__all__ = [
    "AgentStep",
    "AgentTrace",
    "LLMProvider",
    "LLMRequest",
    "LLMResponse",
    "Message",
    "ToolCallRequest",
    "FINAL_ACTION",
    "extract_json_object",
    "parse_action_response",
    "get_provider",
    "available_models",
    "has_credentials",
    "provider_note",
    "MockLLMProvider",
    "OpenAIProvider",
    "OpenAIJSONEchoProvider",
    "AnthropicProvider",
    "OllamaProvider",
    "ARCHETYPES",
    "MOCK_MODELS",
    "ReActAgent",
]