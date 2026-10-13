"""Agent-side abstractions: provider interface, message model and traces.

The agent is provider agnostic. Everything a provider needs is in
:class:`LLMRequest`; everything it must return is in :class:`LLMResponse`.
This is what lets the same experiment run against the deterministic mock brain,
Ollama, or an OpenAI/Anthropic-compatible endpoint.

Action protocol
---------------
Providers are asked to emit a single JSON object per step::

    {"thought": "...", "action": "email.read_message", "arguments": {...}}
    {"thought": "...", "final": "the answer"}

``action == "FINAL"`` (or the presence of ``final``) ends the episode. The
parser is tolerant of markdown fences and leading prose, and every parse
failure is surfaced as :class:`MalformedLLMResponseError` rather than silently
ignored.
"""

from __future__ import annotations

import json
import re
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

from backend.models.enums import AuthorizationDecision, PermissionLevel, ProviderKind
from backend.models.errors import MalformedLLMResponseError
from backend.tools.base import AuthorizationOutcome, LedgerEntry, ToolCallRecord, ToolResult

FINAL_ACTION = "FINAL"


# ---------------------------------------------------------------------------
# Messages
# ---------------------------------------------------------------------------


@dataclass
class Message:
    """One turn in the conversation.

    ``channel`` records the *trust domain* the turn came from, which is what
    lets the agent (and the evaluator) reason about which content was untrusted.
    """

    role: str          # system | human | ai | tool
    content: str
    channel: str = "trusted"   # trusted | untrusted
    name: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "role": self.role,
            "content": self.content,
            "channel": self.channel,
            "name": self.name,
            "metadata": self.metadata,
        }


def message_to_langchain(msg: Message):  # pragma: no cover - thin adapter
    """Convert to a LangChain message (keeps the agent LangChain-compatible)."""
    from langchain_core.messages import AIMessage, HumanMessage, SystemMessage

    if msg.role == "system":
        return SystemMessage(content=msg.content)
    if msg.role in {"human", "user"}:
        return HumanMessage(content=msg.content)
    return AIMessage(content=msg.content)


# ---------------------------------------------------------------------------
# Provider interface
# ---------------------------------------------------------------------------


@dataclass
class LLMRequest:
    """A single completion request."""

    system_prompt: str
    messages: list[Message]
    step: int = 0
    seed: int = 0
    temperature: float = 0.0
    max_tokens: int = 1024
    action_catalog: str = ""
    context: dict[str, Any] = field(default_factory=dict)

    def transcript(self) -> list[dict[str, str]]:
        return [{"role": m.role, "content": m.content} for m in self.messages]


@dataclass
class ToolCallRequest:
    """A tool invocation requested by the model."""

    action: str
    arguments: dict[str, Any] = field(default_factory=dict)
    tool: str = ""

    def split(self) -> tuple[str, str]:
        if self.tool and "." in self.action:
            return self.action.split(".", 1)
        if "." in self.action:
            tool, action = self.action.split(".", 1)
            return tool, action
        return self.tool, self.action


@dataclass
class LLMResponse:
    """What a provider returns for one step."""

    text: str = ""
    tool_call: ToolCallRequest | None = None
    final_answer: str | None = None
    thought: str = ""
    finish_reason: str = "stop"
    model: str = ""
    provider: str = ""
    latency_ms: float = 0.0
    raw: dict[str, Any] = field(default_factory=dict)
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "text": self.text,
            "tool_call": (
                {"tool": self.tool_call.tool, "action": self.tool_call.action, "arguments": self.tool_call.arguments}
                if self.tool_call
                else None
            ),
            "final_answer": self.final_answer,
            "thought": self.thought,
            "finish_reason": self.finish_reason,
            "model": self.model,
            "provider": self.provider,
            "latency_ms": round(self.latency_ms, 3),
            "error": self.error,
        }


class LLMProvider(ABC):
    """Base class for every LLM backend."""

    kind: ProviderKind = ProviderKind.MOCK
    default_model: str = "unknown"
    is_simulation: bool = False

    @abstractmethod
    def complete(self, request: LLMRequest) -> LLMResponse:
        """Produce one decision."""

    def health(self) -> dict[str, Any]:
        return {
            "provider": self.kind.value,
            "model": self.default_model,
            "is_simulation": self.is_simulation,
            "available": True,
        }


# ---------------------------------------------------------------------------
# Tolerant JSON action parser
# ---------------------------------------------------------------------------

_FENCE_RE = re.compile(r"```(?:json)?\s*(.*?)```", re.DOTALL)


def extract_json_object(text: str) -> dict[str, Any]:
    """Pull the first JSON object out of a model reply."""
    if not text or not text.strip():
        raise MalformedLLMResponseError("Provider returned an empty response.")

    candidates: list[str] = []
    fenced = _FENCE_RE.search(text)
    if fenced:
        candidates.append(fenced.group(1))
    candidates.append(text)

    for candidate in candidates:
        candidate = candidate.strip()
        start = candidate.find("{")
        if start == -1:
            continue
        depth = 0
        in_string = False
        escape = False
        for index in range(start, len(candidate)):
            char = candidate[index]
            if in_string:
                if escape:
                    escape = False
                elif char == "\\":
                    escape = True
                elif char == '"':
                    in_string = False
                continue
            if char == '"':
                in_string = True
            elif char == "{":
                depth += 1
            elif char == "}":
                depth -= 1
                if depth == 0:
                    blob = candidate[start : index + 1]
                    try:
                        parsed = json.loads(blob)
                    except json.JSONDecodeError:
                        try:
                            parsed = json.loads(blob.replace("\n", "\\n"))
                        except json.JSONDecodeError:
                            continue
                    if isinstance(parsed, dict):
                        return parsed
    raise MalformedLLMResponseError(
        "Provider response did not contain a parseable JSON action object.",
        details={"excerpt": text[:400]},
    )


def parse_action_response(text: str) -> ToolCallRequest | None | str:
    """Return a :class:`ToolCallRequest`, a final-answer ``str``, or raise."""
    payload = extract_json_object(text)
    if "final" in payload and payload.get("action") in (None, FINAL_ACTION):
        answer = payload.get("final")
        if answer is None:
            raise MalformedLLMResponseError("Final response is missing the 'final' field.")
        return str(answer)
    action = payload.get("action")
    if not action:
        raise MalformedLLMResponseError(
            "Action response is missing the 'action' field.",
            details={"keys": sorted(payload)},
        )
    if str(action).upper() == FINAL_ACTION:
        final = payload.get("final") or payload.get("arguments", {}).get("answer") or ""
        return str(final)
    arguments = payload.get("arguments") or {}
    if not isinstance(arguments, dict):
        raise MalformedLLMResponseError("'arguments' must be a JSON object.")
    return ToolCallRequest(action=str(action), arguments=arguments, tool=str(payload.get("tool") or ""))


# ---------------------------------------------------------------------------
# Traces
# ---------------------------------------------------------------------------


@dataclass
class AgentStep:
    """One reasoning step."""

    step: int
    thought: str
    action: str
    arguments: dict[str, Any]
    raw_response: str
    accepted: bool
    rejection_reason: str = ""
    latency_ms: float = 0.0
    ts: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "step": self.step,
            "thought": self.thought,
            "action": self.action,
            "arguments": self.arguments,
            "raw_response": self.raw_response,
            "accepted": self.accepted,
            "rejection_reason": self.rejection_reason,
            "latency_ms": round(self.latency_ms, 3),
            "ts": self.ts,
        }


@dataclass
class AgentTrace:
    """Complete, replayable record of one agent episode."""

    run_id: str
    task_id: str
    model: str
    provider: str
    defense: str
    condition: str
    attack_id: str | None = None
    steps: list[AgentStep] = field(default_factory=list)
    tool_calls: list[ToolCallRecord] = field(default_factory=list)
    responses: list[dict[str, Any]] = field(default_factory=list)
    messages: list[Message] = field(default_factory=list)
    authorizations: list[AuthorizationOutcome] = field(default_factory=list)
    ledger_entries: list[LedgerEntry] = field(default_factory=list)
    final_answer: str = ""
    finished_reason: str = "final_answer"
    error: str | None = None
    hijacked: bool = False
    hijack_source: str | None = None
    detected_injection: bool = False
    detected_excerpt: str = ""
    total_latency_ms: float = 0.0
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def tool_call_keys(self) -> list[str]:
        return [f"{c.tool}.{c.action}" for c in self.tool_calls]

    def granted_calls(self) -> list[ToolCallRecord]:
        return [
            c for c in self.tool_calls
            if c.status == "ok" and c.authorization is AuthorizationDecision.GRANTED
        ]

    def denied_calls(self) -> list[ToolCallRecord]:
        return [
            c for c in self.tool_calls
            if c.authorization is AuthorizationDecision.DENIED or c.status == "denied"
        ]

    def completed_actions(self) -> list[str]:
        return [f"{c.tool}.{c.action}" for c in self.granted_calls()]

    def to_dict(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "task_id": self.task_id,
            "attack_id": self.attack_id,
            "model": self.model,
            "provider": self.provider,
            "defense": self.defense,
            "condition": self.condition,
            "steps": [s.to_dict() for s in self.steps],
            "tool_calls": [c.to_dict() for c in self.tool_calls],
            "responses": self.responses,
            "messages": [m.to_dict() for m in self.messages],
            "authorizations": [a.to_dict() for a in self.authorizations],
            "ledger_entries": [e.to_dict() for e in self.ledger_entries],
            "final_answer": self.final_answer,
            "finished_reason": self.finished_reason,
            "error": self.error,
            "hijacked": self.hijacked,
            "hijack_source": self.hijack_source,
            "detected_injection": self.detected_injection,
            "detected_excerpt": self.detected_excerpt,
            "total_latency_ms": round(self.total_latency_ms, 3),
            "metadata": self.metadata,
        }


class Timer:
    """Small helper so providers report latency consistently."""

    def __enter__(self) -> "Timer":
        self._start = time.perf_counter()
        return self

    def __exit__(self, *exc: Any) -> None:
        self.ms = (time.perf_counter() - self._start) * 1000.0

    def __init__(self) -> None:
        self.ms = 0.0


__all__ = [
    "Message",
    "LLMRequest",
    "LLMResponse",
    "ToolCallRequest",
    "LLMProvider",
    "AgentStep",
    "AgentTrace",
    "AuthorizationOutcome",
    "AuthorizationDecision",
    "PermissionLevel",
    "ToolResult",
    "ToolCallRecord",
    "FINAL_ACTION",
    "extract_json_object",
    "parse_action_response",
    "message_to_langchain",
    "Timer",
]