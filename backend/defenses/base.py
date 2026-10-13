"""Defense framework (Modules 11, 12, 13).

Every defense is an independent class implementing :class:`Defense`. They are
*not* aliases of one another - each has a genuinely different mechanism:

===========================  =============================================
Defense                       Mechanism
===========================  =============================================
``none``                      No-op baseline (control condition).
``sanitization``              Content rewriting: strips/redacts injection
                              patterns and dangerous encodings before the
                              model ever sees the tool output.
``spotlighting``              Data marking: wraps untrusted content in a
                              per-run datamark token plus a system-prompt
                              clause describing the token's semantics.
``sandwich_prompting``        Task sandwich: trusted reminder -> data ->
                              trusted reminder, immediately around every
                              tool output.
``privilege_separation``      Capability gate: a task policy authorises
                              actions; authority claimed by tool content can
                              never authorise a state-changing action.
``guard_classifier``          Pre-model screening: an explainable classifier
                              redacts flagged content before inference.
===========================  =============================================
"""

from __future__ import annotations

import hashlib
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, ClassVar

from backend.models.enums import (
    AuthorizationDecision,
    AuthorizationSource,
    PermissionLevel,
)
from backend.tools.base import AuthorizationOutcome, AuthorizationRequest, ToolResult


# ---------------------------------------------------------------------------
# Context / outcome plumbing
# ---------------------------------------------------------------------------


@dataclass
class DefenseContext:
    """Everything a defense is allowed to know about the current run."""

    task: Any = None                       # TaskDefinition | None
    attack: Any = None                     # AttackRecord | None
    defense_name: str = "none"
    seed: int = 0
    run_condition: str = "baseline"
    step: int = 0
    config: dict[str, Any] = field(default_factory=dict)


@dataclass
class DefenseOutcome:
    """What a defense did to one tool result."""

    defense: str
    result: ToolResult
    modified: bool = False
    blocked: bool = False
    redacted_spans: int = 0
    notes: list[str] = field(default_factory=list)
    verdict: str | None = None
    confidence: float | None = None
    indicators: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "defense": self.defense,
            "modified": self.modified,
            "blocked": self.blocked,
            "redacted_spans": self.redacted_spans,
            "notes": self.notes,
            "verdict": self.verdict,
            "confidence": self.confidence,
            "indicators": self.indicators,
        }


class Defense(ABC):
    """Base class for every defense."""

    name: ClassVar[str] = "base"
    description: ClassVar[str] = ""
    mechanism: ClassVar[str] = ""
    version: ClassVar[str] = "1.0.0"
    #: Whether the defense rewrites the tool payload.
    rewrites_content: ClassVar[bool] = False
    #: Whether the defense gates sensitive actions.
    gates_actions: ClassVar[bool] = False

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        self.config = dict(config or {})

    # -- content path -----------------------------------------------------
    def on_tool_result(self, result: ToolResult, ctx: DefenseContext) -> DefenseOutcome:
        """Transform untrusted content before it reaches the model."""
        return DefenseOutcome(defense=self.name, result=result)

    # -- prompt path ------------------------------------------------------
    def on_prompt(self, prompt: str, ctx: DefenseContext) -> str:
        """Optionally modify the system prompt (data-marking defenses use this)."""
        return prompt

    # -- authorisation path ----------------------------------------------
    def on_authorization(
        self,
        request: AuthorizationRequest,
        permission: PermissionLevel,
        ctx: DefenseContext,
    ) -> AuthorizationOutcome | None:
        """Return an outcome to override the default grant/deny decision."""
        return None

    # -- introspection ----------------------------------------------------
    def info(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "mechanism": self.mechanism,
            "version": self.version,
            "rewrites_content": self.rewrites_content,
            "gates_actions": self.gates_actions,
            "config": self.config,
        }


def datamark_token(seed: int, salt: str) -> str:
    """Deterministic per-run datamark used by spotlighting."""
    digest = hashlib.blake2b(f"{seed}:{salt}".encode("utf-8"), digest_size=4).hexdigest()
    return f"UD-{digest.upper()}"


def normalise_for_matching(text: str) -> str:
    """Strip invisible characters and collapse whitespace runs."""
    text = re.sub(r"[\u200b\u200c\u200d\u2060\ufeff]", "", text)
    text = text.replace("\u00a0", " ")
    return re.sub(r"[ \t]{2,}", " ", text)


__all__ = [
    "Defense",
    "DefenseContext",
    "DefenseOutcome",
    "datamark_token",
    "normalise_for_matching",
    "AuthorizationDecision",
    "AuthorizationSource",
]