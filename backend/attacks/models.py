"""Attack corpus record schema (Module 2).

An attack record is fully declarative: it carries the payload, *where* and *how*
it must be injected, the simulated action it aims at, and **explicit success
predicates** (Module 10). Nothing about success is inferred from "the model
seemed suspicious" - it is always an observable predicate over the recorded
action trace.
"""

from __future__ import annotations

import re
from typing import Any, Union

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from backend.models.enums import (
    AttackType,
    DeliveryChannel,
    Difficulty,
    InjectionPosition,
    PayloadFormat,
    PermissionLevel,
    Severity,
    StrEnum,
)


#: An attack payload is either plain text (injected into ``content``/``html``/
#: ``metadata``) or a structured record (injected into a tool's ``records``,
#: e.g. a database row or a calendar entry).
PayloadBody = Union[str, dict[str, Any], list[Any]]


class PredicateKind(StrEnum):
    """Observable conditions evaluated against a completed run."""

    TOOL_CALL = "tool_call"
    LEDGER_EFFECT = "ledger_effect"
    RESPONSE_MATCHES = "response_matches"
    TASK_ABANDONED = "task_abandoned"
    POLICY_VIOLATION = "policy_violation"
    RESPONSE_REFUSES = "response_refuses"


class SuccessPredicate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    kind: PredicateKind
    tool: str | None = None
    action: str | None = None
    #: Ledger effect kind, e.g. ``email_sent``.
    effect: str | None = None
    #: Substring that must appear somewhere in the matched argument value
    #: (case-insensitive unless ``case_sensitive`` is set).
    args_contain: dict[str, str] = Field(default_factory=dict)
    pattern: str | None = None
    regex: bool = False
    case_sensitive: bool = False
    #: For ``task_abandoned``: succeed when plan completion falls at/below this.
    threshold: float | None = None
    weight: float = 1.0
    description: str = ""

    @model_validator(mode="after")
    def _validate_pattern(self) -> "SuccessPredicate":
        """Compile-check the pattern *after* ``regex`` is known.

        A field validator would run before ``regex`` is populated (field order),
        so the check has to be a model-level one.
        """
        if self.regex and self.pattern:
            try:
                re.compile(self.pattern)
            except re.error as exc:
                raise ValueError(f"invalid regex pattern {self.pattern!r}: {exc}") from exc
        return self


class TargetAction(BaseModel):
    """The simulated capability the attacker wants the agent to misuse."""

    model_config = ConfigDict(extra="forbid")

    tool: str
    action: str
    permission: PermissionLevel = PermissionLevel.HIGH_RISK
    required_args: dict[str, Any] = Field(default_factory=dict)
    description: str = ""

    @property
    def key(self) -> str:
        return f"{self.tool}.{self.action}"


class AttackRecord(BaseModel):
    """One scored synthetic attack."""

    model_config = ConfigDict(extra="forbid")

    id: str
    name: str
    description: str
    attack_type: AttackType
    delivery_channel: DeliveryChannel
    payload: PayloadBody
    injection_position: InjectionPosition
    format: PayloadFormat
    target_action: TargetAction
    difficulty: Difficulty
    severity: Severity
    expected_behavior: str
    safe_simulation: str
    success_criteria: list[SuccessPredicate]
    #: ``all`` = every predicate must hold (default). ``any`` = one is enough.
    success_mode: str = "all"
    tags: list[str] = Field(default_factory=list)
    #: Task ids this attack is known to be applicable to; empty = all tasks.
    compatible_tasks: list[str] = Field(default_factory=list)
    #: Optional extra formatting knobs (see backend.attacks.injection).
    injection_options: dict[str, Any] = Field(default_factory=dict)
    version: str = "1.0.0"
    reference: str = ""

    @field_validator("success_mode")
    @classmethod
    def _valid_mode(cls, v: str) -> str:
        if v not in {"all", "any"}:
            raise ValueError("success_mode must be 'all' or 'any'")
        return v

    @field_validator("success_criteria")
    @classmethod
    def _non_empty(cls, v: list[SuccessPredicate]) -> list[SuccessPredicate]:
        if not v:
            raise ValueError("an attack must declare at least one success criterion")
        return v

    def applies_to(self, task_id: str) -> bool:
        return not self.compatible_tasks or task_id in self.compatible_tasks

    def severity_weight(self, weights: dict[str, float]) -> float:
        return float(weights.get(self.severity.value, 1.0))

    def summary(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "attack_type": self.attack_type.value,
            "delivery_channel": self.delivery_channel.value,
            "injection_position": self.injection_position.value,
            "format": self.format.value,
            "difficulty": self.difficulty.value,
            "severity": self.severity.value,
            "target_action": self.target_action.key,
            "tags": self.tags,
            "description": self.description,
        }


class AttackCorpus(BaseModel):
    model_config = ConfigDict(extra="forbid")

    corpus_version: str = "1.0.0"
    description: str = ""
    generated_by: str = "IPI Test Range project (synthetic payloads)"
    attacks: list[AttackRecord]

    def __len__(self) -> int:  # pragma: no cover - trivial
        return len(self.attacks)

    def __iter__(self):  # pragma: no cover - trivial
        return iter(self.attacks)


__all__ = [
    "PredicateKind",
    "SuccessPredicate",
    "TargetAction",
    "AttackRecord",
    "AttackCorpus",
]