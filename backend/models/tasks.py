"""Task corpus schema (Module 5).

A task is the *benign* objective the agent is asked to complete. It carries its
own ground truth, an explicit action policy and a reference plan, so the test
range always knows what "correct behaviour" means and can measure it.

The distinction that makes attack detection rigorous:

* **utility**  - did the agent do the task well?  (task criteria + plan)
* **attack success** - did the agent additionally perform an action that the
  task policy forbids, or produce an unsafe simulated side effect?
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from backend.models.enums import DeliveryChannel, Difficulty, PermissionLevel, StrEnum


class ActionPolicy(BaseModel):
    """One entry of the task's allow/deny list for simulated tool actions."""

    model_config = ConfigDict(extra="forbid")

    tool: str
    action: str
    permission: PermissionLevel = PermissionLevel.READ_ONLY
    reason: str = ""

    @property
    def key(self) -> str:
        return f"{self.tool}.{self.action}"


class CriterionKind(StrEnum):
    RESPONSE_CONTAINS = "response_contains"
    RESPONSE_NOT_CONTAINS = "response_not_contains"
    RESPONSE_REGEX = "response_regex"
    PLAN_STEP_DONE = "plan_step_done"
    NO_POLICY_VIOLATION = "no_policy_violation"
    GUARD_REJECTED = "guard_rejected"


class TaskCriterion(BaseModel):
    """A single machine-checkable condition contributing to task utility."""

    model_config = ConfigDict(extra="forbid")

    kind: CriterionKind
    value: str = ""
    weight: float = 1.0
    case_sensitive: bool = False
    tool: str | None = None
    action: str | None = None
    description: str = ""

    @field_validator("weight")
    @classmethod
    def _positive_weight(cls, v: float) -> float:
        if v <= 0:
            raise ValueError("criterion weight must be > 0")
        return v


class PlanStep(BaseModel):
    """A reference step: the canonical way to complete the task."""

    model_config = ConfigDict(extra="forbid")

    step: int
    tool: str
    action: str
    arguments: dict[str, Any] = Field(default_factory=dict)
    purpose: str = ""
    required: bool = True


class TaskDefinition(BaseModel):
    """A synthetic, harmless benchmark task."""

    model_config = ConfigDict(extra="forbid")

    task_id: str
    name: str
    description: str
    user_prompt: str
    expected_outcome: str
    allowed_tools: list[str] = Field(default_factory=list)
    allowed_actions: list[ActionPolicy] = Field(default_factory=list)
    forbidden_actions: list[ActionPolicy] = Field(default_factory=list)
    #: Ledger effect kinds the task legitimately authorises (usually empty).
    allowed_side_effects: list[str] = Field(default_factory=list)
    criteria: list[TaskCriterion] = Field(default_factory=list)
    reference_plan: list[PlanStep] = Field(default_factory=list)
    #: Where an injection may be delivered for this task (primary channel).
    channels: list[DeliveryChannel] = Field(default_factory=list)
    difficulty: Difficulty = Difficulty.EASY
    ground_truth: dict[str, Any] = Field(default_factory=dict)
    tags: list[str] = Field(default_factory=list)
    version: str = "1.0.0"

    # -- derived helpers ---------------------------------------------------
    def allowed_action_keys(self) -> set[str]:
        return {a.key for a in self.allowed_actions}

    def forbidden_action_keys(self) -> set[str]:
        return {a.key for a in self.forbidden_actions}

    def permission_for(self, tool: str, action: str) -> PermissionLevel:
        key = f"{tool}.{action}"
        for policy in self.forbidden_actions:
            if policy.key == key:
                return policy.permission
        for policy in self.allowed_actions:
            if policy.key == key:
                return policy.permission
        return PermissionLevel.READ_ONLY

    def is_tool_allowed(self, tool: str) -> bool:
        return tool in self.allowed_tools

    def tool_hint(self) -> str:
        return ", ".join(self.allowed_tools)

    def summary(self) -> dict[str, Any]:
        return {
            "task_id": self.task_id,
            "name": self.name,
            "description": self.description,
            "allowed_tools": self.allowed_tools,
            "forbidden_actions": sorted(self.forbidden_action_keys()),
            "difficulty": self.difficulty.value,
            "channels": [c.value for c in self.channels],
            "expected_outcome": self.expected_outcome,
            "tags": self.tags,
        }


class TaskCorpus(BaseModel):
    model_config = ConfigDict(extra="forbid")

    corpus_version: str = "1.0.0"
    description: str = ""
    generated_by: str = "IPI Test Range project"
    tasks: list[TaskDefinition]

    def __len__(self) -> int:  # pragma: no cover - trivial
        return len(self.tasks)

    def __iter__(self):  # pragma: no cover - trivial
        return iter(self.tasks)


CriterionLiteral = Literal["response_contains", "response_regex", "plan_step_done"]


__all__ = [
    "ActionPolicy",
    "CriterionKind",
    "TaskCriterion",
    "PlanStep",
    "TaskDefinition",
    "TaskCorpus",
]