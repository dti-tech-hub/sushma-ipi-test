"""Pydantic request/response models for the HTTP API (Module 14)."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from backend.models.enums import AttackType, DeliveryChannel, Difficulty, Severity


class HealthResponse(BaseModel):
    status: str
    version: str
    lab: str
    demo_mode: bool
    database: str
    database_ready: bool
    attacks: int
    tasks: int
    defenses: int
    models: list[str]
    result_provenance: str


class AttackSummary(BaseModel):
    model_config = ConfigDict(extra="allow")

    id: str
    name: str
    attack_type: str
    delivery_channel: str
    injection_position: str
    format: str
    difficulty: str
    severity: str
    target_action: str
    description: str = ""


class AttackDetail(AttackSummary):
    payload_preview: str = ""
    expected_behavior: str
    safe_simulation: str
    success_criteria: list[dict[str, Any]]
    tags: list[str]
    compatible_tasks: list[str]


class TaskSummary(BaseModel):
    model_config = ConfigDict(extra="allow")

    task_id: str
    name: str
    description: str
    allowed_tools: list[str]
    forbidden_actions: list[str]
    difficulty: str
    channels: list[str]
    expected_outcome: str


class TaskDetail(TaskSummary):
    user_prompt: str
    criteria: list[dict[str, Any]]
    reference_plan: list[dict[str, Any]]
    ground_truth: dict[str, Any]
    tags: list[str]


class ModelInfo(BaseModel):
    id: str
    display_name: str
    provider: str
    is_simulation: bool
    available: bool
    requires_api_key: bool
    description: str
    vulnerability: float | None = None
    decoding_ability: float | None = None
    env_var: str | None = None


class DefenseInfo(BaseModel):
    name: str
    description: str
    mechanism: str
    version: str
    rewrites_content: bool
    gates_actions: bool


class InjectionPreviewRequest(BaseModel):
    attack_id: str
    tool: str | None = None
    action: str | None = None
    arguments: dict[str, Any] = Field(default_factory=dict)
    seed: int = 0


class InjectionPreviewResponse(BaseModel):
    attack_id: str
    tool: str
    action: str
    injection_position: str
    payload_format: str
    target_field: str
    encoded: bool
    clean_digest: str
    injected_digest: str
    clean_preview: str
    injected_preview: str


class GuardRequest(BaseModel):
    text: str = Field(min_length=1, max_length=20000)


class GuardResponse(BaseModel):
    verdict: str
    confidence: float
    reason: str
    indicators: list[str]
    families: dict[str, float]
    decoded_layers: list[str]
    text_length: int
    detector: str


class RunExperimentRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    task_ids: list[str] | None = None
    attack_ids: list[str] | None = None
    attack_types: list[str] | None = None
    severities: list[str] | None = None
    difficulties: list[str] | None = None
    delivery_channels: list[str] | None = None
    tags: list[str] | None = None
    provider: str | None = None
    model: str | None = None
    defense: str = "none"
    repetitions: int = Field(default=3, ge=1, le=50)
    random_seed: int | None = Field(default=None, ge=0)
    max_steps: int | None = Field(default=None, ge=1, le=64)
    include_baseline: bool = True
    persist: bool = True
    name: str = ""

    @field_validator("attack_types")
    @classmethod
    def _valid_types(cls, v: list[str] | None) -> list[str] | None:
        if v is None:
            return v
        for item in v:
            AttackType.coerce(item)
        return v

    @field_validator("severities")
    @classmethod
    def _valid_sev(cls, v: list[str] | None) -> list[str] | None:
        for item in v or []:
            Severity.coerce(item)
        return v

    @field_validator("difficulties")
    @classmethod
    def _valid_diff(cls, v: list[str] | None) -> list[str] | None:
        for item in v or []:
            Difficulty.coerce(item)
        return v

    @field_validator("delivery_channels")
    @classmethod
    def _valid_channels(cls, v: list[str] | None) -> list[str] | None:
        for item in v or []:
            DeliveryChannel.coerce(item)
        return v


class RunBatchRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    models: list[dict[str, str]] = Field(default_factory=list)
    defenses: list[str] = Field(default_factory=lambda: ["none"])
    task_ids: list[str] | None = None
    attack_ids: list[str] | None = None
    attack_types: list[str] | None = None
    severities: list[str] | None = None
    difficulties: list[str] | None = None
    delivery_channels: list[str] | None = None
    tags: list[str] | None = None
    repetitions: int = Field(default=3, ge=1, le=50)
    random_seed: int | None = None
    max_steps: int | None = None
    include_baseline: bool = True
    persist: bool = True


class ExperimentSummary(BaseModel):
    experiment_uid: str
    name: str
    provider: str
    model: str
    defense: str
    is_simulation: bool
    provenance_note: str
    status: str
    repetitions: int
    random_seed: int
    n_runs: int
    started_at: str | None = None
    duration_ms: float = 0.0
    asr: float | None = None
    benign_utility: float | None = None
    utility_under_attack: float | None = None
    detection_rate: float | None = None
    swrs: float | None = None


class ExperimentRunResponse(BaseModel):
    model_config = ConfigDict(extra="allow")

    run_uid: str
    condition: str
    task_id: str
    attack_id: str | None = None
    model: str
    defense: str
    attack_succeeded: bool
    attack_detected: bool
    policy_violation: bool
    harmful_effect: bool
    task_utility: float
    plan_completion: float


class ErrorResponse(BaseModel):
    error: str
    code: str
    message: str
    details: dict[str, Any] = Field(default_factory=dict)


__all__ = [
    "HealthResponse",
    "AttackSummary",
    "AttackDetail",
    "TaskSummary",
    "TaskDetail",
    "ModelInfo",
    "DefenseInfo",
    "InjectionPreviewRequest",
    "InjectionPreviewResponse",
    "GuardRequest",
    "GuardResponse",
    "RunExperimentRequest",
    "RunBatchRequest",
    "ExperimentSummary",
    "ExperimentRunResponse",
    "ErrorResponse",
]