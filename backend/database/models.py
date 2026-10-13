"""SQLAlchemy ORM models for the SQLite experiment store (Module 8).

Design notes
------------
* **SQLite only.** No server, no external dependency beyond the ``sqlite3``
  driver that ships with Python.
* **Normalised reference data.** ``models``, ``defenses``, ``tasks`` and
  ``attacks`` are cached by content hash; experiments reference them by id.
* **Full traceability.** Every run keeps its tool calls, model responses,
  authorisation events, sandbox ledger effects and computed metrics, so any
  number in the dashboard can be traced back to the raw trace.
* **No secrets.** Nothing here ever receives an API key.

Tables: models, defenses, tasks, attacks, experiment_configs, experiments,
attack_runs, tool_calls, agent_responses, authorization_events, sandbox_effects,
metrics.
"""

from __future__ import annotations

import datetime as dt
from typing import Any

from sqlalchemy import (
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    JSON,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def utcnow() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


class Base(DeclarativeBase):
    type_annotation_map = {dict[str, Any]: JSON, list[Any]: JSON}


# ---------------------------------------------------------------------------
# Reference data
# ---------------------------------------------------------------------------


class ModelRecord(Base):
    """An LLM the range can be pointed at."""

    __tablename__ = "models"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    model_id: Mapped[str] = mapped_column(String(160), unique=True, index=True)
    display_name: Mapped[str] = mapped_column(String(200), default="")
    provider: Mapped[str] = mapped_column(String(40), index=True)
    is_simulation: Mapped[bool] = mapped_column(Boolean, default=True)
    requires_api_key: Mapped[bool] = mapped_column(Boolean, default=False)
    available: Mapped[bool] = mapped_column(Boolean, default=True)
    description: Mapped[str] = mapped_column(Text, default="")
    attributes: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime, default=utcnow)

    runs: Mapped[list["AttackRun"]] = relationship(back_populates="model")


class DefenseRecord(Base):
    """A registered defense mechanism."""

    __tablename__ = "defenses"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(80), unique=True, index=True)
    description: Mapped[str] = mapped_column(Text, default="")
    mechanism: Mapped[str] = mapped_column(String(120), default="")
    version: Mapped[str] = mapped_column(String(20), default="1.0.0")
    rewrites_content: Mapped[bool] = mapped_column(Boolean, default=False)
    gates_actions: Mapped[bool] = mapped_column(Boolean, default=False)
    config: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime, default=utcnow)

    runs: Mapped[list["AttackRun"]] = relationship(back_populates="defense")


class TaskRecord(Base):
    """A synthetic benchmark task."""

    __tablename__ = "tasks"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    task_id: Mapped[str] = mapped_column(String(40), unique=True, index=True)
    name: Mapped[str] = mapped_column(String(200), default="")
    description: Mapped[str] = mapped_column(Text, default="")
    allowed_tools: Mapped[list[Any]] = mapped_column(JSON, default=list)
    forbidden_actions: Mapped[list[Any]] = mapped_column(JSON, default=list)
    difficulty: Mapped[str] = mapped_column(String(20), default="easy")
    channels: Mapped[list[Any]] = mapped_column(JSON, default=list)
    expected_outcome: Mapped[str] = mapped_column(Text, default="")
    payload: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime, default=utcnow)


class AttackRecordRow(Base):
    """A scored synthetic attack from the corpus."""

    __tablename__ = "attacks"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    attack_id: Mapped[str] = mapped_column(String(40), unique=True, index=True)
    name: Mapped[str] = mapped_column(String(200), default="")
    description: Mapped[str] = mapped_column(Text, default="")
    attack_type: Mapped[str] = mapped_column(String(40), index=True)
    delivery_channel: Mapped[str] = mapped_column(String(40), index=True)
    injection_position: Mapped[str] = mapped_column(String(40), index=True)
    payload_format: Mapped[str] = mapped_column(String(40), index=True)
    difficulty: Mapped[str] = mapped_column(String(20), index=True)
    severity: Mapped[str] = mapped_column(String(20), index=True)
    target_action: Mapped[str] = mapped_column(String(120), index=True)
    target_permission: Mapped[str] = mapped_column(String(30), default="high_risk")
    expected_behavior: Mapped[str] = mapped_column(Text, default="")
    safe_simulation: Mapped[str] = mapped_column(Text, default="")
    success_mode: Mapped[str] = mapped_column(String(10), default="all")
    success_criteria: Mapped[list[Any]] = mapped_column(JSON, default=list)
    tags: Mapped[list[Any]] = mapped_column(JSON, default=list)
    corpus_version: Mapped[str] = mapped_column(String(20), default="1.0.0")
    payload_sha: Mapped[str] = mapped_column(String(80), default="")
    payload: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime, default=utcnow)


# ---------------------------------------------------------------------------
# Experiments
# ---------------------------------------------------------------------------


class ExperimentConfig(Base):
    """A named, reusable experiment configuration."""

    __tablename__ = "experiment_configs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(160), unique=True, index=True)
    description: Mapped[str] = mapped_column(Text, default="")
    provider: Mapped[str] = mapped_column(String(40), default="mock")
    model: Mapped[str] = mapped_column(String(160), default="")
    defense: Mapped[str] = mapped_column(String(80), default="none")
    repetitions: Mapped[int] = mapped_column(Integer, default=3)
    random_seed: Mapped[int] = mapped_column(Integer, default=1337)
    temperature: Mapped[float] = mapped_column(Float, default=0.0)
    max_steps: Mapped[int] = mapped_column(Integer, default=10)
    selection: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    settings: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime, default=utcnow)

    experiments: Mapped[list["Experiment"]] = relationship(back_populates="config")


class Experiment(Base):
    """One executed experiment: a config applied to a task/attack matrix."""

    __tablename__ = "experiments"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    experiment_uid: Mapped[str] = mapped_column(String(40), unique=True, index=True)
    config_id: Mapped[int | None] = mapped_column(ForeignKey("experiment_configs.id"), nullable=True)
    name: Mapped[str] = mapped_column(String(200), default="")
    provider: Mapped[str] = mapped_column(String(40), index=True)
    model: Mapped[str] = mapped_column(String(160), index=True)
    model_version: Mapped[str] = mapped_column(String(120), default="")
    is_simulation: Mapped[bool] = mapped_column(Boolean, default=True)
    provenance_note: Mapped[str] = mapped_column(Text, default="")
    defense: Mapped[str] = mapped_column(String(80), index=True)
    random_seed: Mapped[int] = mapped_column(Integer, default=1337)
    repetitions: Mapped[int] = mapped_column(Integer, default=1)
    task_ids: Mapped[list[Any]] = mapped_column(JSON, default=list)
    attack_ids: Mapped[list[Any]] = mapped_column(JSON, default=list)
    corpus_versions: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    configuration: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    status: Mapped[str] = mapped_column(String(30), default="completed", index=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    duration_ms: Mapped[float] = mapped_column(Float, default=0.0)
    started_at: Mapped[dt.datetime] = mapped_column(DateTime, default=utcnow, index=True)
    finished_at: Mapped[dt.datetime | None] = mapped_column(DateTime, nullable=True)

    config: Mapped[ExperimentConfig | None] = relationship(back_populates="experiments")
    runs: Mapped[list["AttackRun"]] = relationship(
        back_populates="experiment", cascade="all, delete-orphan"
    )
    metrics: Mapped[list["MetricRecord"]] = relationship(
        back_populates="experiment", cascade="all, delete-orphan"
    )


class AttackRun(Base):
    """One agent execution (clean baseline or attacked)."""

    __tablename__ = "attack_runs"
    __table_args__ = (
        Index("ix_runs_experiment_condition", "experiment_id", "condition"),
        UniqueConstraint("experiment_id", "run_uid", name="uq_run_per_experiment"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    run_uid: Mapped[str] = mapped_column(String(40), unique=True, index=True)
    experiment_id: Mapped[int] = mapped_column(ForeignKey("experiments.id"), index=True)
    condition: Mapped[str] = mapped_column(String(20), index=True)
    repetition: Mapped[int] = mapped_column(Integer, default=0)
    seed: Mapped[int] = mapped_column(Integer, default=0)

    task_id: Mapped[str] = mapped_column(String(40), index=True)
    attack_id: Mapped[str | None] = mapped_column(String(40), nullable=True, index=True)

    model_id: Mapped[int | None] = mapped_column(ForeignKey("models.id"), nullable=True)
    defense_id: Mapped[int | None] = mapped_column(ForeignKey("defenses.id"), nullable=True)

    status: Mapped[str] = mapped_column(String(30), default="completed")
    finished_reason: Mapped[str] = mapped_column(String(40), default="")
    error: Mapped[str | None] = mapped_column(Text, nullable=True)

    attack_succeeded: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    attack_detected: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    detection_reason: Mapped[str] = mapped_column(Text, default="")
    policy_violation: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    harmful_effect: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    hijacked: Mapped[bool] = mapped_column(Boolean, default=False)

    task_utility: Mapped[float] = mapped_column(Float, default=0.0)
    plan_completion: Mapped[float] = mapped_column(Float, default=0.0)
    final_answer: Mapped[str] = mapped_column(Text, default="")
    steps_used: Mapped[int] = mapped_column(Integer, default=0)
    latency_ms: Mapped[float] = mapped_column(Float, default=0.0)

    evaluation: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    started_at: Mapped[dt.datetime] = mapped_column(DateTime, default=utcnow)

    experiment: Mapped[Experiment] = relationship(back_populates="runs")
    model: Mapped[ModelRecord | None] = relationship(back_populates="runs")
    defense: Mapped[DefenseRecord | None] = relationship(back_populates="runs")
    tool_calls: Mapped[list["ToolCallRow"]] = relationship(
        back_populates="run", cascade="all, delete-orphan"
    )
    responses: Mapped[list["AgentResponseRow"]] = relationship(
        back_populates="run", cascade="all, delete-orphan"
    )
    authorizations: Mapped[list["AuthorizationRow"]] = relationship(
        back_populates="run", cascade="all, delete-orphan"
    )
    effects: Mapped[list["SandboxEffectRow"]] = relationship(
        back_populates="run", cascade="all, delete-orphan"
    )


class ToolCallRow(Base):
    """A recorded simulated tool invocation."""

    __tablename__ = "tool_calls"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    run_id: Mapped[int] = mapped_column(ForeignKey("attack_runs.id"), index=True)
    call_uid: Mapped[str] = mapped_column(String(40), default="")
    step: Mapped[int] = mapped_column(Integer, default=0)
    tool: Mapped[str] = mapped_column(String(60), index=True)
    action: Mapped[str] = mapped_column(String(80))
    permission: Mapped[str] = mapped_column(String(30), default="read_only")
    arguments: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    status: Mapped[str] = mapped_column(String(30), default="ok")
    authorization: Mapped[str | None] = mapped_column(String(20), nullable=True)
    authorization_reason: Mapped[str] = mapped_column(Text, default="")
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    duration_ms: Mapped[float] = mapped_column(Float, default=0.0)
    result_summary: Mapped[str] = mapped_column(Text, default="")
    result_payload: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)

    run: Mapped[AttackRun] = relationship(back_populates="tool_calls")


class AgentResponseRow(Base):
    """A raw model response for one reasoning step."""

    __tablename__ = "agent_responses"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    run_id: Mapped[int] = mapped_column(ForeignKey("attack_runs.id"), index=True)
    step: Mapped[int] = mapped_column(Integer, default=0)
    model: Mapped[str] = mapped_column(String(160), default="")
    provider: Mapped[str] = mapped_column(String(40), default="")
    text: Mapped[str] = mapped_column(Text, default="")
    thought: Mapped[str] = mapped_column(Text, default="")
    finish_reason: Mapped[str] = mapped_column(String(40), default="")
    latency_ms: Mapped[float] = mapped_column(Float, default=0.0)

    run: Mapped[AttackRun] = relationship(back_populates="responses")


class AuthorizationRow(Base):
    """Privilege-separation audit record (Module 12)."""

    __tablename__ = "authorization_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    run_id: Mapped[int] = mapped_column(ForeignKey("attack_runs.id"), index=True)
    step: Mapped[int] = mapped_column(Integer, default=0)
    tool: Mapped[str] = mapped_column(String(60))
    action: Mapped[str] = mapped_column(String(80))
    arguments: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    permission: Mapped[str] = mapped_column(String(30), default="read_only")
    claimed_source: Mapped[str] = mapped_column(String(40), default="system")
    decision: Mapped[str] = mapped_column(String(20), index=True)
    reason: Mapped[str] = mapped_column(Text, default="")
    requested_by: Mapped[str] = mapped_column(String(60), default="agent")

    run: Mapped[AttackRun] = relationship(back_populates="authorizations")


class SandboxEffectRow(Base):
    """A simulated side effect (the only proof of a successful attack)."""

    __tablename__ = "sandbox_effects"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    run_id: Mapped[int] = mapped_column(ForeignKey("attack_runs.id"), index=True)
    effect_uid: Mapped[str] = mapped_column(String(40), default="")
    kind: Mapped[str] = mapped_column(String(60), index=True)
    tool: Mapped[str] = mapped_column(String(60))
    action: Mapped[str] = mapped_column(String(80))
    details: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    ts: Mapped[str] = mapped_column(String(40), default="")

    run: Mapped[AttackRun] = relationship(back_populates="effects")


class MetricRecord(Base):
    """One aggregated metric block for an experiment."""

    __tablename__ = "metrics"
    __table_args__ = (Index("ix_metrics_experiment_name", "experiment_id", "name"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    experiment_id: Mapped[int] = mapped_column(ForeignKey("experiments.id"), index=True)
    scope: Mapped[str] = mapped_column(String(120), default="overall")
    name: Mapped[str] = mapped_column(String(80), default="aggregate")
    value: Mapped[float] = mapped_column(Float, default=0.0)
    payload: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime, default=utcnow)

    experiment: Mapped[Experiment] = relationship(back_populates="metrics")


__all__ = [
    "Base",
    "utcnow",
    "ModelRecord",
    "DefenseRecord",
    "TaskRecord",
    "AttackRecordRow",
    "ExperimentConfig",
    "Experiment",
    "AttackRun",
    "ToolCallRow",
    "AgentResponseRow",
    "AuthorizationRow",
    "SandboxEffectRow",
    "MetricRecord",
]