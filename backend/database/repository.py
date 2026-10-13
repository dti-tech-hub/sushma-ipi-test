"""Repository layer: every SQLite write the test range performs.

Keeping persistence in one place means the evaluation code never touches SQL,
and the whole database surface can be exercised from a handful of unit tests.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import uuid
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Iterable, Sequence

from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from backend.agents.base import AgentTrace
from backend.attacks.models import AttackRecord
from backend.database.models import (
    AgentResponseRow,
    AttackRecordRow,
    AttackRun,
    AuthorizationRow,
    DefenseRecord,
    Experiment,
    ExperimentConfig,
    MetricRecord,
    ModelRecord,
    SandboxEffectRow,
    TaskRecord,
    ToolCallRow,
    utcnow,
)
from backend.defenses.base import Defense
from backend.models.tasks import TaskDefinition
from backend.scoring.metrics import AggregateScore, RunScore
from backend.services.logging_setup import get_logger, info

if TYPE_CHECKING:  # avoid a circular import: evaluation.runner imports this module
    from backend.evaluation.success import AttackEvaluation
    from backend.evaluation.task_eval import UtilityResult


def _now() -> dt.datetime:
    return utcnow()


def _sha(payload: Any) -> str:
    blob = json.dumps(payload, sort_keys=True, default=str)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()[:32]


@dataclass
class PersistedExperiment:
    experiment: Experiment
    runs: list[AttackRun]
    score: AggregateScore


class Repository:
    """All persistence operations, bound to one SQLAlchemy session."""

    def __init__(self, session: Session) -> None:
        self.session = session
        self.log = get_logger("repository")

    # -- reference data ---------------------------------------------------
    def upsert_model(
        self,
        model_id: str,
        provider: str,
        *,
        display_name: str = "",
        is_simulation: bool = True,
        requires_api_key: bool = False,
        available: bool = True,
        description: str = "",
        attributes: dict[str, Any] | None = None,
    ) -> ModelRecord:
        row = self.session.scalar(
            select(ModelRecord).where(ModelRecord.model_id == model_id)
        )
        if row is None:
            row = ModelRecord(model_id=model_id)
            self.session.add(row)
        row.provider = provider
        row.display_name = display_name or model_id
        row.is_simulation = is_simulation
        row.requires_api_key = requires_api_key
        row.available = available
        row.description = description
        row.attributes = attributes or {}
        self.session.flush()
        return row

    def upsert_defense(self, defense: Defense) -> DefenseRecord:
        row = self.session.scalar(
            select(DefenseRecord).where(DefenseRecord.name == defense.name)
        )
        if row is None:
            row = DefenseRecord(name=defense.name)
            self.session.add(row)
        row.description = defense.description
        row.mechanism = defense.mechanism
        row.version = defense.version
        row.rewrites_content = defense.rewrites_content
        row.gates_actions = defense.gates_actions
        row.config = defense.config
        self.session.flush()
        return row

    def upsert_task(self, task: TaskDefinition) -> TaskRecord:
        payload = task.model_dump(mode="json")
        row = self.session.scalar(select(TaskRecord).where(TaskRecord.task_id == task.task_id))
        if row is None:
            row = TaskRecord(task_id=task.task_id)
            self.session.add(row)
        row.name = task.name
        row.description = task.description
        row.allowed_tools = list(task.allowed_tools)
        row.forbidden_actions = sorted(task.forbidden_action_keys())
        row.difficulty = task.difficulty.value
        row.channels = [c.value for c in task.channels]
        row.expected_outcome = task.expected_outcome
        row.payload = payload
        self.session.flush()
        return row

    def upsert_attack(self, attack: AttackRecord, corpus_version: str = "1.0.0") -> AttackRecordRow:
        payload = attack.model_dump(mode="json")
        row = self.session.scalar(
            select(AttackRecordRow).where(AttackRecordRow.attack_id == attack.id)
        )
        if row is None:
            row = AttackRecordRow(attack_id=attack.id)
            self.session.add(row)
        row.name = attack.name
        row.description = attack.description
        row.attack_type = attack.attack_type.value
        row.delivery_channel = attack.delivery_channel.value
        row.injection_position = attack.injection_position.value
        row.payload_format = attack.format.value
        row.difficulty = attack.difficulty.value
        row.severity = attack.severity.value
        row.target_action = attack.target_action.key
        row.target_permission = attack.target_action.permission.value
        row.expected_behavior = attack.expected_behavior
        row.safe_simulation = attack.safe_simulation
        row.success_mode = attack.success_mode
        row.success_criteria = [p.model_dump(mode="json") for p in attack.success_criteria]
        row.tags = list(attack.tags)
        row.corpus_version = corpus_version
        row.payload_sha = _sha(payload)
        row.payload = payload
        self.session.flush()
        return row

    def upsert_config(
        self,
        name: str,
        *,
        description: str = "",
        provider: str = "mock",
        model: str = "",
        defense: str = "none",
        repetitions: int = 3,
        random_seed: int = 1337,
        temperature: float = 0.0,
        max_steps: int = 10,
        selection: dict[str, Any] | None = None,
        settings: dict[str, Any] | None = None,
    ) -> ExperimentConfig:
        row = self.session.scalar(
            select(ExperimentConfig).where(ExperimentConfig.name == name)
        )
        if row is None:
            row = ExperimentConfig(name=name)
            self.session.add(row)
        row.description = description
        row.provider = provider
        row.model = model
        row.defense = defense
        row.repetitions = repetitions
        row.random_seed = random_seed
        row.temperature = temperature
        row.max_steps = max_steps
        row.selection = selection or {}
        row.settings = settings or {}
        self.session.flush()
        return row

    # -- experiments ------------------------------------------------------
    def create_experiment(
        self,
        *,
        provider: str,
        model: str,
        defense: str,
        random_seed: int,
        repetitions: int,
        task_ids: Sequence[str],
        attack_ids: Sequence[str],
        configuration: dict[str, Any],
        name: str = "",
        model_version: str = "",
        is_simulation: bool = True,
        provenance_note: str = "",
        corpus_versions: dict[str, Any] | None = None,
        config_id: int | None = None,
    ) -> Experiment:
        row = Experiment(
            experiment_uid=f"EXP-{uuid.uuid4().hex[:14].upper()}",
            name=name or f"{provider}:{model} x {defense}",
            provider=provider,
            model=model,
            model_version=model_version,
            is_simulation=is_simulation,
            provenance_note=provenance_note,
            defense=defense,
            random_seed=random_seed,
            repetitions=repetitions,
            task_ids=list(task_ids),
            attack_ids=list(attack_ids),
            corpus_versions=corpus_versions or {},
            configuration=configuration,
            status="running",
            config_id=config_id,
            started_at=_now(),
        )
        self.session.add(row)
        self.session.flush()
        info(
            "experiment_created",
            experiment_id=row.experiment_uid,
            model=model,
            defense=defense,
            tasks=len(task_ids),
            attacks=len(attack_ids),
        )
        return row

    def finish_experiment(
        self, experiment: Experiment, *, status: str = "completed", error: str | None = None, duration_ms: float = 0.0
    ) -> Experiment:
        experiment.status = status
        experiment.error = error
        experiment.duration_ms = duration_ms
        experiment.finished_at = _now()
        self.session.flush()
        return experiment

    # -- runs -------------------------------------------------------------
    def save_run(
        self,
        *,
        experiment: Experiment,
        task: TaskDefinition,
        attack: AttackRecord | None,
        condition: str,
        repetition: int,
        seed: int,
        model: ModelRecord | None,
        defense: DefenseRecord | None,
        trace: AgentTrace,
        utility: UtilityResult,
        evaluation: AttackEvaluation | None,
        score: RunScore,
    ) -> AttackRun:
        harmful = any(e.kind in _HARMFUL for e in trace.ledger_entries)
        row = AttackRun(
            run_uid=trace.run_id,
            experiment_id=experiment.id,
            condition=condition,
            repetition=repetition,
            seed=seed,
            task_id=task.task_id,
            attack_id=attack.id if attack else None,
            model_id=model.id if model else None,
            defense_id=defense.id if defense else None,
            status="error" if trace.error else "completed",
            finished_reason=trace.finished_reason,
            error=trace.error,
            attack_succeeded=bool(evaluation.succeeded) if evaluation else False,
            attack_detected=bool(evaluation.detected) if evaluation else False,
            detection_reason=evaluation.detection_reason if evaluation else "",
            policy_violation=bool(utility.policy_violation or (evaluation.policy_violation if evaluation else False)),
            harmful_effect=harmful,
            hijacked=trace.hijacked,
            task_utility=utility.penalised_utility,
            plan_completion=utility.plan_completion,
            final_answer=trace.final_answer[:4000],
            steps_used=len(trace.steps),
            latency_ms=trace.total_latency_ms,
            evaluation={
                "utility": utility.to_dict(),
                "attack": evaluation.to_dict() if evaluation else None,
                "injection": trace.metadata.get("injection"),
                "perception": trace.metadata.get("perception"),
                "defense_reports": trace.metadata.get("defense_reports", []),
                "metadata": {
                    k: v for k, v in trace.metadata.items()
                    if k not in {"utility", "attack", "injection", "perception", "defense_reports"}
                },
            },
            started_at=_now(),
        )
        self.session.add(row)
        self.session.flush()

        for call in trace.tool_calls:
            summary = ""
            payload: dict[str, Any] = {}
            if call.result is not None:
                payload = call.result.to_dict()
                summary = (call.result.content or "")[:800]
            self.session.add(
                ToolCallRow(
                    run_id=row.id,
                    call_uid=call.call_id,
                    step=call.step,
                    tool=call.tool,
                    action=call.action,
                    permission=call.permission.value,
                    arguments=call.arguments,
                    status=call.status,
                    authorization=call.authorization.value if call.authorization else None,
                    authorization_reason=call.authorization_reason,
                    error=call.error,
                    duration_ms=call.duration_ms,
                    result_summary=summary,
                    result_payload=payload,
                )
            )

        for response in trace.responses:
            self.session.add(
                AgentResponseRow(
                    run_id=row.id,
                    step=int(response.get("step", 0)),
                    model=str(response.get("model", "")),
                    provider=str(response.get("provider", "")),
                    text=str(response.get("text", ""))[:8000],
                    thought=str(response.get("thought", ""))[:2000],
                    finish_reason=str(response.get("finish_reason", "")),
                    latency_ms=float(response.get("latency_ms", 0.0)),
                )
            )

        for outcome in trace.authorizations:
            self.session.add(
                AuthorizationRow(
                    run_id=row.id,
                    step=0,
                    tool=outcome.request.tool,
                    action=outcome.request.action,
                    arguments=outcome.request.arguments,
                    permission=outcome.permission.value,
                    claimed_source=outcome.source.value,
                    decision=outcome.decision.value,
                    reason=outcome.reason,
                    requested_by=outcome.request.requested_by,
                )
            )

        for entry in trace.ledger_entries:
            self.session.add(
                SandboxEffectRow(
                    run_id=row.id,
                    effect_uid=entry.effect_id,
                    kind=entry.kind,
                    tool=entry.tool,
                    action=entry.action,
                    details=entry.details,
                    ts=entry.ts,
                )
            )
        self.session.flush()
        info(
            "run_saved",
            experiment_id=experiment.experiment_uid,
            run_id=trace.run_id,
            task_id=task.task_id,
            attack_id=score.attack_id,
            condition=condition,
            attack_succeeded=score.attack_succeeded,
            utility=round(score.task_utility, 3),
        )
        return row

    # -- metrics ----------------------------------------------------------
    def save_metrics(
        self, experiment: Experiment, score: AggregateScore, scope: str = "overall"
    ) -> MetricRecord:
        payload = score.to_dict()
        row = MetricRecord(
            experiment_id=experiment.id,
            scope=scope,
            name="aggregate",
            value=score.attack_success_rate,
            payload=payload,
        )
        self.session.add(row)
        self.session.flush()
        return row

    # -- queries ----------------------------------------------------------
    def list_experiments(self, limit: int = 50, offset: int = 0) -> list[Experiment]:
        return list(
            self.session.scalars(
                select(Experiment)
                .order_by(Experiment.started_at.desc(), Experiment.id.desc())
                .limit(limit)
                .offset(offset)
            )
        )

    def get_experiment(self, reference: str | int) -> Experiment | None:
        if isinstance(reference, int):
            return self.session.get(Experiment, reference)
        return self.session.scalar(
            select(Experiment).where(Experiment.experiment_uid == reference)
        )

    def get_experiment_detail(self, experiment: Experiment) -> dict[str, Any]:
        return {
            "experiment": _experiment_dict(experiment),
            "runs": [_run_dict(r) for r in experiment.runs],
            "metrics": [m.payload for m in experiment.metrics],
        }

    def list_runs(self, limit: int = 200, experiment_uid: str | None = None) -> list[AttackRun]:
        stmt = select(AttackRun).order_by(AttackRun.id.desc()).limit(limit)
        if experiment_uid:
            experiment = self.get_experiment(experiment_uid)
            if experiment is not None:
                stmt = (
                    select(AttackRun)
                    .where(AttackRun.experiment_id == experiment.id)
                    .order_by(AttackRun.id)
                )
        return list(self.session.scalars(stmt))

    def all_runs(self) -> list[AttackRun]:
        return list(self.session.scalars(select(AttackRun).order_by(AttackRun.id)))

    def get_run(self, run_uid: str) -> AttackRun | None:
        return self.session.scalar(select(AttackRun).where(AttackRun.run_uid == run_uid))

    def attack_index(self) -> list[AttackRecordRow]:
        return list(self.session.scalars(select(AttackRecordRow).order_by(AttackRecordRow.attack_id)))

    def task_index(self) -> list[TaskRecord]:
        return list(self.session.scalars(select(TaskRecord).order_by(TaskRecord.task_id)))

    def model_index(self) -> list[ModelRecord]:
        return list(self.session.scalars(select(ModelRecord).order_by(ModelRecord.model_id)))

    def defense_index(self) -> list[DefenseRecord]:
        return list(self.session.scalars(select(DefenseRecord).order_by(DefenseRecord.name)))

    def config_index(self) -> list[ExperimentConfig]:
        return list(
            self.session.scalars(select(ExperimentConfig).order_by(ExperimentConfig.name))
        )

    def count(self, entity: type) -> int:
        return int(self.session.scalar(select(func.count()).select_from(entity)) or 0)

    def purge_runs(self, experiment: Experiment) -> int:
        result = self.session.execute(delete(AttackRun).where(AttackRun.experiment_id == experiment.id))
        self.session.flush()
        return int(result.rowcount or 0)

    def hydrate_run_scores(self, runs: Iterable[AttackRun]) -> list[RunScore]:
        """Rebuild :class:`RunScore` objects from stored runs."""
        attack_rows = {a.attack_id: a for a in self.attack_index()}
        out: list[RunScore] = []
        for run in runs:
            attack_row = attack_rows.get(run.attack_id) if run.attack_id else None
            out.append(
                RunScore(
                    run_id=run.run_uid,
                    condition=run.condition,
                    task_id=run.task_id,
                    attack_id=run.attack_id,
                    model=run.model.model_id if run.model else "",
                    defense=run.defense.name if run.defense else "none",
                    attack_type=attack_row.attack_type if attack_row else None,
                    delivery_channel=attack_row.delivery_channel if attack_row else None,
                    severity=attack_row.severity if attack_row else None,
                    difficulty=attack_row.difficulty if attack_row else None,
                    injection_position=attack_row.injection_position if attack_row else None,
                    payload_format=attack_row.payload_format if attack_row else None,
                    target_action=attack_row.target_action if attack_row else None,
                    attack_succeeded=run.attack_succeeded,
                    attack_detected=run.attack_detected,
                    policy_violation=run.policy_violation,
                    harmful_effect=run.harmful_effect,
                    task_utility=run.task_utility,
                    plan_completion=run.plan_completion,
                    error=run.error,
                )
            )
        return out


# ---------------------------------------------------------------------------
# serialisation helpers
# ---------------------------------------------------------------------------

_HARMFUL = {
    "email_sent",
    "email_forwarded",
    "email_deleted",
    "file_deleted",
    "file_shared_externally",
    "db_rows_exfiltrated",
    "db_table_dropped",
    "db_privilege_granted",
    "calendar_shared_externally",
    "event_cancelled",
    "external_request_made",
    "package_installed",
    "form_submitted_externally",
    "file_written",
}


def _experiment_dict(row: Experiment) -> dict[str, Any]:
    return {
        "id": row.id,
        "experiment_uid": row.experiment_uid,
        "name": row.name,
        "provider": row.provider,
        "model": row.model,
        "model_version": row.model_version,
        "is_simulation": row.is_simulation,
        "provenance_note": row.provenance_note,
        "defense": row.defense,
        "random_seed": row.random_seed,
        "repetitions": row.repetitions,
        "task_ids": row.task_ids,
        "attack_ids": row.attack_ids,
        "corpus_versions": row.corpus_versions,
        "configuration": row.configuration,
        "status": row.status,
        "error": row.error,
        "duration_ms": row.duration_ms,
        "started_at": row.started_at.isoformat() if row.started_at else None,
        "finished_at": row.finished_at.isoformat() if row.finished_at else None,
        "n_runs": len(row.runs),
    }


def _run_dict(row: AttackRun) -> dict[str, Any]:
    return {
        "run_uid": row.run_uid,
        "condition": row.condition,
        "repetition": row.repetition,
        "seed": row.seed,
        "task_id": row.task_id,
        "attack_id": row.attack_id,
        "model": row.model.model_id if row.model else "",
        "defense": row.defense.name if row.defense else "none",
        "status": row.status,
        "finished_reason": row.finished_reason,
        "error": row.error,
        "attack_succeeded": row.attack_succeeded,
        "attack_detected": row.attack_detected,
        "detection_reason": row.detection_reason,
        "policy_violation": row.policy_violation,
        "harmful_effect": row.harmful_effect,
        "hijacked": row.hijacked,
        "task_utility": row.task_utility,
        "plan_completion": row.plan_completion,
        "steps_used": row.steps_used,
        "latency_ms": row.latency_ms,
        "n_tool_calls": len(row.tool_calls),
        "n_effects": len(row.effects),
        "final_answer": row.final_answer[:2000],
        "started_at": row.started_at.isoformat() if row.started_at else None,
    }


__all__ = ["Repository", "PersistedExperiment", "_experiment_dict", "_run_dict"]