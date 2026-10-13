"""SQLite persistence (Module 8)."""

from __future__ import annotations

import pytest
from sqlalchemy import inspect

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
)
from backend.database.repository import Repository
from backend.database.session import EXPECTED_TABLES, get_session_factory, init_db, session_scope
from backend.defenses import get_defense
from backend.models.errors import DatabaseError
from backend.services.config import get_settings


# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------


def test_init_creates_every_expected_table(settings):
    result = init_db(settings)
    missing = [t for t in EXPECTED_TABLES if t not in result["tables"]]
    assert not missing, f"missing tables: {missing}"


def test_init_is_idempotent(settings):
    init_db(settings)
    result = init_db(settings)
    assert result["migrations_applied"] == []


def test_schema_has_expected_columns(settings):
    init_db(settings)
    from backend.database.session import get_engine

    inspector = inspect(get_engine(settings))
    run_columns = {c["name"] for c in inspector.get_columns("attack_runs")}
    for column in (
        "condition", "attack_succeeded", "attack_detected", "policy_violation",
        "harmful_effect", "task_utility", "seed", "repetition",
    ):
        assert column in run_columns


def test_foreign_keys_are_enforced(settings):
    init_db(settings)
    session = get_session_factory(settings)()
    try:
        run = AttackRun(run_uid="X-FK", experiment_id=999999, condition="attack", task_id="T-001")
        session.add(run)
        with pytest.raises(Exception):
            session.flush()
    finally:
        session.rollback()
        session.close()
    # The connection must still be usable afterwards.
    with session_scope(settings) as fresh:
        assert Repository(fresh).count(Experiment) >= 0


def test_database_file_is_created(settings):
    assert settings.db_path.exists()


# ---------------------------------------------------------------------------
# Reference data
# ---------------------------------------------------------------------------


def test_upsert_model(repo):
    row = repo.upsert_model("mock-x", "mock", is_simulation=True, description="d")
    session_id = row.id
    again = repo.upsert_model("mock-x", "mock", is_simulation=True, description="updated")
    assert again.id == session_id, "must update, not duplicate"
    assert again.description == "updated"


def test_upsert_defense(repo):
    row = repo.upsert_defense(get_defense("guard_classifier"))
    assert row.name == "guard_classifier"
    assert row.rewrites_content is True
    assert repo.upsert_defense(get_defense("guard_classifier")).id == row.id


def test_upsert_task(repo, tasks):
    row = repo.upsert_task(tasks.get("T-001"))
    assert row.task_id == "T-001"
    assert "email.send_email" in row.forbidden_actions
    assert repo.upsert_task(tasks.get("T-001")).id == row.id


def test_upsert_attack(repo, attacks):
    row = repo.upsert_attack(attacks.get("GH-001"))
    assert row.attack_id == "GH-001"
    assert row.target_action == "email.send_email"
    assert row.success_criteria
    assert row.payload_sha


def test_attack_sha_is_stable(repo, attacks):
    first = repo.upsert_attack(attacks.get("GH-001")).payload_sha
    second = repo.upsert_attack(attacks.get("GH-001")).payload_sha
    assert first == second


def test_upsert_config(repo):
    row = repo.upsert_config("profile-a", description="d", repetitions=5, random_seed=7)
    assert row.name == "profile-a"
    assert repo.upsert_config("profile-a", repetitions=9).repetitions == 9


def test_indexes_exist(settings):
    init_db(settings)
    from backend.database.session import get_engine

    inspector = inspect(get_engine(settings))
    indexes = {i["name"] for i in inspector.get_indexes("attack_runs")}
    assert any("experiment" in name for name in indexes)


# ---------------------------------------------------------------------------
# Experiments and runs
# ---------------------------------------------------------------------------


def test_create_and_finish_experiment(repo):
    experiment = repo.create_experiment(
        provider="mock", model="mock-vulnerable", defense="none",
        random_seed=1337, repetitions=2, task_ids=["T-001"], attack_ids=["GH-001"],
        configuration={"a": 1}, name="t",
    )
    assert experiment.experiment_uid.startswith("EXP-")
    assert experiment.status == "running"
    repo.finish_experiment(experiment, status="completed", duration_ms=12.0)
    assert experiment.status == "completed"
    assert experiment.finished_at is not None


def test_experiment_uids_are_unique(repo):
    uids = {
        repo.create_experiment(
            provider="mock", model="m", defense="none", random_seed=1,
            repetitions=1, task_ids=[], attack_ids=[], configuration={},
        ).experiment_uid
        for _ in range(5)
    }
    assert len(uids) == 5


def test_get_experiment_by_uid_and_id(repo):
    experiment = repo.create_experiment(
        provider="mock", model="m", defense="none", random_seed=1,
        repetitions=1, task_ids=["T-001"], attack_ids=[], configuration={},
    )
    repo.session.flush()
    assert repo.get_experiment(experiment.experiment_uid).id == experiment.id
    assert repo.get_experiment(experiment.id).experiment_uid == experiment.experiment_uid
    assert repo.get_experiment("EXP-NOPE") is None


def test_list_experiments_is_newest_first(repo):
    before = len(repo.list_experiments())
    created = []
    for index in range(3):
        created.append(
            repo.create_experiment(
                provider="mock", model=f"m{index}", defense="none", random_seed=index,
                repetitions=1, task_ids=[], attack_ids=[], configuration={},
            ).id
        )
        repo.session.flush()
    listed = repo.list_experiments()
    assert len(listed) == before + 3
    ids = [e.id for e in listed]
    assert ids[:3] == sorted(ids[:3], reverse=True)
    assert created[-1] == ids[0], "newest experiment first"
    assert created == sorted(created)


def test_count_works(repo):
    before = repo.count(ModelRecord)
    repo.upsert_model("counted-model", "mock")
    assert repo.count(ModelRecord) == before + 1


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------


@pytest.fixture()
def isolated_repo(tmp_path):
    """A repository bound to a brand-new SQLite file (truly empty)."""
    from backend.database.session import get_session_factory

    path = tmp_path / "isolated.db"
    init_db(settings=get_settings(), path=path)
    session = get_session_factory(path=path)()
    try:
        yield Repository(session)
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def test_runs_dataframe_from_empty_db(isolated_repo):
    from backend.services.reporting import runs_dataframe

    frame = runs_dataframe(isolated_repo)
    assert frame.empty
    assert "attack_succeeded" in frame.columns


def test_hydrate_run_scores_handles_empty(isolated_repo):
    assert isolated_repo.hydrate_run_scores([]) == []


def test_summary_on_empty_db(isolated_repo):
    from backend.services.reporting import build_summary

    summary = build_summary(isolated_repo)
    assert summary["counts"]["runs"] == 0
    assert summary["counts"]["experiments"] == 0
    assert summary["metrics"]["attack_success_rate"] == 0.0
    assert "No experiments recorded" in summary["result_provenance"]


def test_export_writes_all_artifacts(repo, settings, tmp_path):
    from backend.services.reporting import export_all

    result = export_all(repo, tmp_path, settings)
    names = {p.split("\\")[-1].split("/")[-1] for p in result["files"]}
    assert {"runs.csv", "experiments.csv", "summary.json", "report.md", "runs.json"} <= names
    for path in result["files"]:
        from pathlib import Path

        assert Path(path).exists(), f"{path} was not written"


def test_read_log_tail_is_safe_without_a_log(settings):
    from backend.services.reporting import read_log_tail

    assert isinstance(read_log_tail(settings, 10), list)


# ---------------------------------------------------------------------------
# No secrets
# ---------------------------------------------------------------------------


def test_schema_has_no_credential_columns(settings):
    init_db(settings)
    from backend.database.session import get_engine

    inspector = inspect(get_engine(settings))
    for table in EXPECTED_TABLES:
        columns = {c["name"].lower() for c in inspector.get_columns(table)}
        for forbidden in ("api_key", "password", "secret_key", "access_token"):
            assert forbidden not in columns, f"{table}.{forbidden}"