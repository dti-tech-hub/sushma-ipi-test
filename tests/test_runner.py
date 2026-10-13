"""Experiment runner, batch execution and reproducibility (Module 6 / 7 / 16)."""

from __future__ import annotations

import pytest

from backend.database.models import AgentResponseRow, AttackRun, AuthorizationRow, Experiment, SandboxEffectRow, ToolCallRow
from backend.database.repository import Repository
from backend.database.session import session_scope
from backend.evaluation.runner import (
    BatchRequest,
    ExperimentRequest,
    ExperimentRunner,
    reproduce,
    stable_seed,
)
from backend.models.errors import AttackNotFoundError, TaskNotFoundError, TestRangeError


def request(**kwargs) -> ExperimentRequest:
    base = dict(
        task_ids=["T-001"],
        attack_ids=["GH-001"],
        provider="mock",
        model="mock-vulnerable",
        defense="none",
        repetitions=1,
        random_seed=1337,
        persist=False,
    )
    base.update(kwargs)
    return ExperimentRequest(**base)


# ---------------------------------------------------------------------------
# Seeds
# ---------------------------------------------------------------------------


def test_stable_seed_is_deterministic():
    assert stable_seed(1, "T-001", "GH-001") == stable_seed(1, "T-001", "GH-001")


def test_stable_seed_varies_with_input():
    assert stable_seed(1, "T-001") != stable_seed(2, "T-001")
    assert stable_seed(1, "T-001") != stable_seed(1, "T-002")


def test_stable_seed_is_process_independent():
    """BLAKE2b based, unlike Python's randomised ``hash``."""
    import subprocess
    import sys

    code = "import sys;sys.path.insert(0,'.');from backend.evaluation.runner import stable_seed;print(stable_seed(7,'x'))"
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, cwd=".")
    assert out.stdout.strip() == str(stable_seed(7, "x"))


# ---------------------------------------------------------------------------
# Planning
# ---------------------------------------------------------------------------


def test_plan_builds_a_pairing_matrix(settings, tasks, attacks):
    plan = ExperimentRunner(settings).build_plan(
        request(task_ids=None, attack_ids=["GH-001", "TM-001"]), tasks, attacks
    )
    assert plan.size() == 2
    assert set(plan.pairing) <= {"T-001", "T-006"}
    assert "GH-001" in plan.pairing["T-001"]
    assert "TM-001" in plan.pairing["T-006"]


def test_plan_reports_skipped_attacks(settings, tasks, attacks):
    plan = ExperimentRunner(settings).build_plan(
        request(task_ids=["T-001"], attack_ids=["TM-001"]), tasks, attacks
    )
    assert plan.skipped and plan.skipped[0]["attack_id"] == "TM-001"


def test_run_creates_baseline_and_attacked_runs(settings):
    result = ExperimentRunner(settings).run(request(), settings=settings)
    assert result.score["n_baseline"] == 1
    assert result.score["n_attacked"] == 1
    assert result.score["n_runs"] == 2


def test_repetitions_multiply_runs(settings):
    result = ExperimentRunner(settings).run(request(repetitions=3), settings=settings)
    assert result.score["n_attacked"] == 3
    assert result.score["n_baseline"] == 3


def test_include_baseline_can_be_disabled(settings):
    result = ExperimentRunner(settings).run(request(include_baseline=False), settings=settings)
    assert result.score["n_baseline"] == 0
    assert result.score["n_attacked"] == 1


def test_unknown_attack_raises(settings):
    with pytest.raises(AttackNotFoundError):
        ExperimentRunner(settings).run(request(attack_ids=["NOPE"]), settings=settings)


def test_unknown_task_raises(settings):
    with pytest.raises(TaskNotFoundError):
        ExperimentRunner(settings).run(request(task_ids=["T-999"]), settings=settings)


def test_run_pairs_expected_tasks(settings):
    result = ExperimentRunner(settings).run(
        request(task_ids=None, attack_ids=["EX-001"], repetitions=1), settings=settings
    )
    assert result.plan["pairing"], "an exfiltration attack should be paired with a task"
    task_id = next(iter(result.plan["pairing"]))
    assert task_id == "T-006", "database-channel attack should land on a database task"


def test_skipped_attacks_are_reported(settings):
    result = ExperimentRunner(settings).run(
        request(task_ids=["T-001"], attack_ids=["EX-001"]), settings=settings
    )
    assert result.plan["skipped"]
    assert "delivery channel" in result.plan["skipped"][0]["reason"]


def test_demo_mode_cannot_be_bypassed(settings):
    with pytest.raises(TestRangeError):
        ExperimentRunner(settings).run(request(demo_mode=False), settings=settings)


# ---------------------------------------------------------------------------
# Determinism
# ---------------------------------------------------------------------------


def test_same_request_gives_same_metrics(settings):
    a = ExperimentRunner(settings).run(request(repetitions=3), settings=settings)
    b = ExperimentRunner(settings).run(request(repetitions=3), settings=settings)
    for key in ("attack_success_rate", "benign_utility", "utility_under_attack"):
        assert a.score[key] == b.score[key], f"{key} is not reproducible"


def test_different_seeds_give_different_seeds(settings):
    a = ExperimentRunner(settings).run(request(repetitions=3, random_seed=1), settings=settings)
    b = ExperimentRunner(settings).run(request(repetitions=3, random_seed=2), settings=settings)
    assert a.configuration["settings_snapshot"]["random_seed"] == 1
    assert b.configuration["settings_snapshot"]["random_seed"] == 2


def test_run_uids_are_unique_across_persisted_experiments(settings):
    """The same configuration run twice must not collide on the run_uid column."""
    uids = set()
    for _ in range(3):
        result = ExperimentRunner(settings).run(
            request(persist=True, repetitions=2), settings=settings
        )
        assert result.experiment_uid
        with session_scope(settings) as session:
            repo = Repository(session)
            for run in repo.get_experiment(result.experiment_uid).runs:
                uids.add(run.run_uid)
    assert len(uids) == 12, f"expected 12 unique run ids (3 experiments x 2 reps x 2 conditions), got {len(uids)}"


# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------


def test_experiment_is_persisted_with_full_provenance(settings):
    result = ExperimentRunner(settings).run(
        request(persist=True, name="persisted"), settings=settings
    )
    assert result.experiment_uid
    with session_scope(settings) as session:
        repo = Repository(session)
        experiment = repo.get_experiment(result.experiment_uid)
        assert experiment is not None
        assert experiment.model == "mock-vulnerable"
        assert experiment.defense == "none"
        assert experiment.is_simulation is True
        assert "SIMULATED" in experiment.provenance_note or "DEMO" in experiment.provenance_note
        assert experiment.corpus_versions["attacks"]
        assert experiment.configuration["settings_snapshot"]["random_seed"] == 1337
        assert experiment.metrics, "metrics block was not written"


def test_everything_a_number_depends_on_is_stored(settings):
    result = ExperimentRunner(settings).run(
        request(persist=True, attack_ids=["GH-001", "IO-001"]), settings=settings
    )
    with session_scope(settings) as session:
        repo = Repository(session)
        experiment = repo.get_experiment(result.experiment_uid)
        runs = experiment.runs
        assert runs
        attacked = [r for r in runs if r.condition == "attack"]
        assert attacked
        for run in attacked:
            assert run.task_id
            assert run.attack_id
            assert run.seed
            assert run.evaluation, "evaluation payload missing"
            assert run.evaluation["utility"]
            assert run.evaluation["attack"] is not None
            assert run.evaluation["injection"] is not None, "injection provenance missing"
            assert isinstance(run.tool_calls, list)
            assert isinstance(run.responses, list)


def test_tool_calls_and_responses_are_recorded(settings):
    result = ExperimentRunner(settings).run(request(persist=True), settings=settings)
    with session_scope(settings) as session:
        repo = Repository(session)
        assert repo.count(ToolCallRow) > 0
        assert repo.count(AgentResponseRow) > 0
        assert repo.count(AuthorizationRow) > 0


def test_harmful_effects_are_recorded_when_an_attack_succeeds(settings):
    result = ExperimentRunner(settings).run(
        request(persist=True, attack_ids=["GH-001"], repetitions=6), settings=settings
    )
    if result.score["harmful_effect_rate"] > 0:
        with session_scope(settings) as session:
            repo = Repository(session)
            assert repo.count(SandboxEffectRow) > 0


def test_reproduce_uses_the_stored_configuration(settings):
    original = ExperimentRunner(settings).run(request(persist=True), settings=settings)
    replay = reproduce(original.experiment_uid, settings=settings)
    assert replay.experiment_uid != original.experiment_uid, "reproduction must be a new experiment"
    assert replay.configuration["reproduced_from"] == original.experiment_uid
    for key in ("attack_success_rate", "benign_utility", "utility_under_attack"):
        assert replay.score[key] == original.score[key], f"{key} differs on replay"


def test_reproduce_unknown_experiment(settings):
    with pytest.raises(TestRangeError):
        reproduce("EXP-DOES-NOT-EXIST", settings=settings)


# ---------------------------------------------------------------------------
# Batch
# ---------------------------------------------------------------------------


def test_batch_runs_model_by_defense(settings):
    result = ExperimentRunner(settings).run_batch(
        BatchRequest(
            models=[{"provider": "mock", "name": "mock-vulnerable"}, {"provider": "mock", "name": "mock-hardened"}],
            defenses=["none", "guard_classifier"],
            selection={"task_ids": ["T-001"], "attack_ids": ["GH-001"]},
            repetitions=1,
            random_seed=1337,
            persist=False,
        ),
        settings=settings,
    )
    assert len(result.experiments) == 4
    assert result.total_cells == 4
    assert result.total_seconds >= 0


def test_batch_defenses_change_outcomes(settings):
    batch = ExperimentRunner(settings).run_batch(
        BatchRequest(
            models=[{"provider": "mock", "name": "mock-vulnerable"}],
            defenses=["none", "privilege_separation"],
            selection={"task_ids": ["T-001"], "attack_ids": ["GH-001", "IO-001"]},
            repetitions=4,
            random_seed=7,
            persist=False,
        ),
        settings=settings,
    )
    by_defense = {e.defense: e.score["attack_success_rate"] for e in batch.experiments}
    assert by_defense["privilege_separation"] < by_defense["none"]


def test_batch_persists_every_experiment(settings):
    batch = ExperimentRunner(settings).run_batch(
        BatchRequest(
            models=[{"provider": "mock", "name": "mock-vulnerable"}],
            defenses=["none", "sanitization"],
            selection={"task_ids": ["T-001"], "attack_ids": ["GH-001"]},
            repetitions=1,
            persist=True,
        ),
        settings=settings,
    )
    with session_scope(settings) as session:
        repo = Repository(session)
        for experiment in batch.experiments:
            assert repo.get_experiment(experiment.experiment_uid) is not None


def test_errors_do_not_kill_a_batch(settings):
    """One bad cell must not abort the sweep."""
    result = ExperimentRunner(settings).run(
        request(task_ids=["T-001"], attack_ids=["GH-001", "TM-001", "OB-001"], repetitions=1),
        settings=settings,
    )
    assert isinstance(result.errors, list)
    assert result.score["n_attacked"] >= 1


def test_result_serialises(settings):
    payload = ExperimentRunner(settings).run(request(), settings=settings).to_dict()
    for key in ("provider", "model", "defense", "is_simulation", "provenance_note", "plan", "score"):
        assert key in payload


def test_result_is_labelled_as_simulation(settings):
    result = ExperimentRunner(settings).run(request(), settings=settings)
    assert result.is_simulation is True
    assert "SIMULATED" in result.provenance_note or "DEMO" in result.provenance_note