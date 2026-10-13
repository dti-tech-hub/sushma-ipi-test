"""Corpus loading and validation (Module 2 / Module 18)."""

from __future__ import annotations

import json

import pytest

from backend.attacks.models import AttackCorpus, AttackRecord
from backend.attacks.loader import AttackRepository, TaskRepository
from backend.models.enums import AttackType, DeliveryChannel, Difficulty, InjectionPosition, Severity
from backend.models.errors import AttackNotFoundError, CorpusError, DuplicateRecordError, TaskNotFoundError
from backend.models.tasks import TaskDefinition
from backend.services.config import PROJECT_ROOT
from backend.tools.registry import ToolRegistry

REQUIRED_FIELDS = (
    "id", "name", "description", "attack_type", "delivery_channel", "payload",
    "injection_position", "format", "target_action", "difficulty", "severity",
    "expected_behavior", "safe_simulation", "success_criteria", "tags",
)

CHANNEL_TO_TOOL = {"web": "web_search", "api": "code_interpreter", "file": "file_reader"}


# ---------------------------------------------------------------------------
# Size and coverage
# ---------------------------------------------------------------------------


def test_corpus_has_at_least_fifty_attacks(attacks):
    assert len(attacks) >= 50, "the corpus should be substantial, not a toy set"


def test_all_five_attack_categories_present(attacks):
    seen = {a.attack_type for a in attacks.all()}
    assert seen == set(AttackType), f"missing categories: {set(AttackType) - seen}"


def test_categories_are_reasonably_balanced(attacks):
    counts = {}
    for record in attacks.all():
        counts[record.attack_type] = counts.get(record.attack_type, 0) + 1
    assert min(counts.values()) >= 10, counts


def test_all_delivery_channels_covered(attacks):
    channels = {a.delivery_channel for a in attacks.all()}
    assert channels == set(DeliveryChannel), f"missing channels: {set(DeliveryChannel) - channels}"


def test_all_injection_positions_exercised(attacks):
    positions = {a.injection_position for a in attacks.all()}
    assert positions == set(InjectionPosition), f"missing: {set(InjectionPosition) - positions}"


def test_all_severities_and_difficulties_exercised(attacks):
    assert {a.severity for a in attacks.all()} == set(Severity)
    assert {a.difficulty for a in attacks.all()} == set(Difficulty)


def test_multiple_payload_formats_present(attacks):
    formats = {a.format.value for a in attacks.all()}
    assert len(formats) >= 8, formats


# ---------------------------------------------------------------------------
# Record validity
# ---------------------------------------------------------------------------


def test_every_record_has_all_required_fields(attacks):
    for record in attacks.all():
        dumped = record.model_dump()
        for field in REQUIRED_FIELDS:
            assert field in dumped, f"{record.id} missing {field}"


def test_every_attack_declares_success_criteria(attacks):
    for record in attacks.all():
        assert record.success_criteria, f"{record.id} has no success criteria"


def test_every_attack_states_a_safe_simulation(attacks):
    for record in attacks.all():
        assert len(record.safe_simulation) > 20
        assert "simulat" in record.safe_simulation.lower()


def test_attack_ids_are_unique_and_sorted_stable(attacks):
    ids = [a.id for a in attacks.all()]
    assert len(ids) == len(set(ids))


def test_every_attack_has_a_description_and_expected_behavior(attacks):
    for record in attacks.all():
        assert len(record.description) > 20, record.id
        assert len(record.expected_behavior) > 10, record.id


# ---------------------------------------------------------------------------
# Targets resolve to real simulated tools
# ---------------------------------------------------------------------------


def test_target_actions_reference_registered_tools_and_actions(attacks):
    registry = ToolRegistry()
    for record in attacks.all():
        tool = record.target_action.tool
        assert tool in registry, f"{record.id}: unknown tool {tool}"
        assert record.target_action.action in registry.spec(tool).actions, (
            f"{record.id}: {tool}.{record.target_action.action} does not exist"
        )


def test_delivery_channels_map_to_registered_tools(attacks):
    registry = ToolRegistry()
    for record in attacks.all():
        tool = CHANNEL_TO_TOOL.get(record.delivery_channel.value, record.delivery_channel.value)
        assert tool in registry, f"{record.id}: channel {record.delivery_channel} has no tool"


def test_high_risk_targets_are_actually_high_risk(attacks):
    registry = ToolRegistry()
    for record in attacks.all():
        actual = registry.permission_for(record.target_action.tool, record.target_action.action)
        assert actual.rank >= 1, f"{record.id} targets a READ_ONLY action"


# ---------------------------------------------------------------------------
# Corpus files on disk
# ---------------------------------------------------------------------------


def test_corpus_files_are_valid_json(settings):
    files = sorted(settings.attacks_dir.glob("*.json"))
    assert files, "no attack corpus files found"
    for path in files:
        data = json.loads(path.read_text(encoding="utf-8"))
        corpus = AttackCorpus.model_validate(data)
        assert corpus.attacks


def test_corpus_files_match_the_builder(settings):
    """The JSON corpus must be reproducible from scripts/build_corpus.py."""
    from scripts.build_corpus import check_corpora

    problems = check_corpora(settings.attacks_dir)
    assert not problems, f"corpus out of date: {problems}"


def test_json_schemas_exist(settings):
    schema_dir = settings.schemas_dir
    for name in (
        "attack.schema.json", "attack_corpus.schema.json",
        "task.schema.json", "task_corpus.schema.json",
    ):
        assert (schema_dir / name).exists(), f"missing {name}"


# ---------------------------------------------------------------------------
# Repository behaviour
# ---------------------------------------------------------------------------


def test_select_by_type(attacks):
    subset = attacks.select(attack_types=["obfuscation"])
    assert subset and all(a.attack_type is AttackType.OBFUSCATION for a in subset)


def test_select_by_channel(attacks):
    subset = attacks.select(delivery_channels=["email"])
    assert subset and all(a.delivery_channel is DeliveryChannel.EMAIL for a in subset)


def test_select_by_severity(attacks):
    subset = attacks.select(severities=["critical"])
    assert subset and all(a.severity is Severity.CRITICAL for a in subset)


def test_select_multiple_filters_are_anded(attacks):
    subset = attacks.select(attack_types=["obfuscation"], severities=["critical"])
    assert all(
        a.attack_type is AttackType.OBFUSCATION and a.severity is Severity.CRITICAL for a in subset
    )


def test_select_unknown_id_raises(attacks):
    with pytest.raises(AttackNotFoundError):
        attacks.select(attack_ids=["DOES-NOT-EXIST"])


def test_unknown_attack_lookup_raises(attacks):
    with pytest.raises(AttackNotFoundError) as excinfo:
        attacks.get("NOPE")
    assert "NOPE" in str(excinfo.value)


def test_stats_are_consistent(attacks):
    stats = attacks.stats()
    assert stats["total"] == len(attacks)
    assert sum(stats["by_attack_type"].values()) == len(attacks)
    assert sum(stats["by_delivery_channel"].values()) == len(attacks)
    assert sum(stats["by_severity"].values()) == len(attacks)


def test_malformed_corpus_raises_corpus_error(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text("{not json", encoding="utf-8")
    with pytest.raises(CorpusError):
        AttackRepository.from_directory(tmp_path)


def test_schema_violation_raises_corpus_error(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps({"attacks": [{"id": "X"}]}), encoding="utf-8")
    with pytest.raises(CorpusError):
        AttackRepository.from_directory(tmp_path)


def test_empty_directory_raises(tmp_path):
    with pytest.raises(CorpusError):
        AttackRepository.from_directory(tmp_path)


def test_missing_directory_raises(tmp_path):
    with pytest.raises(CorpusError):
        AttackRepository.from_directory(tmp_path / "nope")


def test_duplicate_ids_rejected(attacks):
    with pytest.raises(DuplicateRecordError):
        AttackRepository([attacks.get("GH-001"), attacks.get("GH-001")])


def test_attack_applies_to_task_helper(attacks):
    assert attacks.get("GH-001").applies_to("T-001") is True
    constrained = attacks.get("GH-001").model_copy(update={"compatible_tasks": ["T-002"]})
    assert constrained.applies_to("T-001") is False
    assert constrained.applies_to("T-002") is True


# ---------------------------------------------------------------------------
# Task corpus
# ---------------------------------------------------------------------------


def test_task_corpus_loads(tasks):
    assert len(tasks) >= 5


def test_every_task_defines_allowed_tools_and_criteria(tasks):
    for task in tasks.all():
        assert task.allowed_tools, task.task_id
        assert task.criteria, task.task_id
        assert task.reference_plan, task.task_id


def test_every_task_forbids_at_least_one_action(tasks):
    for task in tasks.all():
        assert task.forbidden_actions, f"{task.task_id} forbids nothing"


def test_task_policy_has_no_allow_forbid_overlap(tasks):
    for task in tasks.all():
        overlap = task.allowed_action_keys() & task.forbidden_action_keys()
        assert not overlap, f"{task.task_id}: {overlap}"


def test_task_policy_tools_are_registered(tasks):
    registry = ToolRegistry()
    for task in tasks.all():
        for policy in list(task.allowed_actions) + list(task.forbidden_actions):
            assert policy.tool in registry
            assert policy.action in registry.spec(policy.tool).actions


def test_unknown_task_raises(tasks):
    with pytest.raises(TaskNotFoundError):
        tasks.get("T-NOPE")


def test_supporting_tasks_match_channel(attacks, tasks):
    supporting = tasks.supporting(attacks.get("GH-003"))  # database channel
    assert supporting
    assert all("database" in [c.value for c in t.channels] for t in supporting)


def test_task_criteria_weights_are_positive(tasks):
    for task in tasks.all():
        for criterion in task.criteria:
            assert criterion.weight > 0


def test_task_reference_plan_points_at_real_actions(tasks):
    registry = ToolRegistry()
    for task in tasks.all():
        for step in task.reference_plan:
            assert step.tool in registry
            assert step.action in registry.spec(step.tool).actions


def test_task_corpus_file_is_valid(settings):
    path = settings.tasks_dir / "tasks.json"
    assert path.exists()
    data = json.loads(path.read_text(encoding="utf-8"))
    assert len(data["tasks"]) >= 5


def test_attack_record_rejects_bad_regex():
    with pytest.raises(Exception):
        AttackRecord.model_validate(
            {
                "id": "X", "name": "x", "description": "d", "attack_type": "obfuscation",
                "delivery_channel": "web", "payload": "p", "injection_position": "end",
                "format": "visible_text",
                "target_action": {"tool": "email", "action": "send_email"},
                "difficulty": "easy", "severity": "low",
                "expected_behavior": "e", "safe_simulation": "s",
                "success_criteria": [{"kind": "response_matches", "pattern": "[unclosed", "regex": True}],
            }
        )


def test_task_definition_rejects_unknown_field():
    with pytest.raises(Exception):
        TaskDefinition.model_validate(
            {
                "task_id": "T-X", "name": "n", "description": "d", "user_prompt": "u",
                "expected_outcome": "o", "bogus_field": 1,
            }
        )