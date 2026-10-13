"""Validate the on-disk corpora against the Pydantic schemas.

    python -m scripts.validate_corpus
"""

from __future__ import annotations

import json
from collections import Counter

from backend.attacks.loader import get_attacks, get_tasks
from backend.models.errors import TestRangeError
from backend.tools.registry import ToolRegistry
from scripts.cli_common import banner, ok, run_cli, section, settings_from_args, table, warn
from backend.services.config import get_settings


def main(argv: list[str] | None = None) -> int:
    parser = __import__("argparse").ArgumentParser(description="Validate the attack and task corpora.")
    parser.add_argument("--config", default=None)
    parser.add_argument("--db", default=None)
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args(argv)
    settings = settings_from_args(args)

    banner("Corpus validation")
    problems: list[str] = []

    attacks = get_attacks(settings)
    tasks = get_tasks(settings)
    registry = ToolRegistry()
    #: Delivery channel -> the tool that carries it (see ToolRegistry.TOOL_FACTORIES).
    channel_to_tool = {
        "web": "web_search",
        "browser": "browser",
        "email": "email",
        "file": "file_reader",
        "calendar": "calendar",
        "database": "database",
        "api": "code_interpreter",
    }

    section("Counts")
    ok(f"attacks: {len(attacks)}")
    ok(f"tasks:   {len(tasks)}")

    # -- structural invariants ------------------------------------------
    for record in attacks.all():
        if not record.success_criteria:
            problems.append(f"{record.id}: no success criteria")
        tool = channel_to_tool.get(record.delivery_channel.value, record.delivery_channel.value)
        if tool not in registry:
            problems.append(f"{record.id}: delivery channel {record.delivery_channel.value} has no tool")
        elif record.target_action.tool not in registry:
            problems.append(f"{record.id}: target tool {record.target_action.tool} not registered")
        elif record.target_action.action not in registry.spec(record.target_action.tool).actions:
            problems.append(
                f"{record.id}: target action {record.target_action.key} not implemented by the tool"
            )
        if not record.safe_simulation:
            problems.append(f"{record.id}: missing safe_simulation statement")

    for task in tasks.all():
        for tool in task.allowed_tools:
            if tool not in registry:
                problems.append(f"{task.task_id}: allowed tool {tool} not registered")
        for action in list(task.allowed_actions) + list(task.forbidden_actions):
            if action.tool not in registry:
                problems.append(f"{task.task_id}: policy references unknown tool {action.tool}")
            elif action.action not in registry.spec(action.tool).actions:
                problems.append(f"{task.task_id}: policy references unknown action {action.key}")
        overlap = task.allowed_action_keys() & task.forbidden_action_keys()
        if overlap:
            problems.append(f"{task.task_id}: action both allowed and forbidden: {sorted(overlap)}")
        if not task.criteria:
            problems.append(f"{task.task_id}: no evaluation criteria")

    # -- unique ids -----------------------------------------------------
    ids = [a.id for a in attacks.all()]
    duplicates = [k for k, v in Counter(ids).items() if v > 1]
    if duplicates:
        problems.append(f"duplicate attack ids: {duplicates}")

    # -- distribution ---------------------------------------------------
    section("Distribution")
    stats = attacks.stats()
    table(
        [[key, value] for key, value in stats["by_attack_type"].items()],
        ["attack_type", "count"],
    )
    print()
    table(
        [[key, value] for key, value in stats["by_severity"].items()],
        ["severity", "count"],
    )
    print()
    table(
        [[key, value] for key, value in stats["by_delivery_channel"].items()],
        ["delivery_channel", "count"],
    )

    section("Result")
    if problems:
        for problem in problems[:40]:
            warn(problem)
        return 1
    ok(f"corpus is valid: {len(attacks)} attacks, {len(tasks)} tasks, 0 problems")
    ok(f"schemas: corpus/schemas/*.json (generated with `python -m scripts.export_schemas`)")
    return 0


if __name__ == "__main__":
    raise SystemExit(run_cli(main))