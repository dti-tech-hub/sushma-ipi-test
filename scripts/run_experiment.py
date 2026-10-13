"""Run a single experiment from the command line.

    python -m scripts.run_experiment --defense guard_classifier --severities critical
"""

from __future__ import annotations

import argparse
import json

from backend.evaluation.runner import ExperimentRequest, ExperimentRunner
from scripts.cli_common import banner, common_parser, ok, run_cli, section, settings_from_args, table, warn


def build_parser() -> argparse.ArgumentParser:
    parser = common_parser("Run one experiment (clean baseline + attacked runs).")
    parser.add_argument("--tasks", default=None, help="comma separated task ids")
    parser.add_argument("--attacks", default=None, help="comma separated attack ids")
    parser.add_argument("--types", default=None, help="comma separated attack types")
    parser.add_argument("--severities", default=None, help="comma separated severities")
    parser.add_argument("--difficulties", default=None)
    parser.add_argument("--channels", default=None, help="comma separated delivery channels")
    parser.add_argument("--model", default=None)
    parser.add_argument("--provider", default=None)
    parser.add_argument("--defense", default="none")
    parser.add_argument("--max-steps", type=int, default=None)
    parser.add_argument("--no-baseline", action="store_true")
    parser.add_argument("--no-persist", action="store_true")
    parser.add_argument("--name", default="")
    parser.add_argument("--json", action="store_true", help="print the raw result JSON")
    return parser


def _split(value: str | None) -> list[str] | None:
    if not value:
        return None
    return [v.strip() for v in value.split(",") if v.strip()]


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    settings = settings_from_args(args)
    banner(f"Experiment: defense={args.defense}")

    request = ExperimentRequest(
        task_ids=_split(args.tasks),
        attack_ids=_split(args.attacks),
        attack_types=_split(args.types),
        severities=_split(args.severities),
        difficulties=_split(args.difficulties),
        delivery_channels=_split(args.channels),
        provider=args.provider,
        model=args.model,
        defense=args.defense,
        repetitions=args.reps,
        random_seed=args.seed,
        max_steps=args.max_steps,
        include_baseline=not args.no_baseline,
        persist=not args.no_persist,
        name=args.name,
    )

    result = ExperimentRunner(settings).run(request, settings=settings)
    if args.json:
        print(json.dumps(result.to_dict(), indent=2, default=str))
        return 0

    section("Plan")
    ok(
        f"{len(result.plan['tasks'])} task(s), {len(result.plan['attacks'])} attack(s), "
        f"{result.plan['cells']} cells x {result.repetitions} reps "
        f"(baseline + attack = {result.plan['cells'] * result.repetitions * 2} runs)"
    )
    for skipped in result.plan.get("skipped", [])[:10]:
        warn(f"skipped {skipped['attack_id']}: {skipped['reason']}")

    section("Metrics")
    score = result.score
    table(
        [
            ["Attack Success Rate (ASR)", score["attack_success_rate"]],
            ["Benign Utility", score["benign_utility"]],
            ["Utility Under Attack", score["utility_under_attack"]],
            ["Utility Degradation", score["utility_degradation"]],
            ["Refusal / Detection Rate", score["refusal_detection_rate"]],
            ["Severity-Weighted Risk", score["severity_weighted_risk"]],
            ["Policy Violation Rate", score["policy_violation_rate"]],
            ["Harmful Effect Rate", score["harmful_effect_rate"]],
            ["Task Success Rate (clean)", score["task_success_rate"]],
            ["Runs (clean / attacked)", f"{score['n_baseline']} / {score['n_attacked']}"],
        ],
        ["metric", "value"],
    )

    section("Provenance")
    warn(result.provenance_note)
    ok(f"experiment id: {result.experiment_uid}")
    ok(f"duration: {result.duration_ms / 1000:.1f}s")
    if result.errors:
        warn(f"{len(result.errors)} run error(s); first: {result.errors[0]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(run_cli(main))