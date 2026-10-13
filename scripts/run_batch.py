"""Run a batch sweep: every model x every defense over a corpus selection.

    python -m scripts.run_batch --config configs/experiment_batch.yaml
    python -m scripts.run_batch --models mock-vulnerable mock-hardened --defenses none guard_classifier
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import yaml

from backend.evaluation.runner import BatchRequest, ExperimentRunner
from backend.services.config import PROJECT_ROOT
from scripts.cli_common import (
    banner,
    common_parser,
    fail,
    ok,
    run_cli,
    section,
    settings_from_args,
    table,
    warn,
)


def build_parser() -> argparse.ArgumentParser:
    parser = common_parser("Run a batch experiment sweep.")
    parser.add_argument("--models", default=None, help="comma separated model names")
    parser.add_argument("--provider", default="mock")
    parser.add_argument("--defenses", default=None, help="comma separated defenses")
    parser.add_argument("--tasks", default=None)
    parser.add_argument("--attacks", default=None)
    parser.add_argument("--types", default=None)
    parser.add_argument("--severities", default=None)
    parser.add_argument("--difficulties", default=None)
    parser.add_argument("--channels", default=None)
    parser.add_argument("--max-steps", type=int, default=None)
    parser.add_argument("--no-baseline", action="store_true")
    parser.add_argument("--no-persist", action="store_true")
    parser.add_argument("--batch-config", default=None, help="YAML batch profile")
    parser.add_argument("--json", action="store_true")
    return parser


def _split(value: str | None) -> list[str] | None:
    if not value:
        return None
    return [v.strip() for v in value.split(",") if v.strip()]


def _load_profile(path: str) -> dict:
    candidate = Path(path)
    if not candidate.is_absolute():
        candidate = PROJECT_ROOT / candidate
    if not candidate.exists():
        raise FileNotFoundError(f"Batch profile not found: {candidate}")
    return yaml.safe_load(candidate.read_text(encoding="utf-8")) or {}


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    settings = settings_from_args(args)
    profile = _load_profile(args.batch_config) if args.batch_config else {}
    banner("Batch experiment sweep")

    models = (
        [{"provider": m.strip(), "name": m.strip()} for m in (args.models or "").split(",") if m.strip()]
        or profile.get("models")
        or [{"provider": args.provider, "name": settings.model_name}]
    )
    defenses = (
        _split(args.defenses)
        or profile.get("defenses")
        or [settings.get("defense.default", "none")]
    )
    selection = {
        "task_ids": _split(args.tasks) or profile.get("selection", {}).get("task_ids"),
        "attack_ids": _split(args.attacks) or profile.get("selection", {}).get("attack_ids"),
        "attack_types": _split(args.types) or profile.get("selection", {}).get("attack_types"),
        "severities": _split(args.severities) or profile.get("selection", {}).get("severities"),
        "difficulties": _split(args.difficulties) or profile.get("selection", {}).get("difficulties"),
        "delivery_channels": _split(args.channels) or profile.get("selection", {}).get("delivery_channels"),
    }

    section("Plan")
    ok(f"{len(models)} model(s) x {len(defenses)} defense(s)")
    ok(f"models:   {', '.join(m.get('name', '?') for m in models)}")
    ok(f"defenses: {', '.join(defenses)}")

    result = ExperimentRunner(settings).run_batch(
        BatchRequest(
            models=models,
            defenses=defenses,
            selection=selection,
            repetitions=args.reps or (profile.get("execution") or {}).get("repetitions"),
            random_seed=args.seed if args.seed is not None else (profile.get("execution") or {}).get("random_seed"),
            max_steps=args.max_steps,
            include_baseline=not args.no_baseline,
            persist=not args.no_persist,
        ),
        settings=settings,
    )

    if args.json:
        print(json.dumps(result.to_dict(), indent=2, default=str))
        return 0

    section("Results")
    rows = []
    for experiment in result.experiments:
        score = experiment.score
        rows.append(
            [
                experiment.model,
                experiment.defense,
                score["n_attacked"],
                score["attack_success_rate"],
                score["benign_utility"],
                score["utility_under_attack"],
                score["refusal_detection_rate"],
                score["severity_weighted_risk"],
                experiment.experiment_uid or "-",
            ]
        )
    table(
        rows,
        ["model", "defense", "n_att", "ASR", "BU", "UUA", "RDR", "SWRS", "experiment"],
    )
    print()
    ok(f"{result.total_cells} (task, attack) cells in {result.total_seconds:.1f}s")
    for experiment in result.experiments:
        if experiment.errors:
            warn(f"{experiment.model}/{experiment.defense}: {len(experiment.errors)} run error(s)")
    if not rows:
        fail("no experiments were produced")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(run_cli(main))