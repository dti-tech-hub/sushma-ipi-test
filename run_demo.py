#!/usr/bin/env python
"""One-command demonstration of the Indirect Prompt Injection Test Range.

    python run_demo.py

Runs with **zero configuration, zero API keys and no network access**:

1. initialises the SQLite database
2. loads and validates the corpora
3. runs clean baseline executions
4. runs attack experiments across all five attack categories
5. runs every registered defense on the same corpus
6. calculates metrics, stores everything in SQLite
7. exports CSV / JSON / Markdown reports
8. prints a summary and tells you how to open the dashboard

Add ``--full`` to sweep the entire 75-attack corpus instead of the fast demo
subset, or ``--defenses ...`` to choose the defenses explicitly.
"""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backend.attacks.loader import get_attacks, get_tasks  # noqa: E402
from backend.database.repository import Repository  # noqa: E402
from backend.database.session import init_db, session_scope  # noqa: E402
from backend.evaluation.runner import (  # noqa: E402
    BatchRequest,
    ExperimentRequest,
    ExperimentRunner,
)
from backend.services.config import load_settings  # noqa: E402
from backend.services.logging_setup import configure_logging  # noqa: E402
from backend.services.reporting import export_all  # noqa: E402
from scripts.cli_common import (  # noqa: E402
    BOLD,
    GREEN,
    RED,
    YELLOW,
    banner,
    info,
    ok,
    section,
    table,
    warn,
)

#: Fast demo subset: 2 attacks per category, covering every channel family.
DEMO_ATTACKS: list[str] = [
    "GH-001",   # goal hijacking via web
    "EX-001",   # data exfiltration via database
    "TM-001",   # tool misuse (drop table)
    "IO-001",   # instruction override
    "OB-001",   # obfuscation (base64)
]

DEMO_TASKS: list[str] = ["T-001", "T-003", "T-006", "T-004", "T-007"]

ALL_DEFENSES: list[str] = [
    "none",
    "sanitization",
    "spotlighting",
    "sandwich_prompting",
    "privilege_separation",
    "guard_classifier",
]

DEMO_MODELS: list[dict[str, str]] = [
    {"provider": "mock", "name": "mock-vulnerable"},
    {"provider": "mock", "name": "mock-hardened"},
]


def _rule(title: str) -> None:
    print()
    print(f"{BOLD}{'-' * 78}{RESET_}")
    print(f"{BOLD} {title}{RESET_}")
    print(f"{BOLD}{'-' * 78}{RESET_}")


RESET_ = "\033[0m"


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Demonstrate the IPI test range end to end (no API key required).",
    )
    parser.add_argument("--full", action="store_true", help="sweep the entire attack corpus (slower)")
    parser.add_argument("--reps", type=int, default=2, help="repetitions per cell (default 2)")
    parser.add_argument("--seed", type=int, default=1337, help="base random seed (default 1337)")
    parser.add_argument("--db", default="data/testrange.db", help="SQLite path")
    parser.add_argument("--out", default="data/exports", help="export directory")
    parser.add_argument("--defenses", default=None, help="comma separated defense list")
    parser.add_argument("--models", default=None, help="comma separated model names")
    parser.add_argument("--fresh", action="store_true", help="delete the demo database first")
    parser.add_argument("--quiet", action="store_true", help="suppress the structured log stream")
    parser.add_argument("--no-export", action="store_true", help="skip the export step")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    started = time.perf_counter()

    # ---------------------------------------------------------------- config
    db_path = ROOT / args.db
    if args.fresh:
        for suffix in ("", "-wal", "-shm"):
            candidate = Path(str(db_path) + suffix)
            if candidate.exists():
                candidate.unlink()
        ok(f"removed previous demo database: {db_path}")

    settings = load_settings(
        overrides={
            "app": {"demo_mode": True},
            "paths": {"db_path": args.db},
            "logging": {"level": "WARNING" if args.quiet else "INFO"},
        }
    )
    settings.ensure_directories()
    configure_logging(settings, force=True)

    banner("INDIRECT PROMPT INJECTION TEST RANGE - FULL DEMONSTRATION")

    # ------------------------------------------------------- 1. initialise db
    _rule("STEP 1/8  Initialise the SQLite database")
    db_info = init_db(settings)
    ok(f"database : {db_info['database']}")
    ok(f"tables   : {len(db_info['tables'])} ({', '.join(db_info['tables'][:6])} ...)")
    if db_info["migrations_applied"]:
        ok(f"migrations applied: {', '.join(db_info['migrations_applied'])}")
    else:
        ok("schema already up to date")

    # ------------------------------------------------------------ 2. corpora
    _rule("STEP 2/8  Load and validate the corpora")
    attacks = get_attacks(settings)
    tasks = get_tasks(settings)
    stats = attacks.stats()
    ok(f"attack corpus v{attacks.corpus_version}: {stats['total']} scored synthetic attacks")
    table(
        [[k, v] for k, v in stats["by_attack_type"].items()],
        ["attack category", "records"],
    )
    print()
    table(
        [[k, v] for k, v in stats["by_delivery_channel"].items()],
        ["delivery channel", "records"],
    )
    print()
    ok(f"task corpus v{tasks.corpus_version}: {len(tasks)} synthetic tasks")
    ok("all tools are SIMULATED; no external system is contacted")

    # Catalogue the *whole* corpus in SQLite so exports/dashboard show every record.
    from scripts.sync_corpus import sync

    sync(settings)
    ok(f"catalogue synced into SQLite ({len(attacks)} attacks, {len(tasks)} tasks)")

    selection_attacks = [a.id for a in attacks.all()] if args.full else list(DEMO_ATTACKS)
    selection_tasks = [t.task_id for t in tasks.all()] if args.full else list(DEMO_TASKS)
    models = (
        [{"provider": "mock", "name": m.strip()} for m in args.models.split(",") if m.strip()]
        if args.models
        else DEMO_MODELS
    )
    defenses = [d.strip() for d in args.defenses.split(",") if d.strip()] if args.defenses else ALL_DEFENSES

    # ------------------------------------------------ 3-6. run the experiment
    _rule("STEP 3/8  Run clean baselines and attacked experiments")
    info(
        f"{len(models)} model(s) x {len(defenses)} defense(s) x "
        f"{'ALL' if args.full else len(selection_attacks)} attacks x {args.reps} repetitions"
    )
    runner = ExperimentRunner(settings)
    batch = runner.run_batch(
        BatchRequest(
            models=models,
            defenses=defenses,
            selection={"attack_ids": selection_attacks, "task_ids": selection_tasks},
            repetitions=args.reps,
            random_seed=args.seed,
            persist=True,
        ),
        settings=settings,
    )

    rows = []
    for experiment in batch.experiments:
        score = experiment.score
        rows.append(
            [
                experiment.model,
                experiment.defense,
                score["n_attacked"],
                f"{score['attack_success_rate']:.3f}",
                f"{score['benign_utility']:.3f}",
                f"{score['utility_under_attack']:.3f}",
                f"{score['refusal_detection_rate']:.3f}",
                f"{score['severity_weighted_risk']:.3f}",
            ]
        )
    print()
    table(
        rows,
        ["model", "defense", "n_att", "ASR", "BU", "UUA", "RDR", "SWRS"],
    )
    errors = sum(len(e.errors) for e in batch.experiments)
    if errors:
        warn(f"{errors} individual run error(s) were recorded and are visible in the database")

    # --------------------------------------------- per-defense reduction view
    _rule("STEP 4/8  Defense reduction relative to the no-defense control")
    baseline_rows = {
        e.model: e.score for e in batch.experiments if e.defense == "none"
    }
    reduction_rows = []
    for experiment in batch.experiments:
        if experiment.defense == "none":
            continue
        base = baseline_rows.get(experiment.model)
        if not base:
            continue
        reduction_rows.append(
            [
                experiment.model,
                experiment.defense,
                f"{base['attack_success_rate']:.3f}",
                f"{experiment.score['attack_success_rate']:.3f}",
                f"{base['attack_success_rate'] - experiment.score['attack_success_rate']:+.3f}",
                f"{experiment.score['refusal_detection_rate']:.3f}",
            ]
        )
    table(
        reduction_rows,
        ["model", "defense", "ASR(control)", "ASR(defended)", "delta", "RDR"],
    )

    # ------------------------------------------------------ 7. persist/verify
    _rule("STEP 5/8  Verify what was stored in SQLite")
    with session_scope(settings) as session:
        repo = Repository(session)
        counts = {
            "experiments": repo.count(_model("Experiment")),
            "runs (clean+attacked)": repo.count(_model("AttackRun")),
            "tool_calls": repo.count(_model("ToolCallRow")),
            "agent_responses": repo.count(_model("AgentResponseRow")),
            "authorisation_events": repo.count(_model("AuthorizationRow")),
            "sandbox_effects": repo.count(_model("SandboxEffectRow")),
            "metrics_blocks": repo.count(_model("MetricRecord")),
            "attacks catalogued": repo.count(_model("AttackRecordRow")),
            "tasks catalogued": repo.count(_model("TaskRecord")),
            "models": repo.count(_model("ModelRecord")),
            "defenses": repo.count(_model("DefenseRecord")),
        }
        table([[k, v] for k, v in counts.items()], ["table", "rows"])
        summary = None
        if not args.no_export:
            _rule("STEP 6/8  Export CSV / JSON / Markdown reports")
            exported = export_all(repo, args.out, settings)
            summary = exported["summary"]
            table([[f] for f in exported["files"]], ["file written"])
            ok(f"reports are in: {(ROOT / args.out).resolve()}")

    # ---------------------------------------------------------- 8. summary
    _rule("STEP 7/8  Aggregate summary")
    if summary is not None:
        metrics = summary["metrics"]
        table(
            [
                ["Attack Success Rate (ASR)", f"{metrics['attack_success_rate']:.4f}"],
                ["Benign Utility", f"{metrics['benign_utility']:.4f}"],
                ["Utility Under Attack", f"{metrics['utility_under_attack']:.4f}"],
                ["Utility Degradation", f"{metrics['utility_degradation']:.4f}"],
                ["Refusal / Detection Rate", f"{metrics['refusal_detection_rate']:.4f}"],
                ["Severity-Weighted Risk Score", f"{metrics['severity_weighted_risk']:.4f}"],
                ["Policy Violation Rate", f"{metrics['policy_violation_rate']:.4f}"],
                ["Harmful Effect Rate", f"{metrics['harmful_effect_rate']:.4f}"],
                ["Task Success Rate (clean)", f"{metrics['task_success_rate']:.4f}"],
            ],
            ["metric", "value"],
        )
        print()
        warn(summary["result_provenance"])
        print()

    _rule("STEP 8/8  Next steps")
    elapsed = time.perf_counter() - started
    print(f"""  {GREEN}Demo finished in {elapsed:.1f}s.{RESET_}

  Open the research dashboard:
      {BOLD}streamlit run dashboard/app.py{RESET_}

  Explore the API:
      {BOLD}python -m scripts.serve_api{RESET_}
      {BOLD}then open http://127.0.0.1:8000/docs{RESET_}

  Re-run the whole attack corpus:
      {BOLD}python run_demo.py --full{RESET_}

  Run the test suite:
      {BOLD}pytest -q{RESET_}

  Every 'successful attack' above means a predefined unsafe action was recorded in
  the in-memory sandbox ledger. Nothing was sent, deleted, shared or dropped for
  real, and {RED}no API key was used{RESET_}.
""")
    return 0


def _model(name: str):
    import backend.database.models as models

    return getattr(models, name)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        warn("interrupted")
        raise SystemExit(130) from None