"""Synchronise the JSON corpora into the SQLite catalogue tables.

    python -m scripts.sync_corpus

The experiment runner only catalogues the attacks/tasks it actually executes.
This utility loads the *entire* corpus so the dashboard's Attack Corpus page and
the ``attack_corpus.csv`` export reflect every record, not just the sampled ones.
"""

from __future__ import annotations

from backend.attacks.loader import get_attacks, get_tasks
from backend.database.repository import Repository
from backend.database.session import init_db, session_scope
from backend.defenses import DEFENSE_ORDER, get_defense
from scripts.cli_common import banner, common_parser, ok, run_cli, section, settings_from_args, table


def sync(settings, *, include_corpus: bool = True) -> dict[str, int]:
    """Populate models/defenses/tasks/attacks reference tables."""
    init_db(settings)
    counts = {"attacks": 0, "tasks": 0, "defenses": 0}
    with session_scope(settings) as session:
        repo = Repository(session)
        for name in DEFENSE_ORDER:
            repo.upsert_defense(get_defense(name))
        counts["defenses"] = len(DEFENSE_ORDER)
        if include_corpus:
            attacks = get_attacks(settings)
            tasks = get_tasks(settings)
            for task in tasks.all():
                repo.upsert_task(task)
            for attack in attacks.all():
                repo.upsert_attack(attack, attacks.corpus_version)
            counts["attacks"] = len(attacks)
            counts["tasks"] = len(tasks)
    return counts


def main(argv: list[str] | None = None) -> int:
    parser = common_parser("Sync the JSON corpora into the SQLite catalogue tables.")
    parser.add_argument("--no-attacks", action="store_true", help="only sync defenses")
    args = parser.parse_args(argv)
    settings = settings_from_args(args)

    banner("Corpus synchronisation")
    counts = sync(settings, include_corpus=not args.no_attacks)
    section("Rows written")
    table([[k, v] for k, v in counts.items()], ["table", "rows"])
    ok(f"catalogue synced into {settings.db_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(run_cli(main))