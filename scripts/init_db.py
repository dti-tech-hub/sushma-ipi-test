"""Create / upgrade the SQLite schema.

    python -m scripts.init_db
"""

from __future__ import annotations

import sys

from backend.database.session import init_db
from scripts.cli_common import banner, common_parser, ok, run_cli, settings_from_args, table


def main(argv: list[str] | None = None) -> int:
    parser = common_parser("Initialise the test range SQLite database.")
    parser.add_argument("--force", action="store_true", help="re-apply migrations even if up to date")
    args = parser.parse_args(argv)
    settings = settings_from_args(args)

    banner("SQLite initialisation")
    result = init_db(settings, force=args.force)
    ok(f"database: {result['database']}")
    ok(f"tables ({len(result['tables'])}): {', '.join(result['tables'])}")
    if result["migrations_applied"]:
        ok(f"migrations applied: {', '.join(result['migrations_applied'])}")
    else:
        ok("schema already up to date")
    return 0


if __name__ == "__main__":
    raise SystemExit(run_cli(main))