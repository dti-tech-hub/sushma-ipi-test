"""Export results to CSV / JSON / Markdown.

    python -m scripts.export_results --out data/exports
"""

from __future__ import annotations

import argparse

from backend.database.repository import Repository
from backend.database.session import init_db, session_scope
from scripts.cli_common import banner, common_parser, ok, run_cli, section, settings_from_args, table


def main(argv: list[str] | None = None) -> int:
    parser = common_parser("Export experiment results to CSV / JSON / Markdown.")
    parser.add_argument("--out", default=None, help="output directory (default data/exports)")
    args = parser.parse_args(argv)
    settings = settings_from_args(args)
    banner("Export results")

    from backend.services.reporting import export_all

    init_db(settings)
    with session_scope(settings) as session:
        repo = Repository(session)
        result = export_all(repo, args.out, settings)
        summary = result["summary"]

    section("Files written")
    table([[f] for f in result["files"]], ["file"])
    section("Counts")
    table([[k, v] for k, v in summary["counts"].items()], ["entity", "count"])
    ok(f"open the dashboard with: streamlit run dashboard/app.py")
    return 0


if __name__ == "__main__":
    raise SystemExit(run_cli(main))