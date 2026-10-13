"""Shared CLI helpers: argument parsing, banners, consistent error output."""

from __future__ import annotations

import argparse
import sys
from typing import Any, Sequence

from backend.models.errors import TestRangeError
from backend.services.config import Settings, load_settings
from backend.services.logging_setup import configure_logging

BANNER = r"""
  _  _ _____   ___      _                _
 | \| |_   _\ / _ \ ___| |__   ___ _ __ | |_ ___  __ _
 | . ` | | | | | | / __| '_ \ / _ \ '_ \| __/ _ \/ _` |
 |_|\_| |_| |_| |_| \__ \ | | |  __/ | | | ||  __/ (_| |
    \___/\___/ \___/|___/_| |_|\___|_| |_|\__\___|\__,_|
  I n d i r e c t   P r o m p t   I n j e c t i o n   T e s t   R a n g e
"""

RESET = "\033[0m"
BOLD = "\033[1m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
RED = "\033[31m"
CYAN = "\033[36m"


def banner(title: str) -> None:
    print(BANNER)
    print(f"{BOLD}{title}{RESET}")
    print("-" * 78)


def ok(msg: str) -> None:
    print(f"{GREEN}[ok]{RESET} {msg}")


def warn(msg: str) -> None:
    print(f"{YELLOW}[warn]{RESET} {msg}")


def fail(msg: str) -> None:
    print(f"{RED}[fail]{RESET} {msg}")


def info(msg: str) -> None:
    print(f"{CYAN}[info]{RESET} {msg}")


def section(title: str) -> None:
    print()
    print(f"{BOLD}== {title} =={RESET}")


def table(rows: Sequence[Sequence[Any]], headers: Sequence[str]) -> None:
    """Print an aligned plain-text table (no third-party dependency)."""
    if not rows:
        print("  (no rows)")
        return
    columns = len(headers)
    widths = [len(str(h)) for h in headers]
    for row in rows:
        for index in range(columns):
            widths[index] = max(widths[index], len(str(row[index]) if index < len(row) else ""))
    line = "  " + "  ".join(str(h).ljust(widths[i]) for i, h in enumerate(headers))
    print(line)
    print("  " + "  ".join("-" * widths[i] for i in range(columns)))
    for row in rows:
        print("  " + "  ".join(str(row[i] if i < len(row) else "").ljust(widths[i]) for i in range(columns)))


def common_parser(description: str) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument("--config", default=None, help="path to a YAML config override")
    parser.add_argument("--db", default=None, help="override the SQLite database path")
    parser.add_argument("--seed", type=int, default=None, help="override the base random seed")
    parser.add_argument("--reps", type=int, default=None, help="override repetitions per cell")
    parser.add_argument("--quiet", action="store_true", help="suppress the structured log stream")
    return parser


def settings_from_args(args: argparse.Namespace) -> Settings:
    overrides: dict[str, Any] = {}
    if getattr(args, "db", None):
        overrides["paths"] = {"db_path": args.db}
    if getattr(args, "seed", None) is not None:
        overrides["execution"] = {"random_seed": args.seed}
    if getattr(args, "reps", None) is not None:
        overrides["execution"] = {**overrides.get("execution", {}), "repetitions": args.reps}
    settings = load_settings(getattr(args, "config", None), overrides=overrides)
    settings.ensure_directories()
    configure_logging(
        settings, force=True
    ) if getattr(args, "quiet", False) else configure_logging(settings)
    return settings


def run_cli(main_func) -> int:
    """Wrap a CLI entry point with consistent, readable error output."""
    try:
        return int(main_func() or 0)
    except TestRangeError as exc:
        fail(f"{exc.code}: {exc.message}")
        if exc.details:
            print(f"       details: {exc.details}")
        return 2
    except KeyboardInterrupt:  # pragma: no cover - interactive
        warn("interrupted by user")
        return 130
    except Exception as exc:  # noqa: BLE001 - CLI boundary
        fail(f"unexpected {type(exc).__name__}: {exc}")
        return 1


__all__ = [
    "banner",
    "ok",
    "warn",
    "fail",
    "info",
    "section",
    "table",
    "common_parser",
    "settings_from_args",
    "run_cli",
]