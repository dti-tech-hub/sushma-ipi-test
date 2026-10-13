"""Shared pytest fixtures.

Every test runs against a **temporary SQLite file** and the repository's real
JSON corpora, so tests never touch ``data/testrange.db``.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from backend.attacks.loader import get_attacks, get_tasks
from backend.database.repository import Repository
from backend.database.session import init_db, reset_db_cache, session_scope
from backend.defenses import get_defense
from backend.services.config import load_settings
from backend.services.logging_setup import configure_logging
from backend.tools.registry import ToolRegistry

PROJECT_ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(scope="session", autouse=True)
def _isolated_environment(tmp_path_factory):
    """Point every settings singleton at a throwaway database and log dir."""
    tmp = tmp_path_factory.mktemp("testrange")
    os.environ["TESTRANGE_PATHS__DB_PATH"] = str(tmp / "test.db")
    os.environ["TESTRANGE_PATHS__LOGS_DIR"] = str(tmp / "logs")
    os.environ["TESTRANGE_PATHS__EXPORT_DIR"] = str(tmp / "exports")
    os.environ["TESTRANGE_LOGGING__CONSOLE"] = "false"
    os.environ["TESTRANGE_LOGGING__LEVEL"] = "WARNING"
    from backend.services.config import reset_settings_cache

    reset_settings_cache()
    settings = load_settings()
    settings.ensure_directories()
    configure_logging(settings, force=True)
    init_db(settings)
    yield
    reset_db_cache()
    for key in list(os.environ):
        if key.startswith("TESTRANGE_"):
            os.environ.pop(key, None)
    reset_settings_cache()


@pytest.fixture()
def settings(_isolated_environment):
    from backend.services.config import get_settings

    return get_settings()


@pytest.fixture()
def repo(settings):
    """A repository bound to a fresh, committed session."""
    factory = __import__("backend.database.session", fromlist=["get_session_factory"]).get_session_factory(settings)
    session = factory()
    try:
        yield Repository(session)
        session.commit()
    finally:
        session.close()


@pytest.fixture(scope="session")
def attacks():
    return get_attacks()


@pytest.fixture(scope="session")
def tasks():
    return get_tasks()


@pytest.fixture()
def registry():
    return ToolRegistry()


@pytest.fixture()
def sample_task(tasks):
    return tasks.get("T-001")


@pytest.fixture()
def sample_attack(attacks):
    return attacks.get("GH-001")


@pytest.fixture()
def clean_result(registry):
    return registry.invoke("web_search", "search", {"query": "aerolite drone x2 review"})


@pytest.fixture()
def defense_none():
    return get_defense("none")


__all__ = ["PROJECT_ROOT"]