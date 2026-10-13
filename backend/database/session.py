"""Engine, session and lightweight migration handling (Module 8).

SQLite file is created on demand. ``PRAGMA foreign_keys=ON`` keeps referential
integrity, and ``init_db`` is idempotent so it can be called from the CLI, the
API startup hook and the test suite.
"""

from __future__ import annotations

import logging
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

from sqlalchemy import create_engine, event, inspect, text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from backend.database.models import Base
from backend.models.errors import DatabaseError
from backend.services.config import Settings, get_settings
from backend.services.logging_setup import get_logger, log_event

_lock = threading.Lock()
_engines: dict[str, Engine] = {}
_factories: dict[str, sessionmaker[Session]] = {}

#: Tables created by :meth:`Base.metadata.create_all`, in dependency order.
EXPECTED_TABLES: tuple[str, ...] = (
    "models",
    "defenses",
    "tasks",
    "attacks",
    "experiment_configs",
    "experiments",
    "attack_runs",
    "tool_calls",
    "agent_responses",
    "authorization_events",
    "sandbox_effects",
    "metrics",
)

#: Incremental migrations. Each entry: table -> set of columns that must exist.
#: Adding a column to an existing SQLite file is handled by ALTER TABLE, so an
#: older database file upgrades in place without data loss.
MIGRATIONS: tuple[tuple[str, dict[str, str]], ...] = (
    ("attack_runs", {"detection_reason": "TEXT DEFAULT ''"}),
    ("attack_runs", {"hijacked": "BOOLEAN DEFAULT 0"}),
    ("experiments", {"provenance_note": "TEXT DEFAULT ''"}),
    ("experiments", {"corpus_versions": "JSON"}),
    ("models", {"attributes": "JSON"}),
)


def _engine_key(db_path: Path) -> str:
    """Single canonical key for an engine/session-factory pair.

    ``get_engine`` and ``get_session_factory`` must agree on this, otherwise a
    caller that passes an explicit ``path`` gets a KeyError.
    """
    return str(db_path.resolve())


def get_engine(settings: Settings | None = None, *, path: str | Path | None = None) -> Engine:
    """Return (and memoise) an engine for the configured SQLite file."""
    settings = settings or get_settings()
    db_path = Path(path) if path else settings.db_path
    db_path.parent.mkdir(parents=True, exist_ok=True)
    key = _engine_key(db_path)

    with _lock:
        if key not in _engines:
            engine = create_engine(
                f"sqlite:///{key}",
                future=True,
                echo=False,
                connect_args={"check_same_thread": False, "timeout": 30},
            )

            @event.listens_for(engine, "connect")
            def _set_sqlite_pragma(dbapi_connection, _record):  # pragma: no cover - driver hook
                cursor = dbapi_connection.cursor()
                cursor.execute("PRAGMA foreign_keys=ON")
                cursor.execute("PRAGMA journal_mode=WAL")
                cursor.execute("PRAGMA synchronous=NORMAL")
                cursor.close()

            _engines[key] = engine
            _factories[key] = sessionmaker(bind=engine, expire_on_commit=False, future=True)
        return _engines[key]


def get_session_factory(settings: Settings | None = None, *, path: str | Path | None = None) -> sessionmaker[Session]:
    settings = settings or get_settings()
    db_path = Path(path) if path else settings.db_path
    get_engine(settings, path=db_path)
    return _factories[_engine_key(db_path)]


@contextmanager
def session_scope(
    settings: Settings | None = None, *, path: str | Path | None = None
) -> Iterator[Session]:
    """Transactional session context manager."""
    factory = get_session_factory(settings, path=path)
    session = factory()
    try:
        yield session
        # A handler may have flushed and caught an IntegrityError, which leaves
        # the session needing a rollback; committing then would raise a
        # confusing PendingRollbackError.
        if session.is_active and not session.in_nested_transaction():
            try:
                session.commit()
            except Exception:  # pragma: no cover - defensive
                session.rollback()
                raise
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def init_db(settings: Settings | None = None, *, path: str | Path | None = None, force: bool = False) -> dict:
    """Create (or upgrade) the SQLite schema. Idempotent."""
    settings = settings or get_settings()
    engine = get_engine(settings, path=path)
    logger = get_logger("database")
    try:
        Base.metadata.create_all(engine)
        applied = _apply_migrations(engine) if not force else []
        existing = set(inspect(engine).get_table_names())
    except Exception as exc:  # pragma: no cover - surfaced as a typed error
        raise DatabaseError(f"Failed to initialise the database: {exc}") from exc

    missing = [t for t in EXPECTED_TABLES if t not in existing]
    if missing:
        raise DatabaseError(f"Schema incomplete after init, missing tables: {missing}")
    log_event(
        logger,
        logging.INFO,
        "database_initialised",
        db_path=str(path or settings.db_path),
        tables=len(existing),
        migrations_applied=len(applied),
    )
    return {
        "database": str(path or settings.db_path),
        "tables": sorted(existing),
        "migrations_applied": applied,
        "already_initialised": not force,
    }


def _apply_migrations(engine: Engine) -> list[str]:
    applied: list[str] = []
    inspector = inspect(engine)
    tables = set(inspector.get_table_names())
    for table, columns in MIGRATIONS:
        if table not in tables:
            continue
        existing = {c["name"] for c in inspector.get_columns(table)}
        for column, ddl in columns.items():
            if column in existing:
                continue
            with engine.begin() as conn:
                conn.execute(text(f"ALTER TABLE {table} ADD COLUMN {column} {ddl}"))
            applied.append(f"{table}.{column}")
    return applied


def reset_db_cache() -> None:
    """Dispose engines (used by tests that point at a temporary file)."""
    with _lock:
        for engine in _engines.values():
            engine.dispose()
        _engines.clear()
        _factories.clear()


__all__ = [
    "get_engine",
    "get_session_factory",
    "session_scope",
    "init_db",
    "reset_db_cache",
    "EXPECTED_TABLES",
    "MIGRATIONS",
]