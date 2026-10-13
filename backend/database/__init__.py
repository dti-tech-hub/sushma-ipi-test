"""SQLite persistence layer (Module 8)."""

from backend.database.models import (
    AgentResponseRow,
    AttackRecordRow,
    AttackRun,
    AuthorizationRow,
    Base,
    DefenseRecord,
    Experiment,
    ExperimentConfig,
    MetricRecord,
    ModelRecord,
    SandboxEffectRow,
    TaskRecord,
    ToolCallRow,
)
from backend.database.repository import Repository
from backend.database.session import (
    EXPECTED_TABLES,
    MIGRATIONS,
    get_engine,
    get_session_factory,
    init_db,
    reset_db_cache,
    session_scope,
)

__all__ = [
    "Base",
    "Repository",
    "get_engine",
    "get_session_factory",
    "session_scope",
    "init_db",
    "reset_db_cache",
    "EXPECTED_TABLES",
    "MIGRATIONS",
    "ModelRecord",
    "DefenseRecord",
    "TaskRecord",
    "AttackRecordRow",
    "ExperimentConfig",
    "Experiment",
    "AttackRun",
    "ToolCallRow",
    "AgentResponseRow",
    "AuthorizationRow",
    "SandboxEffectRow",
    "MetricRecord",
]