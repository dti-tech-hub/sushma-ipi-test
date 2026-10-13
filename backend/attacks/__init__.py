"""Attack corpus: schemas, loader and the deterministic injection engine."""

from backend.attacks.injection import InjectionEngine, InjectionResult, inject_attack
from backend.attacks.loader import (
    AttackRepository,
    TaskRepository,
    clear_caches,
    get_attacks,
    get_tasks,
)
from backend.attacks.models import (
    AttackCorpus,
    AttackRecord,
    PredicateKind,
    SuccessPredicate,
    TargetAction,
)

__all__ = [
    "AttackRepository",
    "TaskRepository",
    "get_attacks",
    "get_tasks",
    "clear_caches",
    "AttackRecord",
    "AttackCorpus",
    "TargetAction",
    "SuccessPredicate",
    "PredicateKind",
    "InjectionEngine",
    "InjectionResult",
    "inject_attack",
]