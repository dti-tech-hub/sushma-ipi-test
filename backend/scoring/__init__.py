"""Scoring engine: deterministic, documented, unit-tested metric formulas."""

from backend.scoring.metrics import (
    DEFAULT_SEVERITY_WEIGHTS,
    AggregateScore,
    RunScore,
    aggregate,
    attack_success_rate,
    benign_utility,
    defense_reduction,
    flatten,
    refusal_detection_rate,
    severity_weight,
    severity_weighted_risk,
    utility_cost,
    utility_under_attack,
)

__all__ = [
    "RunScore",
    "AggregateScore",
    "aggregate",
    "attack_success_rate",
    "benign_utility",
    "utility_under_attack",
    "refusal_detection_rate",
    "severity_weighted_risk",
    "severity_weight",
    "defense_reduction",
    "utility_cost",
    "flatten",
    "DEFAULT_SEVERITY_WEIGHTS",
]