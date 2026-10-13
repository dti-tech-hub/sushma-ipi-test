"""Defense registry.

``get_defense(name)`` is the only way the agent/runner obtains a defense, so the
set of defenses is explicit and enumerable in the API and dashboard.
"""

from __future__ import annotations

from typing import Any

from backend.defenses.base import Defense, DefenseContext, DefenseOutcome
from backend.defenses.guard_classifier import (
    GuardClassifier,
    GuardResult,
    GuardVerdict,
    MALICIOUS_THRESHOLD,
    SUSPICIOUS_THRESHOLD,
    classify_text,
)
from backend.defenses.guard_classifier_defense import GuardClassifierDefense
from backend.defenses.none_defense import NoDefense
from backend.defenses.privilege_separation import (
    DefaultAuthorizer,
    PrivilegeSeparationDefense,
    TRUSTED_SOURCES,
)
from backend.defenses.sanitization import SanitizationDefense
from backend.defenses.sandwich import SandwichPromptingDefense
from backend.defenses.spotlighting import SpotlightingDefense, extract_marked_spans
from backend.models.errors import ValidationError

DEFENSE_REGISTRY: dict[str, type[Defense]] = {
    NoDefense.name: NoDefense,
    SanitizationDefense.name: SanitizationDefense,
    SpotlightingDefense.name: SpotlightingDefense,
    SandwichPromptingDefense.name: SandwichPromptingDefense,
    PrivilegeSeparationDefense.name: PrivilegeSeparationDefense,
    GuardClassifierDefense.name: GuardClassifierDefense,
}

#: Canonical display order used by the API and dashboard.
DEFENSE_ORDER: tuple[str, ...] = (
    "none",
    "sanitization",
    "spotlighting",
    "sandwich_prompting",
    "privilege_separation",
    "guard_classifier",
)


def get_defense(name: str, config: dict[str, Any] | None = None) -> Defense:
    key = str(name or "none").strip().lower()
    aliases = {"sanitisation": "sanitization", "spotlight": "spotlighting", "sandwich": "sandwich_prompting",
               "privilege": "privilege_separation", "guard": "guard_classifier"}
    key = aliases.get(key, key)
    if key not in DEFENSE_REGISTRY:
        raise ValidationError(
            f"Unknown defense {name!r}. Available: {list(DEFENSE_ORDER)}",
            details={"defense": name},
        )
    return DEFENSE_REGISTRY[key](config)


def list_defenses() -> list[dict[str, Any]]:
    """Metadata for every registered defense (no instances created)."""
    out: list[dict[str, Any]] = []
    for key in DEFENSE_ORDER:
        cls = DEFENSE_REGISTRY[key]
        out.append(
            {
                "name": cls.name,
                "description": cls.description,
                "mechanism": cls.mechanism,
                "version": cls.version,
                "rewrites_content": cls.rewrites_content,
                "gates_actions": cls.gates_actions,
            }
        )
    return out


__all__ = [
    "Defense",
    "DefenseContext",
    "DefenseOutcome",
    "DEFENSE_REGISTRY",
    "DEFENSE_ORDER",
    "get_defense",
    "list_defenses",
    "GuardClassifier",
    "GuardResult",
    "GuardVerdict",
    "GuardClassifierDefense",
    "classify_text",
    "MALICIOUS_THRESHOLD",
    "SUSPICIOUS_THRESHOLD",
    "NoDefense",
    "SanitizationDefense",
    "SpotlightingDefense",
    "SandwichPromptingDefense",
    "PrivilegeSeparationDefense",
    "DefaultAuthorizer",
    "TRUSTED_SOURCES",
    "extract_marked_spans",
]