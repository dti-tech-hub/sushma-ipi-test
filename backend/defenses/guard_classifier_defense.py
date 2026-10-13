"""Guard-classifier defense (Module 11.6).

Mechanism: *pre-inference screening*. Every untrusted tool output is passed
through :class:`~backend.defenses.guard_classifier.GuardClassifier` before the
model sees it.

* ``MALICIOUS`` -> the payload span is redacted and the run records a
  **detection** (this feeds the Refusal/Detection Rate metric).
* ``SUSPICIOUS`` -> the flagged spans are redacted but the run records a
  detection only when the confidence is at or above ``threshold``.
* ``SAFE`` -> passthrough.

The classifier is a transparent heuristic (see ``guard_classifier``); this
project makes no claim that it is state of the art.
"""

from __future__ import annotations

import re
from typing import Any, ClassVar

from backend.defenses.base import Defense, DefenseContext, DefenseOutcome
from backend.defenses.guard_classifier import GuardClassifier
from backend.models.enums import GuardVerdict
from backend.tools.base import ToolResult

_FLAGGABLE_FIELDS = ("content", "html")


class GuardClassifierDefense(Defense):
    """Redact tool output flagged by the explainable guard classifier."""

    name: ClassVar[str] = "guard_classifier"
    description: ClassVar[str] = (
        "Guard classifier: an explainable heuristic classifier screens every "
        "untrusted tool output and redacts flagged spans before inference."
    )
    mechanism: ClassVar[str] = "pre_inference_screening"
    rewrites_content: ClassVar[bool] = True

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        super().__init__(config)
        self.threshold: float = float(self.config.get("threshold", 0.5))
        self.clf = GuardClassifier(
            malicious_threshold=float(self.config.get("malicious_threshold", 0.75)),
            suspicious_threshold=float(self.config.get("suspicious_threshold", 0.40)),
            inspect_encoded=bool(self.config.get("inspect_encoded", True)),
        )
        self.block_on_suspicious: bool = bool(self.config.get("block_on_suspicious", True))

    def on_tool_result(self, result: ToolResult, ctx: DefenseContext) -> DefenseOutcome:
        notes: list[str] = []
        indicators: list[str] = []
        confidence = 0.0
        verdict = GuardVerdict.SAFE
        modified = False

        combined = "\n".join(
            part for part in (result.content, result.html, _stringify(result.metadata), _stringify(result.records)) if part
        )
        guard = self.clf.classify(combined)
        verdict = guard.verdict
        confidence = guard.confidence
        indicators = guard.indicators

        should_block = verdict is GuardVerdict.MALICIOUS or (
            self.block_on_suspicious and confidence >= self.threshold and guard.is_flagged
        )

        new_content, new_html = result.content, result.html
        if should_block:
            new_content = _redact_flagged(new_content, self.clf)
            new_html = _redact_flagged(new_html, self.clf)
            notes.append(f"guard_verdict={verdict.value}")
            notes.append(f"guard_confidence={confidence:.3f}")
            notes.append("guard_action=redact")
            notes.append(guard.reason)
            modified = new_content != result.content or new_html != result.html
        else:
            notes.append(f"guard_verdict={verdict.value}")
            notes.append("guard_action=passthrough")

        detected = verdict is GuardVerdict.MALICIOUS or (
            guard.is_flagged and confidence >= self.threshold
        )

        return DefenseOutcome(
            defense=self.name,
            result=ToolResult(
                tool=result.tool,
                action=result.action,
                status=result.status,
                content=new_content,
                html=new_html,
                records=result.records,
                metadata={**result.metadata, "guard_verdict": verdict.value, "guard_confidence": confidence},
                permission=result.permission,
                latency_ms=result.latency_ms,
                is_untrusted=True,
                meta={**result.meta, "guard": guard.to_dict()},
                error=result.error,
            ),
            modified=modified,
            blocked=should_block and verdict is GuardVerdict.MALICIOUS,
            redacted_spans=0 if not should_block else 1,
            notes=notes,
            verdict=verdict.value,
            confidence=confidence,
            indicators=indicators,
        )


def _stringify(value: Any) -> str:
    import json

    try:
        return json.dumps(value, default=str)
    except (TypeError, ValueError):  # pragma: no cover - defensive
        return str(value)


def _redact_flagged(text: str | None, clf: GuardClassifier) -> str | None:
    """Replace whole flagged lines with a marker, keeping benign lines."""
    if not text:
        return text
    kept: list[str] = []
    removed = 0
    for line in text.splitlines():
        verdict = clf.classify(line)
        if verdict.is_flagged:
            removed += 1
            kept.append(f"[REDACTED:guard-classifier verdict={verdict.verdict.value} conf={verdict.confidence:.2f}]")
        else:
            kept.append(line)
    if removed:
        return "\n".join(kept)
    return text


__all__ = ["GuardClassifierDefense"]