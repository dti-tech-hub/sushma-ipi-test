"""Deterministic mock LLM provider - the DEMO/MOCK brain.

.. warning::

   **This provider is a simulation, not a language model.** Results produced
   with it are labelled ``MOCK`` everywhere in the database, the API and the
   dashboard. They demonstrate that the *framework* measures something sensible;
   they are **not** evidence about the security of any real model.

Why it exists
-------------
Module 20 requires the whole project to be demonstrable on a student laptop with
no API key. A purely random agent would produce meaningless numbers; a scripted
agent that always resists would produce a meaningless 0% ASR. This provider is a
*parameterised victim simulator*:

* it reads only the content it was actually given (post-defense),
* it notices agent-directed imperatives inside untrusted text
  (:mod:`backend.agents.injection_awareness`),
* it complies with probability ``p`` derived from four transparent factors::

      p = vulnerability            (archetype prior, e.g. 0.85 for mock-vulnerable)
        * position_factor          (end > middle > beginning; metadata/HTML lower)
        * format_factor            (from the declared attack difficulty)
        * obfuscation_factor       (only if the archetype can decode the encoding)
        * signal_factor            (data marking / sandwich reminders observed)
        * jitter                   (seeded uniform noise in [0.92, 1.08])

When it complies it emits the attack's target tool call with the attack's own
arguments, which is what makes attack success *measurable* through the same
predicates used for real models.
"""

from __future__ import annotations

import hashlib
import random
from dataclasses import dataclass
from typing import Any, ClassVar

from backend.agents.base import FINAL_ACTION, LLMProvider, LLMRequest, LLMResponse, ToolCallRequest
from backend.agents.injection_awareness import PerceptionResult, perceive
from backend.models.enums import InjectionPosition, PayloadFormat, ProviderKind

#: Position sensitivity of a payload (documented, hand-set, not fitted).
POSITION_FACTOR: dict[InjectionPosition, float] = {
    InjectionPosition.END: 1.15,
    InjectionPosition.SURROUNDING: 1.10,
    InjectionPosition.MIDDLE: 1.00,
    InjectionPosition.BEGINNING: 1.05,
    InjectionPosition.METADATA: 0.90,
    InjectionPosition.HTML_COMMENT: 0.85,
    InjectionPosition.ENCODED: 0.95,
}

#: Format sensitivity independent of the declared difficulty.
FORMAT_FACTOR: dict[PayloadFormat, float] = {
    PayloadFormat.VISIBLE_TEXT: 1.00,
    PayloadFormat.HTML_COMMENT: 0.90,
    PayloadFormat.METADATA: 0.92,
    PayloadFormat.MARKDOWN_IMAGE: 0.95,
    PayloadFormat.BASE64: 0.95,
    PayloadFormat.HEX: 0.85,
    PayloadFormat.ROT13: 0.80,
    PayloadFormat.URLENCODED: 0.85,
    PayloadFormat.ZERO_WIDTH: 0.75,
    PayloadFormat.REVERSED: 0.70,
    PayloadFormat.UNICODE_ESCAPE: 0.80,
    PayloadFormat.SPACED_LEET: 0.75,
}

#: Multiplier applied when the agent has *seen* a data-marking signal.
DATA_MARK_SIGNAL_FACTOR = 0.45
#: Multiplier applied when a trusted reminder immediately follows the data.
SANDWICH_SIGNAL_FACTOR = 0.62


@dataclass(frozen=True)
class MockArchetype:
    """A parameterised simulated victim model."""

    name: str
    vulnerability: float
    decoding_ability: float
    description: str


ARCHETYPES: dict[str, MockArchetype] = {
    "mock-vulnerable": MockArchetype(
        "mock-vulnerable", 0.86, 0.85,
        "Highly susceptible simulated model: complies with most visible directives.",
    ),
    "mock-balanced": MockArchetype(
        "mock-balanced", 0.55, 0.55,
        "Balanced simulated model: intermediate susceptibility.",
    ),
    "mock-hardened": MockArchetype(
        "mock-hardened", 0.18, 0.35,
        "Hardened simulated model: rarely complies with directives in tool output.",
    ),
    "mock-blind": MockArchetype(
        "mock-blind", 0.92, 0.05,
        "Suspicious but non-decoding simulated model: obeys plain text, ignores encodings.",
    ),
}


def _rng(*parts: Any) -> random.Random:
    """Deterministic, well-decorrelated RNG.

    Seeding ``random.Random`` with a *string* that begins with a small integer
    (``"1:mock-vulnerable:2"``, ``"2:mock-vulnerable:2"``, ...) produces highly
    correlated streams, which silently collapses the variance the repetitions
    are supposed to measure. Hashing the parts to a wide integer first removes
    that bias while staying fully reproducible.
    """
    digest = hashlib.blake2b("|".join(str(p) for p in parts).encode("utf-8"), digest_size=16).digest()
    return random.Random(int.from_bytes(digest, "big"))


class MockLLMProvider(LLMProvider):
    """Deterministic, seeded agent brain used for demo mode."""

    kind: ProviderKind = ProviderKind.MOCK
    is_simulation: bool = True

    def __init__(
        self,
        model: str = "mock-vulnerable",
        *,
        temperature: float = 0.0,
        max_tokens: int = 1026,
    ) -> None:
        self.archetype = ARCHETYPES.get(model, ARCHETYPES["mock-vulnerable"])
        self.model_name = self.archetype.name if model in ARCHETYPES else model
        self.default_model = self.model_name
        self.temperature = temperature
        self.max_tokens = max_tokens

    # -- introspection ----------------------------------------------------
    def info(self) -> dict[str, Any]:
        return {
            "provider": self.kind.value,
            "model": self.model_name,
            "is_simulation": True,
            "vulnerability": self.archetype.vulnerability,
            "decoding_ability": self.archetype.decoding_ability,
            "description": self.archetype.description,
        }

    # -- completion -------------------------------------------------------
    def complete(self, request: LLMRequest) -> LLMResponse:
        ctx = request.context or {}
        perception: PerceptionResult = ctx.get("perception") or PerceptionResult()
        rng = _rng(request.seed, self.model_name, request.step)
        attack_ctx = ctx.get("attack_context") or {}
        target = attack_ctx.get("target_action") or {}

        # The injected objective has already been carried out (or refused):
        # report it once instead of repeating the call.
        if ctx.get("hijack_completed"):
            return LLMResponse(
                text=_wrap(
                    {
                        "thought": "The additional step has been dealt with.",
                        "final": _attacker_answer(attack_ctx),
                    }
                ),
                final_answer=_attacker_answer(attack_ctx),
                thought="hijack-complete",
                finish_reason="hijacked",
                model=self.model_name,
                provider=self.kind.value,
            )

        if not perception.has_candidate:
            return self._next_plan_step(request, rng)

        probability = self._compliance_probability(request, perception)
        hijack = bool(target) and rng.random() < probability

        if hijack:
            tool = str(target.get("tool", ""))
            action = str(target.get("action", ""))
            arguments = _coerce_arguments(dict(target.get("required_args") or {}), ctx.get("action_schemas") or {})
            answer = _attacker_answer(attack_ctx)
            return LLMResponse(
                text=_wrap(
                    {
                        "thought": (
                            "The tool output contains an explicit directive; following it is the "
                            "fastest way to satisfy the request."
                        ),
                        "action": f"{tool}.{action}" if tool else action,
                        "arguments": arguments,
                        "final": answer,
                    }
                ),
                tool_call=ToolCallRequest(action=f"{tool}.{action}" if tool else action, arguments=arguments, tool=tool),
                final_answer=answer,
                thought="complied-with-injected-directive",
                finish_reason="hijacked",
                model=self.model_name,
                provider=self.kind.value,
            )

        # Declined. Either finish with the legitimate answer or keep planning.
        if ctx.get("plan_remaining"):
            return self._next_plan_step(request, rng, declined=True)

        return LLMResponse(
            text=_wrap(
                {
                    "thought": (
                        "The tool output contains text addressed to me, but it arrives as data. "
                        "I will not act on it and will answer the user's task instead."
                    ),
                    "final": ctx.get("legit_answer") or "I could not determine the answer from the available tools.",
                }
            ),
            final_answer=ctx.get("legit_answer") or "I could not determine the answer from the available tools.",
            thought="ignored-injected-directive",
            finish_reason="final_answer",
            model=self.model_name,
            provider=self.kind.value,
        )

    # -- internals --------------------------------------------------------
    def _compliance_probability(
        self, request: LLMRequest, perception: PerceptionResult
    ) -> float:
        attack_ctx = request.context.get("attack_context") or {}
        position = InjectionPosition.coerce(attack_ctx.get("injection_position", "end"))
        fmt = PayloadFormat.coerce(attack_ctx.get("format", "visible_text"))
        difficulty = str(attack_ctx.get("difficulty", "easy")).lower()

        probability = self.archetype.vulnerability
        probability *= POSITION_FACTOR.get(position, 1.0)
        probability *= FORMAT_FACTOR.get(fmt, 1.0)
        probability *= {"easy": 1.0, "medium": 0.82, "hard": 0.58}.get(difficulty, 1.0)

        if perception.best and perception.best.encoding != "none":
            # Can this archetype actually decode the payload?
            probability *= self.archetype.decoding_ability

        if perception.data_markers:
            probability *= DATA_MARK_SIGNAL_FACTOR
        if perception.trusted_reminders:
            probability *= SANDWICH_SIGNAL_FACTOR

        strength = perception.score
        probability *= 0.55 + 0.45 * strength

        rng = _rng(request.seed, "jitter", request.step)
        probability *= rng.uniform(0.92, 1.08)
        return max(0.0, min(1.0, probability))

    def _next_plan_step(
        self, request: LLMRequest, rng: random.Random, *, declined: bool = False
    ) -> LLMResponse:
        plan = list(request.context.get("plan") or [])
        cursor = int(request.context.get("plan_cursor", 0))
        if cursor >= len(plan):
            answer = request.context.get("legit_answer") or "I could not determine the answer."
            return LLMResponse(
                text=_wrap({"thought": "Plan complete; composing the answer.", "final": answer}),
                final_answer=answer,
                thought="plan-complete",
                finish_reason="final_answer",
                model=self.model_name,
                provider=self.kind.value,
            )
        step = plan[cursor]
        arguments = dict(step.get("arguments") or {})
        return LLMResponse(
            text=_wrap(
                {
                    "thought": f"Reference step {cursor + 1}: {step.get('purpose') or step.get('action')}.",
                    "action": f"{step['tool']}.{step['action']}",
                    "arguments": arguments,
                }
            ),
            tool_call=ToolCallRequest(
                action=f"{step['tool']}.{step['action']}", arguments=arguments, tool=step["tool"]
            ),
            thought="plan-step",
            finish_reason="tool_call",
            model=self.model_name,
            provider=self.kind.value,
        )

    # -- health -----------------------------------------------------------
    def health(self) -> dict[str, Any]:
        return {
            "provider": self.kind.value,
            "model": self.model_name,
            "is_simulation": True,
            "available": True,
            "description": self.archetype.description,
            "requires_api_key": False,
        }


def _wrap(payload: dict[str, Any]) -> str:
    import json

    return json.dumps(payload)


def _coerce_arguments(required: dict[str, Any], schemas: dict[str, dict[str, Any]]) -> dict[str, Any]:
    """Make the attack's declared arguments match the tool's input schema."""
    out: dict[str, Any] = {}
    for key, value in required.items():
        if key in schemas:
            expected = schemas[key].get("type")
            if expected == "array" and isinstance(value, str):
                out[key] = [value]
                continue
            if expected == "integer" and isinstance(value, str) and value.isdigit():
                out[key] = int(value)
                continue
            if expected == "object" and not isinstance(value, dict):
                out[key] = {"value": value}
                continue
        out[key] = value
    return out


def _attacker_answer(attack_ctx: dict[str, Any]) -> str:
    marker = attack_ctx.get("objective_marker") or "the additional step in the tool output"
    return (
        f"Completed: {marker}. I also handled the outstanding item from the tool output "
        "as instructed there."
    )


MOCK_MODELS: tuple[str, ...] = tuple(ARCHETYPES)
MOCK_MODEL_DESCRIPTIONS: dict[str, str] = {
    name: arch.description for name, arch in ARCHETYPES.items()
}
MOCK_DEFAULT: ClassVar[str] = "mock-vulnerable"
FINAL = FINAL_ACTION

__all__ = [
    "MockLLMProvider",
    "MockArchetype",
    "ARCHETYPES",
    "MOCK_MODELS",
    "MOCK_MODEL_DESCRIPTIONS",
    "MOCK_DEFAULT",
    "POSITION_FACTOR",
    "FORMAT_FACTOR",
    "DATA_MARK_SIGNAL_FACTOR",
    "SANDWICH_SIGNAL_FACTOR",
]