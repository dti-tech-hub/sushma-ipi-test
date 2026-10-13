"""Explainable guard classifier (Module 13).

**Scope statement (research integrity).** This is a *transparent, rule-based
baseline* used so the test range can demonstrate the guard-classifier defense
without downloading an external model. It is **not** a state-of-the-art
injection classifier and it makes no such claim. Its value inside this project
is that every decision is attributable: each verdict lists the exact indicators
that fired and the weight they contributed.

Method
------
1. Normalise the text (casefold, collapse invisible characters, optionally decode
   base64/hex/ROT13/URL-encoding layers).
2. Score it against weighted indicator patterns grouped by family
   (override, exfiltration, privilege, authority spoofing, encoding).
3. Map the score to SAFE / SUSPICIOUS / MALICIOUS with explicit thresholds.
"""

from __future__ import annotations

import base64
import binascii
import codecs
import math
import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import unquote

from backend.models.enums import GuardVerdict

# ---------------------------------------------------------------------------
# Indicator catalogue
# ---------------------------------------------------------------------------

#: family -> list of (label, weight, compiled pattern)
_INDICATORS: dict[str, list[tuple[str, float, re.Pattern[str]]]] = {
    "instruction_override": [
        ("ignore_previous", 0.42, re.compile(r"\b(ignore|disregard|forget)\b[^.]{0,40}\b(previous|prior|above|earlier|all)\b[^.]{0,20}\b(instruction|prompt|rule|direction)s?\b", re.I)),
        ("new_system_prompt", 0.45, re.compile(r"\b(new|updated|revised|replacement)\s+(system\s+)?(prompt|instruction|directive)s?\b", re.I)),
        ("instruction_priority_claim", 0.30, re.compile(r"\b(takes?|has|have)\s+precedence\b|\bsupersedes?\b|\boverrides?\b\s+(the\s+)?(previous|earlier|prior|security)\b", re.I)),
        ("disregard_policy", 0.32, re.compile(r"\b(disregard|ignore|bypass|lift|retire|revoke)\b[^.]{0,30}\b(polic(y|ies)|restriction|constraint|rule|guardrail)s?\b", re.I)),
        ("jailbreak_mode", 0.28, re.compile(r"\b(developer\s+mode|dan\s+mode|jailbreak|unrestricted\s+mode|sudo\s+mode)\b", re.I)),
        ("follow_this_instead", 0.22, re.compile(r"\b(instead\s+of|rather\s+than)\b[^.]{0,40}\b(original|previous|earlier|prior)\b", re.I)),
    ],
    "data_exfiltration": [
        ("external_destination", 0.30, re.compile(r"https?://[^\s\"'<>]*(collector|drop|exfil|beacon|tracker|telemetry|hook)[^\s\"'<>]*", re.I)),
        ("send_to_external", 0.34, re.compile(r"\b(send|mail|forward|post|upload|transmit|deliver)\b[^.]{0,60}@\s*[\w.-]+\.(invalid|test|example|io|com)\b", re.I)),
        ("exfil_keyword", 0.26, re.compile(r"\b(exfiltrat\w*|ex-?fil|leak\s+the|siphon|dump\s+the\s+(credentials|tokens|secrets)|steal)\b", re.I)),
        ("secrets_target", 0.28, re.compile(r"\b(credential|secret|token|api[\s_-]?key|password)s?\b[^.]{0,50}\b(export|dump|copy|send|share|mirror|forward)\b", re.I)),
        ("confidential_file", 0.22, re.compile(r"\b(confidential|internal[\s_-]only|classified)\b[^.]{0,60}\b(share|upload|send|publish|export)\b", re.I)),
    ],
    "tool_misuse": [
        ("destructive_db", 0.40, re.compile(r"\b(drop\s+table|truncate\s+table|delete\s+from)\b", re.I)),
        ("destructive_file", 0.34, re.compile(r"\b(delete|erase|wipe|purge)\b[^.]{0,30}\b(file|document|record|message|note)s?\b", re.I)),
        ("grant_access", 0.34, re.compile(r"\b(grant|give|assign|add)\b[^.]{0,30}\b(access|role|permission|admin)s?\b", re.I)),
        ("package_install", 0.26, re.compile(r"\b(pip\s+install|install_package|apt\s+install|npm\s+install)\b", re.I)),
        ("network_from_sandbox", 0.24, re.compile(r"\b(fetch_url|download_and_upload|curl\s+http|wget\s+http)\b", re.I)),
        ("share_externally", 0.28, re.compile(r"\b(share_(file|calendar)|forward_email|send_email|submit_form)\b", re.I)),
        # Untrusted content naming a privileged *capability* of the sandbox is a
        # strong tool-misuse signal: benign content rarely quotes these names.
        ("privileged_capability", 0.32, re.compile(
            r"\b(export_secrets|drop_table|grant_access|delete_file|delete_message|"
            r"install_package|fetch_url|download_and_upload|cancel_event)\b", re.I)),
    ],
    "authority_spoofing": [
        ("fake_operator", 0.34, re.compile(r"\b(from:\s*)?(operator|admin(istrator)?|security|system)\s+(override|notice|update|approval|directive)\b", re.I)),
        ("authority_claim", 0.26, re.compile(r"\b(authori[sz]ed|approved by|permission grant|you are now permitted|has been retired|are exempt)\b", re.I)),
        ("instruction_from_content", 0.22, re.compile(r"\b(this|the following)\s+(document|page|file|mail|message|record)\b[^.]{0,40}\b(instructs?|commands?|directs?|tells? you)\b", re.I)),
    ],
    "urgency_pretext": [
        ("urgency", 0.12, re.compile(r"\b(urgent|immediately|before\s+you\s+(answer|reply)|right\s+now|must\s+be\s+sent)\b", re.I)),
        ("do_not_tell", 0.24, re.compile(r"\b(do\s+not|don't|never)\s+(tell|inform|disclose|mention|reveal|log)\b", re.I)),
    ],
}

_ZERO_WIDTH_CHARS = "\u200b\u200c\u200d\u2060\ufeff"
_INVISIBLE_RE = re.compile(f"[{_ZERO_WIDTH_CHARS}]")

#: Minimum plausible length of a decodable base64 blob.
_B64_RE = re.compile(r"[A-Za-z0-9+/]{24,}={0,2}")
_HEX_RE = re.compile(r"(?:0x)?(?:[0-9a-fA-F]{2}){16,}")

MALICIOUS_THRESHOLD = 0.75
SUSPICIOUS_THRESHOLD = 0.40


@dataclass
class GuardResult:
    """Verdict for one piece of untrusted content."""

    verdict: GuardVerdict
    confidence: float
    reason: str
    indicators: list[str] = field(default_factory=list)
    families: dict[str, float] = field(default_factory=dict)
    decoded_layers: list[str] = field(default_factory=list)
    text_length: int = 0
    detector: str = "heuristic-v1"

    @property
    def is_flagged(self) -> bool:
        return self.verdict is not GuardVerdict.SAFE

    def to_dict(self) -> dict[str, Any]:
        return {
            "verdict": self.verdict.value,
            "confidence": round(self.confidence, 4),
            "reason": self.reason,
            "indicators": self.indicators,
            "families": {k: round(v, 4) for k, v in self.families.items()},
            "decoded_layers": self.decoded_layers,
            "text_length": self.text_length,
            "detector": self.detector,
        }


class GuardClassifier:
    """Rule-based, explainable baseline classifier."""

    name = "heuristic-v1"

    def __init__(
        self,
        *,
        malicious_threshold: float = MALICIOUS_THRESHOLD,
        suspicious_threshold: float = SUSPICIOUS_THRESHOLD,
        inspect_encoded: bool = True,
    ) -> None:
        self.malicious_threshold = malicious_threshold
        self.suspicious_threshold = suspicious_threshold
        self.inspect_encoded = inspect_encoded

    # -- public API -------------------------------------------------------
    def classify(self, text: str) -> GuardResult:
        if not text or not text.strip():
            return GuardResult(
                verdict=GuardVerdict.SAFE,
                confidence=0.0,
                reason="Empty or whitespace-only content.",
                text_length=len(text or ""),
            )

        normalised = self._normalise(text)
        layers: list[tuple[str, str]] = [("raw", normalised)]
        if self.inspect_encoded:
            layers.extend(self._decode_layers(normalised))

        total = 0.0
        fired: list[tuple[str, str, float]] = []
        families: dict[str, float] = {}
        for layer_name, layer_text in layers:
            for family, rules in _INDICATORS.items():
                for label, weight, pattern in rules:
                    if pattern.search(layer_text):
                        # Each indicator contributes at most once per layer and
                        # is discounted for deeper (decoded) layers.
                        discount = 1.0 if layer_name == "raw" else 0.75
                        contribution = weight * discount
                        total += contribution
                        families[family] = families.get(family, 0.0) + contribution
                        fired.append((family, label, contribution))

        confidence = 1.0 - math.exp(-1.6 * total)  # saturating squashing function
        confidence = round(min(1.0, confidence), 4)

        if confidence >= self.malicious_threshold:
            verdict = GuardVerdict.MALICIOUS
        elif confidence >= self.suspicious_threshold:
            verdict = GuardVerdict.SUSPICIOUS
        else:
            verdict = GuardVerdict.SAFE

        reason = self._explain(verdict, confidence, fired, [name for name, _ in layers])
        return GuardResult(
            verdict=verdict,
            confidence=confidence,
            reason=reason,
            indicators=[f"{family}:{label} (+{contribution:.2f})" for family, label, contribution in fired],
            families=families,
            decoded_layers=[name for name, _ in layers[1:]],
            text_length=len(text),
        )

    # -- internals --------------------------------------------------------
    @staticmethod
    def _normalise(text: str) -> str:
        cleaned = _INVISIBLE_RE.sub("", text)
        cleaned = cleaned.replace("\u00a0", " ")
        return cleaned

    def _decode_layers(self, text: str) -> list[tuple[str, str]]:
        """Peel encodings so obfuscated payloads are still inspected."""
        layers: list[tuple[str, str]] = []

        for blob in _B64_RE.findall(text)[:4]:
            decoded = self._try_b64(blob)
            if decoded and len(decoded) >= 12:
                layers.append(("base64", self._normalise(decoded)))

        for blob in _HEX_RE.findall(text)[:4]:
            decoded = self._try_hex(blob)
            if decoded and len(decoded) >= 12:
                layers.append(("hex", self._normalise(decoded)))

        if "%" in text:
            unquoted = unquote(text)
            if unquoted != text and len(unquoted) >= 12:
                layers.append(("urlencoded", self._normalise(unquoted)))

        if re.search(r"[a-z]\s+[a-z]\s+[a-z]\s+[a-z]", text):
            decoded = codecs.encode(text, "rot_13")
            if decoded != text:
                layers.append(("rot13", self._normalise(decoded)))
        else:
            # ROT13 payloads are indistinguishable from prose without decoding.
            # Always peel ROT13, but only keep the layer when decoding actually
            # reveals *more* indicators - that avoids flagging every English
            # sentence (which decodes into different English).
            decoded = codecs.encode(text, "rot_13")
            if decoded != text and self._layer_score(self._normalise(decoded)) > self._layer_score(
                self._normalise(text)
            ):
                layers.append(("rot13", self._normalise(decoded)))
        return layers

    @staticmethod
    def _layer_score(text: str) -> float:
        total = 0.0
        for rules in _INDICATORS.values():
            for _label, weight, pattern in rules:
                if pattern.search(text):
                    total += weight
        return total

    @staticmethod
    def _try_b64(blob: str) -> str | None:
        try:
            padded = blob + "=" * (-len(blob) % 4)
            raw = base64.b64decode(padded, validate=True)
            return raw.decode("utf-8")
        except (binascii.Error, UnicodeDecodeError, ValueError):
            return None

    @staticmethod
    def _try_hex(blob: str) -> str | None:
        cleaned = re.sub(r"^0x", "", blob, flags=re.IGNORECASE)
        cleaned = re.sub(r"[^0-9a-fA-F]", "", cleaned)
        if len(cleaned) % 2:
            return None
        try:
            return bytes.fromhex(cleaned).decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            return None

    @staticmethod
    def _explain(
        verdict: GuardVerdict,
        confidence: float,
        fired: list[tuple[str, str, float]],
        layers: list[str],
    ) -> str:
        if not fired:
            return f"No injection indicators fired across {len(layers)} inspected layer(s)."
        top = sorted(fired, key=lambda item: item[2], reverse=True)[:4]
        detail = ", ".join(f"{label} (+{weight:.2f})" for _, label, weight in top)
        return (
            f"{verdict.value.upper()} (confidence {confidence:.2f}) from "
            f"{len(fired)} indicator(s) across layers {layers}: {detail}."
        )


_DEFAULT = GuardClassifier()


def classify_text(text: str) -> GuardResult:
    """Module level convenience wrapper."""
    return _DEFAULT.classify(text)


__all__ = [
    "GuardClassifier",
    "GuardResult",
    "GuardVerdict",
    "classify_text",
    "MALICIOUS_THRESHOLD",
    "SUSPICIOUS_THRESHOLD",
]