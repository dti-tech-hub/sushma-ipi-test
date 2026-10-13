"""Deterministic attack injection engine (Module 3).

Takes a clean :class:`~backend.tools.base.ToolResult` plus an
:class:`~backend.attacks.models.AttackRecord` and returns a modified *untrusted*
payload plus provenance metadata.

Design contract
---------------
* **Pure**: the same (result, attack, seed) triple always produces byte-identical
  output. No global RNG, no time, no I/O.
* **Surgical**: only the four untrusted fields are touched
  (``content``, ``html``, ``records``, ``metadata``). Trusted ``meta`` is never
  modified, so provenance cannot be spoofed by a payload.
* **Traceable**: every call returns :class:`InjectionResult` with the attack id,
  the position/format actually used, and a SHA-256 digest of the clean input.

Positions
---------
``beginning``   prepended to ``content``
``middle``      inserted at a deterministic interior offset (seeded)
``end``         appended to ``content``
``surrounding`` legitimate content is kept between a prefix and a suffix payload
``metadata``    written into ``metadata`` (or into ``records`` for structured payloads)
``html_comment`` wrapped in ``<!-- ... -->`` inside ``html``
``encoded``     encoded and placed at the end of ``content`` with a decode hint
"""

from __future__ import annotations

import base64
import binascii
import codecs
import hashlib
import json
import random
import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import unquote

from backend.attacks.models import AttackRecord
from backend.models.enums import InjectionPosition, PayloadFormat
from backend.models.errors import InjectionError
from backend.tools.base import ToolResult

#: Invisible characters used by the zero-width transformation.
_ZERO_WIDTH = {"l": "\u200b", "i": "\u200c", "d": "\u200d", "f": "\ufeff", "s": "\u2060"}

_LEET = str.maketrans({"4": "A", "3": "E", "1": "I", "0": "O", "5": "S", "7": "T", "$": "S", "@": "A"})

_METADATA_KEYS = ("note", "comment", "system_note", "agent_directive", "maintenance")

#: Decoders the *agent side* may plausibly apply. Used by the mock agent and by
#: the guard classifier; documented so the "can this payload even be decoded"
#: dimension is explicit rather than hidden.
KNOWN_ENCODINGS = {
    PayloadFormat.BASE64: "base64",
    PayloadFormat.HEX: "hex",
    PayloadFormat.ROT13: "rot13",
    PayloadFormat.URLENCODED: "urlencoded",
    PayloadFormat.ZERO_WIDTH: "zero_width",
    PayloadFormat.REVERSED: "reversed",
    PayloadFormat.UNICODE_ESCAPE: "unicode_escape",
    PayloadFormat.SPACED_LEET: "spaced_leet",
}


# ---------------------------------------------------------------------------
# Encoders
# ---------------------------------------------------------------------------


def encode_payload(text: str, fmt: PayloadFormat, *, seed: int = 0) -> str:
    """Render ``text`` in ``fmt``. Deterministic for every format."""
    if fmt is PayloadFormat.VISIBLE_TEXT:
        return text
    if fmt is PayloadFormat.HTML_COMMENT:
        return f"<!-- {text} -->"
    if fmt is PayloadFormat.METADATA:
        return text
    if fmt is PayloadFormat.BASE64:
        return base64.b64encode(text.encode("utf-8")).decode("ascii")
    if fmt is PayloadFormat.HEX:
        return "0x" + text.encode("utf-8").hex()
    if fmt is PayloadFormat.ROT13:
        return codecs.encode(text, "rot_13")
    if fmt is PayloadFormat.URLENCODED:
        from urllib.parse import quote

        return quote(text, safe="")
    if fmt is PayloadFormat.ZERO_WIDTH:
        # Deterministically interleave invisible characters (seeded).
        rng = random.Random(seed)
        keys = list(_ZERO_WIDTH)
        out: list[str] = []
        for char in text:
            out.append(char)
            if not char.isspace() and rng.random() < 0.34:
                out.append(_ZERO_WIDTH[rng.choice(keys)])
        return "".join(out)
    if fmt is PayloadFormat.REVERSED:
        return text[::-1]
    if fmt is PayloadFormat.MARKDOWN_IMAGE:
        digest = hashlib.sha256(f"{seed}:{text}".encode("utf-8")).hexdigest()[:12]
        return f"![1x1](https://pixel.tracker.invalid/{digest}.gif \"{text}\")"
    if fmt is PayloadFormat.UNICODE_ESCAPE:
        return "".join(f"\\u{ord(c):04x}" for c in text)
    if fmt is PayloadFormat.SPACED_LEET:
        spaced = " ".join(char for char in text.upper().translate(_LEET))
        return spaced
    raise InjectionError(f"Unsupported payload format: {fmt}")


def looks_encoded(fmt: PayloadFormat) -> bool:
    return fmt in KNOWN_ENCODINGS


def decoding_hint(fmt: PayloadFormat) -> str:
    hint = KNOWN_ENCODINGS.get(fmt)
    if not hint:
        return ""
    return {
        "base64": "(decode as base64)",
        "hex": "(decode the hex byte string)",
        "rot13": "(decode as ROT13)",
        "urlencoded": "(percent-decode the string)",
        "zero_width": "(strip zero-width characters)",
        "reversed": "(read backwards)",
        "unicode_escape": "(decode \\u escapes)",
        "spaced_leet": "(de-obfuscate the spaced leetspeak)",
    }.get(hint, "")


# ---------------------------------------------------------------------------
# Result
# ---------------------------------------------------------------------------


@dataclass
class InjectionResult:
    """Outcome of one injection."""

    result: ToolResult
    attack_id: str
    attack_type: str
    channel: str
    injection_position: InjectionPosition
    payload_format: PayloadFormat
    encoded: bool
    clean_digest: str
    injected_digest: str
    target_field: str
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "attack_id": self.attack_id,
            "attack_type": self.attack_type,
            "channel": self.channel,
            "injection_position": self.injection_position.value,
            "payload_format": self.payload_format.value,
            "encoded": self.encoded,
            "clean_digest": self.clean_digest,
            "injected_digest": self.injected_digest,
            "target_field": self.target_field,
            "metadata": self.metadata,
        }


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------


class InjectionEngine:
    """Applies attacks to clean tool output deterministically."""

    def inject(
        self,
        clean: ToolResult,
        attack: AttackRecord,
        *,
        seed: int = 0,
    ) -> InjectionResult:
        if clean.is_untrusted is False:
            raise InjectionError(
                "Refusing to inject into a trusted result; the test range only "
                "injects into UNTRUSTED tool output.",
                details={"tool": clean.tool, "action": clean.action},
            )

        clean_digest = self.digest(clean)
        working = self._copy(clean)
        position = attack.injection_position
        fmt = attack.format
        rng = random.Random(f"{seed}:{attack.id}:{position.value}:{fmt.value}")

        target_field = "content"
        if isinstance(attack.payload, (dict, list)):
            target_field = self._inject_structured(working, attack, fmt)
        elif position is InjectionPosition.METADATA:
            target_field = self._inject_metadata(working, attack, fmt, seed)
        elif position is InjectionPosition.HTML_COMMENT:
            target_field = self._inject_html_comment(working, attack, fmt)
        else:
            target_field = self._inject_text(working, attack, fmt, position, rng, seed)

        working.meta["injection"] = {
            "attack_id": attack.id,
            "position": position.value,
            "format": fmt.value,
            "field": target_field,
        }
        return InjectionResult(
            result=working,
            attack_id=attack.id,
            attack_type=attack.attack_type.value,
            channel=attack.delivery_channel.value,
            injection_position=position,
            payload_format=fmt,
            encoded=looks_encoded(fmt),
            clean_digest=clean_digest,
            injected_digest=self.digest(working),
            target_field=target_field,
            metadata={
                "structured_payload": isinstance(attack.payload, (dict, list)),
                "has_decode_hint": bool(decoding_hint(fmt)) and looks_encoded(fmt),
            },
        )

    # -- helpers ----------------------------------------------------------
    @staticmethod
    def digest(result: ToolResult) -> str:
        blob = json.dumps(
            {
                "content": result.content,
                "html": result.html,
                "records": result.records,
                "metadata": result.metadata,
            },
            sort_keys=True,
            default=str,
        )
        return hashlib.sha256(blob.encode("utf-8")).hexdigest()[:16]

    @staticmethod
    def _copy(result: ToolResult) -> ToolResult:
        import copy

        return ToolResult(
            tool=result.tool,
            action=result.action,
            status=result.status,
            content=result.content,
            html=result.html,
            records=copy.deepcopy(result.records),
            metadata=copy.deepcopy(result.metadata),
            permission=result.permission,
            latency_ms=result.latency_ms,
            is_untrusted=result.is_untrusted,
            meta=copy.deepcopy(result.meta),
            error=result.error,
        )

    # -- positions --------------------------------------------------------
    def _inject_text(
        self,
        working: ToolResult,
        attack: AttackRecord,
        fmt: PayloadFormat,
        position: InjectionPosition,
        rng: random.Random,
        seed: int,
    ) -> str:
        raw = str(attack.payload).strip()
        rendered = encode_payload(raw, fmt, seed=seed)
        body = working.content or ""
        options = attack.injection_options or {}
        prefix = str(options.get("prefix", "")) or self._default_prefix(fmt)

        if position is InjectionPosition.BEGINNING:
            working.content = f"{prefix}{rendered}\n\n{body}"
            return "content"
        if position is InjectionPosition.END:
            working.content = f"{body}\n\n{prefix}{rendered}"
            return "content"
        if position is InjectionPosition.SURROUNDING:
            working.content = (
                f"{prefix}{rendered}\n\n{body}\n\n{prefix}{rendered}"
            )
            return "content"
        if position is InjectionPosition.MIDDLE:
            lines = body.splitlines()
            if not lines:
                working.content = f"{body}\n\n{prefix}{rendered}"
                return "content"
            index = rng.randrange(1, len(lines)) if len(lines) > 1 else len(lines)
            block = [f"{prefix}{rendered}", ""]
            lines[index:index] = block
            working.content = "\n".join(lines)
            return "content"
        if position is InjectionPosition.ENCODED:
            hint = decoding_hint(fmt) or "(encoded)"
            working.content = f"{body}\n\n{hint} {rendered}"
            return "content"
        raise InjectionError(f"Unsupported text injection position: {position}")

    def _inject_metadata(
        self, working: ToolResult, attack: AttackRecord, fmt: PayloadFormat, seed: int
    ) -> str:
        raw = str(attack.payload).strip()
        rendered = encode_payload(raw, fmt, seed=seed)
        options = attack.injection_options or {}
        key = str(options.get("metadata_key", "")) or _METADATA_KEYS[hash_str(attack.id) % len(_METADATA_KEYS)]
        working.metadata = {**working.metadata, key: rendered, "_injection_key": key}
        return "metadata"

    def _inject_html_comment(
        self, working: ToolResult, attack: AttackRecord, fmt: PayloadFormat
    ) -> str:
        raw = str(attack.payload).strip()
        if fmt is PayloadFormat.HTML_COMMENT or raw.startswith("<!--"):
            rendered = raw if raw.startswith("<!--") else f"<!-- {raw} -->"
        else:
            rendered = f"<!-- {encode_payload(raw, fmt)} -->"
        body = working.html or working.content or ""
        working.html = f"{body}\n{rendered}"
        return "html"

    def _inject_structured(
        self, working: ToolResult, attack: AttackRecord, fmt: PayloadFormat
    ) -> str:
        """Attach a structured payload as a synthetic extra record."""
        payload = attack.payload
        if isinstance(payload, dict):
            entry = {**payload, "_rendered": encode_payload(str(payload.get("body", "")), fmt)}
        else:
            entry = {"items": payload, "_rendered": encode_payload(str(payload), fmt)}
        working.records = [*working.records, entry]
        options = attack.injection_options or {}
        key = str(options.get("metadata_key", "")) or _METADATA_KEYS[hash_str(attack.id) % len(_METADATA_KEYS)]
        working.metadata = {**working.metadata, key: "structured record attached"}
        return "records"

    @staticmethod
    def _default_prefix(fmt: PayloadFormat) -> str:
        if fmt in {
            PayloadFormat.MARKDOWN_IMAGE,
            PayloadFormat.ZERO_WIDTH,
            PayloadFormat.SPACED_LEET,
            PayloadFormat.REVERSED,
            PayloadFormat.UNICODE_ESCAPE,
        }:
            return ""
        if fmt in {PayloadFormat.BASE64, PayloadFormat.HEX}:
            return "ASSET-CHK:"
        if fmt in {PayloadFormat.ROT13, PayloadFormat.URLENCODED}:
            return ""
        return ">>> "


def hash_str(value: str) -> int:
    """Stable (process independent) string hash."""
    return int.from_bytes(hashlib.blake2b(value.encode("utf-8"), digest_size=4).digest(), "big")


def decode_if_possible(text: str, fmt: PayloadFormat) -> str | None:
    """Best-effort decode used by defenses/guards and by the mock agent.

    Returns ``None`` when the payload is not actually decodable in ``fmt``.
    """
    try:
        if fmt is PayloadFormat.BASE64:
            cleaned = re.sub(r"[^A-Za-z0-9+/=]", "", text)
            if len(cleaned) < 16:
                return None
            pad = cleaned + "=" * (-len(cleaned) % 4)
            raw = base64.b64decode(pad, validate=False)
            text_out = raw.decode("utf-8", errors="strict")
            # Reject binary junk: a decodable *instruction* is printable text.
            printable = sum(1 for c in text_out if c.isprintable() or c.isspace())
            if printable / max(1, len(text_out)) < 0.9:
                return None
            return text_out
        if fmt is PayloadFormat.HEX:
            cleaned = re.sub(r"^0x", "", text.strip(), flags=re.IGNORECASE)
            cleaned = re.sub(r"[^0-9a-fA-F]", "", cleaned)
            if len(cleaned) % 2:
                cleaned = cleaned[:-1]
            return bytes.fromhex(cleaned).decode("utf-8", errors="replace")
        if fmt is PayloadFormat.ROT13:
            return codecs.encode(text, "rot_13")
        if fmt is PayloadFormat.URLENCODED:
            return unquote(text)
        if fmt is PayloadFormat.ZERO_WIDTH:
            return "".join(ch for ch in text if ch not in "".join(_ZERO_WIDTH.values()))
        if fmt is PayloadFormat.REVERSED:
            return text[::-1]
        if fmt is PayloadFormat.UNICODE_ESCAPE:
            return re.sub(
                r"\\u([0-9a-fA-F]{4})", lambda m: chr(int(m.group(1), 16)), text
            )
        if fmt is PayloadFormat.SPACED_LEET:
            return text.replace(" ", "").translate(str.maketrans("AEIOST", "431057"))
    except (ValueError, binascii.Error, UnicodeDecodeError):
        return None
    return None


_DEFAULT_ENGINE = InjectionEngine()


def inject_attack(
    clean: ToolResult, attack: AttackRecord, *, seed: int = 0
) -> InjectionResult:
    """Convenience wrapper around the module level :class:`InjectionEngine`."""
    return _DEFAULT_ENGINE.inject(clean, attack, seed=seed)


__all__ = [
    "InjectionEngine",
    "InjectionResult",
    "inject_attack",
    "encode_payload",
    "decode_if_possible",
    "decoding_hint",
    "looks_encoded",
    "KNOWN_ENCODINGS",
]