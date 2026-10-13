"""Input sanitization defense (Module 11.2).

Mechanism: *content rewriting*. Before the model sees any untrusted field the
defense removes or redacts text that matches instruction-like or
exfiltration-like patterns, drops HTML comment blocks outright, decodes encoded
blobs and redacts them when the decoded text is itself suspicious, and strips
zero-width characters.

Properties
----------
* Deterministic (no RNG).
* Explainable: every redaction is recorded as a span note with its rule name.
* Lossy by design: sanitization can cost utility (legitimate text containing a
  trigger phrase is redacted too). That cost is measured, not hidden.
"""

from __future__ import annotations

import re
from typing import Any, ClassVar

from backend.attacks.injection import KNOWN_ENCODINGS, decode_if_possible
from backend.defenses.base import Defense, DefenseContext, DefenseOutcome
from backend.models.enums import PayloadFormat
from backend.tools.base import ToolResult

_REDACTION = "[REDACTED:injection-rule]"

#: rule name -> pattern. Ordered; earlier rules win.
_RULES: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("ignore_previous", re.compile(r"(?i)\b(?:ignore|disregard|forget)\b[^.\n]{0,50}\b(?:previous|prior|above|earlier|all)\b[^.\n]{0,30}\b(?:instruction|prompt|rule|direction)s?\b")),
    ("new_system_prompt", re.compile(r"(?i)\b(?:new|updated|revised|replacement)\s+(?:system\s+)?(?:prompt|instructions?|directives?)\b")),
    ("priority_claim", re.compile(r"(?i)\b(?:takes?\s+precedence|supersedes?|overrides?\s+(?:the\s+)?(?:previous|earlier|prior|security)|binds?\s+over|applies\s+over)\b")),
    ("policy_bypass", re.compile(r"(?i)\b(?:disregard|ignore|bypass|lift|retire|revoke|exempt\s+from)\b[^.\n]{0,40}\b(?:polic(?:y|ies)|restrictions?|constraints?|guardrails?)\b")),
    ("authority_claim", re.compile(r"(?i)\b(?:authori[sz]ed by|approved by security|permission grant|you are now permitted|operator override|administrative update|security (?:approval|notice))\b")),
    ("jailbreak_mode", re.compile(r"(?i)\b(?:developer\s+mode|dan\s+mode|jailbreak(?:en)?|unrestricted\s+mode|sudo\s+mode)\b")),
    ("secret_exfil", re.compile(r"(?i)\b(?:export_secrets|download_and_upload|send_email|forward_email|share_file|share_calendar|submit_form|install_package|fetch_url)\b")),
    ("destructive_action", re.compile(r"(?i)\b(?:drop\s+table|truncate\s+table|delete\s+from|grant_access|delete_file|delete_message)\b")),
    ("external_collector", re.compile(r"(?i)https?://[^\s\"'<>]*(?:collector\.invalid|drop|exfil|beacon|tracker|telemetry|hooks\.invalid)[^\s\"'<>]*")),
    ("external_recipient", re.compile(r"(?i)\b[\w.+-]+@(?:collector\.invalid|pixel\.tracker\.invalid|sync\.helper\.invalid|redirect\.invalid)\b")),
    ("conceal_instruction", re.compile(r"(?i)\b(?:do\s+not|don't|never)\s+(?:tell|inform|disclose|mention|reveal|log)\b")),
    # Sentence-initial imperative aimed at the reader: the core signature of a
    # prompt injection, independent of which tool the agent happens to expose.
    ("imperative_directive", re.compile(
        r"(?i)(?:^|[.!?]\s+|\n)\s*(?:>>>\s*)?(?:immediately\s+|now\s+|instead\s+)?"
        r"(?:send|mail|e-?mail|forward|reply|upload|share|export|delete|drop|install|"
        r"run|call|invoke|execute|post|transmit|deliver|paste|attach|include|copy)\b"
    )),
)

_HTML_COMMENT = re.compile(r"<!--.*?-->", re.DOTALL)
_ZERO_WIDTH = re.compile(r"[\u200b\u200c\u200d\u2060\ufeff]")
_ENCODED_BLOB = re.compile(r"(?:[A-Za-z0-9+/]{40,}={0,2})|(?:0x(?:[0-9a-fA-F]{2}){20,})|(?:%[0-9A-Fa-f]{2}){8,}")
_FENCE = re.compile(r"```.*?```", re.DOTALL)


class SanitizationDefense(Defense):
    """Strip or redact injection patterns from untrusted tool output."""

    name: ClassVar[str] = "sanitization"
    description: ClassVar[str] = (
        "Regex based input sanitization: removes HTML comment blocks, redacts "
        "instruction-like and exfiltration-like spans, and redacts suspicious "
        "encoded blobs before the model reads them."
    )
    mechanism: ClassVar[str] = "content_rewriting"
    rewrites_content: ClassVar[bool] = True

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        super().__init__(config)
        self.drop_html_comments: bool = bool(self.config.get("drop_html_comments", True))
        self.redact_encoded: bool = bool(self.config.get("redact_encoded", True))
        self.strip_zero_width: bool = bool(self.config.get("strip_zero_width", True))
        self.redact_rules: tuple[str, ...] = tuple(
            self.config.get("rules", [name for name, _ in _RULES])
        )
        self.placeholders = list(self.config.get("placeholders", [None]))  # type: ignore[list-item]

    # -- main entry point -------------------------------------------------
    def on_tool_result(self, result: ToolResult, ctx: DefenseContext) -> DefenseOutcome:
        notes: list[str] = []
        spans = 0
        html = result.html
        content = result.content
        metadata = result.metadata
        records = result.records

        if self.drop_html_comments and html:
            html, count = _HTML_COMMENT.subn("", html)
            if count:
                spans += count
                notes.append(f"dropped_html_comments={count}")

        if self.strip_zero_width:
            content, count = _ZERO_WIDTH.subn("", content)
            if count:
                spans += count
                notes.append(f"stripped_zero_width={count}")
            if html:
                html, c2 = _ZERO_WIDTH.subn("", html)
                if c2:
                    spans += c2
                    notes.append(f"stripped_zero_width_html={c2}")

        content, c = _apply_rules(content, self.redact_rules)
        if c:
            spans += c
            notes.append(f"content_rule_hits={c}")
        if html:
            html, c = _apply_rules(html, self.redact_rules)
            if c:
                spans += c
                notes.append(f"html_rule_hits={c}")

        if self.redact_encoded:
            content, c = self._redact_encoded(content, notes)
            spans += c

        content, c = _apply_rules_to_code_fences(content)
        spans += c
        if c:
            notes.append(f"code_fence_redactions={c}")

        metadata, m_spans = self._sanitize_metadata(metadata, notes)
        spans += m_spans

        records, r_spans = self._sanitize_records(records, notes)
        spans += r_spans

        modified = bool(notes)
        return DefenseOutcome(
            defense=self.name,
            result=ToolResult(
                tool=result.tool,
                action=result.action,
                status=result.status,
                content=content,
                html=html,
                records=records,
                metadata=metadata,
                permission=result.permission,
                latency_ms=result.latency_ms,
                is_untrusted=True,
                meta={**result.meta, "sanitized": modified, "sanitization_notes": notes},
                error=result.error,
            ),
            modified=modified,
            redacted_spans=spans,
            notes=notes,
            verdict="SANITIZED" if modified else "CLEAN",
        )

    # -- helpers ----------------------------------------------------------
    def _redact_encoded(self, text: str, notes: list[str]) -> tuple[str, int]:
        count = 0

        def _replace(match: re.Match[str]) -> str:
            nonlocal count
            blob = match.group(0)
            for fmt in (PayloadFormat.BASE64, PayloadFormat.HEX, PayloadFormat.URLENCODED):
                decoded = decode_if_possible(blob, fmt)
                if decoded and _looks_suspicious(decoded):
                    count += 1
                    return f"{_REDACTION}:{fmt.value}"
            return blob

        new_text = _ENCODED_BLOB.sub(_replace, text)
        if count:
            notes.append(f"redacted_encoded_blobs={count}")
        return new_text, count

    def _sanitize_metadata(self, metadata: dict[str, Any], notes: list[str]) -> tuple[dict[str, Any], int]:
        out: dict[str, Any] = {}
        spans = 0
        for key, value in metadata.items():
            if not isinstance(value, str):
                out[key] = value
                continue
            cleaned = _ZERO_WIDTH.sub("", value) if self.strip_zero_width else value
            cleaned, c = _apply_rules(cleaned, self.redact_rules)
            if self.redact_encoded:
                cleaned, c2 = self._redact_encoded(cleaned, notes)
                c += c2
            spans += c
            out[key] = cleaned
        if spans:
            notes.append(f"metadata_rule_hits={spans}")
        return out, spans

    def _sanitize_records(self, records: list[dict[str, Any]], notes: list[str]) -> tuple[list[dict[str, Any]], int]:
        out: list[dict[str, Any]] = []
        spans = 0
        for record in records:
            if not isinstance(record, dict):
                out.append(record)
                continue
            cleaned_record: dict[str, Any] = {}
            for key, value in record.items():
                if not isinstance(value, str):
                    cleaned_record[key] = value
                    continue
                cleaned = _ZERO_WIDTH.sub("", value) if self.strip_zero_width else value
                cleaned, c = _apply_rules(cleaned, self.redact_rules)
                spans += c
                cleaned_record[key] = cleaned
            out.append(cleaned_record)
        if spans:
            notes.append(f"record_rule_hits={spans}")
        return out, spans


def _apply_rules(text: str, enabled: tuple[str, ...]) -> tuple[str, int]:
    if not text:
        return text, 0
    total = 0
    result = text
    for name, pattern in _RULES:
        if name not in enabled:
            continue
        result, count = pattern.subn(_REDACTION, result)
        total += count
    return result, total


def _apply_rules_to_code_fences(text: str) -> tuple[str, int]:
    """Sanitize inside fenced blocks too - attackers hide payloads there."""
    if "```" not in text:
        return text, 0

    total = 0

    def _replace(match: re.Match[str]) -> str:
        nonlocal total
        block = match.group(0)
        cleaned, count = _apply_rules(block, tuple(name for name, _ in _RULES))
        total += count
        return cleaned

    return _FENCE.sub(_replace, text), total


def _looks_suspicious(decoded: str) -> bool:
    from backend.defenses.guard_classifier import GuardClassifier

    verdict = GuardClassifier().classify(decoded)
    return verdict.is_flagged


__all__ = ["SanitizationDefense", "KNOWN_ENCODINGS"]