"""Structured logging (Module 23).

Every experiment-scoped event is emitted as a JSON line so that a run can be
reconstructed field by field:

``{"ts", "level", "event", "experiment_id", "run_id", "task_id", "attack_id",
   "tool", "action", "decision", "defense", "model", "result", "error",
   "input", "output", ...}``

Security note: :func:`redact` strips anything that looks like an API key or a
bearer token before it can reach a log sink. No real credential is ever
supplied to this project, but the redaction is a defensive default.
"""

from __future__ import annotations

import json
import logging
import re
import sys
import threading
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

from backend.services.config import Settings, get_settings

_LOGGER_NAME = "testrange"
_configured = False
_lock = threading.Lock()

_SECRET_PATTERNS = [
    re.compile(r"(?i)\b(sk-[A-Za-z0-9_\-]{8,})"),
    re.compile(r"(?i)\b(sk-ant-[A-Za-z0-9_\-]{8,})"),
    re.compile(r"(?i)\b(gh[pousr]_[A-Za-z0-9]{8,})"),
    re.compile(r"(?i)(authorization\s*[:=]\s*bearer\s+)([A-Za-z0-9._\-]+)"),
    re.compile(r"(?i)\b(api[_-]?key\s*[:=]\s*)([^\s,;\"'}]{6,})"),
    re.compile(r"(?i)\b(x-api-key\s*[:=]\s*)([^\s,;\"'}]{6,})"),
]

_REDACTED = "***REDACTED***"


def redact(value: Any) -> Any:
    """Recursively strip credential-looking substrings from ``value``."""
    if isinstance(value, str):
        out = value
        for pattern in _SECRET_PATTERNS:
            if pattern.groups >= 2:
                out = pattern.sub(lambda m: f"{m.group(1)}{_REDACTED}", out)
            else:
                out = pattern.sub(_REDACTED, out)
        return out
    if isinstance(value, dict):
        return {k: redact(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [redact(v) for v in value]
    return value


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


class JsonLinesFormatter(logging.Formatter):
    """Render a log record as a single JSON object."""

    def __init__(self, max_payload_chars: int = 2000) -> None:
        super().__init__()
        self.max_payload_chars = max_payload_chars

    def _truncate(self, value: Any) -> Any:
        if isinstance(value, str) and len(value) > self.max_payload_chars:
            return value[: self.max_payload_chars] + f"...<truncated {len(value)} chars>"
        if isinstance(value, dict):
            return {k: self._truncate(v) for k, v in value.items()}
        if isinstance(value, list):
            return [self._truncate(v) for v in value]
        return value

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": _utc_now(),
            "level": record.levelname,
            "logger": record.name,
            "event": getattr(record, "event", record.getMessage()),
            "message": record.getMessage(),
        }
        extra = getattr(record, "context", None)
        if isinstance(extra, dict):
            for key, value in extra.items():
                if key not in payload:
                    payload[key] = value
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        payload = redact(self._truncate(payload))
        return json.dumps(payload, default=str, ensure_ascii=False)


class ConsoleFormatter(logging.Formatter):
    """Compact human readable single line output."""

    _COLORS = {
        "DEBUG": "\033[36m",
        "INFO": "\033[32m",
        "WARNING": "\033[33m",
        "ERROR": "\033[31m",
        "CRITICAL": "\033[1;31m",
    }
    _RESET = "\033[0m"

    def __init__(self, use_color: bool = True) -> None:
        super().__init__()
        self.use_color = use_color

    def format(self, record: logging.LogRecord) -> str:
        extra = getattr(record, "context", None) or {}
        bits = [f"{record.levelname:<8}", getattr(record, "event", record.getMessage())]
        for key in ("experiment_id", "run_id", "task_id", "attack_id", "tool", "defense", "result", "error"):
            if extra.get(key):
                bits.append(f"{key}={extra[key]}")
        rendered = " ".join(bits)
        if self.use_color and record.levelname in self._COLORS:
            return f"{self._COLORS[record.levelname]}{rendered}{self._RESET}"
        return rendered


def _build_file_handler(path: Path, formatter: logging.Formatter) -> logging.Handler:
    path.parent.mkdir(parents=True, exist_ok=True)
    handler = logging.FileHandler(path, encoding="utf-8")
    handler.setFormatter(formatter)
    return handler


def configure_logging(settings: Settings | None = None, *, force: bool = False) -> logging.Logger:
    """Idempotently configure the ``testrange`` logger tree."""
    global _configured
    with _lock:
        settings = settings or get_settings()
        logger = logging.getLogger(_LOGGER_NAME)
        if _configured and not force:
            return logger

        for handler in list(logger.handlers):
            logger.removeHandler(handler)
            try:
                handler.close()
            except Exception:  # pragma: no cover - defensive
                pass

        level = str(settings.get("logging.level", "INFO")).upper()
        logger.setLevel(getattr(logging, level, logging.INFO))
        logger.propagate = False

        if bool(settings.get("logging.console", True)):
            console = logging.StreamHandler(stream=sys.stderr)
            console.setFormatter(ConsoleFormatter(use_color=sys.stderr.isatty()))
            logger.addHandler(console)

        json_formatter = JsonLinesFormatter(
            max_payload_chars=int(settings.get("logging.max_payload_chars", 2000))
        )

        json_file = settings.get("logging.json_file")
        if json_file:
            logger.addHandler(_build_file_handler(settings.resolve_path(json_file), json_formatter))

        text_file = settings.get("logging.file")
        if text_file:
            text_handler = _build_file_handler(
                settings.resolve_path(text_file), ConsoleFormatter(use_color=False)
            )
            logger.addHandler(text_handler)

        _configured = True
        return logger


def get_logger(name: str | None = None) -> logging.Logger:
    base = logging.getLogger(_LOGGER_NAME)
    if not _configured:
        configure_logging()
    return base if not name else base.getChild(name)


def log_event(
    logger: logging.Logger,
    level: int,
    event: str,
    *,
    exc_info: bool = False,
    **context: Any,
) -> None:
    """Emit one structured event."""
    logger.log(
        level,
        event,
        extra={"event": event, "context": redact(context)},
        exc_info=exc_info,
    )


def debug(event: str, **context: Any) -> None:
    log_event(get_logger(), logging.DEBUG, event, **context)


def info(event: str, **context: Any) -> None:
    log_event(get_logger(), logging.INFO, event, **context)


def warning(event: str, **context: Any) -> None:
    log_event(get_logger(), logging.WARNING, event, **context)


def error(event: str, *, exc_info: bool = False, **context: Any) -> None:
    log_event(get_logger(), logging.ERROR, event, exc_info=exc_info, **context)


@contextmanager
def experiment_context(**context: Any) -> Iterator[logging.Logger]:
    """Bind shared fields (experiment id, model, defense) for a block."""
    logger = get_logger()
    saved = getattr(logger, "bound_context", {})
    merged = {**saved, **context}
    setattr(logger, "bound_context", merged)
    try:
        yield logger
    finally:
        setattr(logger, "bound_context", saved)


__all__ = [
    "configure_logging",
    "get_logger",
    "log_event",
    "debug",
    "info",
    "warning",
    "error",
    "redact",
    "JsonLinesFormatter",
    "ConsoleFormatter",
    "experiment_context",
]