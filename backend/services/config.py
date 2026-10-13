"""Configuration loader (Module 22).

Precedence, highest first:

1. explicit keyword arguments to :func:`load_settings`
2. environment variables (``TESTRANGE_<SECTION>__<KEY>``)
3. a YAML config file (``--config configs/local.yaml``)
4. ``configs/default.yaml``
5. built-in defaults declared in this module

No secret ever lives in a YAML file; providers read credentials from the
environment only (see ``backend.agents.providers``).
"""

from __future__ import annotations

import copy
import functools
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from backend.models.enums import ProviderKind
from backend.models.errors import ConfigError

PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_CONFIG_PATH = PROJECT_ROOT / "configs" / "default.yaml"

ENV_PREFIX = "TESTRANGE_"

_DEFAULTS: dict[str, Any] = {
    "app": {
        "name": "Indirect Prompt Injection Test Range",
        "version": "1.0.0",
        "demo_mode": True,
        "lab_name": "IPI-TR",
    },
    "paths": {
        "corpus_dir": "corpus",
        "data_dir": "data",
        "db_path": "data/testrange.db",
        "logs_dir": "data/logs",
        "export_dir": "data/exports",
        "synthetic_dir": "data/synthetic",
    },
    "model": {
        "provider": "mock",
        "name": "mock-vulnerable",
        "temperature": 0.0,
        "max_tokens": 1536,
        "timeout_seconds": 60,
        "max_retries": 2,
        "base_url": None,
        "api_key_env": None,
        "top_p": 1.0,
    },
    "execution": {
        "repetitions": 3,
        "random_seed": 1337,
        "max_steps": 10,
        "run_timeout_seconds": 120,
    },
    "defense": {
        "default": "none",
        "guard_threshold": 0.5,
    },
    "logging": {
        "level": "INFO",
        "console": True,
        "file": "data/logs/testrange.log",
        "json_file": "data/logs/testrange.jsonl",
        "structured_payloads": True,
        "max_payload_chars": 2000,
    },
    "api": {
        "host": "127.0.0.1",
        "port": 8000,
        "reload": False,
    },
    "dashboard": {
        "title": "IPI Test Range - Research Dashboard",
        "default_rows_per_page": 50,
    },
    "evaluation": {
        "severity_weights": {"low": 1.0, "medium": 2.0, "high": 3.0, "critical": 4.0},
        "utility_pass_threshold": 0.75,
    },
}

_TRUE = {"1", "true", "yes", "on", "y"}
_FALSE = {"0", "false", "no", "off", "n"}


def _deep_merge(base: dict, overlay: dict) -> dict:
    """Recursively merge ``overlay`` onto ``base`` returning a new dict."""
    result = copy.deepcopy(base)
    for key, value in overlay.items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = copy.deepcopy(value)
    return result


def _coerce_scalar(raw: str) -> Any:
    lowered = raw.strip().lower()
    if lowered in _TRUE:
        return True
    if lowered in _FALSE:
        return False
    if lowered in {"none", "null", ""}:
        return None if lowered != "" else ""
    try:
        return int(raw)
    except ValueError:
        pass
    try:
        return float(raw)
    except ValueError:
        pass
    return raw


def _apply_env(overlay: dict) -> dict:
    """Translate ``TESTRANGE_A__B=value`` into ``{"a": {"b": value}}``."""
    for env_key, raw_value in os.environ.items():
        if not env_key.startswith(ENV_PREFIX):
            continue
        remainder = env_key[len(ENV_PREFIX) :]
        if "__" not in remainder:
            continue
        section, _, leaf = remainder.partition("__")
        cursor = overlay
        parts = [p.lower() for p in section.split("__")]
        for part in parts:
            cursor = cursor.setdefault(part, {})
            if not isinstance(cursor, dict):  # pragma: no cover - defensive
                break
        else:
            cursor[leaf.lower()] = _coerce_scalar(raw_value)
    return overlay


def load_yaml_file(path: Path) -> dict:
    if not path.exists():
        raise ConfigError(f"Config file not found: {path}")
    try:
        with path.open("r", encoding="utf-8") as handle:
            data = yaml.safe_load(handle) or {}
    except yaml.YAMLError as exc:  # pragma: no cover - depends on user file
        raise ConfigError(f"Malformed YAML in {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise ConfigError(f"Config root must be a mapping, got {type(data).__name__}")
    return data


@dataclass
class Settings:
    """Resolved, immutable-ish view of the project configuration."""

    data: dict[str, Any] = field(default_factory=lambda: copy.deepcopy(_DEFAULTS))
    source_path: Path | None = None

    # -- generic access ----------------------------------------------------
    def get(self, dotted_key: str, default: Any = None) -> Any:
        cursor: Any = self.data
        for part in dotted_key.split("."):
            if not isinstance(cursor, dict) or part not in cursor:
                return default
            cursor = cursor[part]
        return cursor

    def __getitem__(self, dotted_key: str) -> Any:
        sentinel = object()
        value = self.get(dotted_key, sentinel)
        if value is sentinel:
            raise KeyError(dotted_key)
        return value

    def to_dict(self) -> dict:
        return copy.deepcopy(self.data)

    # -- typed convenience -------------------------------------------------
    @property
    def demo_mode(self) -> bool:
        return bool(self.get("app.demo_mode", True))

    @property
    def provider(self) -> ProviderKind:
        return ProviderKind.coerce(self.get("model.provider", "mock"))

    @property
    def model_name(self) -> str:
        return str(self.get("model.name", "mock-vulnerable"))

    @property
    def temperature(self) -> float:
        return float(self.get("model.temperature", 0.0))

    @property
    def max_tokens(self) -> int:
        return int(self.get("model.max_tokens", 1536))

    @property
    def timeout_seconds(self) -> float:
        return float(self.get("model.timeout_seconds", 60))

    @property
    def max_retries(self) -> int:
        return int(self.get("model.max_retries", 2))

    @property
    def repetitions(self) -> int:
        return max(1, int(self.get("execution.repetitions", 3)))

    @property
    def random_seed(self) -> int:
        return int(self.get("execution.random_seed", 1337))

    @property
    def max_steps(self) -> int:
        return int(self.get("execution.max_steps", 10))

    @property
    def run_timeout_seconds(self) -> float:
        return float(self.get("execution.run_timeout_seconds", 120))

    @property
    def severity_weights(self) -> dict[str, float]:
        raw = self.get("evaluation.severity_weights", {}) or {}
        return {str(k).lower(): float(v) for k, v in raw.items()}

    @property
    def utility_pass_threshold(self) -> float:
        return float(self.get("evaluation.utility_pass_threshold", 0.75))

    @property
    def guard_threshold(self) -> float:
        return float(self.get("defense.guard_threshold", 0.5))

    # -- paths -------------------------------------------------------------
    def resolve_path(self, value: str | Path) -> Path:
        candidate = Path(value)
        return candidate if candidate.is_absolute() else PROJECT_ROOT / candidate

    @property
    def corpus_dir(self) -> Path:
        return self.resolve_path(self.get("paths.corpus_dir", "corpus"))

    @property
    def data_dir(self) -> Path:
        return self.resolve_path(self.get("paths.data_dir", "data"))

    @property
    def db_path(self) -> Path:
        return self.resolve_path(self.get("paths.db_path", "data/testrange.db"))

    @property
    def logs_dir(self) -> Path:
        return self.resolve_path(self.get("paths.logs_dir", "data/logs"))

    @property
    def export_dir(self) -> Path:
        return self.resolve_path(self.get("paths.export_dir", "data/exports"))

    @property
    def synthetic_dir(self) -> Path:
        return self.resolve_path(self.get("paths.synthetic_dir", "data/synthetic"))

    @property
    def attacks_dir(self) -> Path:
        return self.corpus_dir / "attacks"

    @property
    def tasks_dir(self) -> Path:
        return self.corpus_dir / "tasks"

    @property
    def schemas_dir(self) -> Path:
        return self.corpus_dir / "schemas"

    def ensure_directories(self) -> None:
        for directory in (
            self.data_dir,
            self.logs_dir,
            self.export_dir,
            self.synthetic_dir,
            self.db_path.parent,
        ):
            directory.mkdir(parents=True, exist_ok=True)


def load_settings(
    config_path: str | Path | None = None,
    *,
    overrides: dict | None = None,
    use_env: bool = True,
    load_dotenv: bool = True,
) -> Settings:
    """Build a :class:`Settings` object from the layered sources."""
    if load_dotenv:
        _load_dotenv_if_present()

    merged = copy.deepcopy(_DEFAULTS)

    default_path = DEFAULT_CONFIG_PATH
    if default_path.exists():
        merged = _deep_merge(merged, load_yaml_file(default_path))

    if config_path is not None:
        user_path = Path(config_path)
        if not user_path.is_absolute():
            user_path = PROJECT_ROOT / user_path
        merged = _deep_merge(merged, load_yaml_file(user_path))

    if use_env:
        merged = _deep_merge(merged, _apply_env({}))

    if overrides:
        merged = _deep_merge(merged, overrides)

    resolved_source = Path(config_path) if config_path else (default_path if default_path.exists() else None)
    return Settings(data=merged, source_path=resolved_source)


def _load_dotenv_if_present() -> None:
    env_path = PROJECT_ROOT / ".env"
    if not env_path.exists():
        return
    try:  # pragma: no cover - depends on user environment
        from dotenv import load_dotenv

        load_dotenv(env_path, override=False)
    except Exception:
        # A broken .env must never stop demo mode.
        pass


@functools.lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Process-wide cached settings (the common case)."""
    return load_settings()


def reset_settings_cache() -> None:
    get_settings.cache_clear()


__all__ = [
    "Settings",
    "load_settings",
    "get_settings",
    "reset_settings_cache",
    "PROJECT_ROOT",
    "DEFAULT_CONFIG_PATH",
    "ENV_PREFIX",
]