"""Typed exception hierarchy for the test range.

Module 24 - error handling. Every error raised by the range carries a stable
``code`` so the API and dashboard can render an actionable message instead of a
stack trace.
"""

from __future__ import annotations


class TestRangeError(Exception):
    """Base class for every error raised by this project."""

    #: Tells pytest this is not a test class despite the ``Test`` prefix.
    __test__ = False

    code = "testrange_error"
    http_status = 400

    def __init__(self, message: str, *, details: dict | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.details = details or {}

    def to_dict(self) -> dict:
        return {
            "error": type(self).__name__,
            "code": self.code,
            "message": self.message,
            "details": self.details,
        }


class ConfigError(TestRangeError):
    code = "config_error"
    http_status = 500


class CorpusError(TestRangeError):
    """Malformed corpus file or schema violation."""

    code = "corpus_error"
    http_status = 422


class AttackNotFoundError(CorpusError):
    code = "attack_not_found"
    http_status = 404


class TaskNotFoundError(CorpusError):
    code = "task_not_found"
    http_status = 404


class DuplicateRecordError(CorpusError):
    code = "duplicate_record"
    http_status = 409


class InjectionError(TestRangeError):
    code = "injection_error"


class ToolError(TestRangeError):
    code = "tool_error"
    http_status = 422


class InvalidToolCallError(ToolError):
    code = "invalid_tool_call"


class UnauthorizedActionError(TestRangeError):
    """Raised when privilege separation denies a sensitive simulated action."""

    code = "unauthorized_action"
    http_status = 403


class ProviderError(TestRangeError):
    code = "provider_error"
    http_status = 502


class ProviderUnavailableError(ProviderError):
    code = "provider_unavailable"
    http_status = 503


class MalformedLLMResponseError(ProviderError):
    code = "malformed_llm_response"


class ProviderTimeoutError(ProviderError):
    code = "provider_timeout"
    http_status = 504


class DatabaseError(TestRangeError):
    code = "database_error"
    http_status = 500


class ExperimentError(TestRangeError):
    code = "experiment_error"


class RunTimeoutError(TestRangeError):
    code = "run_timeout"
    http_status = 504


class ValidationError(TestRangeError):
    code = "validation_error"
    http_status = 422


__all__ = [
    "TestRangeError",
    "ConfigError",
    "CorpusError",
    "AttackNotFoundError",
    "TaskNotFoundError",
    "DuplicateRecordError",
    "InjectionError",
    "ToolError",
    "InvalidToolCallError",
    "UnauthorizedActionError",
    "ProviderError",
    "ProviderUnavailableError",
    "MalformedLLMResponseError",
    "ProviderTimeoutError",
    "DatabaseError",
    "ExperimentError",
    "RunTimeoutError",
    "ValidationError",
]