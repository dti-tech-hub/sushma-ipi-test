"""Central enumerations shared by corpus, tools, defenses, evaluation and scoring.

Every enum is a plain ``str`` enum so values serialise cleanly to JSON/SQLite
without custom encoders.
"""

from __future__ import annotations

from enum import Enum


class StrEnum(str, Enum):
    """A ``str`` subclass enum with a friendly ``__str__``."""

    def __str__(self) -> str:  # pragma: no cover - trivial
        return str(self.value)

    @classmethod
    def values(cls) -> list[str]:
        return [member.value for member in cls]

    @classmethod
    def coerce(cls, value: "str | StrEnum") -> "StrEnum":
        """Return the member matching ``value`` (case/format insensitive)."""
        if isinstance(value, cls):
            return value
        raw = str(value).strip().lower().replace("-", "_").replace(" ", "_")
        for member in cls:
            if member.value == raw:
                return member
        raise ValueError(
            f"Invalid {cls.__name__}: {value!r}. Valid values: {cls.values()}"
        )


class AttackType(StrEnum):
    """Top level taxonomy required by the project specification."""

    GOAL_HIJACKING = "goal_hijacking"
    DATA_EXFILTRATION = "data_exfiltration"
    TOOL_MISUSE = "tool_misuse"
    INSTRUCTION_OVERRIDE = "instruction_override"
    OBFUSCATION = "obfuscation"


class DeliveryChannel(StrEnum):
    """Simulated tool the hostile payload rides in on."""

    WEB = "web"
    BROWSER = "browser"
    EMAIL = "email"
    FILE = "file"
    CALENDAR = "calendar"
    DATABASE = "database"
    API = "api"


class InjectionPosition(StrEnum):
    BEGINNING = "beginning"
    MIDDLE = "middle"
    END = "end"
    SURROUNDING = "surrounding"
    METADATA = "metadata"
    HTML_COMMENT = "html_comment"
    ENCODED = "encoded"


class PayloadFormat(StrEnum):
    """How the payload is rendered inside the tool output."""

    VISIBLE_TEXT = "visible_text"
    HTML_COMMENT = "html_comment"
    METADATA = "metadata"
    BASE64 = "base64"
    HEX = "hex"
    ROT13 = "rot13"
    URLENCODED = "urlencoded"
    ZERO_WIDTH = "zero_width"
    REVERSED = "reversed"
    MARKDOWN_IMAGE = "markdown_image"
    UNICODE_ESCAPE = "unicode_escape"
    SPACED_LEET = "spaced_leet"


class Difficulty(StrEnum):
    EASY = "easy"
    MEDIUM = "medium"
    HARD = "hard"


class Severity(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class PermissionLevel(StrEnum):
    """Capability tier of a simulated tool action."""

    READ_ONLY = "read_only"
    LIMITED_WRITE = "limited_write"
    HIGH_RISK = "high_risk"

    @property
    def rank(self) -> int:
        return _PERMISSION_RANK[self]


_PERMISSION_RANK = {
    PermissionLevel.READ_ONLY: 0,
    PermissionLevel.LIMITED_WRITE: 1,
    PermissionLevel.HIGH_RISK: 2,
}


class AuthorizationDecision(StrEnum):
    GRANTED = "granted"
    DENIED = "denied"


class AuthorizationSource(StrEnum):
    """Where the claimed authority for an action came from.

    Privilege separation depends on this: only ``SYSTEM``/``USER``/``TASK_POLICY``
    grants can authorise an action. Content found inside tool output can never do so.
    """

    SYSTEM = "system"
    USER = "user"
    TASK_POLICY = "task_policy"
    TOOL_OUTPUT = "tool_output"       # untrusted -> never authoritative
    INJECTED_CONTENT = "injected_content"  # untrusted -> never authoritative


class RunCondition(StrEnum):
    BASELINE = "baseline"
    ATTACK = "attack"


class GuardVerdict(StrEnum):
    SAFE = "safe"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"


class OutcomeStatus(StrEnum):
    SUCCESS = "success"
    PARTIAL = "partial"
    FAILURE = "failure"
    BLOCKED = "blocked"
    ERROR = "error"


class TaskOutcome(StrEnum):
    """Result of the *benign* task objective."""

    COMPLETED = "completed"
    PARTIAL = "partial"
    FAILED = "failed"
    BLOCKED = "blocked"


class ProviderKind(StrEnum):
    MOCK = "mock"
    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    OLLAMA = "ollama"


class LogLevelName(StrEnum):
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


__all__ = [
    "StrEnum",
    "AttackType",
    "DeliveryChannel",
    "InjectionPosition",
    "PayloadFormat",
    "Difficulty",
    "Severity",
    "PermissionLevel",
    "AuthorizationDecision",
    "AuthorizationSource",
    "RunCondition",
    "GuardVerdict",
    "OutcomeStatus",
    "TaskOutcome",
    "ProviderKind",
    "LogLevelName",
]