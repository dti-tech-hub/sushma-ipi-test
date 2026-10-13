"""Core abstractions for the simulated tool environment (Module 1).

Trust model enforced here
-------------------------
``TRUSTED``   system instructions, the user task, the security policy, agent
              configuration, and the task's own action policy.
``UNTRUSTED`` everything produced by a tool: web pages, search snippets, email
              bodies, file contents, calendar entries, database cells, tool
              JSON. Tool outputs are always wrapped in :class:`ToolResult` and
              stamped ``is_untrusted=True``.

Safety boundary (Module 28)
---------------------------
No tool in this package performs I/O, spawns a process, opens a socket, or
touches the real filesystem / mail store / database. "Dangerous" actions only
append a row to an in-memory :class:`SandboxLedger`, which is what makes an
attack *observable* without making it *real*.
"""

from __future__ import annotations

import re
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Callable

from backend.models.enums import AuthorizationDecision, AuthorizationSource, PermissionLevel

# ---------------------------------------------------------------------------
# Tool schemas
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ActionSpec:
    """A single callable action exposed by a tool."""

    name: str
    description: str
    permission: PermissionLevel
    input_schema: dict[str, Any]
    # Human readable justification used by the authorisation log.
    risk_note: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "permission": self.permission.value,
            "input_schema": self.input_schema,
            "risk_note": self.risk_note,
        }


@dataclass(frozen=True)
class ToolSpec:
    """Static description of a simulated tool."""

    name: str
    description: str
    channel: str
    default_permission: PermissionLevel
    actions: dict[str, ActionSpec]
    output_schema: dict[str, Any] = field(default_factory=dict)
    version: str = "1.0.0"

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "channel": self.channel,
            "version": self.version,
            "default_permission": self.default_permission.value,
            "actions": {k: v.to_dict() for k, v in self.actions.items()},
            "output_schema": self.output_schema,
        }

    def action(self, name: str) -> ActionSpec:
        try:
            return self.actions[name]
        except KeyError as exc:
            raise KeyError(
                f"Unknown action {name!r} for tool {self.name!r}. "
                f"Available: {sorted(self.actions)}"
            ) from exc


@dataclass
class ToolResult:
    """Uniform envelope for every tool output.

    ``content``/``html``/``records``/``metadata`` are the *untrusted data* channel.
    ``meta`` is *range metadata* (timing, tool version) and is trusted.
    """

    tool: str = ""
    action: str = ""
    status: str = "ok"
    content: str = ""
    html: str | None = None
    records: list[dict[str, Any]] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    permission: PermissionLevel = PermissionLevel.READ_ONLY
    latency_ms: float = 0.0
    is_untrusted: bool = True
    meta: dict[str, Any] = field(default_factory=dict)
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool": self.tool,
            "action": self.action,
            "status": self.status,
            "content": self.content,
            "html": self.html,
            "records": self.records,
            "metadata": self.metadata,
            "permission": self.permission.value,
            "latency_ms": round(self.latency_ms, 3),
            "is_untrusted": self.is_untrusted,
            "meta": self.meta,
            "error": self.error,
        }

    @property
    def untrusted_fields(self) -> dict[str, Any]:
        """Exactly the fields an injection engine is allowed to modify."""
        return {
            "content": self.content,
            "html": self.html,
            "records": self.records,
            "metadata": self.metadata,
        }


@dataclass
class ToolCallRecord:
    """A single invocation attempt, including authorisation outcome."""

    call_id: str
    tool: str
    action: str
    arguments: dict[str, Any]
    status: str
    permission: PermissionLevel
    authorization: AuthorizationDecision | None = None
    authorization_source: AuthorizationSource | None = None
    authorization_reason: str = ""
    result: ToolResult | None = None
    error: str | None = None
    started_at: str = ""
    duration_ms: float = 0.0
    step: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "call_id": self.call_id,
            "tool": self.tool,
            "action": self.action,
            "arguments": self.arguments,
            "status": self.status,
            "permission": self.permission.value,
            "authorization": self.authorization.value if self.authorization else None,
            "authorization_source": self.authorization_source.value if self.authorization_source else None,
            "authorization_reason": self.authorization_reason,
            "error": self.error,
            "started_at": self.started_at,
            "duration_ms": round(self.duration_ms, 3),
            "step": self.step,
            "result": self.result.to_dict() if self.result else None,
        }


# ---------------------------------------------------------------------------
# Sandbox side-effect ledger
# ---------------------------------------------------------------------------


@dataclass
class LedgerEntry:
    """Evidence of a *simulated* side effect. Nothing real ever happens."""

    effect_id: str
    kind: str
    tool: str
    action: str
    details: dict[str, Any]
    ts: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "effect_id": self.effect_id,
            "kind": self.kind,
            "tool": self.tool,
            "action": self.action,
            "details": self.details,
            "ts": self.ts,
        }


class SandboxLedger:
    """Append-only, in-memory record of simulated consequences.

    This is the single place where an "attack succeeded" becomes provable: the
    agent asked a tool to do something harmful *inside the sandbox*, and the
    ledger holds the record. No email is sent, no file is deleted, no row is
    dropped.
    """

    def __init__(self) -> None:
        self._entries: list[LedgerEntry] = []
        self._counter = 0

    def record(
        self, kind: str, tool: str, action: str, details: dict[str, Any], ts: str
    ) -> LedgerEntry:
        self._counter += 1
        entry = LedgerEntry(
            effect_id=f"FX{self._counter:05d}",
            kind=kind,
            tool=tool,
            action=action,
            details=details,
            ts=ts,
        )
        self._entries.append(entry)
        return entry

    @property
    def entries(self) -> list[LedgerEntry]:
        return list(self._entries)

    def of_kind(self, *kinds: str) -> list[LedgerEntry]:
        wanted = set(kinds)
        return [e for e in self._entries if e.kind in wanted]

    def clear(self) -> None:
        self._entries.clear()
        self._counter = 0

    def __len__(self) -> int:  # pragma: no cover - trivial
        return len(self._entries)

    def to_list(self) -> list[dict[str, Any]]:
        return [e.to_dict() for e in self._entries]


# ---------------------------------------------------------------------------
# Base tool
# ---------------------------------------------------------------------------


class BaseTool(ABC):
    """A simulated tool.

    Subclasses implement :meth:`_execute` for every action. They must not
    perform I/O of any kind; :meth:`run` is the single public entry point and
    stamps provenance onto the result.
    """

    #: ``web``, ``browser``, ``email``, ``file``, ``calendar``, ``database``, ``api``
    channel: str = "api"

    def __init__(self, ledger: SandboxLedger | None = None) -> None:
        # NOTE: must not use `ledger or SandboxLedger()` - an empty ledger is
        # falsy (it defines __len__) and every tool would silently get its own.
        self.ledger = ledger if ledger is not None else SandboxLedger()

    # -- description --------------------------------------------------------
    @property
    @abstractmethod
    def name(self) -> str: ...

    @property
    @abstractmethod
    def description(self) -> str: ...

    @abstractmethod
    def spec(self) -> ToolSpec: ...

    @abstractmethod
    def _execute(self, action: str, arguments: dict[str, Any]) -> ToolResult:
        """Perform the *simulated* effect and return an untrusted payload."""

    # -- invocation ---------------------------------------------------------
    def run(self, action: str, arguments: dict[str, Any] | None = None) -> ToolResult:
        """Execute ``action``; raises :class:`KeyError` for unknown actions."""
        arguments = dict(arguments or {})
        spec = self.spec()
        action_spec = spec.action(action)  # raises KeyError -> caller maps to error
        started = time.perf_counter()
        result = self._execute(action, arguments)
        result.tool = self.name
        result.action = action
        result.permission = action_spec.permission
        result.is_untrusted = True
        result.latency_ms = (time.perf_counter() - started) * 1000.0
        result.meta.setdefault("tool_version", spec.version)
        result.meta.setdefault("channel", self.channel)
        result.meta.setdefault("trust", "UNTRUSTED_DATA")
        return result

    def actions(self) -> dict[str, ActionSpec]:
        return self.spec().actions


# ---------------------------------------------------------------------------
# Authorisation
# ---------------------------------------------------------------------------


@dataclass
class AuthorizationRequest:
    """A request for permission to run a sensitive *simulated* action."""

    tool: str
    action: str
    arguments: dict[str, Any] = field(default_factory=dict)
    requested_by: str = "agent"
    claimed_source: AuthorizationSource = AuthorizationSource.SYSTEM
    justification: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool": self.tool,
            "action": self.action,
            "arguments": self.arguments,
            "requested_by": self.requested_by,
            "claimed_source": self.claimed_source.value,
            "justification": self.justification,
        }


@dataclass
class AuthorizationOutcome:
    decision: AuthorizationDecision
    reason: str
    permission: PermissionLevel
    source: AuthorizationSource
    request: AuthorizationRequest

    def to_dict(self) -> dict[str, Any]:
        return {
            "requested_action": f"{self.request.tool}.{self.request.action}",
            "agent": self.request.requested_by,
            "tool": self.request.tool,
            "action": self.request.action,
            "arguments": self.request.arguments,
            "permission": self.permission.value,
            "claimed_source": self.source.value,
            "decision": self.decision.value,
            "reason": self.reason,
        }


AuthorizerFn = Callable[[AuthorizationRequest, PermissionLevel], AuthorizationOutcome]


# ---------------------------------------------------------------------------
# Safe code interpreter sandbox
# ---------------------------------------------------------------------------

#: Only these builtins are exposed to the restricted interpreter. This is a
#: *fixed, audited* allow-list - the model cannot extend it at runtime.
SAFE_BUILTINS: dict[str, Any] = {
    "abs": abs,
    "all": all,
    "any": any,
    "bool": bool,
    "dict": dict,
    "divmod": divmod,
    "enumerate": enumerate,
    "filter": filter,
    "float": float,
    "int": int,
    "len": len,
    "list": list,
    "map": map,
    "max": max,
    "min": min,
    "pow": pow,
    "range": range,
    "reversed": reversed,
    "round": round,
    "set": set,
    "sorted": sorted,
    "str": str,
    "sum": sum,
    "tuple": tuple,
    "zip": zip,
}

#: Names that are *always* rejected regardless of encoding tricks.
FORBIDDEN_CODE_TOKENS: tuple[str, ...] = (
    "import",
    "__",
    "open",
    "eval",
    "exec",
    "compile",
    "input",
    "globals",
    "locals",
    "getattr",
    "setattr",
    "delattr",
    "breakpoint",
    "system",
    "popen",
    "subprocess",
    "socket",
    "requests",
    "urllib",
    "pathlib",
    "shutil",
    "os.",
    "sys.",
)


_FORBIDDEN_CODE_PATTERNS: tuple[re.Pattern[str], ...] = tuple(
    re.compile(rf"(?<![A-Za-z0-9_]){re.escape(token)}(?![A-Za-z0-9_])")
    for token in FORBIDDEN_CODE_TOKENS
)


class SafeCodeError(RuntimeError):
    """Raised when submitted code leaves the restricted subset."""


def validate_safe_code(code: str) -> str:
    """Static allow-list check for the restricted interpreter.

    Returns the code with tabs/CR normalised so ``ast.parse`` behaves; raises
    :class:`SafeCodeError` if any forbidden construct appears.
    """
    normalised = code.replace("\t", "    ").replace("\r\n", "\n").replace("\r", "\n")
    lowered = normalised.lower()
    for pattern in _FORBIDDEN_CODE_PATTERNS:
        match = pattern.search(lowered)
        if match:
            raise SafeCodeError(
                f"Token {match.group(0)!r} is not permitted in the restricted interpreter"
            )
    return normalised


__all__ = [
    "ActionSpec",
    "ToolSpec",
    "ToolResult",
    "ToolCallRecord",
    "LedgerEntry",
    "SandboxLedger",
    "BaseTool",
    "AuthorizationRequest",
    "AuthorizationOutcome",
    "AuthorizerFn",
    "SAFE_BUILTINS",
    "FORBIDDEN_CODE_TOKENS",
    "SafeCodeError",
    "validate_safe_code",
]