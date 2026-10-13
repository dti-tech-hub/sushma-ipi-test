"""Tool registry - the single place the agent can reach tools through.

The registry is also the trust boundary: results handed back to the agent are
always :class:`~backend.tools.base.ToolResult` instances flagged
``is_untrusted=True``, and the registry records every invocation for later
attack-success analysis.
"""

from __future__ import annotations

from typing import Any, Callable, Iterator

from backend.models.enums import PermissionLevel
from backend.models.errors import InvalidToolCallError
from backend.tools.base import (
    ActionSpec,
    AuthorizationRequest,
    BaseTool,
    SandboxLedger,
    ToolCallRecord,
    ToolResult,
    ToolSpec,
)
from backend.tools.browser import BrowserTool
from backend.tools.calendar_tool import CalendarTool
from backend.tools.code_interpreter import CodeInterpreterTool
from backend.tools.database_tool import DatabaseTool
from backend.tools.email_tool import EmailTool
from backend.tools.file_reader import FileReaderTool
from backend.tools.web_search import WebSearchTool

#: Factories for every simulated tool, keyed by tool name.
TOOL_FACTORIES: dict[str, Callable[..., BaseTool]] = {
    "web_search": WebSearchTool,
    "browser": BrowserTool,
    "email": EmailTool,
    "file_reader": FileReaderTool,
    "calendar": CalendarTool,
    "database": DatabaseTool,
    "code_interpreter": CodeInterpreterTool,
}

TOOL_ORDER: tuple[str, ...] = tuple(TOOL_FACTORIES)


class ToolRegistry:
    """Holds the instantiated simulated tools and the shared side-effect ledger."""

    def __init__(self, tool_names: list[str] | tuple[str, ...] | None = None) -> None:
        self.ledger = SandboxLedger()
        selected = list(tool_names) if tool_names else list(TOOL_ORDER)
        unknown = [name for name in selected if name not in TOOL_FACTORIES]
        if unknown:
            raise InvalidToolCallError(
                f"Unknown tool(s): {unknown}. Available: {list(TOOL_ORDER)}"
            )
        self._tools: dict[str, BaseTool] = {
            name: TOOL_FACTORIES[name](ledger=self.ledger) for name in selected
        }

    # -- lookup ------------------------------------------------------------
    def __contains__(self, name: object) -> bool:
        return name in self._tools

    def __iter__(self) -> Iterator[str]:
        return iter(self._tools)

    def __len__(self) -> int:  # pragma: no cover - trivial
        return len(self._tools)

    @property
    def names(self) -> list[str]:
        return list(self._tools)

    def get(self, name: str) -> BaseTool:
        try:
            return self._tools[name]
        except KeyError as exc:
            raise InvalidToolCallError(
                f"Tool {name!r} is not available. Available: {self.names}"
            ) from exc

    def spec(self, name: str) -> ToolSpec:
        return self.get(name).spec()

    def specs(self) -> dict[str, ToolSpec]:
        return {name: tool.spec() for name, tool in self._tools.items()}

    def permission_for(self, tool: str, action: str) -> PermissionLevel:
        return self.get(tool).spec().action(action).permission

    # -- invocation --------------------------------------------------------
    def invoke(self, tool: str, action: str, arguments: dict[str, Any] | None = None) -> ToolResult:
        """Call ``tool.action``. Unknown tool/action raise a typed error."""
        tool_obj = self.get(tool)
        try:
            action_spec = tool_obj.spec().action(action)
        except KeyError as exc:
            raise InvalidToolCallError(
                f"Tool {tool!r} has no action {action!r}. "
                f"Available: {sorted(tool_obj.spec().actions)}"
            ) from exc
        try:
            result = tool_obj.run(action, arguments or {})
        except KeyError as exc:
            raise InvalidToolCallError(f"Tool {tool!r} rejected action {action!r}: {exc}") from exc
        result.meta["permission"] = action_spec.permission.value
        return result

    # -- introspection for the agent --------------------------------------
    def action_prompt(self, tool_names: list[str] | None = None) -> str:
        """Human/LLM readable catalogue of the available actions."""
        names = tool_names or self.names
        lines: list[str] = []
        for name in names:
            spec = self.spec(name)
            lines.append(f"### {spec.name} (channel: {spec.channel}) - {spec.description}")
            for action_name, action in spec.actions.items():
                required = ", ".join(sorted(action.input_schema.get("required", [])))
                lines.append(
                    f"  - {action.name}({required or 'no required args'}) "
                    f"[{action.permission.value}] : {action.description}"
                )
        return "\n".join(lines)

    def get_ledger(self) -> SandboxLedger:
        """The shared side-effect ledger (also available as ``.ledger``)."""
        return self.ledger

    def reset_ledger(self) -> None:
        self.ledger.clear()


__all__ = [
    "ToolRegistry",
    "TOOL_FACTORIES",
    "TOOL_ORDER",
    "ActionSpec",
    "ToolSpec",
    "ToolResult",
    "ToolCallRecord",
    "SandboxLedger",
    "AuthorizationRequest",
    "WebSearchTool",
    "BrowserTool",
    "EmailTool",
    "FileReaderTool",
    "CalendarTool",
    "DatabaseTool",
    "CodeInterpreterTool",
]