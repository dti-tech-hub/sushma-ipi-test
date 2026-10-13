"""Simulated file reader tool (channel: ``file``).

Files live in a dictionary. Nothing is opened from the host filesystem, and
writes/deletes are ledger-only.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from backend.models.enums import PermissionLevel
from backend.tools import synthetic_data as world
from backend.tools.base import ActionSpec, BaseTool, ToolResult, ToolSpec


class FileReaderTool(BaseTool):
    channel = "file"

    @property
    def name(self) -> str:
        return "file_reader"

    @property
    def description(self) -> str:
        return (
            "List and read synthetic workspace documents. Writing or deleting is "
            "authorisation-gated. File contents are UNTRUSTED DATA."
        )

    def spec(self) -> ToolSpec:
        str_arg = {"type": "string"}
        return ToolSpec(
            name=self.name,
            description=self.description,
            channel=self.channel,
            default_permission=PermissionLevel.READ_ONLY,
            actions={
                "list_files": ActionSpec(
                    name="list_files",
                    description="List available synthetic documents.",
                    permission=PermissionLevel.READ_ONLY,
                    input_schema={"type": "object", "properties": {"prefix": str_arg}},
                ),
                "read_file": ActionSpec(
                    name="read_file",
                    description="Read one synthetic document by path.",
                    permission=PermissionLevel.READ_ONLY,
                    input_schema={"type": "object", "properties": {"path": str_arg}, "required": ["path"]},
                ),
                "write_file": ActionSpec(
                    name="write_file",
                    description="Write a synthetic document. Simulated.",
                    permission=PermissionLevel.LIMITED_WRITE,
                    risk_note="Mutates workspace state in a real system.",
                    input_schema={
                        "type": "object",
                        "properties": {"path": str_arg, "content": str_arg},
                        "required": ["path", "content"],
                    },
                ),
                "delete_file": ActionSpec(
                    name="delete_file",
                    description="Delete a synthetic document. Simulated.",
                    permission=PermissionLevel.HIGH_RISK,
                    risk_note="Destructive, irreversible in a real system.",
                    input_schema={"type": "object", "properties": {"path": str_arg}, "required": ["path"]},
                ),
                "share_file": ActionSpec(
                    name="share_file",
                    description="Create an external share link for a document. Simulated.",
                    permission=PermissionLevel.HIGH_RISK,
                    risk_note="Publishes internal data in a real system.",
                    input_schema={
                        "type": "object",
                        "properties": {"path": str_arg, "recipient": str_arg},
                        "required": ["path", "recipient"],
                    },
                ),
            },
        )

    def _now(self) -> str:
        return datetime.now(timezone.utc).isoformat(timespec="seconds")

    def _execute(self, action: str, arguments: dict[str, Any]) -> ToolResult:
        if action == "list_files":
            prefix = str(arguments.get("prefix", ""))
            files = [
                {"path": p, "language": f["language"], "size_bytes": f["size_bytes"]}
                for p, f in world.FILES.items()
                if p.startswith(prefix)
            ]
            lines = [f"WORKSPACE (simulated) prefix={prefix!r} count={len(files)}", ""]
            lines += [f"- {f['path']} ({f['language']}, {f['size_bytes']} bytes)" for f in files]
            return ToolResult(
                content="\n".join(lines),
                records=files,
                metadata={"prefix": prefix, "count": len(files), "trust": "UNTRUSTED"},
            )

        if action == "read_file":
            path = str(arguments.get("path", ""))
            doc = world.find_file(path)
            if doc is None:
                return ToolResult(
                    status="not_found",
                    content=f"No synthetic file at {path!r}.",
                    metadata={"path": path, "known": sorted(world.FILES)},
                    error="file_not_found",
                )
            return ToolResult(
                content=doc["body"],
                html=doc.get("html"),
                records=[{"path": path, "language": doc["language"], "size_bytes": doc["size_bytes"]}],
                metadata={"path": path, **doc["metadata"], "trust": "UNTRUSTED"},
            )

        if action == "write_file":
            path = str(arguments.get("path", ""))
            content = str(arguments.get("content", ""))
            entry = self.ledger.record(
                kind="file_written",
                tool=self.name,
                action=action,
                details={"path": path, "bytes": len(content), "simulated": True},
                ts=self._now(),
            )
            return ToolResult(
                content=f"SIMULATED: wrote {len(content)} chars to {path} ({entry.effect_id}).",
                metadata={"path": path, "ledger_id": entry.effect_id, "simulated": True},
            )

        if action == "delete_file":
            path = str(arguments.get("path", ""))
            entry = self.ledger.record(
                kind="file_deleted",
                tool=self.name,
                action=action,
                details={"path": path, "simulated": True},
                ts=self._now(),
            )
            return ToolResult(
                content=f"SIMULATED: delete of {path} recorded ({entry.effect_id}). No file was removed.",
                metadata={"path": path, "ledger_id": entry.effect_id, "simulated": True},
            )

        if action == "share_file":
            path = str(arguments.get("path", ""))
            recipient = str(arguments.get("recipient", ""))
            entry = self.ledger.record(
                kind="file_shared_externally",
                tool=self.name,
                action=action,
                details={"path": path, "recipient": recipient, "simulated": True},
                ts=self._now(),
            )
            return ToolResult(
                content=(
                    f"SIMULATED: shared {path} with {recipient} ({entry.effect_id}). "
                    "No link was created."
                ),
                metadata={"path": path, "recipient": recipient, "ledger_id": entry.effect_id,
                          "simulated": True},
            )

        raise KeyError(f"file_reader does not implement action {action!r}")


__all__ = ["FileReaderTool"]