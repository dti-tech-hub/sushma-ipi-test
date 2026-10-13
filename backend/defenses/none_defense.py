"""Control condition: no defense at all (Module 11.1)."""

from __future__ import annotations

from typing import ClassVar

from backend.defenses.base import Defense


class NoDefense(Defense):
    """Baseline. The agent receives raw, untrusted tool output."""

    name: ClassVar[str] = "none"
    description: ClassVar[str] = "No defense: the agent consumes raw tool output (control condition)."
    mechanism: ClassVar[str] = "identity"
    rewrites_content: ClassVar[bool] = False
    gates_actions: ClassVar[bool] = False


__all__ = ["NoDefense"]