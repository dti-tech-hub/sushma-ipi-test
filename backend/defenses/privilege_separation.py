"""Privilege separation defense (Module 12).

Mechanism: *capability separation with task-scoped authorisation*. This is the
only defense that changes what the agent is **able** to do rather than what it
**sees**.

Authorisation rule
------------------
An action is authorised only if **all** of the following hold:

1. ``requested_by`` is the agent and the action belongs to a registered tool.
2. The requested permission level is covered by the **task policy**:
   ``task.allowed_actions``. A tool that is not listed for the task is denied
   for anything above ``READ_ONLY``.
3. The claimed authority is a **trusted** source. Authority that originates from
   tool output (``AuthorizationSource.TOOL_OUTPUT`` /
   ``INJECTED_CONTENT``) can never authorise a ``LIMITED_WRITE`` or
   ``HIGH_RISK`` action - this is the core invariant of the defense.

Every decision (requested action, agent, tool, permission, decision, reason) is
returned for the authorisation audit log.

Note on scope: this is a *reference* policy for the simulated tools in this
project, not a production authorisation service. The point being demonstrated is
the invariant "untrusted data must not confer capability".
"""

from __future__ import annotations

from typing import Any, ClassVar

from backend.defenses.base import Defense, DefenseContext, DefenseOutcome
from backend.models.enums import AuthorizationDecision, AuthorizationSource, PermissionLevel
from backend.tools.base import AuthorizationOutcome, AuthorizationRequest

#: Authority that the test range treats as legitimate.
TRUSTED_SOURCES = frozenset(
    {AuthorizationSource.SYSTEM, AuthorizationSource.USER, AuthorizationSource.TASK_POLICY}
)


class PrivilegeSeparationDefense(Defense):
    """Gate every state-changing action behind an explicit task-policy grant."""

    name: ClassVar[str] = "privilege_separation"
    description: ClassVar[str] = (
        "Privilege separation: state-changing simulated actions require an "
        "explicit grant in the task policy, and authority claimed by tool output "
        "never authorises a LIMITED_WRITE or HIGH_RISK action."
    )
    mechanism: ClassVar[str] = "capability_gate"
    gates_actions: ClassVar[bool] = True

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        super().__init__(config)
        #: When true, READ_ONLY calls to tools outside the task's allow-list are
        #: still allowed (read-only is considered low risk).
        self.allow_unlisted_reads: bool = bool(self.config.get("allow_unlisted_reads", True))
        #: Deny everything above READ_ONLY that the task did not explicitly grant.
        self.strict: bool = bool(self.config.get("strict", True))

    def on_authorization(
        self,
        request: AuthorizationRequest,
        permission: PermissionLevel,
        ctx: DefenseContext,
    ) -> AuthorizationOutcome:
        task = ctx.task
        action_key = f"{request.tool}.{request.action}"

        def outcome(decision: AuthorizationDecision, reason: str) -> AuthorizationOutcome:
            return AuthorizationOutcome(
                decision=decision,
                reason=reason,
                permission=permission,
                source=request.claimed_source,
                request=request,
            )

        # 1. Read-only traffic is low risk; allow it unless the task forbids it.
        if permission is PermissionLevel.READ_ONLY:
            if task is None:
                return outcome(AuthorizationDecision.GRANTED, "READ_ONLY call, no task policy present.")
            forbidden = action_key in task.forbidden_action_keys()
            if forbidden:
                return outcome(
                    AuthorizationDecision.DENIED,
                    f"{action_key} is explicitly forbidden by the task policy.",
                )
            if action_key in task.allowed_action_keys() or task.is_tool_allowed(request.tool):
                return outcome(
                    AuthorizationDecision.GRANTED,
                    f"READ_ONLY call to {action_key}; the tool is in the task's allow-list.",
                )
            if self.allow_unlisted_reads:
                return outcome(
                    AuthorizationDecision.GRANTED,
                    f"READ_ONLY call to {action_key} on a tool outside the task allow-list "
                    "(reads are permitted by configuration).",
                )
            return outcome(
                AuthorizationDecision.DENIED,
                f"READ_ONLY call to {action_key} but {request.tool} is not in the task allow-list.",
            )

        # 2. State-changing actions require an explicit grant in the task policy.
        if task is None:
            return outcome(
                AuthorizationDecision.DENIED,
                f"{action_key} requires {permission.value} access but no task policy is loaded.",
            )

        if action_key in task.forbidden_action_keys():
            return outcome(
                AuthorizationDecision.DENIED,
                f"{action_key} is explicitly forbidden by the task policy.",
            )

        if action_key not in task.allowed_action_keys():
            return outcome(
                AuthorizationDecision.DENIED,
                f"{action_key} requires {permission.value} access but the task policy does not "
                "grant it. Untrusted content cannot grant capabilities.",
            )

        # 3. Authority must be trusted, not derived from tool output.
        if request.claimed_source not in TRUSTED_SOURCES:
            return outcome(
                AuthorizationDecision.DENIED,
                f"{action_key} was requested with authority claimed from "
                f"{request.claimed_source.value}; only the system, the user or the task "
                "policy can authorise a state change.",
            )

        return outcome(
            AuthorizationDecision.GRANTED,
            f"{action_key} is granted by the task policy ({permission.value}) with trusted authority.",
        )


class DefaultAuthorizer:
    """Authorisation used when no defense gate is active (**control condition**).

    Deliberately permissive: in the ``none`` condition the sandbox has *no*
    authorisation layer, so the agent may invoke any registered simulated tool
    action. That is what makes the control condition meaningful - a harness that
    pre-blocked the dangerous action would report 0% ASR for every model and the
    whole comparison would be vacuous.

    Safety is unaffected: every action still lands in the simulated sandbox and
    only appends to :class:`~backend.tools.base.SandboxLedger`. Turning on
    :class:`PrivilegeSeparationDefense` is what introduces enforcement.
    """

    def __call__(
        self, request: AuthorizationRequest, permission: PermissionLevel, ctx: DefenseContext
    ) -> AuthorizationOutcome:
        return AuthorizationOutcome(
            decision=AuthorizationDecision.GRANTED,
            reason=(
                f"No authorisation layer is active (defense={ctx.defense_name!r}); "
                f"{request.tool}.{request.action} runs inside the simulated sandbox only."
            ),
            permission=permission,
            source=request.claimed_source,
            request=request,
        )


def make_outcome(defense: str, decision: AuthorizationDecision, reason: str, ctx: DefenseContext) -> DefenseOutcome:
    """Small helper so authorisations can also be surfaced as defense outcomes."""
    return DefenseOutcome(defense=defense, modified=decision is AuthorizationDecision.DENIED,
                          blocked=decision is AuthorizationDecision.DENIED,
                          notes=[reason], verdict=decision.value)


__all__ = [
    "PrivilegeSeparationDefense",
    "DefaultAuthorizer",
    "TRUSTED_SOURCES",
]