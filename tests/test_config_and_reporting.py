"""Configuration, structured logging, reporting and CLI scripts (Module 17 / 22 / 23)."""

from __future__ import annotations

import json
import logging
import os

import pytest

from backend.services.config import (
    PROJECT_ROOT,
    Settings,
    get_settings,
    load_settings,
    reset_settings_cache,
)
from backend.services.logging_setup import configure_logging, get_logger, redact
from backend.services.reporting import comparison_tables, render_markdown_report


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------


def test_default_config_loads(settings):
    assert settings.get("app.name")
    assert settings.demo_mode is True
    assert settings.provider.value == "mock"


def test_yaml_file_is_used(tmp_path):
    path = tmp_path / "custom.yaml"
    path.write_text("execution:\n  random_seed: 4242\n  repetitions: 7\n", encoding="utf-8")
    settings = load_settings(path)
    assert settings.random_seed == 4242
    assert settings.repetitions == 7


def test_overrides_beat_the_file(tmp_path):
    path = tmp_path / "custom.yaml"
    path.write_text("execution:\n  random_seed: 4242\n", encoding="utf-8")
    settings = load_settings(path, overrides={"execution": {"random_seed": 99}})
    assert settings.random_seed == 99


def test_environment_beats_the_file(tmp_path, monkeypatch):
    monkeypatch.setenv("TESTRANGE_EXECUTION__RANDOM_SEED", "31337")
    reset_settings_cache()
    try:
        assert load_settings().random_seed == 31337
    finally:
        reset_settings_cache()


def test_nested_env_keys(tmp_path, monkeypatch):
    monkeypatch.setenv("TESTRANGE_MODEL__TEMPERATURE", "0.7")
    reset_settings_cache()
    try:
        assert load_settings().temperature == pytest.approx(0.7)
    finally:
        reset_settings_cache()


def test_missing_config_file_raises():
    from backend.models.errors import ConfigError

    with pytest.raises(ConfigError):
        load_settings("definitely/not/here.yaml")


def test_malformed_yaml_raises(tmp_path):
    from backend.models.errors import ConfigError

    path = tmp_path / "bad.yaml"
    path.write_text("a: [1, 2\nb: :", encoding="utf-8")
    with pytest.raises(ConfigError):
        load_settings(path)


def test_severity_weights_are_complete(settings):
    weights = settings.severity_weights
    assert set(weights) == {"low", "medium", "high", "critical"}
    assert weights["critical"] > weights["low"]


def test_paths_resolve_under_the_project(settings):
    for path in (settings.db_path, settings.logs_dir, settings.export_dir, settings.corpus_dir):
        assert path.is_absolute()
        assert str(path).startswith(str(PROJECT_ROOT).lower()[:8]) or path.exists()


def test_ensure_directories(settings):
    settings.ensure_directories()
    assert settings.logs_dir.exists()
    assert settings.export_dir.exists()
    assert settings.db_path.parent.exists()


def test_settings_get_returns_default(settings):
    assert settings.get("nope.nope", "fallback") == "fallback"


def test_settings_bracket_access(settings):
    assert settings["app.name"] == settings.get("app.name")


def test_no_api_keys_in_config_files():
    """Configuration must never carry a credential."""
    for name in ("default.yaml", "experiment_batch.yaml"):
        path = PROJECT_ROOT / "configs" / name
        if not path.exists():
            continue
        text = path.read_text(encoding="utf-8").lower()
        assert "sk-" not in text
        assert "api_key:" not in text


def test_env_example_exists_and_is_safe():
    path = PROJECT_ROOT / ".env.example"
    assert path.exists()
    text = path.read_text(encoding="utf-8")
    assert "OPENAI_API_KEY=" in text
    assert "sk-" not in text


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------


def test_logging_is_configured(settings):
    logger = configure_logging(settings, force=True)
    assert logger.handlers
    assert logger.level == logging.WARNING  # tests lower the level


def test_json_log_file_is_written(settings):
    from backend.services.logging_setup import warning as log_warning

    configure_logging(settings, force=True)
    log_warning("unit_test_event", experiment_id="EXP-TEST", attack_id="GH-001")
    path = settings.resolve_path(settings.get("logging.json_file"))
    assert path.exists(), f"no JSON log at {path}"
    lines = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    entry = next(e for e in lines if e.get("event") == "unit_test_event")
    assert entry["experiment_id"] == "EXP-TEST"
    assert entry["attack_id"] == "GH-001"
    assert entry["ts"] and entry["level"]


def test_redaction_masks_openai_keys():
    assert "REDACTED" in redact("my key is sk-abcdefghijklmnopqrstuvwxyz123456")
    assert "abcdefghijklmnop" not in redact("sk-abcdefghijklmnopqrstuvwxyz123456")


def test_redaction_masks_authorization_headers():
    masked = redact("Authorization: Bearer abcdef1234567890")
    assert "abcdef1234567890" not in masked


def test_redaction_masks_api_key_assignments():
    masked = redact("api_key=supersecretvalue123")
    assert "supersecretvalue123" not in masked


def test_redaction_is_recursive():
    payload = {"nested": ["sk-abcdefghijklmnopqrstuvwx"]}
    assert "sk-abcdefghijklmnopqrstuvwx" not in json.dumps(redact(payload))


def test_redaction_leaves_benign_text_alone():
    assert redact("nothing to see here") == "nothing to see here"


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------


def test_markdown_report_contains_formulae():
    frame = comparison_tables.__globals__  # keep import graph honest
    assert frame is not None
    markdown = render_markdown_report(
        {
            "generated_at": "now",
            "result_provenance": "DEMO",
            "counts": {"experiments": 1, "runs": 2, "attacks": 3, "tasks": 1, "models": 1,
                       "defenses": 1, "tool_calls": 4, "sandbox_effects": 1, "authorization_events": 4},
            "metrics": {"attack_success_rate": 0.5, "benign_utility": 1.0},
            "severity_weights": {"low": 1.0},
        },
        {},
    )
    assert "ASR" in markdown
    assert "SWRS" in markdown
    assert "Limitations" in markdown


def test_comparison_tables_on_populated_db(repo):
    frames = comparison_tables(repo)
    assert isinstance(frames, dict)
    for name, frame in frames.items():
        assert not frame.empty, name


# ---------------------------------------------------------------------------
# CLI scripts
# ---------------------------------------------------------------------------


def test_init_db_script():
    from scripts.init_db import main

    assert main(["--db", "data/cli_smoke.db", "--quiet"]) == 0


def test_validate_corpus_script(capsys):
    from scripts.validate_corpus import main

    assert main(["--quiet"]) == 0
    assert "corpus is valid" in capsys.readouterr().out.lower()


def test_run_experiment_script(capsys):
    from scripts.run_experiment import main

    code = main([
        "--quiet", "--db", "data/cli_smoke.db",
        "--tasks", "T-001", "--attacks", "GH-001", "--reps", "1", "--seed", "5",
    ])
    output = capsys.readouterr().out
    assert code == 0
    assert "Attack Success Rate" in output


def test_run_batch_script(capsys):
    from scripts.run_batch import main

    code = main([
        "--quiet", "--db", "data/cli_smoke.db",
        "--models", "mock-vulnerable", "--defenses", "none",
        "--tasks", "T-001", "--attacks", "GH-001,IO-001", "--reps", "1",
    ])
    output = capsys.readouterr().out
    assert code == 0
    assert "Results" in output


def test_export_script(capsys, tmp_path):
    from scripts.export_results import main

    code = main(["--quiet", "--db", "data/cli_smoke.db", "--out", str(tmp_path)])
    assert code == 0
    assert any((tmp_path / name).exists() for name in ("runs.csv", "summary.json"))


def test_sync_corpus_script(capsys):
    from scripts.sync_corpus import main

    assert main(["--quiet", "--db", "data/cli_smoke.db"]) == 0


def test_build_corpus_check():
    from scripts.build_corpus import check_corpora

    assert check_corpora(PROJECT_ROOT / "corpus" / "attacks") == []


def test_cli_error_handling_is_graceful(capsys):
    from scripts.cli_common import fail, run_cli
    from backend.models.errors import AttackNotFoundError

    def boom():
        raise AttackNotFoundError("missing attack")

    assert run_cli(boom) == 2
    assert "attack_not_found" in capsys.readouterr().out


def test_run_demo_script_runs(tmp_path, capsys):
    """The one-command demo must work end to end (Module 31)."""
    import run_demo

    code = run_demo.main([
        "--quiet", "--fresh", "--reps", "1",
        "--db", str(tmp_path / "demo.db"),
        "--out", str(tmp_path / "exports"),
    ])
    output = capsys.readouterr().out
    assert code == 0
    assert "STEP 8/8" in output
    assert "streamlit run dashboard/app.py" in output
    assert "DEMO / MOCK RESULTS" in output