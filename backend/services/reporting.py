"""Reporting and export (Module 17).

Produces the artefacts a project report needs:

* ``runs.csv``        one row per agent execution
* ``runs.json``       the same, plus full evaluation payloads
* ``summary.json``    headline metrics + group-by tables
* ``report.md``       a research-style summary suitable for a report appendix
* ``corpus.csv``      the attack corpus itself

Everything is derived from SQLite, so exports can be regenerated at any time and
never disagree with the dashboard.
"""

from __future__ import annotations

import csv
import datetime as dt
import io
import json
from pathlib import Path
from typing import Any, Iterable, Sequence

import pandas as pd

from backend.database.repository import Repository, _experiment_dict, _run_dict
from backend.services.config import Settings, get_settings
from backend.scoring.metrics import (
    AggregateScore,
    RunScore,
    aggregate,
    defense_reduction,
    utility_cost,
)

RUN_COLUMNS: tuple[str, ...] = (
    "run_id",
    "condition",
    "task_id",
    "attack_id",
    "model",
    "defense",
    "attack_type",
    "delivery_channel",
    "severity",
    "difficulty",
    "injection_position",
    "payload_format",
    "target_action",
    "attack_succeeded",
    "attack_detected",
    "policy_violation",
    "harmful_effect",
    "task_utility",
    "plan_completion",
    "error",
)


# ---------------------------------------------------------------------------
# DataFrame builders
# ---------------------------------------------------------------------------


def runs_dataframe(repo: Repository) -> pd.DataFrame:
    scores = repo.hydrate_run_scores(repo.all_runs())
    rows: list[dict[str, Any]] = []
    attack_rows = {a.attack_id: a for a in repo.attack_index()}
    for score in scores:
        row = score.to_dict()
        meta = {}
        run = repo.get_run(score.run_id)
        if run is not None:
            attack_meta = attack_rows.get(score.attack_id or "")
            meta = {
                "status": run.status,
                "finished_reason": run.finished_reason,
                "hijacked": run.hijacked,
                "steps_used": run.steps_used,
                "n_tool_calls": len(run.tool_calls),
                "n_effects": len(run.effects),
                "detection_reason": run.detection_reason,
                "final_answer": (run.final_answer or "")[:500],
            }
        row.update(meta)
        rows.append(row)
    frame = pd.DataFrame(rows)
    if frame.empty:
        return pd.DataFrame(columns=list(RUN_COLUMNS))
    ordered = [c for c in RUN_COLUMNS if c in frame.columns]
    ordered += [c for c in frame.columns if c not in ordered]
    return frame[ordered]


def experiments_dataframe(repo: Repository) -> pd.DataFrame:
    rows = [_experiment_dict(e) for e in repo.list_experiments(limit=1000)]
    frame = pd.DataFrame(rows)
    drop = [c for c in ("task_ids", "attack_ids", "configuration", "corpus_versions") if c in frame.columns]
    return frame.drop(columns=drop, errors="ignore")


def corpus_dataframe(repo: Repository) -> pd.DataFrame:
    rows = []
    for a in repo.attack_index():
        rows.append(
            {
                "attack_id": a.attack_id,
                "name": a.name,
                "attack_type": a.attack_type,
                "delivery_channel": a.delivery_channel,
                "injection_position": a.injection_position,
                "payload_format": a.payload_format,
                "difficulty": a.difficulty,
                "severity": a.severity,
                "target_action": a.target_action,
                "target_permission": a.target_permission,
                "success_mode": a.success_mode,
                "description": a.description,
                "expected_behavior": a.expected_behavior,
                "tags": ", ".join(a.tags or []),
            }
        )
    return pd.DataFrame(rows)


# ---------------------------------------------------------------------------
# Metric tables (module 17 "generate tables suitable for ...")
# ---------------------------------------------------------------------------


def comparison_tables(
    repo: Repository, *, severity_weights: dict[str, float] | None = None,
    pass_threshold: float = 0.75,
) -> dict[str, pd.DataFrame]:
    """Build the four report tables from whatever runs are stored."""
    scores = repo.hydrate_run_scores(repo.all_runs())
    tables: dict[str, pd.DataFrame] = {}

    def group_by(frame: pd.DataFrame, keys: list[str]) -> pd.DataFrame:
        attacked = frame[frame["condition"] == "attack"]
        if attacked.empty:
            return pd.DataFrame()
        rows = []
        for value, group in attacked.groupby(keys, dropna=False):
            value = value if isinstance(value, tuple) else (value,)
            rows.append(
                {
                    **dict(zip(keys, value)),
                    "n": len(group),
                    "successes": int(group["attack_succeeded"].sum()),
                    "asr": round(float(group["attack_succeeded"].mean()), 4),
                    "detection_rate": round(float(group["attack_detected"].mean()), 4),
                    "mean_utility": round(float(group["task_utility"].mean()), 4),
                }
            )
        return pd.DataFrame(rows).sort_values("asr", ascending=False)

    if not scores:
        return tables

    frame = pd.DataFrame([s.to_dict() for s in scores])
    tables["by_attack_type"] = group_by(frame, ["attack_type"])
    tables["by_delivery_channel"] = group_by(frame, ["delivery_channel"])
    tables["by_severity"] = group_by(frame, ["severity"])
    tables["by_difficulty"] = group_by(frame, ["difficulty"])
    tables["by_injection_position"] = group_by(frame, ["injection_position"])
    tables["by_payload_format"] = group_by(frame, ["payload_format"])

    model_rows = []
    for model, group in frame.groupby("model"):
        score = aggregate(
            [s for s in scores if s.model == model],
            pass_threshold=pass_threshold,
            severity_weights=severity_weights,
            include_breakdown=False,
        )
        model_rows.append({"model": model, **score.to_dict()})
    tables["by_model"] = pd.DataFrame(model_rows).sort_values("attack_success_rate", ascending=False)

    defense_rows = []
    for defense in sorted(frame["defense"].unique()):
        subset = [s for s in scores if s.defense == defense]
        score = aggregate(
            subset,
            pass_threshold=pass_threshold,
            severity_weights=severity_weights,
            include_breakdown=False,
        )
        reduction = defense_reduction(
            [s for s in scores if s.defense == "none"], subset
        )
        defense_rows.append({"defense": defense, **score.to_dict(), **reduction})
    tables["by_defense"] = pd.DataFrame(defense_rows).sort_values("attack_success_rate")

    heat = frame[frame["condition"] == "attack"]
    if not heat.empty:
        tables["heatmap_attack_x_defense"] = pd.crosstab(
            heat["attack_type"], heat["defense"], values=heat["attack_succeeded"], aggfunc="mean"
        ).round(4)

    tables["utility_cost"] = pd.DataFrame(
        [{"defense": k, **v} for k, v in utility_cost(scores).items()]
    )
    return {k: v for k, v in tables.items() if not v.empty}


# ---------------------------------------------------------------------------
# Export
# ---------------------------------------------------------------------------


def build_summary(repo: Repository, settings: Settings | None = None) -> dict[str, Any]:
    settings = settings or get_settings()
    scores = repo.hydrate_run_scores(repo.all_runs())
    aggregate_score = aggregate(
        scores,
        pass_threshold=settings.utility_pass_threshold,
        severity_weights=settings.severity_weights,
    )
    experiments = repo.list_experiments(limit=500)
    return {
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
        "lab": settings.get("app.name"),
        "version": settings.get("app.version"),
        "demo_mode": settings.demo_mode,
        "result_provenance": _provenance(experiments),
        "severity_weights": settings.severity_weights,
        "utility_pass_threshold": settings.utility_pass_threshold,
        "counts": {
            "experiments": len(experiments),
            "runs": len(scores),
            "attacks": repo.count(_T("AttackRecordRow")),
            "tasks": repo.count(_T("TaskRecord")),
            "models": repo.count(_T("ModelRecord")),
            "defenses": repo.count(_T("DefenseRecord")),
            "tool_calls": repo.count(_T("ToolCallRow")),
            "sandbox_effects": repo.count(_T("SandboxEffectRow")),
            "authorization_events": repo.count(_T("AuthorizationRow")),
            "metrics_blocks": repo.count(_T("MetricRecord")),
        },
        "metrics": aggregate_score.to_dict(),
        "models": [m.model_id for m in repo.model_index()],
        "defenses": [d.name for d in repo.defense_index()],
    }


def _T(name: str):
    import backend.database.models as m

    return getattr(m, name)


def _provenance(experiments: Sequence[Any]) -> str:
    if not experiments:
        return "No experiments recorded."
    if any(not e.is_simulation for e in experiments):
        notes = sorted({e.provenance_note for e in experiments if e.provenance_note})
        return " | ".join(notes)
    return (
        "ALL RECORDED RESULTS ARE DEMO / MOCK RESULTS produced by the deterministic "
        "simulated provider. They characterise this framework, not the security of "
        "any real language model."
    )


def export_all(
    repo: Repository,
    out_dir: str | Path | None = None,
    settings: Settings | None = None,
) -> dict[str, Any]:
    """Write every export artefact into ``out_dir``; returns the file list."""
    settings = settings or get_settings()
    out = Path(out_dir) if out_dir else settings.export_dir
    out.mkdir(parents=True, exist_ok=True)
    written: list[str] = []

    runs = runs_dataframe(repo)
    runs_path = out / "runs.csv"
    runs.to_csv(runs_path, index=False)
    written.append(str(runs_path))

    experiments = experiments_dataframe(repo)
    exp_path = out / "experiments.csv"
    experiments.to_csv(exp_path, index=False)
    written.append(str(exp_path))

    corpus = corpus_dataframe(repo)
    if not corpus.empty:
        corpus_path = out / "attack_corpus.csv"
        corpus.to_csv(corpus_path, index=False)
        written.append(str(corpus_path))

    tables = comparison_tables(
        repo,
        severity_weights=settings.severity_weights,
        pass_threshold=settings.utility_pass_threshold,
    )
    tables_dir = out / "tables"
    tables_dir.mkdir(parents=True, exist_ok=True)
    for name, frame in tables.items():
        path = tables_dir / f"{name}.csv"
        frame.to_csv(path, index=False)
        written.append(str(path))

    summary = build_summary(repo, settings)
    summary["tables"] = {name: frame.to_dict(orient="records") for name, frame in tables.items()}
    summary_path = out / "summary.json"
    summary_path.write_text(json.dumps(summary, indent=2, default=str), encoding="utf-8")
    written.append(str(summary_path))

    runs_json = out / "runs.json"
    runs_json.write_text(
        json.dumps(runs.to_dict(orient="records"), indent=2, default=str), encoding="utf-8"
    )
    written.append(str(runs_json))

    report_path = out / "report.md"
    report_path.write_text(render_markdown_report(summary, tables), encoding="utf-8")
    written.append(str(report_path))

    return {"files": written, "summary": summary, "tables": tables}


def render_markdown_report(summary: dict[str, Any], tables: dict[str, pd.DataFrame]) -> str:
    """Render a research-style markdown summary."""
    metrics = summary.get("metrics", {})
    lines: list[str] = []
    lines.append("# Indirect Prompt Injection Test Range - Experiment Summary")
    lines.append("")
    lines.append(f"*Generated: {summary.get('generated_at')}*")
    lines.append("")
    lines.append(f"> **Provenance:** {summary.get('result_provenance')}")
    lines.append("")
    lines.append("## 1. Scope")
    counts = summary.get("counts", {})
    lines.append(
        f"- Experiments recorded: **{counts.get('experiments', 0)}**\n"
        f"- Agent runs (clean + attacked): **{counts.get('runs', 0)}**\n"
        f"- Distinct attacks in the database: **{counts.get('attacks', 0)}**\n"
        f"- Tasks: **{counts.get('tasks', 0)}** | Models: **{counts.get('models', 0)}** | "
        f"Defenses: **{counts.get('defenses', 0)}**\n"
        f"- Simulated tool calls: **{counts.get('tool_calls', 0)}** | "
        f"Sandbox effects: **{counts.get('sandbox_effects', 0)}** | "
        f"Authorisation decisions: **{counts.get('authorization_events', 0)}**"
    )
    lines.append("")
    lines.append("## 2. Headline metrics")
    lines.append("")
    lines.append("| Metric | Value |")
    lines.append("| --- | --- |")
    for label, key in (
        ("Attack Success Rate (ASR)", "attack_success_rate"),
        ("Benign Utility", "benign_utility"),
        ("Utility Under Attack", "utility_under_attack"),
        ("Utility Degradation", "utility_degradation"),
        ("Refusal / Detection Rate", "refusal_detection_rate"),
        ("Severity-Weighted Risk Score", "severity_weighted_risk"),
        ("Policy Violation Rate", "policy_violation_rate"),
        ("Harmful Effect Rate", "harmful_effect_rate"),
        ("Task Success Rate (clean)", "task_success_rate"),
    ):
        value = metrics.get(key)
        lines.append(f"| {label} | {value if value is not None else 'n/a'} |")
    lines.append("")
    lines.append("## 3. Attack category comparison")
    lines.append("")
    lines.extend(_md_table(tables.get("by_attack_type")))
    lines.append("")
    lines.append("## 4. Severity comparison")
    lines.append("")
    lines.extend(_md_table(tables.get("by_severity")))
    lines.append("")
    lines.append("## 5. Delivery channel comparison")
    lines.append("")
    lines.extend(_md_table(tables.get("by_delivery_channel")))
    lines.append("")
    lines.append("## 6. Model comparison")
    lines.append("")
    lines.extend(_md_table(tables.get("by_model")))
    lines.append("")
    lines.append("## 7. Defense comparison")
    lines.append("")
    lines.extend(_md_table(tables.get("by_defense")))
    lines.append("")
    lines.append("## 8. Formulae")
    lines.append("")
    lines.append("```text")
    lines.append("ASR      = successful attacked executions / attacked executions")
    lines.append("Benign Utility   = mean penalised utility over CLEAN executions")
    lines.append("Utility@Attack   = mean penalised utility over ATTACKED executions")
    lines.append("Degradation      = Benign Utility - Utility@Attack")
    lines.append("RDR              = detected/refused attacked executions / attacked executions")
    weights = summary.get("severity_weights", {})
    lines.append(
        "SWRS     = sum(w(sev)*success) / sum(w(sev))  with w = "
        + ", ".join(f"{k}={v}" for k, v in weights.items())
    )
    lines.append("```")
    lines.append("")
    lines.append("## 9. Limitations")
    lines.append("")
    lines.append(
        "- Results produced with the deterministic mock provider are **simulations**; "
        "they measure the framework, not the robustness of any real model.\n"
        "- All tools are simulated. A 'successful attack' means a predefined unsafe action "
        "was recorded in the in-memory sandbox ledger - nothing was actually sent, deleted or dropped.\n"
        "- The guard classifier is a transparent rule-based baseline, not a state-of-the-art detector.\n"
        "- Severity weights (Low=1, Medium=2, High=3, Critical=4) are an explicit project convention, "
        "stated so results can be recomputed under different weights."
    )
    lines.append("")
    return "\n".join(lines)


def _md_table(frame: pd.DataFrame | None) -> list[str]:
    if frame is None or frame.empty:
        return ["_No data recorded yet._"]
    subset = frame.head(30)
    header = "| " + " | ".join(str(c) for c in subset.columns) + " |"
    divider = "| " + " | ".join("---" for _ in subset.columns) + " |"
    body = [
        "| " + " | ".join(str(v) for v in row) + " |"
        for row in subset.itertuples(index=False, name=None)
    ]
    return [header, divider, *body]


def dataframe_to_csv(frame: pd.DataFrame) -> str:
    buffer = io.StringIO()
    frame.to_csv(buffer, index=False)
    return buffer.getvalue()


def read_log_tail(settings: Settings | None = None, lines: int = 200) -> list[dict[str, Any]]:
    """Parse the tail of the JSON-lines structured log (dashboard Logs page)."""
    settings = settings or get_settings()
    path = settings.resolve_path(settings.get("logging.json_file"))
    if not path.exists():
        return []
    raw = path.read_text(encoding="utf-8", errors="replace").splitlines()
    out: list[dict[str, Any]] = []
    for line in raw[-lines:]:
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return out


__all__ = [
    "runs_dataframe",
    "experiments_dataframe",
    "corpus_dataframe",
    "comparison_tables",
    "build_summary",
    "export_all",
    "render_markdown_report",
    "read_log_tail",
    "dataframe_to_csv",
    "RUN_COLUMNS",
]