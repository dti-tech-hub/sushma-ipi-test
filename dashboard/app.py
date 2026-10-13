"""Streamlit research dashboard (Module 15).

Run with::

    streamlit run dashboard/app.py

Twelve pages covering the corpus, experiment control, results analysis and
export. The dashboard reads the SQLite experiment store and the JSON corpora
directly - it does not need the API to be running.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import pandas as pd
import plotly.express as px
import streamlit as st

from backend.attacks.loader import get_attacks, get_tasks
from backend.database.repository import Repository
from backend.database.session import init_db, session_scope
from backend.defenses import DEFENSE_ORDER, list_defenses
from backend.evaluation.runner import BatchRequest, ExperimentRequest, ExperimentRunner
from backend.agents.llm import available_models
from backend.services.config import get_settings
from backend.services.reporting import (
    build_summary,
    comparison_tables,
    export_all,
    read_log_tail,
    runs_dataframe,
)
from backend.tools.registry import ToolRegistry

st.set_page_config(
    page_title="IPI Test Range - Research Dashboard",
    page_icon="\U0001f6e1",
    layout="wide",
    initial_sidebar_state="expanded",
)

SETTINGS = get_settings()

PAGES = [
    "Overview",
    "Attack Corpus",
    "Run Experiment",
    "Batch Experiments",
    "Attack Results",
    "Model Comparison",
    "Defense Comparison",
    "Severity Analysis",
    "Tool / Channel Analysis",
    "Detailed Experiment",
    "Logs",
    "Export Results",
]

PAGE_ICONS = {
    "Overview": "\U0001f3e0",
    "Attack Corpus": "\U0001f5c2\ufe0f",
    "Run Experiment": "\U0001f9ea",
    "Batch Experiments": "\U0001f9f1",
    "Attack Results": "\U0001f3af",
    "Model Comparison": "\U0001f4ca",
    "Defense Comparison": "\U0001f6e1\ufe0f",
    "Severity Analysis": "\u26a0\ufe0f",
    "Tool / Channel Analysis": "\U0001f6e0\ufe0f",
    "Detailed Experiment": "\U0001f50d",
    "Logs": "\U0001f4dc",
    "Export Results": "\U0001f4e6",
}

PAGE_TAGS = {
    "Overview": "System status, headline metrics and corpus composition.",
    "Attack Corpus": "Every record carries type, channel, position, format, difficulty, severity and explicit success criteria.",
    "Run Experiment": "Execute a clean baseline and attacked runs, then persist everything to SQLite.",
    "Batch Experiments": "Sweep several models x several defenses over a corpus selection.",
    "Attack Results": "Success behaviour per attack, grouped by corpus metadata.",
    "Model Comparison": "Metrics for every model that has been run.",
    "Defense Comparison": "Each defense is an independent mechanism; the control condition is `none`.",
    "Severity Analysis": "Risk weighted by declared severity: Low=1, Medium=2, High=3, Critical=4.",
    "Tool / Channel Analysis": "Where payloads ride and which capabilities they target.",
    "Detailed Experiment": "Drill into one experiment: runs, tool calls, authorisations and sandbox effects.",
    "Logs": "Structured JSON log tail; credentials are redacted before anything is written.",
    "Export Results": "Write CSV, JSON and a Markdown research summary to disk.",
}

SEVERITY_COLORS = {
    "low": "#34d399",
    "medium": "#60a5fa",
    "high": "#fb923c",
    "critical": "#f87171",
}

DEFENSE_PALETTE = ["#6366f1", "#22d3ee", "#34d399", "#fbbf24", "#f472b6", "#a78bfa"]
ATTACK_PALETTE = ["#6366f1", "#22d3ee", "#34d399", "#fbbf24", "#f472b6", "#fb923c", "#a78bfa"]
CHANNEL_PALETTE = ["#6366f1", "#0ea5e9", "#14b8a6", "#84cc16", "#f59e0b", "#ec4899", "#8b5cf6"]
SEVERITY_ORDER = ["low", "medium", "high", "critical"]


# ---------------------------------------------------------------------------
# Theme: custom CSS + helpers (presentation only - no logic changes)
# ---------------------------------------------------------------------------


def inject_css() -> None:
    st.markdown(
        """
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;600&display=swap');

html, body, [class*="css"] { font-family: 'Inter', system-ui, -apple-system, sans-serif; }

/* App background: soft layered gradient */
.stApp {
  background:
    radial-gradient(1200px 500px at 85% -5%, rgba(99,102,241,.14), transparent 60%),
    radial-gradient(900px 420px at 5% 0%, rgba(34,211,238,.12), transparent 60%),
    linear-gradient(180deg, #f8fafc 0%, #eef2ff 45%, #f8fafc 100%);
}
/* Base text: always dark on the light app background */
.stApp, .stApp p, .stApp li, .stMarkdown, .stCaption {
  color: #0f172a;
}
div[data-testid="stAppViewContainer"] label {
  color: #0f172a !important; font-weight: 600;
}
div[data-testid="stAppViewContainer"] .stCaption {
  color: #475569 !important;
}
section[data-testid="stSidebar"] {
  background: linear-gradient(180deg, #0f172a 0%, #1e1b4b 55%, #312e81 100%) !important;
}
/* Sidebar chrome text only - never touch alert boxes, inputs or pills */
section[data-testid="stSidebar"] .brand .b-title,
section[data-testid="stSidebar"] h1, section[data-testid="stSidebar"] h2,
section[data-testid="stSidebar"] h3,
section[data-testid="stSidebar"] label,
section[data-testid="stSidebar"] [data-testid="stWidgetLabel"],
section[data-testid="stSidebar"] .stRadio label,
section[data-testid="stSidebar"] .stCaption {
  color: #e2e8f0 !important;
}
section[data-testid="stSidebar"] .brand .b-sub { color: #c7d2fe !important; }
/* Alert boxes keep dark readable text on their pale backgrounds */
section[data-testid="stSidebar"] .stAlert,
section[data-testid="stSidebar"] .stAlert *,
div[data-testid="stAppViewContainer"] .stAlert,
div[data-testid="stAppViewContainer"] .stAlert * {
  color: #0f172a !important;
}
/* Pills keep their own badge colors (beat the sidebar chrome rule) */
.pill-demo { color: #92400e !important; }
.pill-live { color: #166534 !important; }
.pill-db { color: #3730a3 !important; }

/* Hero banner */
.hero {
  border-radius: 18px;
  padding: 22px 26px;
  margin: 4px 0 18px 0;
  color: #fff;
  background: linear-gradient(120deg, #312e81 0%, #6d28d9 45%, #0ea5e9 100%);
  box-shadow: 0 12px 32px rgba(76,29,149,.35);
  border: 1px solid rgba(255,255,255,.25);
}
.hero h1 { margin: 0; font-size: 1.7rem; font-weight: 800; letter-spacing: -.02em; color: #ffffff !important; text-shadow: 0 2px 10px rgba(15,23,42,.45); }
.hero p { margin: 6px 0 0 0; opacity: 1; font-size: .95rem; color: #ffffff !important; text-shadow: 0 1px 8px rgba(15,23,42,.45); }
.hero .crumb {
  display: inline-block; font-size: .72rem; font-weight: 700; letter-spacing: .08em;
  text-transform: uppercase; background: rgba(255,255,255,.18);
  border: 1px solid rgba(255,255,255,.35); padding: 3px 10px; border-radius: 999px;
  margin-bottom: 8px;
}

/* KPI cards */
.kpi-grid { display: flex; gap: 12px; margin: 6px 0 14px 0; }
.kpi {
  flex: 1; border-radius: 16px; padding: 14px 16px;
  background: rgba(255,255,255,.86); backdrop-filter: blur(6px);
  border: 1px solid rgba(148,163,184,.35);
  border-left: 6px solid var(--accent, #6366f1);
  box-shadow: 0 6px 18px rgba(15,23,42,.08);
}
.kpi .k-label { font-size: .72rem; font-weight: 700; letter-spacing: .08em; text-transform: uppercase; color: #475569; }
.kpi .k-value { font-size: 1.55rem; font-weight: 800; color: #0f172a; margin: 2px 0; font-variant-numeric: tabular-nums; }
.kpi .k-sub { font-size: .78rem; color: #475569; }

/* Section cards */
.card {
  background: rgba(255,255,255,.9); border: 1px solid rgba(148,163,184,.3);
  border-radius: 16px; padding: 16px 18px; margin: 12px 0;
  box-shadow: 0 8px 22px rgba(15,23,42,.07);
}
.card, .card p, .card li, .card span, .card div { color: #0f172a; }
.card h3 { margin-top: 0; color: #0f172a; }
.section-label { font-size: .75rem; font-weight: 800; letter-spacing: .1em; text-transform: uppercase; color: #4f46e5; margin-bottom: 2px; }

/* Pills / badges */
.pill { display: inline-block; padding: 2px 10px; border-radius: 999px; font-size: .72rem; font-weight: 700; }
.pill-demo { background: #fef3c7; color: #92400e; border: 1px solid #f59e0b; }
.pill-live { background: #dcfce7; color: #166534; border: 1px solid #22c55e; }
.pill-db { background: #e0e7ff; color: #3730a3; border: 1px solid #818cf8; }

/* Sidebar brand */
.brand {
  border-radius: 14px; padding: 12px 14px; margin-bottom: 10px;
  background: linear-gradient(120deg, rgba(99,102,241,.35), rgba(34,211,238,.25));
  border: 1px solid rgba(165,180,252,.4);
}
.brand .b-title { font-weight: 800; font-size: 1.05rem; }
.brand .b-sub { font-size: .75rem; color: #c7d2fe !important; }

/* Buttons */
.stButton > button[kind="primary"], .stFormSubmitButton > button[kind="primary"] {
  background: linear-gradient(120deg, #6366f1, #0ea5e9) !important;
  border: none !important; border-radius: 12px !important; font-weight: 700 !important;
  box-shadow: 0 8px 20px rgba(99,102,241,.4) !important;
}
.stDownloadButton > button { border-radius: 12px !important; font-weight: 600 !important; }

/* Dataframes */
[data-testid="stDataFrame"] { border-radius: 14px; overflow: hidden; border: 1px solid rgba(148,163,184,.3); }

/* Tabs */
.stTabs [data-baseweb="tab-list"] { gap: 6px; }
.stTabs [data-baseweb="tab"] { border-radius: 10px 10px 0 0; font-weight: 600; }

/* Code blocks */
code { font-family: 'JetBrains Mono', monospace !important; }

/* Footer */
.footer-note { text-align: center; color: #475569; font-size: .75rem; padding: 18px 0 6px 0; }

/* Dark OS / browser theme: keep text readable instead of white-on-light */
@media (prefers-color-scheme: dark) {
  .stApp {
    background:
      radial-gradient(1200px 500px at 85% -5%, rgba(99,102,241,.22), transparent 60%),
      radial-gradient(900px 420px at 5% 0%, rgba(34,211,238,.18), transparent 60%),
      linear-gradient(180deg, #0b1120 0%, #141a33 45%, #0b1120 100%);
  }
  .stApp, .stApp p, .stApp li, .stMarkdown,
  div[data-testid="stAppViewContainer"] label {
    color: #f1f5f9 !important;
  }
  div[data-testid="stAppViewContainer"] .stCaption { color: #cbd5e1 !important; }
  .kpi, .card { background: rgba(30,41,59,.92); border-color: rgba(148,163,184,.4); }
  .kpi .k-value, .card, .card p, .card li, .card span, .card div, .card h3 { color: #f1f5f9; }
  .kpi .k-label, .kpi .k-sub, .section-label, .footer-note { color: #cbd5e1; }
  .section-label { color: #a5b4fc; }
}
</style>
        """,
        unsafe_allow_html=True,
    )


def style_fig(fig, height: int = 380):
    """Apply the dashboard chart theme (transparent bg, Inter font, soft grid)."""
    fig.update_layout(
        template="plotly_white",
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font=dict(family="Inter, system-ui, sans-serif", size=12, color="#1e293b"),
        margin=dict(l=10, r=10, t=46, b=10),
        height=height,
        legend=dict(orientation="h", y=-0.28, x=0),
        hoverlabel=dict(font_size=12),
    )
    fig.update_xaxes(gridcolor="rgba(148,163,184,.25)", zerolinecolor="rgba(148,163,184,.45)")
    fig.update_yaxes(gridcolor="rgba(148,163,184,.25)", zerolinecolor="rgba(148,163,184,.45)")
    return fig


def hero(title: str, subtitle: str = "", crumb: str = "IPI Test Range") -> None:
    icon = PAGE_ICONS.get(title, "\U0001f6e1")
    st.markdown(
        f'<div class="hero"><div class="crumb">{crumb}</div>'
        f"<h1>{icon} {title}</h1>"
        + (f"<p>{subtitle}</p>" if subtitle else "")
        + "</div>",
        unsafe_allow_html=True,
    )


def header(title: str, subtitle: str = "") -> None:
    hero(title, subtitle)


def kpi_cards(items: list[tuple[str, str, str, str]]) -> None:
    """Render KPI cards. Each item: (label, value, sub, accent-color)."""
    cards = "".join(
        f'<div class="kpi" style="--accent:{accent}">'
        f'<div class="k-label">{label}</div>'
        f'<div class="k-value">{value}</div>'
        f'<div class="k-sub">{sub}</div></div>'
        for label, value, sub, accent in items
    )
    st.markdown(f'<div class="kpi-grid">{cards}</div>', unsafe_allow_html=True)


def section(label: str, title: str) -> None:
    st.markdown(
        f'<div class="section-label">{label}</div><h3 style="margin-top:0">{title}</h3>',
        unsafe_allow_html=True,
    )


def card_open() -> None:
    st.markdown('<div class="card">', unsafe_allow_html=True)


def card_close() -> None:
    st.markdown("</div>", unsafe_allow_html=True)


inject_css()


# ---------------------------------------------------------------------------
# Cached data access
# ---------------------------------------------------------------------------


@st.cache_data(show_spinner=False)
def load_runs() -> pd.DataFrame:
    init_db(SETTINGS)
    with session_scope(SETTINGS) as session:
        frame = runs_dataframe(Repository(session))
    if frame.empty:
        frame = pd.DataFrame(
            columns=[
                "run_id", "condition", "task_id", "attack_id", "model", "defense",
                "attack_type", "delivery_channel", "severity", "difficulty",
                "injection_position", "payload_format", "target_action",
                "attack_succeeded", "attack_detected", "policy_violation",
                "harmful_effect", "task_utility", "plan_completion", "error",
            ]
        )
    return frame


@st.cache_data(show_spinner=False)
def load_summary() -> dict:
    with session_scope(SETTINGS) as session:
        return build_summary(Repository(session), SETTINGS)


@st.cache_data(show_spinner="Building comparison tables...")
def load_tables() -> dict[str, pd.DataFrame]:
    with session_scope(SETTINGS) as session:
        return comparison_tables(
            Repository(session),
            severity_weights=SETTINGS.severity_weights,
            pass_threshold=SETTINGS.utility_pass_threshold,
        )


@st.cache_data(show_spinner=False)
def load_attacks() -> list[dict]:
    return [a.summary() for a in get_attacks(SETTINGS).all()]


@st.cache_data(show_spinner=False)
def load_attack_full() -> dict[str, dict]:
    return {a.id: a.model_dump(mode="json") for a in get_attacks(SETTINGS).all()}


@st.cache_data(show_spinner=False)
def load_tasks() -> list[dict]:
    return [t.summary() for t in get_tasks(SETTINGS).all()]


@st.cache_data(show_spinner=False)
def load_experiments() -> list[dict]:
    with session_scope(SETTINGS) as session:
        repo = Repository(session)
        return [
            {
                "experiment_uid": e.experiment_uid,
                "name": e.name,
                "model": e.model,
                "defense": e.defense,
                "is_simulation": e.is_simulation,
                "status": e.status,
                "n_runs": len(e.runs),
                "started_at": e.started_at,
                "duration_ms": e.duration_ms,
            }
            for e in repo.list_experiments(limit=500)
        ]


# ---------------------------------------------------------------------------
# Sidebar
# ---------------------------------------------------------------------------

with st.sidebar:
    st.markdown(
        f"""<div class="brand"><div class="b-title">\U0001f6e1 IPI Test Range</div>
        <div class="b-sub">v{SETTINGS.get('app.version')} &middot; {SETTINGS.get('app.name')}</div></div>""",
        unsafe_allow_html=True,
    )
    if SETTINGS.demo_mode:
        st.markdown(
            '<span class="pill pill-demo">\U0001f7e2 DEMO MODE \u2014 simulated provider</span>',
            unsafe_allow_html=True,
        )
        st.warning(
            "The deterministic simulated provider is active. "
            "All numbers below characterise this framework, not any real model.",
            icon="\U0001f7e2",
        )
    else:
        st.markdown(
            '<span class="pill pill-live">\U0001f310 LIVE PROVIDER</span>',
            unsafe_allow_html=True,
        )
        st.info("Live provider configured.", icon="\U0001f310")
    st.divider()
    page = st.radio("Navigate", PAGES)
    st.divider()
    st.markdown(
        f'<span class="pill pill-db">\U0001f5c4\ufe0f {SETTINGS.db_path.name}</span> '
        f'<span class="pill pill-db">{len(load_attacks())} attacks \u00b7 {len(load_tasks())} tasks</span>',
        unsafe_allow_html=True,
    )
    st.caption(f"Database: `{SETTINGS.db_path.name}`")
    st.caption(f"Attacks: {len(load_attacks())} | Tasks: {len(load_tasks())}")


def metric_row(frame: pd.DataFrame) -> None:
    attacked = frame[frame["condition"] == "attack"] if not frame.empty else frame
    baseline = frame[frame["condition"] == "baseline"] if not frame.empty else frame
    n_att = len(attacked)

    def fmt(series, col):
        try:
            return f"{series[col].mean():.3f}"
        except Exception:
            return "n/a"

    kpi_cards(
        [
            ("ASR", fmt(attacked, "attack_succeeded") if n_att else "n/a", f"{n_att} attacked runs", "#f472b6"),
            ("Benign utility", fmt(baseline, "task_utility") if len(baseline) else "n/a", f"{len(baseline)} clean runs", "#34d399"),
            ("Utility @ attack", fmt(attacked, "task_utility") if n_att else "n/a", "penalised utility", "#60a5fa"),
            ("Detection rate", fmt(attacked, "attack_detected") if n_att else "n/a", "refusal / detection", "#fbbf24"),
            ("Runs", f"{len(frame)}", "total episodes", "#6366f1"),
        ]
    )


def risk_score(frame: pd.DataFrame) -> float:
    weights = SETTINGS.severity_weights
    attacked = frame[frame["condition"] == "attack"] if not frame.empty else frame
    if attacked.empty:
        return 0.0
    total = sum(weights.get(str(s).lower(), 1.0) for s in attacked["severity"])
    realised = sum(
        weights.get(str(row.severity).lower(), 1.0)
        for row in attacked.itertuples()
        if row.attack_succeeded
    )
    return realised / total if total else 0.0


def empty_state(message: str, hint: str = "") -> None:
    st.markdown(
        f"""<div class="card">\U0001f4ed <b>{message}</b><br>
        <span style="color:#475569">{hint}</span></div>""",
        unsafe_allow_html=True,
    )


# ===========================================================================
# 1. Overview
# ===========================================================================
if page == "Overview":
    header("Overview", "System status, headline metrics and corpus composition.")
    summary = load_summary()
    metrics = summary["metrics"]
    counts = summary["counts"]
    kpi_cards(
        [
            ("Experiments", f"{counts['experiments']}", "stored conditions", "#6366f1"),
            ("Runs", f"{counts['runs']}", "clean + attacked", "#0ea5e9"),
            ("Tool calls", f"{counts['tool_calls']}", "simulated invocations", "#14b8a6"),
            ("Sandbox effects", f"{counts['sandbox_effects']}", "provable consequences", "#f59e0b"),
            ("Auth decisions", f"{counts['authorization_events']}", "allow / deny audit", "#a78bfa"),
        ]
    )

    section("Headline", "Effectiveness at a glance")
    kpi_cards(
        [
            ("ASR", f"{metrics['attack_success_rate']:.3f}", "attack success rate", "#f472b6"),
            ("Benign utility", f"{metrics['benign_utility']:.3f}", "clean inputs", "#34d399"),
            ("Utility @ attack", f"{metrics['utility_under_attack']:.3f}", "under attack", "#60a5fa"),
            ("Detection rate", f"{metrics['refusal_detection_rate']:.3f}", "refusal / detection", "#fbbf24"),
            ("Risk score", f"{metrics['severity_weighted_risk']:.3f}", "severity-weighted", "#fb923c"),
        ]
    )

    if SETTINGS.demo_mode:
        st.warning(summary["result_provenance"], icon="\U0001f9ea")

    tab1, tab2 = st.tabs(["\U0001f4ca Corpus composition", "\U0001f6e1\ufe0f Defenses & safety"])
    with tab1:
        left, right = st.columns(2)
        attacks = load_attacks()
        frame = pd.DataFrame(attacks)
        with left:
            card_open()
            section("Corpus", "Attack categories")
            if not frame.empty:
                counts_df = frame["attack_type"].value_counts().reset_index()
                counts_df.columns = ["attack_type", "records"]
                fig = px.bar(counts_df, x="attack_type", y="records", color="attack_type",
                             color_discrete_sequence=ATTACK_PALETTE, text="records")
                st.plotly_chart(style_fig(fig), width="stretch")
            card_close()
        with right:
            card_open()
            section("Corpus", "Delivery channels")
            if not frame.empty:
                counts_df = frame["delivery_channel"].value_counts().reset_index()
                counts_df.columns = ["delivery_channel", "records"]
                fig = px.bar(counts_df, x="delivery_channel", y="records", color="delivery_channel",
                             color_discrete_sequence=CHANNEL_PALETTE, text="records")
                st.plotly_chart(style_fig(fig), width="stretch")
            card_close()
    with tab2:
        card_open()
        section("Safety", "Safety boundary")
        st.markdown(
            """
All tools in this range are **simulated**. A *successful attack* means a predefined
unsafe action was recorded in the in-memory sandbox ledger (`sandbox_effects` table).
No e-mail is transmitted, no file is deleted, no table is dropped, no credential is
read and no network request is made. Exfiltration targets use reserved, non-routable
`.invalid` / `.test` domains.
"""
        )
        with st.expander("Registered defenses"):
            st.dataframe(pd.DataFrame(list_defenses()), width="stretch")
        card_close()


# ===========================================================================
# 2. Attack Corpus
# ===========================================================================
elif page == "Attack Corpus":
    header("Attack Corpus", "Every record carries type, channel, position, format, difficulty, severity and explicit success criteria.")
    attacks = load_attacks()
    frame = pd.DataFrame(attacks)

    card_open()
    section("Filter", "Slice the corpus")
    f1, f2, f3, f4, f5 = st.columns(5)
    type_filter = f1.multiselect("Attack type", sorted(frame["attack_type"].unique()))
    channel_filter = f2.multiselect("Channel", sorted(frame["delivery_channel"].unique()))
    severity_filter = f3.multiselect("Severity", ["low", "medium", "high", "critical"])
    difficulty_filter = f4.multiselect("Difficulty", ["easy", "medium", "hard"])
    position_filter = f5.multiselect("Position", sorted(frame["injection_position"].unique()))

    view = frame
    if type_filter:
        view = view[view["attack_type"].isin(type_filter)]
    if channel_filter:
        view = view[view["delivery_channel"].isin(channel_filter)]
    if severity_filter:
        view = view[view["severity"].isin(severity_filter)]
    if difficulty_filter:
        view = view[view["difficulty"].isin(difficulty_filter)]
    if position_filter:
        view = view[view["injection_position"].isin(position_filter)]

    st.caption(f"{len(view)} of {len(frame)} attacks")
    st.dataframe(view, width="stretch", hide_index=True)
    card_close()

    if len(view):
        card_open()
        section("Inspect", "Record detail")
        selected = st.selectbox("Inspect an attack", view["id"].tolist())
        detail = load_attack_full()[selected]
        sev = str(detail["severity"]).lower()
        sev_color = SEVERITY_COLORS.get(sev, "#6366f1")
        st.markdown(
            f"### {detail['id']} \u2014 {detail['name']} "
            f'<span class="pill" style="background:{sev_color}22;color:{sev_color};border:1px solid {sev_color}">{sev.upper()}</span>',
            unsafe_allow_html=True,
        )
        st.write(detail["description"])
        col_a, col_b = st.columns(2)
        with col_a:
            st.json(
                {
                    "attack_type": detail["attack_type"],
                    "delivery_channel": detail["delivery_channel"],
                    "injection_position": detail["injection_position"],
                    "format": detail["format"],
                    "difficulty": detail["difficulty"],
                    "severity": detail["severity"],
                    "target_action": detail["target_action"]["tool"] + "." + detail["target_action"]["action"],
                    "target_permission": detail["target_action"]["permission"],
                    "tags": detail["tags"],
                },
                expanded=False,
            )
        with col_b:
            st.markdown("**Payload (synthetic)**")
            st.code(str(detail["payload"])[:1500], language="text")
        st.markdown("**Expected behaviour**")
        st.info(detail["expected_behavior"])
        st.markdown("**Safety statement**")
        st.success(detail["safe_simulation"])
        st.markdown("**Success criteria (attack succeeds only if these hold)**")
        st.dataframe(pd.DataFrame(detail["success_criteria"]), width="stretch", hide_index=True)
        card_close()


# ===========================================================================
# 3. Run Experiment
# ===========================================================================
elif page == "Run Experiment":
    header("Run Experiment", "Execute a clean baseline and attacked runs, then persist everything to SQLite.")
    runs = load_runs()
    attack_ids = [a["id"] for a in load_attacks()]
    task_ids = [t["task_id"] for t in load_tasks()]
    models = available_models()

    card_open()
    section("Launch", "New experiment")
    with st.form("run_experiment"):
        c1, c2, c3 = st.columns(3)
        model_choice = c1.selectbox(
            "Model", [m["id"] for m in models],
            format_func=lambda x: next((m["display_name"] for m in models if m["id"] == x), x),
        )
        defense_choice = c2.selectbox("Defense", DEFENSE_ORDER)
        reps = c3.number_input("Repetitions", min_value=1, max_value=20, value=2)
        c4, c5, c6 = st.columns(3)
        selected_tasks = c4.multiselect("Tasks", task_ids, default=[])
        selected_attacks = c5.multiselect("Attacks", attack_ids, default=[], help="leave empty for the whole corpus")
        seed = c6.number_input("Random seed", min_value=0, value=1337)
        include_baseline = st.checkbox("Include clean baseline runs", value=True)
        name = st.text_input("Experiment name (optional)", value="")
        submit = st.form_submit_button("Run experiment", type="primary")

    if submit:
        if not selected_attacks:
            st.warning("Select at least one attack (the full corpus would take a while interactively).")
        else:
            with st.spinner("Running experiment..."):
                try:
                    result = ExperimentRunner(SETTINGS).run(
                        ExperimentRequest(
                            task_ids=selected_tasks or None,
                            attack_ids=selected_attacks,
                            provider="mock" if model_choice.startswith("mock") else None,
                            model=model_choice,
                            defense=defense_choice,
                            repetitions=int(reps),
                            random_seed=int(seed),
                            include_baseline=include_baseline,
                            name=name,
                        ),
                        settings=SETTINGS,
                    )
                except Exception as exc:  # noqa: BLE001 - surface actionable message
                    st.error(f"{type(exc).__name__}: {exc}")
                else:
                    st.success(
                        f"Experiment {result.experiment_uid} finished in "
                        f"{result.duration_ms / 1000:.1f}s - "
                        f"{result.score['n_runs']} runs, {len(result.errors)} error(s)."
                    )
                    st.write(result.provenance_note)
                    st.dataframe(
                        pd.DataFrame(
                            [{k: v for k, v in result.score.items() if k != "breakdown"}]
                        ),
                        width="stretch",
                        hide_index=True,
                    )
                    if result.errors:
                        with st.expander("Run errors"):
                            st.write(result.errors[:20])
                    load_runs.clear()
    card_close()

    st.divider()
    card_open()
    section("History", "Stored runs")
    if runs.empty:
        empty_state("No runs recorded yet.", "Run an experiment above, or `python run_demo.py`.")
    else:
        cols = st.columns([2, 2, 2, 2, 1])
        filt_model = cols[0].multiselect("Model", sorted(runs["model"].unique()))
        filt_def = cols[1].multiselect("Defense", sorted(runs["defense"].unique()))
        filt_cond = cols[2].multiselect("Condition", ["baseline", "attack"])
        filt_sev = cols[3].multiselect("Severity", ["low", "medium", "high", "critical"])
        show = runs
        for column, values in (
            ("model", filt_model), ("defense", filt_def),
            ("condition", filt_cond), ("severity", filt_sev),
        ):
            if values:
                show = show[show[column].isin(values)]
        st.dataframe(show, width="stretch", hide_index=True)
        st.download_button(
            "Download filtered runs (CSV)",
            show.to_csv(index=False),
            file_name="runs_filtered.csv",
            mime="text/csv",
        )
    card_close()


# ===========================================================================
# 4. Batch Experiments
# ===========================================================================
elif page == "Batch Experiments":
    header("Batch Experiments", "Sweep several models x several defenses over a corpus selection.")
    models = [m["id"] for m in available_models() if m["provider"] == "mock"]
    attack_ids = [a["id"] for a in load_attacks()]

    card_open()
    section("Launch", "Batch matrix")
    with st.form("batch"):
        c1, c2, c3 = st.columns(3)
        model_batch = c1.multiselect("Models", models, default=models[:2])
        defense_batch = c2.multiselect("Defenses", DEFENSE_ORDER, default=["none", "guard_classifier"])
        reps = c3.number_input("Repetitions", min_value=1, max_value=20, value=2)
        c4, c5 = st.columns(2)
        batch_attacks = c4.multiselect(
            "Attacks", attack_ids, default=[],
            help="empty = the whole corpus (slow interactively)",
        )
        seed = c5.number_input("Seed", min_value=0, value=1337)
        run_batch = st.form_submit_button("Run batch", type="primary")

    if run_batch:
        if not batch_attacks:
            st.warning("Select at least one attack for an interactive batch.")
        else:
            progress = st.progress(0.0)
            with st.spinner("Running batch..."):
                try:
                    result = ExperimentRunner(SETTINGS).run_batch(
                        BatchRequest(
                            models=[{"provider": "mock", "name": m} for m in model_batch],
                            defenses=defense_batch,
                            selection={"attack_ids": batch_attacks},
                            repetitions=int(reps),
                            random_seed=int(seed),
                        ),
                        settings=SETTINGS,
                    )
                except Exception as exc:  # noqa: BLE001
                    st.error(f"{type(exc).__name__}: {exc}")
                else:
                    progress.progress(1.0)
                    rows = [
                        {
                            "model": e.model,
                            "defense": e.defense,
                            "n_attacked": e.score["n_attacked"],
                            "ASR": e.score["attack_success_rate"],
                            "benign_utility": e.score["benign_utility"],
                            "utility_under_attack": e.score["utility_under_attack"],
                            "detection_rate": e.score["refusal_detection_rate"],
                            "risk_score": e.score["severity_weighted_risk"],
                            "experiment_uid": e.experiment_uid,
                        }
                        for e in result.experiments
                    ]
                    st.success(f"{len(rows)} experiments, {result.total_cells} cells, {result.total_seconds:.1f}s")
                    st.dataframe(pd.DataFrame(rows), width="stretch", hide_index=True)
                    load_runs.clear()
    card_close()

    st.divider()
    card_open()
    section("CLI", "Non-interactive equivalent")
    st.code(
        "python -m scripts.run_batch "
        "--models mock-vulnerable,mock-hardened --defenses none,guard_classifier\n"
        "python -m scripts.run_batch --batch-config configs/experiment_batch.yaml\n"
        "python run_demo.py --full",
        language="bash",
    )
    card_close()


# ===========================================================================
# 5. Attack Results
# ===========================================================================
elif page == "Attack Results":
    header("Attack Results", "Success behaviour per attack, grouped by corpus metadata.")
    runs = load_runs()
    if runs.empty:
        empty_state("No runs recorded yet.", "Run `python run_demo.py` first.")
    else:
        metric_row(runs)
        attacked = runs[runs["condition"] == "attack"]
        tables = load_tables()
        left, right = st.columns(2)
        with left:
            card_open()
            section("Breakdown", "ASR by attack type")
            frame = tables.get("by_attack_type")
            if frame is not None and not frame.empty:
                fig = px.bar(frame, x="attack_type", y="asr", color="asr", text="asr",
                             color_continuous_scale="Plasma")
                st.plotly_chart(style_fig(fig), width="stretch")
            card_close()
        with right:
            card_open()
            section("Breakdown", "ASR by severity")
            frame = tables.get("by_severity")
            if frame is not None and not frame.empty:
                fig = px.bar(frame, x="severity", y="asr", color="severity",
                             color_discrete_map=SEVERITY_COLORS,
                             category_orders={"severity": SEVERITY_ORDER})
                st.plotly_chart(style_fig(fig), width="stretch")
            card_close()
        card_open()
        section("Breakdown", "ASR by delivery channel")
        frame = tables.get("by_delivery_channel")
        if frame is not None and not frame.empty:
            fig = px.bar(frame, x="delivery_channel", y="asr", color="asr",
                         color_continuous_scale="Viridis")
            st.plotly_chart(style_fig(fig), width="stretch")
        card_close()

        card_open()
        section("Heatmap", "Success heatmap (attack type x defense)")
        heat = tables.get("heatmap_attack_x_defense")
        if heat is not None and not heat.empty:
            fig = px.imshow(heat, text_auto=".2f", aspect="auto",
                            labels=dict(x="defense", y="attack type", color="ASR"),
                            zmin=0, zmax=1, color_continuous_scale="RdYlGn_r")
            st.plotly_chart(style_fig(fig, height=420), width="stretch")
        else:
            st.info("Run more than one defense to build the heatmap.")
        card_close()

        card_open()
        section("Table", "Per-attack outcomes")
        if not attacked.empty:
            per_attack = (
                attacked.groupby(["attack_id", "attack_type", "delivery_channel", "severity"], dropna=False)
                .agg(
                    runs=("run_id", "count"),
                    successes=("attack_succeeded", "sum"),
                    detected=("attack_detected", "mean"),
                    utility=("task_utility", "mean"),
                )
                .reset_index()
            )
            per_attack["asr"] = (per_attack["successes"] / per_attack["runs"]).round(3)
            per_attack["detected"] = per_attack["detected"].round(3)
            per_attack["utility"] = per_attack["utility"].round(3)
            st.dataframe(per_attack.sort_values("asr", ascending=False),
                         width="stretch", hide_index=True)
            st.download_button("Download per-attack outcomes", per_attack.to_csv(index=False),
                               "per_attack_outcomes.csv", "text/csv")
        card_close()


# ===========================================================================
# 6. Model Comparison
# ===========================================================================
elif page == "Model Comparison":
    header("Model Comparison", "Metrics for every model that has been run.")
    runs = load_runs()
    if runs.empty:
        empty_state("No runs recorded yet.")
    else:
        tables = load_tables()
        frame = tables.get("by_model")
        if frame is not None and not frame.empty:
            keep = [
                "model", "n_runs", "n_attacked", "attack_success_rate", "benign_utility",
                "utility_under_attack", "utility_degradation", "refusal_detection_rate",
                "severity_weighted_risk", "harmful_effect_rate",
            ]
            view = frame[[c for c in keep if c in frame.columns]].copy()
            card_open()
            section("Table", "Model scorecard")
            st.dataframe(view, width="stretch", hide_index=True)
            card_close()
            card_open()
            section("Chart", "Attack success rate by model")
            fig = px.bar(view, x="model", y="attack_success_rate", color="model",
                         color_discrete_sequence=ATTACK_PALETTE,
                         barmode="group", labels={"attack_success_rate": "ASR"}, text="attack_success_rate")
            st.plotly_chart(style_fig(fig), width="stretch")
            card_close()
            card_open()
            section("Chart", "Utility: clean vs under attack")
            fig = px.bar(
                view.melt(
                    id_vars="model",
                    value_vars=["benign_utility", "utility_under_attack"],
                    var_name="condition", value_name="utility",
                ),
                x="model", y="utility", color="condition", barmode="group",
                color_discrete_sequence=["#34d399", "#f472b6"],
            )
            st.plotly_chart(style_fig(fig), width="stretch")
            card_close()
        else:
            st.info("No model comparison data yet.")

        card_open()
        section("Catalogue", "Available models")
        st.dataframe(pd.DataFrame(available_models()), width="stretch", hide_index=True)
        if SETTINGS.demo_mode:
            st.warning(
                "Simulated entries (`mock-*`) are deterministic victim models for offline "
                "demonstration, not language models. Live entries require the environment "
                "variable shown in the `env_var` column.",
                icon="\U0001f9ea",
            )
        card_close()


# ===========================================================================
# 7. Defense Comparison
# ===========================================================================
elif page == "Defense Comparison":
    header("Defense Comparison", "Each defense is an independent mechanism; the control condition is `none`.")
    runs = load_runs()
    if runs.empty:
        empty_state("No runs recorded yet.")
    else:
        tables = load_tables()
        frame = tables.get("by_defense")
        if frame is not None and not frame.empty:
            keep = [
                "defense", "n_attacked", "attack_success_rate", "asr_reduction",
                "refusal_detection_rate", "detection_gain", "benign_utility",
                "severity_weighted_risk", "swrs_reduction",
            ]
            view = frame[[c for c in keep if c in frame.columns]].copy()
            card_open()
            section("Table", "Defense scorecard")
            st.dataframe(view, width="stretch", hide_index=True)
            card_close()
            card_open()
            section("Chart", "Attack success rate by defense")
            fig = px.bar(view, x="defense", y="attack_success_rate", color="attack_success_rate",
                         color_continuous_scale="RdYlGn_r",
                         labels={"attack_success_rate": "ASR"}, text="attack_success_rate")
            st.plotly_chart(style_fig(fig), width="stretch")
            card_close()
            card_open()
            section("Chart", "Detection rate by defense")
            fig = px.bar(view, x="defense", y="refusal_detection_rate", color="refusal_detection_rate",
                         color_continuous_scale="Blues",
                         labels={"refusal_detection_rate": "detection rate"}, text="refusal_detection_rate")
            st.plotly_chart(style_fig(fig), width="stretch")
            card_close()
        else:
            st.info("Run at least two defenses to compare.")

        card_open()
        section("Cost", "Utility cost of each defense (clean runs)")
        cost = tables.get("utility_cost")
        if cost is not None and not cost.empty:
            st.dataframe(cost, width="stretch", hide_index=True)
            fig = px.bar(cost, x="defense", y="mean_utility", color="defense",
                         color_discrete_sequence=DEFENSE_PALETTE,
                         labels={"mean_utility": "mean clean utility"})
            st.plotly_chart(style_fig(fig), width="stretch")
        else:
            st.info("No clean baseline runs recorded.")
        card_close()

        card_open()
        section("Reference", "Defense mechanisms")
        st.dataframe(pd.DataFrame(list_defenses()), width="stretch", hide_index=True)
        card_close()


# ===========================================================================
# 8. Severity Analysis
# ===========================================================================
elif page == "Severity Analysis":
    header("Severity Analysis", "Risk weighted by declared severity: Low=1, Medium=2, High=3, Critical=4.")
    runs = load_runs()
    if runs.empty:
        empty_state("No runs recorded yet.")
    else:
        attacked = runs[runs["condition"] == "attack"]
        kpi_cards(
            [
                ("Severity-weighted risk", f"{risk_score(runs):.4f}", "realised / total weight", "#fb923c"),
                ("Realised weight", f"{int(attacked[attacked['attack_succeeded']]['severity'].map(lambda s: SETTINGS.severity_weights.get(str(s).lower(), 1)).sum()) if not attacked.empty else 0}", "weight of successes", "#f472b6"),
                ("Total weight", f"{int(attacked['severity'].map(lambda s: SETTINGS.severity_weights.get(str(s).lower(), 1)).sum()) if not attacked.empty else 0}", "weight of all attacks", "#6366f1"),
            ]
        )

        if not attacked.empty:
            left, right = st.columns(2)
            with left:
                card_open()
                section("Chart", "ASR by severity")
                grouped = (
                    attacked.groupby("severity")
                    .agg(runs=("run_id", "count"), successes=("attack_succeeded", "sum"))
                    .reset_index()
                )
                grouped["asr"] = (grouped["successes"] / grouped["runs"]).round(3)
                fig = px.bar(grouped, x="severity", y="asr", color="severity",
                             color_discrete_map=SEVERITY_COLORS,
                             category_orders={"severity": SEVERITY_ORDER},
                             text="asr")
                st.plotly_chart(style_fig(fig), width="stretch")
                card_close()
            with right:
                card_open()
                section("Weights", "Severity weights in force")
                weights = pd.DataFrame(
                    [{"severity": k, "weight": v} for k, v in SETTINGS.severity_weights.items()]
                )
                weights["order"] = range(len(weights))
                fig = px.bar(weights.sort_values("order"), x="severity", y="weight", color="severity",
                             color_discrete_map=SEVERITY_COLORS,
                             category_orders={"severity": SEVERITY_ORDER})
                st.plotly_chart(style_fig(fig), width="stretch")
                st.dataframe(weights.sort_values("order")[["severity", "weight"]],
                             width="stretch", hide_index=True)
                card_close()
            tables = load_tables()
            frame = tables.get("by_severity")
            if frame is not None and not frame.empty:
                card_open()
                section("Table", "Severity breakdown")
                st.dataframe(frame, width="stretch", hide_index=True)
                card_close()
            card_open()
            section("Chart", "Risk distribution by severity and defense")
            if not attacked.empty and attacked["defense"].nunique() > 1:
                fig = px.histogram(attacked, x="severity", color="defense", barmode="group",
                                   color_discrete_sequence=DEFENSE_PALETTE,
                                   category_orders={"severity": SEVERITY_ORDER})
                st.plotly_chart(style_fig(fig), width="stretch")
            card_close()
        else:
            st.info("No attacked runs recorded.")


# ===========================================================================
# 9. Tool / Channel Analysis
# ===========================================================================
elif page == "Tool / Channel Analysis":
    header("Tool / Channel Analysis", "Where payloads ride and which capabilities they target.")
    runs = load_runs()
    tables = load_tables()

    card_open()
    section("Catalogue", "Simulated tool catalogue")
    registry = ToolRegistry()
    rows = []
    for name in registry.names:
        spec = registry.spec(name)
        for action_name, action in spec.actions.items():
            rows.append(
                {
                    "tool": name,
                    "channel": spec.channel,
                    "action": action_name,
                    "permission": action.permission.value,
                    "description": action.description,
                }
            )
    st.dataframe(pd.DataFrame(rows), width="stretch", hide_index=True)
    card_close()

    if not runs.empty:
        left, right = st.columns(2)
        with left:
            card_open()
            section("Chart", "ASR by delivery channel")
            frame = tables.get("by_delivery_channel")
            if frame is not None and not frame.empty:
                fig = px.bar(frame, x="delivery_channel", y="asr", color="asr", text="asr",
                             color_continuous_scale="Teal")
                st.plotly_chart(style_fig(fig), width="stretch")
            card_close()
        with right:
            card_open()
            section("Chart", "Most targeted capabilities")
            attacked = runs[runs["condition"] == "attack"]
            if not attacked.empty and attacked["target_action"].notna().any():
                counts = attacked["target_action"].value_counts().head(15).reset_index()
                counts.columns = ["target_action", "runs"]
                fig = px.bar(counts, x="target_action", y="runs", color="runs",
                             color_continuous_scale="Blues")
                st.plotly_chart(style_fig(fig), width="stretch")
            else:
                st.info("No target-action data yet.")
            card_close()

        card_open()
        section("Chart", "ASR by injection position")
        frame = tables.get("by_injection_position")
        if frame is not None and not frame.empty:
            fig = px.bar(frame, x="injection_position", y="asr", color="asr", text="asr",
                         color_continuous_scale="Sunset")
            st.plotly_chart(style_fig(fig), width="stretch")
        card_close()
        card_open()
        section("Table", "ASR by payload format")
        frame = tables.get("by_payload_format")
        if frame is not None and not frame.empty:
            st.dataframe(frame, width="stretch", hide_index=True)
        card_close()


# ===========================================================================
# 10. Detailed Experiment
# ===========================================================================
elif page == "Detailed Experiment":
    header("Detailed Experiment", "Drill into one experiment: runs, tool calls, authorisations and sandbox effects.")
    experiments = load_experiments()
    if not experiments:
        empty_state("No experiments recorded yet.", "Run `python run_demo.py` first.")
    else:
        card_open()
        section("Select", "Experiment")
        uids = [e["experiment_uid"] for e in experiments]
        chosen = st.selectbox("Experiment", uids)
        init_db(SETTINGS)
        with session_scope(SETTINGS) as session:
            repo = Repository(session)
            detail = repo.get_experiment_detail(repo.get_experiment(chosen))
        experiment = detail["experiment"]
        kpi_cards(
            [
                ("Model", str(experiment["model"]), "victim model", "#6366f1"),
                ("Defense", str(experiment["defense"]), "active defense", "#14b8a6"),
                ("Runs", str(experiment["n_runs"]), "episodes", "#f59e0b"),
                ("Status", str(experiment["status"]), experiment["experiment_uid"], "#a78bfa"),
            ]
        )
        st.caption(experiment["provenance_note"])

        metrics = detail["metrics"]
        if metrics:
            st.markdown("**Metrics for this experiment**")
            flat = {k: v for k, v in metrics[0].items() if k != "breakdown"}
            st.dataframe(pd.DataFrame([flat]), width="stretch", hide_index=True)

        st.markdown("**Runs**")
        run_rows = pd.DataFrame(detail["runs"])
        st.dataframe(run_rows, width="stretch", hide_index=True)

        if len(run_rows):
            run_uid = st.selectbox("Inspect a run", run_rows["run_uid"].tolist())
            init_db(SETTINGS)
            with session_scope(SETTINGS) as session:
                repo = Repository(session)
                run = repo.get_run(run_uid)
                tab_calls, tab_auth, tab_fx, tab_eval = st.tabs(
                    ["\U0001f6e0\ufe0f Tool calls", "\U0001f510 Authorisations", "\u2623\ufe0f Sandbox effects", "\U0001f4dd Evaluation"]
                )
                with tab_calls:
                    if run.tool_calls:
                        st.dataframe(
                            pd.DataFrame(
                                [
                                    {
                                        "step": c.step,
                                        "tool": c.tool,
                                        "action": c.action,
                                        "permission": c.permission,
                                        "status": c.status,
                                        "authorization": c.authorization,
                                        "arguments": str(c.arguments)[:160],
                                        "result_preview": c.result_summary[:160],
                                    }
                                    for c in run.tool_calls
                                ]
                            ),
                            width="stretch",
                            hide_index=True,
                        )
                    else:
                        st.info("No tool calls recorded for this run.")
                with tab_auth:
                    st.markdown("Authorisation decisions (privilege separation audit)")
                    if run.authorizations:
                        st.dataframe(
                            pd.DataFrame(
                                [
                                    {
                                        "tool": a.tool,
                                        "action": a.action,
                                        "permission": a.permission,
                                        "claimed_source": a.claimed_source,
                                        "decision": a.decision,
                                        "reason": a.reason[:220],
                                    }
                                    for a in run.authorizations
                                ]
                            ),
                            width="stretch",
                            hide_index=True,
                        )
                    else:
                        st.info("No authorisation events recorded for this run.")
                with tab_fx:
                    st.markdown("Sandbox effects (simulated)")
                    if run.effects:
                        st.dataframe(
                            pd.DataFrame(
                                [
                                    {"kind": e.kind, "tool": e.tool, "action": e.action,
                                     "details": str(e.details)[:220], "ts": e.ts}
                                    for e in run.effects
                                ]
                            ),
                            width="stretch",
                            hide_index=True,
                        )
                    else:
                        st.info("No simulated side effect was recorded for this run.")
                with tab_eval:
                    st.markdown("**Final answer**")
                    st.write(run.final_answer or "(empty)")
                    st.markdown("**Evaluation payload**")
                    st.json(run.evaluation, expanded=False)
        card_close()

        card_open()
        section("Reproduce", "Replay this experiment")
        st.code(
            'curl -X POST http://127.0.0.1:8000/experiments/{uid}/reproduce\n'
            "# or from Python:\n"
            "from backend.evaluation.runner import reproduce\n"
            f"reproduce({chosen!r})",
            language="bash",
        )
        card_close()


# ===========================================================================
# 11. Logs
# ===========================================================================
elif page == "Logs":
    header("Logs", "Structured JSON log tail; credentials are redacted before anything is written.")
    entries = read_log_tail(SETTINGS, lines=1000)
    if not entries:
        empty_state(
            "No log entries found.",
            f"Expected a JSON-lines log at `{SETTINGS.resolve_path(SETTINGS.get('logging.json_file'))}`.",
        )
    else:
        card_open()
        section("Tail", "Recent events")
        lines = st.slider("Lines to show", 25, len(entries), min(200, len(entries)))
        frame = pd.DataFrame(entries[-lines:])
        st.dataframe(frame, width="stretch", hide_index=True)
        st.download_button("Download log tail (JSON)", frame.to_json(orient="records", indent=2),
                           "log_tail.json", "application/json")
        card_close()

        card_open()
        section("Chart", "Event distribution")
        events = frame["event"].value_counts().reset_index()
        events.columns = ["event", "count"]
        fig = px.bar(events.head(20), x="count", y="event", orientation="h",
                     color="count", color_continuous_scale="Blues")
        st.plotly_chart(style_fig(fig, height=420), width="stretch")
        card_close()

        with st.expander("Raw entry viewer"):
            index = st.number_input("Entry index", 0, len(entries) - 1, len(entries) - 1)
            st.json(entries[int(index)])


# ===========================================================================
# 12. Export Results
# ===========================================================================
elif page == "Export Results":
    header("Export Results", "Write CSV, JSON and a Markdown research summary to disk.")
    runs = load_runs()
    summary = load_summary()

    card_open()
    section("Dataset", "Current dataset")
    counts = summary["counts"]
    kpi_cards(
        [
            ("Experiments", f"{counts['experiments']}", "conditions", "#6366f1"),
            ("Runs", f"{counts['runs']}", "episodes", "#0ea5e9"),
            ("Tool calls", f"{counts['tool_calls']}", "invocations", "#14b8a6"),
            ("Sandbox effects", f"{counts['sandbox_effects']}", "consequences", "#f59e0b"),
            ("Auth events", f"{counts['authorization_events']}", "audit trail", "#a78bfa"),
        ]
    )
    st.json(
        {
            "experiments": summary["counts"]["experiments"],
            "runs": summary["counts"]["runs"],
            "tool_calls": summary["counts"]["tool_calls"],
            "sandbox_effects": summary["counts"]["sandbox_effects"],
            "authorization_events": summary["counts"]["authorization_events"],
            "provenance": summary["result_provenance"],
        },
        expanded=False,
    )

    out_dir = st.text_input("Output directory", value=str(SETTINGS.export_dir))
    if st.button("Write all reports", type="primary"):
        with st.spinner("Exporting..."):
            try:
                with session_scope(SETTINGS) as session:
                    result = export_all(Repository(session), out_dir, SETTINGS)
            except Exception as exc:  # noqa: BLE001
                st.error(f"{type(exc).__name__}: {exc}")
            else:
                st.success(f"Wrote {len(result['files'])} files to {out_dir}")
                st.dataframe(pd.DataFrame({"file": result["files"]}), width="stretch", hide_index=True)
    card_close()

    st.divider()
    card_open()
    section("Download", "Download directly")
    if not runs.empty:
        st.download_button("runs.csv", runs.to_csv(index=False), "runs.csv", "text/csv")
        st.download_button("runs.json", runs.to_json(orient="records", indent=2), "runs.json", "application/json")
    st.download_button(
        "summary.json",
        __import__("json").dumps(summary, indent=2, default=str),
        "summary.json",
        "application/json",
    )

    tables = load_tables()
    if tables:
        st.markdown("**Comparison tables**")
        for name, frame in tables.items():
            with st.expander(name):
                st.dataframe(frame, width="stretch", hide_index=True)
                st.download_button(f"{name}.csv", frame.to_csv(index=False), f"{name}.csv", "text/csv")
    card_close()

    st.divider()
    st.warning(
        "Exports carry the provenance banner from the database. When `demo_mode` is on, "
        "every exported number is a simulation result and is labelled as such in "
        "`summary.json` and `report.md`.",
        icon="\U0001f9ea",
    )


st.sidebar.divider()
st.sidebar.caption("Simulated research environment - no real credentials, files, mail or databases are touched.")
st.markdown(
    '<div class="footer-note">\U0001f6e1 IPI Test Range \u00b7 simulated research environment \u00b7 '
    "no real credentials, files, mail or databases are touched.</div>",
    unsafe_allow_html=True,
)
