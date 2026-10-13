# 🛡️ Indirect Prompt Injection Test Range

**A sandboxed, reproducible benchmark for measuring how tool-using LLM agents behave when an
adversarial instruction is hidden inside the data a tool returns.**

![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![Tests](https://img.shields.io/badge/tests-452%20passing-brightgreen)
![API](https://img.shields.io/badge/API-FastAPI-009688)
![Dashboard](https://img.shields.io/badge/dashboard-Streamlit-ff4b4b)
![Keys](https://img.shields.io/badge/API%20keys-none%20required-lightgrey)

> **🔒 Safety notice.** Every tool in this project is **simulated**. A *successful attack* means a
> predefined unsafe action was recorded in an in-memory sandbox ledger. No e-mail is sent, no file
> is deleted, no database row is dropped, no credential is read and no network request is made.
> Exfiltration targets use reserved, non-routable `.invalid` / `.test` domains (RFC 2606 / 6761).
>
> **🔬 Research integrity.** With the default `demo_mode: true`, every number produced is a
> **SIMULATED** result from a deterministic victim model. Such results characterise *this
> framework*, not the security of any real language model. Results are labelled as simulation
> in the database, the API, the dashboard and every exported report.

---

## ✨ What you get

| # | Capability | Where it lives |
|---|---|---|
| 1 | 🧰 7 simulated tools across 7 delivery channels (web, browser, email, file, calendar, database, code) with a permission model + sandbox ledger | `backend/tools/` |
| 2 | 🗡️ Scored corpus of **78 synthetic attacks** — 5 categories × 7 channels × 7 positions × 12 formats, each with explicit machine-checkable success criteria | `corpus/attacks/`, `scripts/build_corpus.py` |
| 3 | 💉 Deterministic injection engine — surgical edits to untrusted fields only, with provenance tracking | `backend/attacks/injection.py` |
| 4 | 🤖 ReAct agent with injection awareness, authorization gating and hijack detection (mock / Ollama / OpenAI / Anthropic providers) | `backend/agents/` |
| 5 | 🛡️ **6 independently implemented defenses** (none, sanitization, spotlighting, sandwich prompting, privilege separation, guard classifier) | `backend/defenses/` |
| 6 | 📏 Standardised scoring: ASR, benign utility, utility under attack, detection rate, severity-weighted risk | `backend/scoring/metrics.py` |
| 7 | 🗄️ SQLite experiment history (12 tables), seeded reproducible runner, reproduce-by-UID | `backend/database/`, `backend/evaluation/runner.py` |
| 8 | 🔌 FastAPI with **24 endpoints** + interactive Swagger UI | `backend/api/` |
| 9 | 📊 12-page Streamlit research dashboard with themed UI | `dashboard/app.py` |
| 10 | ✅ **452 passing tests**, one-command demo, CSV/JSON/Markdown exports | `tests/`, `run_demo.py`, `scripts/` |

---

## 📊 Results snapshot (real values, `data/exports/`)

37 experiments · **6,108 runs** (3,054 clean + 3,054 attacked) · 11,768 tool calls · 1,553 sandbox effects.

| Metric | Value |
|---|---|
| Attack Success Rate (ASR) | **0.2115** (646 / 3,054) |
| Benign Utility | **1.0000** |
| Utility Under Attack | **0.7785** |
| Refusal / Detection Rate | **0.7233** (2,209 / 3,054) |
| Severity-Weighted Risk | **0.2066** (2,276 / 11,014) |

| Defense | ASR | RDR | ASR reduction vs control |
|---|---|---|---|
| `none` (control) | 0.3622 | 0.4902 | — |
| `privilege_separation` | **0.0000** | 0.8622 | **+0.3622** |
| `sanitization` | 0.1713 | 0.8917 | +0.1909 |
| `spotlighting` | 0.2087 | 0.6555 | +0.1535 |
| `guard_classifier` | 0.2160 | 0.7432 | +0.1463 |
| `sandwich_prompting` | 0.3110 | 0.6969 | +0.0512 |

> Full breakdowns by model, attack type, channel, severity, position and format are in
> `data/exports/tables/*.csv`, and the conference-paper draft with every table is
> [`docs/conference-paper.md`](docs/conference-paper.md).

---

## 🏗️ Architecture

```
                      +-------------------+
                      |  attack corpus    |  78 scored records (JSON)
                      |  task corpus      |  10 synthetic tasks (JSON)
                      +---------+---------+
                                |
                                v
  clean tool output ---> +------+---------------+  deterministic injection engine
                        |  InjectionEngine     |  7 positions x 12 formats
                        +----------+-----------+
                                   |
                                   v
                        +----------+-----------+
                        |  Defense pipeline    |  6 independent mechanisms
                        +----------+-----------+
                                   |
   simulated tools <---------------+--------------> agent loop <----> LLM provider
   (7 tools, ledger)                                   (mock / Ollama / OpenAI / Anthropic)
                                   |
                                   v
                        +----------+-----------+
                        |  Evaluation          |  attack success + task utility
                        +----------+-----------+
                                   |
                                   v
                    SQLite <-------+------> scoring engine --> FastAPI / Streamlit / CSV / JSON / MD
```

---

## 📁 Project structure

```
sushma-ipi-test/
├── backend/            # agents, api, attacks, database, defenses, evaluation, scoring, tools, services
├── corpus/             # attacks/*.json (78 records), tasks.json, schemas
├── configs/            # default.yaml, experiment_batch.yaml
├── dashboard/          # Streamlit app (12 pages, themed UI)
├── scripts/            # CLI: init_db, build_corpus, run_experiment, run_batch, export_results, serve_api …
├── tests/              # 452 pytest tests
├── docs/               # architecture, attack-corpus, database, defenses, metrics, testing,
│                       # experiment-guide, limitations, conference-paper
├── data/               # SQLite DB + exports (git-ignored, recreated by setup)
├── experiments/        # batch configs + results (results git-ignored)
├── run_demo.py         # one-command end-to-end demo
├── requirements.txt
└── .env.example        # copy to .env for live-model keys (never commit .env)
```

---

## 🚀 Setup — step by step

### Step 0 · Prerequisites

- **Python 3.10+** (tested on 3.14) — check with `python --version`
- **Git**
- **No API keys needed.** Demo mode is fully offline. *(Optional: OpenAI/Anthropic keys or a local
  Ollama server only if you want live-model runs — see Step 8.)*

### Step 1 · Clone the repository

```bash
git clone https://github.com/dti-tech-hub/sushma-ipi-test.git
cd sushma-ipi-test
```

### Step 2 · Create and activate a virtual environment

```bash
# Windows (PowerShell)
python -m venv .venv
.\.venv\Scripts\Activate.ps1

# macOS / Linux
python3 -m venv .venv
source .venv/bin/activate
```

### Step 3 · Install dependencies

```bash
pip install --upgrade pip
pip install -r requirements.txt
```

### Step 4 · (Optional) Configure live-model keys

Skip this for the offline demo. For real-model runs:

```bash
copy .env.example .env        # Windows
# cp .env.example .env        # macOS / Linux
```

Then edit `.env`: set `app.demo_mode: false` and add `OPENAI_API_KEY` / `ANTHROPIC_API_KEY`,
or point `llm.ollama_base_url` at your local Ollama server. **Never commit `.env`** (git-ignored).

### Step 5 · Initialise the database

```bash
python -m scripts.init_db
```

Creates `data/testrange.db` (12 tables, WAL mode). Safe to re-run — it is idempotent.

### Step 6 · Run the end-to-end demo ✅ (start here)

```bash
python run_demo.py
```

In ~12 seconds it: initialises the DB → validates the 78-attack + 10-task corpora → runs
2 models × 6 defenses → prints ASR/utility/detection tables → verifies SQLite → writes 14
report artefacts to `data/exports/` → prints an aggregate summary. For the full 78-attack
corpus sweep:

```bash
python run_demo.py --full
```

### Step 7 · Open the dashboard 📊 (12 pages)

```bash
streamlit run dashboard/app.py
```

Open **http://127.0.0.1:8501** — Overview, Attack Corpus, Run/Batch Experiments,
Attack Results, Model/Defense Comparison, Severity & Channel Analysis, Detailed Experiment,
Logs, Export Results. Look for the yellow **DEMO MODE** badge in the sidebar.

### Step 8 · Start the API 🔌 (24 endpoints)

```bash
python -m scripts.serve_api
```

Open **http://127.0.0.1:8000/docs** for Swagger UI. Quick checks:

```bash
curl http://127.0.0.1:8000/health
curl "http://127.0.0.1:8000/attacks?severity=high"
curl -X POST http://127.0.0.1:8000/experiments/run ^
  -H "Content-Type: application/json" ^
  -d "{\"model\":\"mock-vulnerable\",\"defense\":\"privilege_separation\",\"attack_ids\":[\"GH-001\"],\"repetitions\":2,\"random_seed\":42}"
```

### Step 9 · Run the test suite 🧪

```bash
pytest -q
```

Expect **452 passed in ~6 s**. Tests use an isolated temp database — your `data/testrange.db`
is never touched.

### Step 10 · Run your own experiments

```bash
# Single condition
python -m scripts.run_experiment --model mock-vulnerable --defense guard_classifier \
  --attacks GH-001,IO-001 --repetitions 3 --seed 42

# Batch from config
python -m scripts.run_batch --batch-config configs/experiment_batch.yaml

# Export reports
python -m scripts.export_results
```

### Step 11 · (Optional) Live-model runs

Set `demo_mode: false`, provide keys (Step 4), and re-run any command above with
`--provider openai|anthropic|ollama --model <id>`. Every live result is stored with
`is_simulation = 0` so it can never be confused with demo numbers.

---

## 🔌 API endpoints (24)

| Group | Endpoints |
|---|---|
| Health | `GET /health` |
| Attacks | `GET /attacks` (filter: `type, channel, position, format, severity, difficulty`), `GET /attacks/{id}` |
| Tasks | `GET /tasks`, `GET /tasks/{id}` |
| Defenses / Models / Tools | `GET /defenses`, `GET /models`, `GET /tools` |
| Experiments | `GET /experiments`, `GET /experiments/{uid}`, `POST /experiments/run`, `POST /experiments/batch`, `POST /experiments/{uid}/reproduce`, `GET /experiments/{uid}/export` |
| Metrics | `GET /metrics` (`group_by=defense\|model\|attack_type\|severity\|…`), `GET /metrics/definitions` |
| Reports | `GET /reports/summary`, `GET /reports/tables`, `GET /reports/export` |
| Corpus | `GET /corpus/stats` |

Invalid enums → `422`, unknown ids → `404`. Every response carries simulation provenance.

---

## 🧪 Tests

```
pytest -q                                   # whole suite (452 tests)
pytest tests/test_scoring.py -q             # one module
pytest -q -k "injection or defense"         # by keyword
pytest --cov=backend --cov-report=term-missing   # coverage (needs pytest-cov)
```

Coverage: corpus schema & builder consistency, every injection position/format + round-trips,
7 tools + sandbox ledger + safe interpreter, 6 defenses + guard classifier, agent loop,
evaluation predicates (prose never counts as success), all metric formulas, DB schema +
no-credential-columns, runner determinism + reproduction, all API endpoints + lifespan,
config precedence + every CLI script + `run_demo` end-to-end. See [`docs/testing.md`](docs/testing.md).

---

## ⚙️ Configuration

Everything lives in `configs/default.yaml` (severity weights, utility threshold, paths, provider
settings) with env-var / `.env` overrides — see [`docs/experiment-guide.md`](docs/experiment-guide.md).
Key knobs: `app.demo_mode`, `evaluation.severity_weights`, `paths.db_path`, `llm.*`.

---

## 📄 Writing a conference paper?

Start from [`docs/conference-paper.md`](docs/conference-paper.md) — a complete draft skeleton
(abstract → related work → design → corpus → defenses → metric formulas → **all result tables
with the real values above** → discussion → 10 limitations → conclusion → references) plus the
required/recommended **figure list with exact CSV sources** and a reproducibility checklist.

---

## 🛠️ Troubleshooting

| Symptom | Fix |
|---|---|
| `streamlit` / `pytest` not found | Activate the venv (Step 2) and reinstall (Step 3) |
| `127.0.0.1 refused to connect` | The server isn't running — start it (Steps 7/8); API is `:8000`, dashboard is `:8501` |
| Port already in use | `python -m scripts.serve_api --port 8611` / `streamlit run dashboard/app.py --server.port 8601` |
| Stale numbers in dashboard | `streamlit cache clear`, or re-run `python run_demo.py` |
| Reset everything | `rm data/testrange.db` (or `del` on Windows) → `python -m scripts.init_db` → `python run_demo.py` |
| Live-model auth errors | Check `.env` keys and `app.demo_mode: false`; mock models always work offline |

---

## 🤝 Contributing

Issues and PRs are welcome. Please keep the honesty framing intact: new metrics need tests in
`tests/test_scoring.py`, new attacks need a corpus rebuild (`scripts/build_corpus.py`), and
simulation provenance (`is_simulation`, DEMO banners) must survive every change. See
[`docs/limitations.md`](docs/limitations.md) before claiming real-model results.

## 📜 License

[MIT — see `LICENSE` if present; otherwise all code in this repository is shared for research
and education. Synthetic data only; no real credentials, mail, or personal data are included.]
