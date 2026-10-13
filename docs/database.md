# Database

SQLite is the only datastore. No server, no driver install, no connection string to configure.
The file is created on demand by `python -m scripts.init_db` (and automatically by the API, the
dashboard and the demo).

Default path: `data/testrange.db` (override with `--db`, `TESTRANGE_PATHS__DB_PATH`, or
`settings.resolve_path`).

## 1. Schema overview

12 tables. Reference data is content-addressed; runs are the high-volume fact table.

```
models ────┐
defenses ──┤
           ├──► experiments ──► attack_runs ──► tool_calls
experiment_configs ─┘              │  ├──► agent_responses
                                    │  ├──► authorization_events
                                    │  └──► sandbox_effects
                                    └──► metrics

tasks, attacks   (reference corpora, independent of any experiment)
```

| Table | Rows after the recorded run | Purpose |
|---|---|---|
| `models` | 2 | LLM registry + `is_simulation`, `attributes` (vulnerability, decoding ability) |
| `defenses` | 6 | defense registry + `mechanism`, `config` |
| `tasks` | 10 | full `TaskDefinition` JSON plus indexed summary columns |
| `attacks` | 78 | full `AttackRecord` JSON plus indexed summary columns and `payload_sha` |
| `experiment_configs` | 0 | named reusable configurations (populated by the API/config workflow) |
| `experiments` | 12 | one row per experiment: model, defense, seed, repetitions, configuration, provenance |
| `attack_runs` | 5,616 | one row per agent episode |
| `tool_calls` | 10,946 | every simulated tool invocation with its authorisation decision |
| `agent_responses` | 16,557 | raw model output per step |
| `authorization_events` | 10,946 | privilege-separation audit trail |
| `sandbox_effects` | 1,511 | simulated side effects — the proof of a successful attack |
| `metrics` | 12 | one aggregate block per experiment |

45,696 rows total for a 78-attack x 2-model x 6-defense x 3-repetition sweep.

## 2. Reference tables

### `models`
`model_id` (unique), `provider`, `is_simulation`, `requires_api_key`, `available`,
`attributes` (JSON: vulnerability, decoding ability, description).

### `defenses`
`name` (unique), `mechanism`, `rewrites_content`, `gates_actions`, `config` (JSON).

### `tasks`
Indexed columns for fast filtering (`allowed_tools`, `forbidden_actions`, `difficulty`,
`channels`) plus the complete `TaskDefinition` in `payload`.

### `attacks`
Indexed columns for every filter used by the API and dashboard: `attack_type`,
`delivery_channel`, `injection_position`, `payload_format`, `difficulty`, `severity`,
`target_action`. `success_criteria` (JSON) and `payload_sha` (SHA-256 of the record) allow
change detection.

## 3. `experiments`

| Column | Notes |
|---|---|
| `experiment_uid` | `EXP-<14 hex>`, human-facing id used by the API and dashboard |
| `config_id` | optional FK to a named `experiment_configs` row |
| `provider`, `model`, `model_version` | provider selection |
| `is_simulation` | **provenance flag**; drives every "SIMULATED" label |
| `provenance_note` | full sentence stored with the run |
| `defense` | defense name |
| `random_seed`, `repetitions` | reproducibility inputs |
| `task_ids`, `attack_ids` | the resolved matrix |
| `corpus_versions` | `{attacks, tasks}` versions, so a replay knows what it replayed |
| `configuration` | complete request + settings snapshot |
| `status` | `running` / `completed` / `partial` |
| `started_at`, `finished_at`, `duration_ms` | timing |

## 4. `attack_runs`

| Column | Notes |
|---|---|
| `run_uid` | unique per run (`RUN-<12 hex>`); random by design so repeated experiments never collide |
| `experiment_id`, `condition`, `repetition`, `seed` | the deterministic seed **is** stored here |
| `task_id`, `attack_id` | what was run |
| `attack_succeeded`, `attack_detected`, `detection_reason` | evaluation verdict |
| `policy_violation`, `harmful_effect`, `hijacked` | behavioural flags |
| `task_utility`, `plan_completion`, `steps_used`, `latency_ms` | utility metrics |
| `final_answer` | truncated answer |
| `evaluation` | JSON: full utility block, attack verdict with per-predicate results, **injection provenance** (position, format, digests, channel match), agent perception, defense reports |

## 5. Child tables

`tool_calls`, `agent_responses`, `authorization_events`, `sandbox_effects` cascade-delete with
their run (`cascade="all, delete-orphan"`).

`authorization_events` stores exactly the fields Module 12 requires: requested action, agent, tool,
permission, claimed authority source, decision and reason.

`sandbox_effects` stores `effect_uid`, `kind`, `tool`, `action`, `details`, `ts` — the only place
where an "attack succeeded" becomes provable, and the only place where a harmful consequence is
recorded (inside the sandbox).

## 6. Indexes

| Index | Table | Columns |
|---|---|---|
| `ix_attack_runs_experiment_condition` | `attack_runs` | `(experiment_id, condition)` |
| `ix_runs_*` | `attack_runs` | `run_uid`, `task_id`, `attack_id`, `attack_succeeded`, `attack_detected`, `policy_violation`, `harmful_effect` |
| `ix_tool_calls_*` | `tool_calls` | `run_id`, `tool` |
| `ix_authorization_events_*` | `authorization_events` | `run_id`, `decision` |
| `ix_sandbox_effects_*` | `sandbox_effects` | `run_id`, `kind` |
| `ix_metrics_experiment_name` | `metrics` | `(experiment_id, name)` |
| `ix_attacks_*` | `attacks` | type, channel, position, format, difficulty, severity, target |
| `ix_experiments_*` | `experiments` | `experiment_uid`, `model`, `defense`, `provider`, `started_at`, `status` |

## 7. Engine settings

`backend/database/session.py` applies on every connection:

```sql
PRAGMA foreign_keys = ON     -- referential integrity is enforced (tested)
PRAGMA journal_mode = WAL    -- concurrent readers during a batch
PRAGMA synchronous = NORMAL
```

Engines and session factories are memoised per resolved database path, and both use the same key
function (`_engine_key`), so passing an explicit `path` can never desynchronise them.

## 8. Migrations

`init_db()` calls `create_all()` and then applies `MIGRATIONS`: a tuple of
`(table, {column: ddl})` entries executed as `ALTER TABLE ... ADD COLUMN` when the column is
missing. `init_db` is idempotent and reports what it applied:

```json
{"database": ".../data/testrange.db", "tables": [...12...],
 "migrations_applied": [], "already_initialised": true}
```

Add a migration by appending to `MIGRATIONS` in `backend/database/session.py`.

## 9. Programmatic access

```python
from backend.database.repository import Repository
from backend.database.session import init_db, session_scope

init_db()
with session_scope() as session:
    repo = Repository(session)
    for experiment in repo.list_experiments(limit=10):
        print(experiment.experiment_uid, experiment.model, experiment.defense,
              len(experiment.runs))

    scores = repo.hydrate_run_scores(repo.all_runs())
    from backend.scoring.metrics import aggregate
    print(aggregate(scores).to_dict())
```

`hydrate_run_scores` joins run rows back to the `attacks` table so every `RunScore` carries its
attack metadata — that is how the dashboard can group by type/severity/position/format without a
second query.

## 10. Security properties (tested)

- `tests/test_database.py::test_schema_has_no_credential_columns` asserts no `api_key`,
  `password`, `secret_key` or `access_token` column exists anywhere.
- Credentials are never passed to the repository layer; providers read them from the environment.
- The structured logger redacts key-shaped strings before they reach a sink.
- The database holds only synthetic data and simulated effects.

## 11. Housekeeping

`data/testrange.db` is git-ignored. To reset:

```bash
python run_demo.py --fresh        # demo database
rm -f data/testrange.db && python -m scripts.init_db
```

To inspect directly:

```bash
sqlite3 data/testrange.db
  .tables
  SELECT kind, COUNT(*) FROM sandbox_effects GROUP BY kind;
  SELECT defense, AVG(attack_succeeded) FROM attack_runs WHERE condition='attack' GROUP BY defense;
```