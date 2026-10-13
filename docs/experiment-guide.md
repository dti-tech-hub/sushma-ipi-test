# Experiment guide

## 1. Concepts

| Term | Meaning |
|---|---|
| **Task** | a synthetic benign objective with ground truth, an action policy and a reference plan |
| **Attack** | a scored payload with a declared target action and explicit success predicates |
| **Cell** | one (task, attack) pairing produced by the planner |
| **Run** | one agent episode (a cell x condition x repetition) |
| **Condition** | `baseline` (clean output) or `attack` (payload present) |
| **Experiment** | one configuration applied to a matrix of cells |

A single experiment therefore produces `cells x repetitions x 2` agent runs.

## 2. Quick start

```bash
python run_demo.py                          # fast, no-API-key demonstration
python run_demo.py --full --reps 3          # entire 78-attack corpus
```

## 3. CLI reference

### `scripts/run_experiment.py`

```bash
python -m scripts.run_experiment \
    --tasks T-001,T-003 \
    --attacks GH-001,IO-001,OB-016 \
    --types data_exfiltration \
    --severities critical,high \
    --difficulties hard \
    --channels email \
    --model mock-vulnerable \
    --provider mock \
    --defense guard_classifier \
    --reps 5 --seed 1337 \
    --max-steps 10 \
    --name "critical-email-guard"
```

`--json` prints the raw result object. All filters are AND-combined.

### `scripts/run_batch.py`

```bash
python -m scripts.run_batch --models mock-vulnerable,mock-hardened \
                            --defenses none,sanitization,spotlighting,sandwich_prompting,privilege_separation,guard_classifier \
                            --severities critical --reps 3

python -m scripts.run_batch --batch-config configs/experiment_batch.yaml
```

### Other scripts

| Command | Purpose |
|---|---|
| `python -m scripts.init_db` | create/upgrade the SQLite schema |
| `python -m scripts.validate_corpus` | structural + referential validation |
| `python -m scripts.sync_corpus` | load the whole corpus into the catalogue tables |
| `python -m scripts.export_results --out data/exports` | CSV / JSON / Markdown artefacts |
| `python -m scripts.serve_api --port 8000` | FastAPI |
| `python -m scripts.build_corpus` | regenerate `corpus/attacks/*.json` |
| `python -m scripts.export_schemas` | regenerate JSON Schemas |

## 4. Programmatic use

```python
from backend.evaluation.runner import ExperimentRequest, ExperimentRunner
from backend.services.config import load_settings

settings = load_settings()
result = ExperimentRunner(settings).run(
    ExperimentRequest(
        task_ids=["T-001"],
        attack_ids=["GH-001", "IO-001"],
        provider="mock",
        model="mock-vulnerable",
        defense="guard_classifier",
        repetitions=5,
        random_seed=1337,
    ),
    settings=settings,
)

print(result.experiment_uid, result.score["attack_success_rate"])
```

Over HTTP:

```bash
curl -X POST http://127.0.0.1:8000/experiments/run \
  -H 'Content-Type: application/json' \
  -d '{"task_ids":["T-001"],"attack_ids":["GH-001"],"model":"mock-vulnerable",
       "defense":"guard_classifier","repetitions":3,"random_seed":1337}'
```

From the dashboard: **Run Experiment** / **Batch Experiments** pages.

## 5. How pairing works

1. Tasks are filtered by `task_ids` (all tasks if empty).
2. Attacks are filtered by every supplied criterion.
3. For each attack, `TaskRepository.supporting()` returns tasks whose declared channels match;
   the intersection with the filtered task set is used.
4. A task whose channels match exactly is preferred, else the first supporting task.
5. If no supporting task survives the filter, the attack is **skipped with a reason**, never
   silently dropped:

```json
{"attack_id": "EX-001", "reason": "no task in the current selection declares this attack's delivery channel (database)"}
```

## 6. What a run records

| Table | Contents |
|---|---|
| `experiments` | model, defense, seed, repetitions, full configuration, corpus versions, provenance note |
| `attack_runs` | condition, repetition, derived seed, success/detection/violation flags, utility, final answer, full evaluation payload |
| `tool_calls` | tool, action, permission, arguments, authorisation decision + reason, result summary |
| `agent_responses` | raw model text per step |
| `authorization_events` | privilege-separation audit trail |
| `sandbox_effects` | simulated side effects (the proof of a successful attack) |
| `metrics` | the aggregate block |

`run.evaluation` additionally carries the injection provenance (attack id, position, format,
digests, whether the channel matched), the agent's perception, and per-defense reports.

## 7. Reproducibility

```bash
curl -X POST http://127.0.0.1:8000/experiments/EXP-XXXX/reproduce
```

```python
from backend.evaluation.runner import reproduce
replay = reproduce("EXP-XXXX")
```

Seeds are derived as
`blake2b(base_seed | task | attack | defense | condition | repetition)` — BLAKE2b, never
Python's randomised `hash`, so the value is stable across processes and platforms. A test asserts
a subprocess computes the same value.

`run_uid` values are random by design so repeated experiments never collide; the deterministic
seed is stored on the run row instead.

## 8. Using a real model

```bash
# .env
TESTRANGE_DEMO_MODE=false
TESTRANGE_MODEL__PROVIDER=openai
TESTRANGE_MODEL__NAME=gpt-4o-mini
OPENAI_API_KEY=...
```

```bash
python -m scripts.run_experiment --provider openai --model gpt-4o-mini \
    --severities critical --reps 3 --max-steps 8
```

The provider is asked for one JSON object per step:

```json
{"thought": "...", "action": "email.read_message", "arguments": {"mail_id": "mail-001"}}
{"thought": "...", "final": "The price is 249 USD."}
```

The parser is tolerant of markdown fences and leading prose. A malformed response is recorded as
`finished_reason="provider_error"` and the batch continues.

Notes for live runs: use a smaller `--reps` (API cost and latency), keep `--max-steps` modest, and
record `model_version` in the provenance note.

## 9. Interpreting results responsibly

1. In demo mode every result is a **simulation**. Check `is_simulation` and `provenance_note`.
2. Compare defenses **against the `none` control at the same seed and repetitions**.
3. Small `n` produces noisy ASR. A `delta` of ±0.05 at n=10 is sampling noise; the recorded
   full-corpus run used n=234 per cell.
4. `privilege_separation` scoring 0.000 reflects the read-only task policies, not a general claim.
5. Always report the *utility cost* alongside ASR. This range currently reports a Benign Utility
   of 1.000 for all defenses, which means it does **not** yet capture sanitization's false-positive
   cost.

## 10. Troubleshooting

| Problem | Cause | Fix |
|---|---|---|
| All cells skipped | `task_ids` too narrow for the attack channels | widen `task_ids` or drop the filter |
| ASR identical across defenses | defenses not registered for the run | check `--defense` spelling |
| `provider_error` finished reason | malformed or failing model output | lower `--max-steps`, check the key |
| Runs very slow | large matrix | reduce `--reps`, filter `--severities` |
| Duplicate experiment rows | expected — each run persists | use `GET /experiments` to find them |