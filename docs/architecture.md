# Architecture

## 1. Design goals

1. **Safety first.** No simulated tool may touch a real external system.
2. **Determinism.** A given configuration must replay byte-identically.
3. **Separation of concerns.** Corpus, injection, tools, agent, evaluation, scoring, persistence
   and presentation are separate packages with one-directional dependencies.
4. **Explainability.** Every number traces back to a recorded action.
5. **Replaceable pieces.** Any LLM provider, defense or metric backend can be swapped without
   touching the rest.

## 2. Layer diagram

```
                corpus/*.json                configs/*.yaml          .env
                     |                             |                    |
                     v                             v                    v
   +-------------------------------------------------------------+
   |  backend.attacks.loader        backend.services.config        |
   |  (Pydantic validation)         (YAML < env < code)            |
   +------------------------------+------------------------------+
                                  |
               +------------------+------------------+
               |                                     |
               v                                     v
   +------------------------+            +-------------------------+
   | backend.attacks         |            | backend.tools           |
   |   .injection (engine)   |            |   7 simulated tools     |
   +------------------------+            |   PermissionLevel       |
                                          |   SandboxLedger         |
                                          +------------+------------+
                                                       |
   +----------------------+      +--------------------+-------------+
   | backend.defenses     +----->| backend.agents.react_agent    |
   |   6 mechanisms       |      |   perceive -> decide ->        |
   |   GuardClassifier    |      |   authorise -> execute ->      |
   +----------------------+      |   observe -> record           |
                                 +---------------+---------------+
                                                 |
                         +-----------------------+-------------------+
                         |                       |                   |
                         v                       v                   v
        +-----------------------+  +------------------------+  +--------------+
        | backend.evaluation    |  | backend.agents         |  | backend.models|
        |   .task_eval (utility)|  |   .providers           |  |  enums/errors |
        |   .success  (attack)  |  |   mock/ollama/openai/  |  +--------------+
        |   .runner   (matrix)  |  |   anthropic            |
        +-----------+-----------+  +------------------------+
                    |
                    v
        +------------------------+
        | backend.scoring        |   ASR, utility, detection, SWRS
        +-----------+------------+
                    |
                    v
        +------------------------+        +--------------------------+
        | backend.database       |------->| backend.api (FastAPI)    |
        |   models / repository  |        | dashboard (Streamlit)   |
        |   session / migrations |        | scripts (CLI)           |
        +-----------+------------+        +--------------------------+
                    |
                    v
        +------------------------+
        | backend.services       |   reporting (CSV/JSON/MD), logging
        +------------------------+
```

## 3. Data flow of a single run

```
1. build_plan        resolve (task, attack) matrix; skip incompatible cells
2. baseline run      agent -> tools -> clean outputs -> utility scored
3. attacked run      agent -> tools -> INJECTED output -> defense -> utility + attack verdict
4. persist           experiment, attack_runs, tool_calls, agent_responses,
                     authorization_events, sandbox_effects, metrics
```

For the attacked run specifically:

```
tool.run()
   │
   ├─ InjectionEngine.inject(clean, attack, seed)   ← only for the first eligible output
   │     sets result.meta["injection"] = {...}      (provenance, never spoofed by payload)
   │
   ├─ Defense.on_tool_result(result, ctx)           ← 6 independent mechanisms
   │     returns DefenseOutcome{result, modified, blocked, notes, verdict}
   │
   ├─ perceive(observed, channel)                   ← what the agent actually saw
   │     delta vs. clean baseline → data_markers / trusted_reminders
   │
   └─ message appended to transcript with channel="untrusted"
```

The next reasoning step receives that message. That is the *only* path by which an attack can
influence the agent, which is what makes the defense comparison meaningful: sanitization and the
guard classifier delete the payload, spotlighting and sandwich prompting only mark it, and
privilege separation does not change what the agent sees at all — it changes what the agent can
*do*.

## 4. Trust model

| Domain | Examples | Enforced by |
|---|---|---|
| TRUSTED | system prompt, security policy, user task, task action policy | `ReActAgent.SYSTEM_PREAMBLE`, `TaskDefinition.allowed_actions` |
| UNTRUSTED | web pages, e-mail, files, calendar, database cells, interpreter output | `ToolResult.is_untrusted`, `InjectionEngine` refusal, `Defense` pipeline |

Trust is represented explicitly in code, not by convention:

- `ToolResult.is_untrusted` defaults to `True` and every `BaseTool.run` stamps it.
- `InjectionEngine.inject` raises `InjectionError` on a trusted result.
- Defenses always return `is_untrusted=True`.
- `Message.channel` records which domain a turn came from; the evaluator can tell "the model read
  hostile data" from "the model was told".

## 5. Package responsibilities

| Package | Public surface | Does **not** do |
|---|---|---|
| `backend.models` | enums, task schema, typed exceptions | I/O, evaluation |
| `backend.tools` | `ToolRegistry`, `BaseTool`, `SandboxLedger` | model calls, scoring |
| `backend.attacks` | corpus models, loader, injection engine | persistence |
| `backend.defenses` | `Defense`, 6 implementations, guard classifier | persistence, agent control |
| `backend.agents` | provider abstraction, agent loop | persistence, scoring |
| `backend.evaluation` | utility, attack success, runner | HTTP, rendering |
| `backend.scoring` | pure metric functions | I/O, SQL |
| `backend.database` | ORM, repository, migrations | HTTP, rendering |
| `backend.services` | config, logging, reporting | HTTP, rendering |
| `backend.api` | FastAPI routes only | business logic |

## 6. Security boundaries (Module 28)

| Boundary | Enforcement |
|---|---|
| No host commands | no `subprocess`, `os.system`, `eval` of untrusted input anywhere |
| No real credentials | credentials only from env vars; a unit test scans the tree for literals |
| No real files | `FileReaderTool` reads a dict; writes/deletes append to the ledger only |
| No real e-mail | `EmailTool.send_email` appends to the ledger and returns "nothing was transmitted" |
| No real DB | `DatabaseTool` runs a restricted `SELECT` parser over in-memory rows |
| No network | no HTTP client in any tool; `OllamaProvider` is the only network caller and it is opt-in |
| Code interpreter | fixed builtin allow-list, AST screen, no imports, no dunder access, no attribute access, exponent cap, node budget |
| External targets | reserved `.invalid` / `.test` domains only |
| DB schema | no `api_key`, `password` or `token` column exists (enforced by a schema test) |
| Logs | `redact()` strips anything key-shaped before it reaches a sink |

## 7. Reproducibility (Module 16)

```
seed(run, repetition) = blake2b(base_seed | task | attack | defense | condition | repetition) >> 1
```

- BLAKE2b, never Python's randomised `hash` (a unit test asserts the value matches a subprocess).
- The experiment row stores the full request, the settings snapshot, corpus versions and the
  provenance note; `reproduce(uid)` re-executes exactly that.
- `run_uid` values are random so that repeating an experiment never collides; reproducibility comes
  from the seed, which is stored per run.
- The injection engine is pure: `(result, attack, seed)` -> identical bytes.

## 8. Extension points

| To add... | Do this |
|---|---|
| an attack | append a record in `scripts/build_corpus.py`, run `python -m scripts.build_corpus` |
| a task | add a `TaskDefinition` to `corpus/tasks/tasks.json` |
| a tool | subclass `BaseTool`, register it in `TOOL_FACTORIES`, declare its channel |
| a defense | subclass `Defense`, register it in `DEFENSE_REGISTRY` and `DEFENSE_ORDER` |
| a metric | add a pure function in `backend/scoring/metrics.py` and test it |
| a model | subclass `LLMProvider` and register it in `backend/agents/llm.py` |