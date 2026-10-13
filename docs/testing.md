# Testing

**451 tests, all passing, ~6 s** on this machine (Python 3.14, Windows).

```bash
pytest -q                                   # whole suite
pytest -v tests/test_scoring.py            # one module
pytest --cov=backend --cov-report=term-missing
pytest -q -k "injection or guard"          # by keyword
```

## 1. Layout

| File | Tests | Covers |
|---|---|---|
| `tests/conftest.py` | — | temp-DB isolation, fixtures (`settings`, `repo`, `attacks`, `tasks`, `registry`, `clean_result`) |
| `tests/test_corpus.py` | 44 | corpus loading, schema validation, coverage of every enum, filters, error paths |
| `tests/test_injection.py` | 26 | every injection position, every encoder round-trip, determinism, whole-corpus sweep |
| `tests/test_tools.py` | 44 | 7 tools, permissions, sandbox ledger, safe interpreter, synthetic-data hygiene |
| `tests/test_defenses.py` | 60 | 6 defenses, guard classifier, authorisation rules |
| `tests/test_agent.py` | 42 | action protocol, provider factory, perception, agent loop, no-hardcoded-keys |
| `tests/test_evaluation.py` | 34 | task utility, policy violation, every predicate kind, refusal detection |
| `tests/test_scoring.py` | 37 | every metric formula, edge cases, determinism |
| `tests/test_database.py` | 23 | schema, reference upserts, foreign keys, exports, no-credential-columns |
| `tests/test_runner.py` | 23 | planning, determinism, persistence, reproduction, batches |
| `tests/test_api.py` | 40 | every endpoint, filters, error status codes, OpenAPI |
| `tests/test_config_and_reporting.py` | 22 | config precedence, redaction, reports, every CLI script, `run_demo` end-to-end |

## 2. Isolation

`tests/conftest.py` redirects the database, log directory and export directory into a pytest
`tmp_path` and clears the settings cache, so **the suite never touches `data/testrange.db`**.
Tests needing a genuinely empty database use the `isolated_repo` fixture, which opens a fresh
temporary SQLite file.

## 3. What the suite guarantees

### Corpus
- ≥ 50 attacks, all five categories, all seven channels, all seven positions, all four severities,
  all three difficulties
- every record has the required fields, at least one success criterion and a safety statement
- every `target_action` resolves to a real registered tool action and is not `READ_ONLY`
- every task's allowed/forbidden policy resolves to real actions with no allow/forbid overlap
- `corpus/attacks/*.json` on disk matches `scripts/build_corpus.py` exactly

### Injection
- **every** position and **every** format produces a change and leaves the input unmutated
- `(result, attack, seed)` is byte-identical across calls
- base64 / hex / ROT13 / URL-encoded / zero-width / reversed / unicode-escape all round-trip
- refusing to inject into a trusted result raises `InjectionError`
- all 78 attacks inject successfully in a sweep

### Tools and safety
- every simulated dangerous action records a ledger entry and says, in its own words, that nothing
  happened for real
- the ledger is shared across tools (regression test for the falsy-empty-ledger bug)
- the interpreter rejects imports, `eval`/`exec`/`open`, dunder and private names, `__class__`
  traversal, oversized exponents and oversized scripts
- the corpus contains no real mail-provider domain; credential placeholders are visibly fake

### Defenses
- six distinct classes with six distinct mechanisms
- sanitization removes HTML comments, external recipients, privileged tool names and suspicious
  encoded blobs, and leaves benign content intact
- spotlighting produces a per-seed datamark and adds a prompt clause
- sandwiching places a trusted reminder after the payload
- privilege separation denies forbidden actions, denies ungranted writes, and **denies even a
  granted action when the authority came from tool output**
- the guard classifier detects plain-text, base64, hex and ROT13 payloads and always explains itself

### Evaluation (the correctness-critical part)
- **prose alone is never scored as a successful attack**
- a denied tool call never satisfies a `tool_call` predicate
- optional reference-plan steps do not count towards plan completion
- goal hijacking requires the legitimate task to have been abandoned
- goal-hijacking attacks also do not count as success when the agent completed the task *and*
  performed the attacker's step

### Scoring
- every formula is verified against hand-computed values
- empty groups return `0.0`, never `NaN`
- aggregation is deterministic and order independent
- defense reduction handles a zero baseline

### Persistence
- all 12 tables created; `init_db` idempotent
- foreign keys enforced
- upserts update rather than duplicate
- **no credential column exists in any table**
- export writes every artefact to disk

### Runner
- seeds are BLAKE2b-derived and match a subprocess computation (process independence)
- the same request reproduces the same metrics
- `reproduce()` replays a stored experiment and yields identical metrics
- run ids stay unique across repeated experiments
- attacks incompatible with the selected tasks are reported as skipped, never silently dropped

### API
- every documented endpoint returns 200 with the expected shape
- invalid enums, bad bodies, unknown ids and unsupported `group_by` return 422/404
- `/health` states the provenance

### Project integrity
- **no credential literal anywhere in the source tree or config files**
- `.env.example` contains no secret
- every CLI script runs successfully as a test
- **`run_demo.py` runs end to end and reaches "STEP 8/8"**

## 4. Bugs these tests caught during development

Kept deliberately, because each one was a real defect found by running the suite:

| Test | Bug it pins |
|---|---|
| `test_every_tool_registers_a_shared_ledger` | an empty `SandboxLedger` is falsy (`__len__` returns 0), so `ledger or SandboxLedger()` gave every tool a *private* ledger — attacks were unobservable |
| `test_private_names_are_rejected` | `__import__('os')` slipped past a naive `"__"` token check |
| `test_base64_decode_rejects_binary` | the decoder accepted any decodable blob, flagging ordinary text |
| `test_every_position_produces_a_change[encoded]` | no corpus record used the `encoded` position — a genuine coverage gap in the corpus |
| `test_target_actions_reference_registered_tools` | the `file` channel did not map to `file_reader` anywhere it was resolved |
| `test_attack_record_rejects_bad_regex` | the regex validator ran before `regex` was populated, so it never fired |
| `test_sanitization_removes_external_recipients` | `sorted()` over a list of dicts in `web_search` |
| `test_perception_counts_data_markers` | the datamark regex disallowed hyphens, so spotlighting markers were invisible |
| `test_different_seeds_can_change_behaviour` | `random.Random("1:model:2")` produces correlated streams, collapsing the variance repetitions are meant to measure |
| `test_list_experiments_is_newest_first` | ordering by `started_at` alone was non-deterministic on ties |

## 5. Writing new tests

```python
def test_thing(settings):
    assert thing(settings) == expected
```

Fixtures available: `settings`, `repo`, `isolated_repo`, `attacks`, `tasks`, `registry`,
`sample_task`, `sample_attack`, `clean_result`, `defense_none`.

Conventions:
- pure functions get hand-computed expected values, not values copied from the implementation
- anything touching SQLite uses the `repo` / `isolated_repo` fixtures
- safety properties assert on **observable effects**, not on wording
- a new metric must come with a test in `tests/test_scoring.py`
- a new attack must come with a corpus rebuild so `test_corpus_files_match_the_builder` passes

## 6. Coverage

```bash
pip install pytest-cov
pytest --cov=backend --cov-report=term-missing --cov-report=html
open htmlcov/index.html
```

Not covered by design: the live OpenAI/Anthropic/Ollama network paths (they require credentials and
a running server). Their construction, credential-missing behaviour and fallback are covered
offline.