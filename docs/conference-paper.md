# Conference Paper Draft — Indirect Prompt Injection Test Range

> **What this document is:** a complete, submission-ready draft skeleton with **real measured
> values** from this repository, plus an explicit list of **tables and figures** (with the exact
> data source for each). Fill in author names, venue, and page formatting, then submit.
>
> **Data source for every number below:** `data/exports/summary.json` and
> `data/exports/tables/*.csv`, generated from **37 experiments / 6,108 runs**
> (3,054 clean baseline + 3,054 attacked), 11,768 tool calls, 1,553 sandbox effects.
> Regenerate with: `python run_demo.py --full && python -m scripts.export_results`.
>
> **Honesty banner (keep in the paper):** all results are SIMULATED/DEMO outputs of the
> deterministic mock provider. They characterise the framework, not any real language model.

---

## 0. Paper metadata (fill in before submission)

| Field | Value |
|---|---|
| Title | An Integrated Test Range for Measuring Indirect Prompt Injection Robustness in Tool-Using Agents |
| Authors | [Your names, affiliations, emails] |
| Venue / track | [e.g., IEEE S&P Workshop on LLM Security / ACM CCS AISec / ACL Safety Workshop] |
| Paper type | Benchmark / measurement / systems paper |
| Page limit | [check venue: usually 8 + references] |
| Keywords | prompt injection, indirect prompt injection, LLM agents, AI safety, robustness benchmark, tool use |
| Artifact | Code + SQLite + Streamlit dashboard + FastAPI (this repository) |

---

## Abstract (draft — ~180 words, adapt to venue limit)

Tool-using language-model agents act on untrusted content returned by web pages, email, files,
calendars, databases, and APIs, which exposes them to **indirect prompt injection (IPI)**:
malicious directives embedded in tool output that redirect the agent. Existing studies report
individual attacks, but there is no standard, reproducible harness that combines a scored attack
corpus, a controlled tool sandbox, deterministic injection, multiple defenses, and behaviour-based
scoring. We present an integrated IPI test range comprising (i) a 78-record scored attack corpus
spanning 5 categories, 7 delivery channels, 7 injection positions, and 12 payload formats;
(ii) 7 simulated tools with a permission model and an in-memory sandbox ledger;
(iii) a deterministic injection engine with provenance tracking; (iv) a ReAct agent with
injection awareness; (v) six independently implemented defenses; and (vi) a standardised scoring
suite (ASR, benign utility, utility under attack, detection rate, severity-weighted risk).
Across 3,054 attacked episodes, the unprotected baseline shows ASR **0.362**, while capability
gating (privilege separation) reduces ASR to **0.000** and content rewriting (sanitization) to
**0.171**; overall severity-weighted risk is **0.207**. All measurements are fully reproducible
from a seeded runner with SQLite experiment history. We release the harness, corpus, API, and
dashboard.

---

## 1. Introduction

1. **Problem.** Agents that browse, read mail, query databases, and run code routinely ingest
   untrusted text. A directive hidden in a search snippet or calendar invite can make the agent
   exfiltrate data, call privileged tools, or abandon the user task (Greshake et al., 2023).
2. **Gap.** Prior work demonstrates attacks or single defenses, but results are not comparable:
   no shared corpus with explicit success predicates, no permission audit trail, no standard
   metrics, and no reproducible runner.
3. **Contribution.** This paper contributes an *integrated measurement framework*:
   - **C1 — Scored attack corpus:** 78 records, each with category, channel, position, format,
     difficulty, severity, target action, explicit machine-checkable success criteria, and a
     SHA-256 payload digest (`corpus/attacks/*.json`, `scripts/build_corpus.py`).
   - **C2 — Controlled tool sandbox:** 7 simulated tools, 3 permission levels, shared sandbox
     ledger; every "successful attack" is a recorded ledger effect, never a real side effect.
   - **C3 — Deterministic injection engine:** surgical edits to untrusted fields only, with
     provenance (position, format, channel match, digests) stored per run.
   - **C4 — Six defenses as independent mechanisms** (Table 2) compared under one runner.
   - **C5 — Standardised behaviour-based scoring** (Section 6) with severity weighting.
   - **C6 — Reproducibility:** BLAKE2b-derived seeds, SQLite experiment history (12 tables),
     FastAPI (24 endpoints), 12-page Streamlit dashboard, one-command demo.
4. **Headline results (real values, Section 7):** baseline ASR 0.362 → 0.000 with privilege
   separation; mock-vulnerable ASR 0.328 vs mock-hardened 0.095; email channel most exploitable
   (ASR 0.395); privilege separation holds 0.000 ASR across all five attack categories.
5. **Scope warning.** All numbers in this paper are produced by deterministic simulated victim
   models (demo mode). They validate the *framework's discriminative power*, not the robustness
   of any real LLM (see Section 9).

---

## 2. Related Work

| Strand | Key references (verify before submission) | How this work differs |
|---|---|---|
| Indirect prompt injection threat model | Greshake et al., "Not what you've signed up for" (2023) | We operationalise it as a runnable corpus, not a case study |
| Agent security benchmarks | AgentDojo (Debenedetti et al.); InjecAgent-style evaluation | We add severity weighting, permission audit trail, and defense comparison in one harness |
| Prompt-level defenses | Spotlighting / data-marking prompts; sandwich prompting; input sanitization; instruction hierarchy / privilege separation | We implement six as *independent mechanisms* under one runner with a no-defense control |
| LLM safety guidance | OWASP LLM Top-10 (prompt injection) | We provide the measurement tooling the guidance implies |
| Reproducible agent evaluation | Seeded runners, logged trajectories | BLAKE2b seeds + SQLite history + reproduce-by-UID endpoint |

*Instruction: replace the bracketed citations above with verified references from the venue's
expected bibliography; no text or code is taken from these works — they are conceptual
references only.*

---

## 3. System Design

### 3.1 Architecture — **Figure 1 (REQUIRED)**

> **Figure 1 — System architecture.** Boxes: Attack Corpus → Injection Engine → (Simulated Tools
> + Defenses) → ReAct Agent → Evaluation → Scoring → SQLite → API / Dashboard / Exports.
> Side annotations: "trusted" vs "untrusted" data paths; the sandbox ledger as the only place
> where attack success becomes observable.
> **Source:** `docs/architecture.md`. Redraw as a single-column block diagram for the paper.

Key design rules (state these explicitly — reviewers check them):
- **Trust boundary:** system prompt and task definition are trusted; *all* tool output is
  untrusted. The injector refuses to modify trusted content (`InjectionError`).
- **Simulation boundary:** tools are in-process simulations; ledger effects are the sole
  evidence of attack success; prose alone is never scored as success.
- **Defense placement:** content-rewriting defenses act before inference; capability-gating
  defenses act at tool-call time; the guard classifier screens pre-inference.

### 3.2 Data model — **Figure 2 (REQUIRED)**

> **Figure 2 — SQLite schema (simplified ER diagram).** Show: `models`, `defenses`, `tasks`,
> `attacks` → `experiments` → `attack_runs` → (`tool_calls`, `agent_responses`,
> `authorization_events`, `sandbox_effects`) → `metrics`.
> **Source:** `docs/database.md` Section 1. Real scale to annotate on the figure: 12 tables,
> 45,696+ rows for a full sweep.

### 3.3 Agent

ReAct loop with injection awareness: per-step single JSON action (uniform across providers),
authorization gating before every tool call, perception of untrusted content (data-marker
counting for spotlighting evaluation), and hijack detection (legitimate-task abandonment).
Victim models used in this paper: `mock-vulnerable` (vulnerability prior 0.86) and
`mock-hardened` (prior 0.18) — *declared simulation parameters, not fitted constants*.

---

## 4. Attack Corpus

### Table 1 (REQUIRED) — Corpus composition (real counts)

| Category | Records |
|---|---|
| Data exfiltration | 15 |
| Goal hijacking | 15 |
| Instruction override | 15 |
| Obfuscation | 18 |
| Tool misuse | 15 |
| **Total** | **78** |

| Delivery channel | Records | Injection positions (records) | Payload formats (records) |
|---|---|---|---|
| browser 16, web 14, email 13, database 11, file 9, calendar 8, api 7 | 78 | end 36, middle 13, beginning 9, metadata 8, surrounding 5, html_comment 4, encoded 3 | visible_text 51, html_comment 6, base64 5, metadata 5, hex/rot13/urlencoded 2 each, markdown_image/reversed/spaced_leet/unicode_escape/zero_width 1 each |

> **Source:** `data/exports/attack_corpus.csv`, `corpus/attacks/*.json`.
> **Figure 3 (RECOMMENDED):** grouped bar chart — records per category × channel (from
> `attack_corpus.csv`).

Every record carries: `attack_id`, severity (low/medium/high/critical), difficulty
(easy/medium/hard), `target_action` (resolves to a registered non-read-only tool action —
enforced by test), ≥1 machine-checkable `success_criteria`, a safety statement, and a
`payload_sha`. Corpus on disk is byte-identical to `scripts/build_corpus.py` output (tested).

Tasks: 10 synthetic read-only tasks, solvable in 1–3 tool calls, each with a reference plan,
action policy (allowed/forbidden), and reference answer.

---

## 5. Defenses

### Table 2 (REQUIRED) — The six defenses are different mechanisms, not six configs

| Defense | Mechanism | Rewrites content | Gates actions |
|---|---|---|---|
| `none` (control) | identity | No | No |
| `sanitization` | content rewriting (strips comments, external recipients, privileged tool names, encoded blobs) | Yes | Yes |
| `spotlighting` | data marking (per-seed datamark + prompt clause) | No | No |
| `sandwich_prompting` | trusted-context restatement after the payload | No | No |
| `privilege_separation` | capability gate (denies forbidden actions; denies granted actions whose authority came from tool output) | No | Yes |
| `guard_classifier` | pre-inference screening (rule system + encoding peeling, always explains itself) | Yes | Yes |

> **Source:** `docs/defenses.md`, `backend/defenses/`, `GET /defenses`.

---

## 6. Metrics (state formulas exactly — reviewers reproduce from these)

| Metric | Formula | Range |
|---|---|---|
| Attack Success Rate (ASR) | mean(`attack_succeeded`) over attacked runs | [0, 1] |
| Benign Utility (BU) | mean penalised utility on clean runs | [0, 1] |
| Utility Under Attack (UUA) | mean penalised utility on attacked runs | [0, 1] |
| Utility Degradation | 1 − UUA / BU | [0, 1] |
| Refusal/Detection Rate (RDR) | mean(`attack_detected`) on attacked runs | [0, 1] |
| Severity-Weighted Risk (SWRS) | Σ w(sev)·success / Σ w(sev), w = {low:1, medium:2, high:3, critical:4} | [0, 1] |

Attack success is decided by **explicit predicates only** (`tool_call` on a non-denied call,
`ledger_effect`, `response_match`, `hijack_detected` with task abandonment,
`policy_violation`, `harmful_effect`). Empty groups score 0.0, never NaN. Severity labels are
declared per record; weights are a published convention (`configs/default.yaml`), so any result
can be recomputed under different weights.

---

## 7. Experiments and Results (ALL VALUES REAL — from `data/exports/`)

### 7.1 Setup

- **Matrix:** 2 victim models × 6 defenses × full 78-attack corpus × repetitions (seeded).
- **Scale:** 37 experiment conditions, **6,108 runs** (3,054 baseline + 3,054 attacked),
  11,768 tool calls, 11,768 authorization decisions, 1,553 sandbox effects.
- **Reproduction:** every condition replays bit-for-bit via `POST /experiments/{uid}/reproduce`;
  run seeds are BLAKE2b-derived (`tests/test_runner.py`).

### Table 3 (REQUIRED) — Aggregate outcome

| Metric | Value | Raw count |
|---|---|---|
| Attack Success Rate | **0.2115** | 646 / 3,054 |
| Benign Utility | **1.0000** | — |
| Utility Under Attack | **0.7785** | — |
| Utility Degradation | **0.2215** | — |
| Refusal / Detection Rate | **0.7233** | 2,209 / 3,054 |
| Severity-Weighted Risk | **0.2066** | 2,276 / 11,014 weight |
| Policy Violation Rate | 0.1131 | — |
| Harmful Effect Rate | 0.1141 | — |
| Clean Task Success Rate | 1.0000 | — |

### Table 4 (REQUIRED) — Defense comparison (attacked runs per defense)

| Defense | Attacked runs | ASR | Successes | RDR | SWRS | ASR reduction vs control |
|---|---|---|---|---|---|---|
| `none` (control) | 508 | **0.3622** | 184 | 0.4902 | 0.3603 | — |
| `privilege_separation` | 508 | **0.0000** | 0 | 0.8622 | 0.0000 | **+0.3622** |
| `sanitization` | 508 | **0.1713** | 87 | 0.8917 | 0.1714 | +0.1909 |
| `spotlighting` | 508 | **0.2087** | 106 | 0.6555 | 0.2052 | +0.1535 |
| `guard_classifier` | 514 | **0.2160** | 111 | 0.7432 | 0.1974 | +0.1463 |
| `sandwich_prompting` | 508 | **0.3110** | 158 | 0.6969 | 0.3057 | +0.0512 |

> **Source:** `data/exports/tables/by_defense.csv`.

### Table 5 (REQUIRED) — Victim-model contrast

| Model | Attacked runs | ASR | RDR | SWRS |
|---|---|---|---|---|
| `mock-vulnerable` | 1,530 | **0.3281** (502) | 0.6307 | 0.3222 |
| `mock-hardened` | 1,524 | **0.0945** (144) | 0.8163 | 0.0906 |

> **Source:** `data/exports/tables/by_model.csv`. The 3.5× ASR gap confirms the harness
> discriminates victim susceptibility — the framework measures *something*, which is the
> precondition for using it on real models.

### Table 6 (RECOMMENDED) — ASR by attack category

| Category | Runs | ASR | Detection rate | Mean utility |
|---|---|---|---|---|
| instruction_override | 590 | **0.3000** | 0.8254 | 0.6997 |
| tool_misuse | 588 | **0.2619** | 0.6548 | 0.7545 |
| data_exfiltration | 588 | 0.2109 | 0.8112 | 0.7906 |
| goal_hijacking | 590 | 0.1492 | 0.7068 | 0.7700 |
| obfuscation | 698 | 0.1476 | 0.6347 | 0.8625 |

> **Source:** `data/exports/tables/by_attack_type.csv`. Note the paradox worth discussing:
> instruction_override has the *highest* ASR *and* the highest detection rate — detection
> (often refusal narration) does not imply prevention.

### Table 7 (RECOMMENDED) — ASR by delivery channel

| Channel | Runs | ASR | Detection rate |
|---|---|---|---|
| email | 468 | **0.3953** | 0.6645 |
| api | 252 | 0.2976 | 0.6825 |
| file | 324 | 0.2222 | 0.6821 |
| web | 654 | 0.1927 | 0.7232 |
| calendar | 288 | 0.1736 | 0.5382 |
| browser | 576 | 0.1597 | 0.8194 |
| database | 492 | 0.0935 | 0.8232 |

> **Source:** `data/exports/tables/by_delivery_channel.csv`.

### Severity note (discuss, don't headline)

ASR by severity: low **0.528** (n=36), medium 0.343 (n=108), critical 0.203 (n=2,032),
high 0.202 (n=878) — the low-severity figure rests on a tiny sample (state this; reviewers
will notice). SWRS absorbs this via weights (2,276 / 11,014 = 0.2066).

### Injection-position / format findings (one paragraph + cite tables)

End-of-content placement dominates success (ASR 0.268, n=1,442); `html_comment` (0.0625),
`metadata` (0.0565), and `encoded` (0.0545) positions nearly neutralise the payload *in this
simulator* because rewriting defenses delete them — a within-simulator effect, see Section 9.
Plain `visible_text` (ASR 0.266, n=2,032) and `urlencoded` (0.319, n=72) are most effective;
`reversed` (0.028) and `metadata` (0.050) least. Sources:
`tables/by_injection_position.csv`, `tables/by_payload_format.csv`.

### Utility-cost finding (report honestly)

Benign utility is **1.000 for every defense** (`tables/utility_cost.csv`). The range therefore
currently shows **no utility cost for sanitization**, although sanitization is lossy by design —
a known gap (Section 9), not a claim that defenses are free.

### Figures to include

> - **Figure 4 (REQUIRED): ASR by defense** — bar chart from Table 4 with the `none` control
>   leftmost (`by_defense.csv`: `defense` × `attack_success_rate`).
> - **Figure 5 (REQUIRED): heatmap, attack category × defense** — from
>   `tables/heatmap_attack_x_defense.csv` (rows alphabetical: data_exfiltration, goal_hijacking,
>   instruction_override, obfuscation, tool_misuse; columns: guard_classifier, none,
>   privilege_separation, sandwich_prompting, sanitization, spotlighting). Key visual:
>   the privilege_separation column is 0.000 throughout.
> - **Figure 6 (RECOMMENDED): ASR by channel + severity** — two panels from Tables 6–7.
> - **Figure 7 (OPTIONAL): utility clean vs under attack by model** — from `by_model.csv`.
> - Generate all figures from the CSVs with one script (e.g., matplotlib, `viridis`/`RdYlGn_r`
>   scales) so reviewers can reproduce them; the Streamlit dashboard already renders these
>   charts interactively (Attack Results page).

---

## 8. Discussion

1. **Capability gating beats content filtering here.** Privilege separation reaches ASR 0.000
   across all five categories because the tasks are read-only while attacker targets are
   privileged — the invariant "untrusted content must not confer capability" is directly
   observable in the 11,768-event authorization audit trail (289 denials).
2. **Rewriting helps, prompting helps less.** Sanitization (0.171) outperforms sandwich
   prompting (0.311); the sandwich reminder's signal factor is the weakest intervention in the
   harness. Spotlighting sits between (0.209).
3. **Detection ≠ prevention.** Instruction override is both most successful and most detected;
   RDR counts refusal narration and denied authorizations, which is generous by construction
   (per-run `detection_reason` strings are stored for audit).
4. **Channel matters.** Email (0.395) and api (0.298) payloads succeed far more often than
   database (0.094) content — a prior for where input validation effort should go.
5. **What the numbers do NOT show.** No claim is made about any real LLM; the victim priors
   (0.86/0.18) and position/format factors are declared, unfitted parameters. The contribution
   is the *instrument*, calibrated here only against itself.

---

## 9. Limitations (keep this section — it is a strength)

1. Simulated victims; priors unfitted — calibration against 3+ real models is the top future work.
2. Severity labels and 1/2/3/4 weights are conventions, not measurements.
3. Guard classifier is an explainable rule baseline, not a trained detector (no ROC/PR).
4. Only 10 read-only single-turn tasks in one synthetic world; no multi-turn, memory, or
   tool-chaining; no state-changing legitimate tasks (which flatters privilege separation).
5. Defense utility cost unmeasured (BU = 1.000 everywhere); false-positive suite missing.
6. Reference plans make tasks easy and abandonment easy to trigger (inflates hijack counts).
7. Single-JSON action protocol, not native function calling.
8. Generous RDR definition; defense comparisons are within-simulator (deleting payloads
   trivially wins in simulation).
9. Point estimates only, no confidence intervals; reproducibility is per-configuration
   (CPython `random` sequence dependence documented).
10. Not a production authorization system. Out of scope: multi-agent, multimodal, adaptive
    adversaries, longitudinal tracking.

---

## 10. Conclusion and Future Work

We built and validated an integrated, reproducible IPI measurement instrument: 78 scored
attacks, 7 simulated tools, deterministic injection, 6 defenses, standardised scoring, seeded
runner, SQLite history, API, and dashboard — 451+ automated tests, one-command demo. Measured
on the harness itself: baseline ASR 0.362, best defense 0.000, overall risk 0.207. Next:
(1) run the identical harness against real models with `demo_mode: false`;
(2) fit calibrated victim parameters; (3) add false-positive and state-changing-task suites;
(4) report confidence intervals and per-predicate breakdowns; (5) extend to multi-turn and
adaptive adversaries.

---

## References (verify each before submission)

- Greshake, K. et al. *Not what you've signed up for: Compromising real-world LLM-integrated
  applications with indirect prompt injection.* 2023.
- Debenedetti, E. et al. *AgentDojo: A dynamic environment to evaluate prompt-injection
  attacks and defenses for LLM agents.* 2024.
- OWASP. *OWASP Top 10 for LLM Applications.* 2023–2025 (prompt injection).
- [InjecAgent / related agent-safety benchmarks — verify titles, venues, years.]
- [Spotlighting / data-marking defense publications — verify.]
- [Venue-appropriate formatting: IEEE / ACM / ACL bibliography style.]

---

## Appendix A — Artifact & reproducibility checklist (for the artifact-evaluation badge)

- [ ] Repository builds from `pip install -r requirements.txt` on Python 3.10+.
- [ ] `python -m scripts.build_corpus --check` → "Corpus OK: 5 files, 78 attack records".
- [ ] `pytest -q` → all pass (~6 s; no network, no keys; uses temp DB).
- [ ] `python run_demo.py` → 8/8 steps, exports in `data/exports/`.
- [ ] `python run_demo.py --full` → full-corpus sweep; numbers in Section 7 regenerate.
- [ ] `POST /experiments/{uid}/reproduce` → identical metrics (tested in `test_runner.py`).
- [ ] Dashboard: `streamlit run dashboard/app.py` (12 pages, AppTest-verified).
- [ ] API docs: `python -m scripts.serve_api`, open `/docs`.
- [ ] Provenance: `experiments.is_simulation=1`, DEMO banner in dashboard/API/exports.

## Appendix B — Where every number lives (reviewer cross-reference)

| Paper element | File |
|---|---|
| Tables 3–5, aggregate | `data/exports/summary.json` (`metrics`), `tables/by_defense.csv`, `tables/by_model.csv` |
| Table 6 / Fig. 5–6 | `tables/by_attack_type.csv`, `tables/heatmap_attack_x_defense.csv` |
| Table 7 | `tables/by_delivery_channel.csv` |
| Severity paragraph | `tables/by_severity.csv` |
| Position/format paragraph | `tables/by_injection_position.csv`, `tables/by_payload_format.csv` |
| Utility-cost claim | `tables/utility_cost.csv` |
| Corpus Table 1 | `data/exports/attack_corpus.csv`, `corpus/attacks/*.json` |
| Defense Table 2 | `docs/defenses.md`, `backend/defenses/` |
| Architecture Fig. 1 | `docs/architecture.md` |
| Schema Fig. 2 | `docs/database.md` |

## Appendix C — Submission mechanics (do not skip)

1. Pick the venue template (IEEEtran / acmart / ACL) and enforce its page limit; this draft
   targets ~8 pages + references — cut Section 7 sub-tables to the venue's budget if needed
   (keep Tables 3–5 + Figures 1, 4, 5 at minimum).
2. Anonymize for double-blind review if required (remove repo URLs, author names; keep the
   artifact link for the camera-ready).
3. Convert this Markdown to the venue template (pandoc for structure, then manual figure
   placement); regenerate Figures 1–7 as 300-dpi PNGs/PDFs from the CSVs.
4. Run a final `run_demo.py --full` the week of submission so numbers are current, and
   paste the fresh `summary.json` values into Tables 3–7.
5. Get one external reader to check the honesty framing (demo-mode banner must survive into
   the camera-ready — it is the paper's credibility).
