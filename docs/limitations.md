# Limitations

Stated plainly, because a security benchmark that overstates its own evidence is worse than
useless.

---

## 1. The headline numbers are simulations

With the default `app.demo_mode: true`, **every result is produced by a deterministic victim
model** in `backend/agents/providers/mock.py`, not by a language model. Those results measure
*this framework's ability to distinguish experimental conditions*. They are **not** evidence that
any real model is, or is not, robust to indirect prompt injection.

Every simulation result is labelled:

- `experiments.is_simulation = 1`
- `experiments.provenance_note = "SIMULATED / DEMO RESULT - produced by the deterministic mock provider, not a real language model."`
- a yellow **DEMO MODE** banner in the dashboard sidebar
- `result_provenance` in `/health`, `/reports/summary`, `summary.json` and `report.md`

To obtain statements about a real model, set `demo_mode: false` and supply credentials.

## 2. The victim model's parameters are declared priors, not measurements

The mock agent complies with an injected directive with probability

```
p = vulnerability            (archetype prior: 0.86 / 0.55 / 0.18 / 0.92)
  x position_factor          (hand-set: end 1.15 ... html_comment 0.85)
  x format_factor            (hand-set: visible 1.00 ... reversed 0.70)
  x difficulty_factor        (easy 1.00, medium 0.82, hard 0.58)
  x obfuscation_factor       (the archetype's decoding ability)
  x signal_factor            (data marking 0.45, sandwich reminder 0.62)
  x strength_factor          (0.55 + 0.45 x perceived directive strength)
  x jitter                   (seeded uniform in [0.92, 1.08])
```

**Every factor was chosen a priori from the mechanism being modelled.** None was fitted to
observations of real models. The factors are documented in
`backend/agents/providers/mock.py` and `docs/limitations.md` §2 precisely so that nobody mistakes
them for empirical constants. A calibrated model — factors fitted to real-model behaviour — is the
single most valuable extension of this project.

## 3. Severity labels are a judgement, not a measurement

`low` / `medium` / `high` / `critical` are declared per record by the corpus author, describing the
target capability. The Severity-Weighted Risk Score then converts them to 1/2/3/4. The weights are
a **project convention**, published in `configs/default.yaml` so any result can be recomputed under
a different weighting. SWRS inherits all of the subjectivity of the labels.

## 4. The guard classifier is a baseline, not a detector

`backend/defenses/guard_classifier.py` is a transparent rule system with ~30 weighted indicators
and an encoding-peeling step. It is:

- **not** a trained classifier,
- **not** claimed to be state-of-the-art,
- **not** calibrated (no ROC/PR curve, no measured FPR/FNR).

It exists so the *guard-classifier defense* can be demonstrated and compared without downloading a
model. Its main value in this project is explainability: every verdict lists its indicators.

## 5. Ten tasks and one synthetic world are small

AgentDojo-style benchmarks use far larger task suites and tool sets. Here:

- 10 tasks, all read-only, all solvable in 1–3 tool calls,
- one synthetic company, one set of synthetic documents,
- single-turn episodes only — no multi-turn conversations and no persistent memory,
- no tool that itself calls another tool.

Because every task is read-only, `privilege_separation` drives ASR to a mechanical `0.000`: the
attacker targets actions the task never authorises. A task suite containing legitimately
state-changing steps would produce a very different — and more informative — result.

## 6. Defense utility cost is NOT measured

In the recorded full-corpus run, **Benign Utility was 1.000 for every defense**. That means this
range currently shows *no* cost for sanitization, even though sanitization is lossy by design and
will redact benign text containing a trigger phrase.

Consequences:

- the ASR reduction attributed to sanitization may be partly **over-credited** (some "reduction" is
  damage to legitimate content that this utility function is too coarse to notice);
- false positives are invisible.

Fixing this requires per-criterion utility with a false-positive set (benign text that *looks*
like an injection) and a precision/recall report for each defense. This is a **known gap**, not a
silent omission.

## 7. The agent is given a reference plan

Tasks carry a `reference_plan`, which the system prompt offers as a trusted suggestion. This makes
the benign task easy and the measurement focused on robustness rather than planning — but it means
**utility numbers are not comparable to benchmarks that require open-ended planning**. A plan
abandonment is also easy for an attacker to cause, which inflates `task_abandoned` detection.

## 8. Action protocol rather than native tool calling

Providers are asked for one JSON object per step instead of using native function-calling. This
keeps the four providers uniform and the parser testable, but it is **not** how a well-integrated
agent is normally built, and some models follow a strict JSON action format more or less reliably
than they use native tools. Malformed responses are counted as `provider_error` rather than
silently dropped, but they still reduce the measured utility.

## 9. Detection rate is generous

`detect_refusal` counts a run as detected when the agent refuses in prose, narrates the refusal in
its reasoning, when a defense redacted or blocked the payload, **or** when any authorisation was
denied. The last criterion is generous: a denial caused by an unrelated policy can inflate RDR.
The per-run `detection_reason` string is stored so each detection can be audited.

## 10. Defense comparisons are within-simulator

Because the mock agent perceives exactly what the defense left in the content, defenses that
*delete* the payload trivially achieve low ASR. This is the correct causal behaviour of the
simulator, but it means the comparison is between mechanisms as much as between defenses. A real
model may resist an explicit payload that the regex missed, and may comply with one the regex
removed but that it could have reasoned about.

## 11. Reproducibility is per-configuration, not across environments

Seeds are derived with BLAKE2b, which is stable across processes and platforms. However, the mock
provider's draw sequence depends on the CPython `random` implementation. Pinning
`PYTHONHASHSEED` is unnecessary (no use of `hash()`), but a CPython major version that changes
`random` would shift the exact sampled outcomes. Recorded metrics remain valid as *what was
measured*; replaying them bit-for-bit requires a compatible interpreter.

## 12. Not a production authorisation system

`PrivilegeSeparationDefense` is a **reference policy for the simulated tools in this project**. It
demonstrates the invariant "untrusted content must not confer capability". It is not a
general-purpose capability system and must not be used as one.

## 13. Scope exclusions

Not implemented, and out of scope for a final-year project at this scale:

- multi-agent systems and inter-agent trust,
- multimodal attacks (images, audio, video),
- adaptive adversaries that learn the defense,
- longitudinal measurements or regression against corpus versions,
- statistical reporting (confidence intervals) — currently point estimates with raw counts shown
  alongside so the reader can judge noise.

## 14. Relationship to prior work — precise framing

Conceptually aligned with published work on indirect prompt injection, agent-security benchmarks
(AgentDojo, InjecAgent-style evaluation), data-marking / spotlighting prompts, and the OWASP LLM
Top-10 prompt-injection risks. **No code or text is copied from any paper**; those works are used as
conceptual references only.

| | Status |
|---|---|
| IPI as a threat model | **existing** |
| Agent-security benchmark harnesses | **existing** |
| Spotlighting / data marking as a defense family | **existing** |
| OWASP prompt-injection guidance | **existing** |
| **This project's contribution** | the *integrated framework*: scored categorized corpus + controlled simulated tool sandbox + deterministic injection engine + reproducible runner + standardised behaviour-based scoring + defense comparison + SQLite experiment history + visual dashboard |

The claim this project makes is therefore **integration and standardisation**, not novelty. Where
this project does go beyond a single cited work is in combining severity-weighted risk scoring with
behaviour-only attack-success predicates and a permission audit trail in one reproducible harness —
but that is a contribution to the *tooling*, not to the underlying science, and no experimental
evidence here supports a stronger claim.

## 15. What would make the results trustworthy

1. Run the identical harness against 3+ real models with `demo_mode: false`.
2. Calibrate the victim model against those observations, then re-measure.
3. Add a false-positive suite so defense utility cost is visible.
4. Extend the task suite with legitimately state-changing tasks, then re-evaluate privilege
   separation.
5. Add tasks that declare multiple valid channels, then report confidence intervals.
6. Report per-predicate breakdowns, not only aggregate ASR, so partial compliance is visible.