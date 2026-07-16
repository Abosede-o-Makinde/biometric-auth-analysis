# Architecture

## Overview

`biometric-auth-analysis` is a Python package with five logical layers:

```
Input Layer         Parsers (YAML config → SystemConfig; CSV/JSON scores → DataFrame)
Engine Layer        Pure functions: metrics, statistics, bias, attack, GDPR assessment
Model Layer         Pydantic v2 input models; dataclass result models
Output Layer        Console (Rich), JSON, PDF (ReportLab), Streamlit dashboard
CLI Layer           Click subcommands wiring parsers → engines → reporters
```

---

## Module Map

```
biometric_auth/
├── models/
│   ├── config.py       SystemConfig (Pydantic v2, all-Optional)
│   └── results.py      EvaluationResult, BiasResult, AttackResult, GDPRReport (dataclasses)
├── data/
│   └── synthetic.py    Synthetic score generator (fixed seeds, committed CSVs)
├── parsers/
│   ├── score_file.py   CSV/JSON → pd.DataFrame (validated)
│   └── config_parser.py YAML → SystemConfig
├── engine/
│   ├── metrics.py      FAR/FRR/EER/ROC/DET — pure functions
│   ├── statistics.py   Bootstrap CI, DeLong AUC, permutation test, ECE
│   ├── bias.py         DPD/EOD/EqOdds/DIR/calibration — pure functions
│   ├── attack.py       7-vector attack simulation, CVSS-like scoring
│   └── gdpr.py         22 Art.9 checks, 7 obligation clusters, run_art9_assessment()
├── reporters/
│   ├── console.py      Rich terminal output
│   ├── json_rep.py     JSON serialisation
│   └── pdf_rep.py      ReportLab PDF: cover + exec summary + findings + roadmap
├── cli.py              Click CLI — 7 subcommands
└── app.py              Streamlit dashboard — 6 tabs
```

---

## Design Principles

### All-Optional Input Models (Pydantic v2)

`SystemConfig` has no required fields. Every field defaults to `None`. This mirrors the
design of the companion `gdpr-security-mapper` project. The consequence:
- Missing field → `PARTIAL` status (not assessed), never a crash
- This makes the tool safe for partial, in-progress configs
- New fields can be added to `SystemConfig` without breaking existing YAML files

### Pure Engine Functions

Every engine function takes a `pd.DataFrame` or `SystemConfig` and returns a result dataclass.
No global state; no side effects. This makes the engines:
- Trivially testable (no mocking needed)
- Composable (CLI, Streamlit, and notebooks all call the same functions)
- Independently runnable (each notebook cell is self-contained)

### Metric-Linked GDPR Checks

Three GDPR checks receive computed results as inputs:

| Check | Input | Trigger |
|-------|-------|---------|
| A9-022 | EvaluationResult.eer | EER > 10% → GAP (DPIA risk) |
| A9-042 | AttackResult.overall_vulnerability_score | Score > 7.0 → GAP (Art.32) |
| A9-061 | BiasResult.equalised_odds_difference | EqOdds ≥ 0.10 → GAP (discrimination) |

Without the corresponding analysis result, these checks return `PARTIAL` (not assessed).
This ensures the GDPR assessment degrades gracefully when only config is provided.

### Satisfied Threshold Lock

`GDPRReport.satisfied_threshold` is always `0.90`. Biometric data is always Art.9 special
category data — there is no lower-risk mode. The field is present in the dataclass and
`to_dict()` output to make this explicit and auditable.

---

## Data Flow

### CLI `biometric-auth gdpr --config <yaml> --scores <csv>`

```
YAML file ──► config_parser.load_config() ──► SystemConfig
CSV file  ──► score_file.load_scores()    ──► pd.DataFrame
                                               │
                                    ┌──────────┼──────────┐
                                    ▼          ▼          ▼
                           metrics.run_evaluation()    bias.run_bias_analysis()
                           attack.run_attack_simulation()
                                    │
                                    ▼
                           gdpr.run_art9_assessment()
                                    │
                           ┌────────┼────────┐
                           ▼        ▼        ▼
                        console   JSON     PDF
```

### Streamlit Dashboard

Identical engine calls, driven by Streamlit file uploaders or the demo data loader.
Results are cached in `st.session_state` to avoid recomputation on tab switches.

---

## Test Architecture

```
tests/
├── conftest.py          Session-scoped fixtures (pre-generated scores, compliant/non-compliant configs)
├── test_metrics.py      Unit tests for metrics engine
├── test_statistics.py   Unit tests for statistical methods
├── test_bias.py         Unit tests for bias engine
├── test_attack.py       Unit tests for attack simulation
├── test_gdpr.py         Integration tests: config + optional results → check assertions
├── test_parsers.py      Round-trip tests for CSV/JSON/YAML parsing
└── test_reporters.py    Output tests: JSON valid, PDF bytes start with %PDF
```

Session-scoped fixtures generate synthetic scores once per test run (40–60s for 2000 bootstrap
resamples). The fixture data is deterministic — same results across every CI run.

---

## Extension Points

### Adding a new GDPR check

1. Add a `_check_a9_0xx()` pure function in `engine/gdpr.py` with signature:
   `(config, evaluation_result=None, bias_result=None, attack_result=None) → Art9CheckResult`
2. Append it to the relevant `_OBLIGATIONS` tuple.
3. Add an assertion to `tests/test_gdpr.py`.
4. Update `GDPR_BIOMETRIC_REFERENCE.md` with the citation.

### Adding a new attack vector

1. Append an `_AttackSpec` to `_ATTACK_SPECS` in `engine/attack.py`.
2. Add a mitigation helper if the vector has unique mitigations.
3. Update `docs/METHODOLOGY.md` §4.

### Adding a new biometric modality / dataset adapter

1. Create `parsers/<modality>_adapter.py` following the `lfw_adapter.py` / `att_adapter.py` pattern.
2. Adapter must return a DataFrame with columns: `score, label, group, algorithm`.
3. Document in `data/synthetic/README.md`.
