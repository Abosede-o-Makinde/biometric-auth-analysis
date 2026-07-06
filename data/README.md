# Data Directory

This repository uses **synthetic data only**. No real participant biometric data from the
MSc research (CETM44) is included — consistent with UK GDPR Art.5(1)(c) data minimisation
and Art.9 special category data protections.

---

## Structure

```
data/
├── README.md              ← this file
├── synthetic/             ← pre-generated score CSV files
│   ├── README.md
│   ├── scores_high_accuracy.csv
│   ├── scores_medium_accuracy.csv
│   └── scores_low_accuracy.csv
└── sample_configs/        ← example system YAML configurations
    ├── system_face_recognition.yaml    (compliant example)
    ├── system_fingerprint.yaml         (partial compliance)
    └── system_iris.yaml                (research / non-compliant)
```

---

## Synthetic score files

Three CSV files (16,500 rows each, deterministic seeds):

| File | Target EER | Represents |
|------|-----------|------------|
| `synthetic/scores_high_accuracy.csv` | ~1% | State-of-the-art system |
| `synthetic/scores_medium_accuracy.csv` | ~5% | Average commercial system |
| `synthetic/scores_low_accuracy.csv` | ~15% | Legacy or degraded system |

**Columns:** `score`, `label`, `group`, `algorithm`

- `score` — comparison score ∈ [0, 1] (higher = more similar)
- `label` — 1 = genuine pair, 0 = impostor pair
- `group` — demographic group for fairness analysis
- `algorithm` — algorithm identifier string

Scores are generated using a two-Gaussian overlap model (see `biometric_auth/data/synthetic.py`
and `docs/METHODOLOGY.md` §6).

---

## Sample configurations

YAML files describing three fictional biometric deployments for GDPR Art.9 assessment
demonstrations. See `biometric_auth/parsers/config_parser.py` for the full schema.

| File | Scenario | Expected compliance |
|------|----------|---------------------|
| `system_face_recognition.yaml` | Production access control | SATISFIED |
| `system_fingerprint.yaml` | Partial controls | PARTIAL |
| `system_iris.yaml` | Research prototype | GAP / CRITICAL |

---

## Regenerating synthetic data

```bash
python -c "
from biometric_auth.data.synthetic import generate_and_save_synthetic_data
generate_and_save_synthetic_data('data/synthetic')
"
```

Or via the CLI after installation: `biometric-auth sample`.

---

## Important

Do **not** commit real biometric images, templates, or participant identifiers to this
repository. If adapting this framework to real evaluation data, ensure appropriate lawful
basis, DPIA, and access controls are in place before processing Art.9 special category data.
