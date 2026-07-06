# Synthetic Biometric Score Data

These CSV files contain **pre-generated synthetic biometric comparison scores**.
They are committed to the repository so the tool works immediately after `pip install`
with no external downloads.

## Why synthetic data?

Raw biometric images (face photos, fingerprints) are themselves GDPR Article 9
special category data and cannot be stored in a public repository.
Synthetic score distributions demonstrate all analysis capabilities
(FAR/FRR, bias measurement, GDPR assessment) without holding any biometric data —
which is itself a GDPR Art.5(1)(c) data minimisation demonstration.

## Columns

| Column      | Type    | Description |
|-------------|---------|-------------|
| `score`     | float   | Comparison score in [0, 1]. Higher = more similar. |
| `label`     | int     | 1 = genuine pair, 0 = impostor pair. |
| `group`     | string  | Synthetic demographic proxy (group_A / group_B / group_C). |
| `algorithm` | string  | System identifier for multi-algorithm comparison. |

## Files

| File | Target EER | Description |
|------|-----------|-------------|
| `scores_high_accuracy.csv`   | ~1%  | State-of-the-art system |
| `scores_medium_accuracy.csv` | ~5%  | Average commercial system |
| `scores_low_accuracy.csv`    | ~15% | Legacy / degraded system |

## Score Model

Scores follow overlapping Gaussians — the canonical biometric score model
(Daugman 2003). The genuine distribution is centred higher than the
impostor distribution; the separation controls the EER.

## Regenerating

```bash
python3 -c "from biometric_auth.data.synthetic import generate_and_save_synthetic_data; generate_and_save_synthetic_data()"
```

Regeneration uses fixed seeds (42, 100, 200) — output is deterministic.
