"""Synthetic biometric score distribution generator.

Generates pre-computed CSV files for use without any real biometric data.
Score distributions use overlapping Gaussians — the canonical model for
genuine/impostor score separation in biometric literature (Daugman 2003).

Scores are in [0, 1]: higher = more similar (genuine pairs score higher).
Each CSV has columns: score, label (1=genuine, 0=impostor), group, algorithm.

Groups are synthetic demographic proxies — never tied to real protected
characteristics. Their sole purpose is to demonstrate bias measurement.
"""

from __future__ import annotations

import numpy as np
import pandas as pd


def _clip(arr: np.ndarray) -> np.ndarray:
    return np.clip(arr, 0.0, 1.0)


def generate_synthetic_scores(
    n_genuine: int = 500,
    n_impostor: int = 5000,
    eer_target: float = 0.05,
    seed: int = 42,
    algorithm: str = "synthetic",
    group: str = "overall",
) -> pd.DataFrame:
    """Generate a single-group score distribution targeting a given EER.

    The EER is controlled by the separation between the Gaussian means:
    a wider gap produces lower EER (higher accuracy). The relationship is
    derived from the Gaussian overlap formula — empirical calibration below.

    Args:
        n_genuine: Number of genuine comparison pairs.
        n_impostor: Number of impostor comparison pairs.
        eer_target: Approximate Equal Error Rate to target (0.01–0.20).
        seed: RNG seed for reproducibility.
        algorithm: Algorithm label for the ``algorithm`` column.
        group: Group label for the ``group`` column.

    Returns:
        DataFrame with columns: score, label, group, algorithm.
    """
    rng = np.random.default_rng(seed)

    # Calibration: separation controls EER. Empirically derived from the
    # standard biometric score model (two Gaussians, equal variance).
    # eer ≈ norm.cdf(-separation / (2 * sigma)) where sigma=0.1
    sigma = 0.10
    from scipy.stats import norm

    # Invert: separation = -2 * sigma * norm.ppf(eer_target)
    separation = max(0.05, -2 * sigma * norm.ppf(min(eer_target, 0.49)))

    impostor_mean = 0.5 - separation / 2
    genuine_mean = 0.5 + separation / 2

    genuine_scores = _clip(rng.normal(genuine_mean, sigma, n_genuine))
    impostor_scores = _clip(rng.normal(impostor_mean, sigma, n_impostor))

    df = pd.DataFrame(
        {
            "score": np.concatenate([genuine_scores, impostor_scores]),
            "label": np.concatenate([np.ones(n_genuine), np.zeros(n_impostor)]),
            "group": group,
            "algorithm": algorithm,
        }
    )
    return df.reset_index(drop=True)


def generate_synthetic_multigroup(
    groups: list[str],
    eer_by_group: dict[str, float],
    n_genuine_per_group: int = 250,
    n_impostor_per_group: int = 2500,
    seed: int = 42,
    algorithm: str = "synthetic",
) -> pd.DataFrame:
    """Generate multi-group scores with group-specific EER to simulate bias.

    Args:
        groups: Group labels.
        eer_by_group: EER target per group.
        n_genuine_per_group: Genuine pairs per group.
        n_impostor_per_group: Impostor pairs per group.
        seed: RNG seed (incremented per group for independence).
        algorithm: Algorithm label.

    Returns:
        DataFrame with columns: score, label, group, algorithm.
    """
    frames = []
    for i, g in enumerate(groups):
        eer = eer_by_group.get(g, 0.05)
        df = generate_synthetic_scores(
            n_genuine=n_genuine_per_group,
            n_impostor=n_impostor_per_group,
            eer_target=eer,
            seed=seed + i,
            algorithm=algorithm,
            group=g,
        )
        frames.append(df)
    return pd.concat(frames, ignore_index=True)


def _save_csv(df: pd.DataFrame, path: str) -> None:
    df.to_csv(path, index=False, float_format="%.6f")


def generate_and_save_synthetic_data(output_dir: str = "data/synthetic") -> None:
    """Generate the three canonical synthetic CSV files and save them.

    High accuracy  (EER ≈ 1%)  — represents a state-of-the-art system
    Medium accuracy (EER ≈ 5%) — represents an average commercial system
    Low accuracy   (EER ≈ 15%) — represents a legacy or degraded system
    """
    import os

    os.makedirs(output_dir, exist_ok=True)

    high = generate_synthetic_multigroup(
        groups=["group_A", "group_B", "group_C"],
        eer_by_group={"group_A": 0.010, "group_B": 0.012, "group_C": 0.011},
        n_genuine_per_group=500,
        n_impostor_per_group=5000,
        seed=42,
        algorithm="high_accuracy_system",
    )
    _save_csv(high, f"{output_dir}/scores_high_accuracy.csv")

    medium = generate_synthetic_multigroup(
        groups=["group_A", "group_B", "group_C"],
        eer_by_group={"group_A": 0.050, "group_B": 0.065, "group_C": 0.055},
        n_genuine_per_group=500,
        n_impostor_per_group=5000,
        seed=100,
        algorithm="medium_accuracy_system",
    )
    _save_csv(medium, f"{output_dir}/scores_medium_accuracy.csv")

    low = generate_synthetic_multigroup(
        groups=["group_A", "group_B", "group_C"],
        eer_by_group={"group_A": 0.150, "group_B": 0.200, "group_C": 0.160},
        n_genuine_per_group=500,
        n_impostor_per_group=5000,
        seed=200,
        algorithm="low_accuracy_system",
    )
    _save_csv(low, f"{output_dir}/scores_low_accuracy.csv")

    readme = """\
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
"""
    with open(f"{output_dir}/README.md", "w") as f:
        f.write(readme)

    print(f"Saved synthetic data to {output_dir}/")
    print(f"  scores_high_accuracy.csv   — {len(high):,} rows (EER target ~1%)")
    print(f"  scores_medium_accuracy.csv — {len(medium):,} rows (EER target ~5%)")
    print(f"  scores_low_accuracy.csv    — {len(low):,} rows (EER target ~15%)")


if __name__ == "__main__":
    generate_and_save_synthetic_data()
