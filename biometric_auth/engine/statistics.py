"""Statistical methods for biometric algorithm comparison and calibration.

References:
    DeLong et al. (1988) — "Comparing the areas under two or more correlated
        receiver operating characteristic curves: a nonparametric approach"
        (the standard academic citation for AUC comparison; used in ISO/IEC 19795)
    Hardt et al. (2016) — "Equality of Opportunity in Supervised Learning"
        (foundational fairness metric reference)
    ISO/IEC 19795-1:2021 — Biometric performance testing and reporting
"""

from __future__ import annotations

from typing import Callable

import numpy as np
import pandas as pd
from sklearn.metrics import auc, roc_curve


def bootstrap_ci(
    scores_df: pd.DataFrame,
    metric_fn: Callable[[pd.DataFrame], float],
    n_bootstrap: int = 2000,
    alpha: float = 0.05,
    seed: int = 42,
) -> tuple[float, float]:
    """Bootstrap percentile confidence interval for any scalar metric.

    Args:
        scores_df: DataFrame with ``score`` and ``label`` columns.
        metric_fn: Pure function (DataFrame → float) to bootstrap.
        n_bootstrap: Number of bootstrap replicates.
        alpha: Significance level. Returns (alpha/2, 1-alpha/2) percentiles.
        seed: RNG seed for reproducibility.

    Returns:
        (lower_bound, upper_bound) of the (1-alpha) CI.
    """
    rng = np.random.default_rng(seed)
    n = len(scores_df)
    values = []
    for _ in range(n_bootstrap):
        sample = scores_df.iloc[rng.integers(0, n, n)]
        # Guard: if sample has only one class, metric is undefined — skip
        if len(sample["label"].unique()) < 2:
            continue
        try:
            values.append(metric_fn(sample))
        except Exception:
            continue
    if len(values) < 10:
        point = metric_fn(scores_df)
        return point, point
    arr = np.array(values)
    return float(np.percentile(arr, 100 * alpha / 2)), float(
        np.percentile(arr, 100 * (1 - alpha / 2))
    )


def _auc_variance_delong(labels: np.ndarray, scores: np.ndarray) -> tuple[float, float]:
    """Compute AUC and its variance using the DeLong (1988) method.

    DeLong's method provides an exact (non-bootstrap) variance estimate
    for the AUC, enabling efficient comparison of two correlated ROC curves.
    This is the standard approach cited in ISO/IEC 19795.
    """
    genuine_idx = np.where(labels == 1)[0]
    impostor_idx = np.where(labels == 0)[0]
    m = len(genuine_idx)
    n = len(impostor_idx)

    if m == 0 or n == 0:
        return 0.5, 0.0

    x = scores[genuine_idx]
    y = scores[impostor_idx]

    # Placement values: V_x[i] = (1/n) * Σ_j I(y_j < x_i) + 0.5*I(y_j == x_i)
    v10 = np.array(
        [np.sum(y < xi) / n + 0.5 * np.sum(y == xi) / n for xi in x]
    )
    v01 = np.array(
        [np.sum(x > yj) / m + 0.5 * np.sum(x == yj) / m for yj in y]
    )

    auc_val = float(np.mean(v10))
    # DeLong variance
    s10 = float(np.var(v10, ddof=1) / m)
    s01 = float(np.var(v01, ddof=1) / n)
    variance = s10 + s01
    return auc_val, variance


def delong_auc_comparison(
    scores_a: pd.DataFrame,
    scores_b: pd.DataFrame,
) -> tuple[float, float]:
    """Compare two AUCs using the DeLong (1988) non-parametric test.

    Both DataFrames must have ``score`` and ``label`` columns and should
    represent matched evaluations (same subjects, different algorithms).

    Returns:
        (z_statistic, p_value) — two-sided test.
    """
    from scipy.stats import norm

    labels_a = scores_a["label"].to_numpy()
    scores_a_arr = scores_a["score"].to_numpy()
    labels_b = scores_b["label"].to_numpy()
    scores_b_arr = scores_b["score"].to_numpy()

    auc_a, var_a = _auc_variance_delong(labels_a, scores_a_arr)
    auc_b, var_b = _auc_variance_delong(labels_b, scores_b_arr)

    se = np.sqrt(var_a + var_b)
    if se < 1e-12:
        return 0.0, 1.0

    z = float((auc_a - auc_b) / se)
    p_value = float(2.0 * norm.sf(abs(z)))
    return z, p_value


def permutation_test(
    scores_a: pd.DataFrame,
    scores_b: pd.DataFrame,
    metric: str = "eer",
    n_permutations: int = 5000,
    seed: int = 42,
) -> float:
    """Permutation test comparing EER or AUC between two systems.

    Null hypothesis: both systems have the same underlying performance.
    Returns a two-sided p-value.

    Args:
        scores_a: First system's scores.
        scores_b: Second system's scores.
        metric: "eer" or "auc".
        n_permutations: Number of permutation replicates.
        seed: RNG seed.

    Returns:
        p_value (two-sided).
    """
    from biometric_auth.engine.metrics import compute_eer

    rng = np.random.default_rng(seed)

    def _metric(df: pd.DataFrame) -> float:
        if metric == "eer":
            e, _ = compute_eer(df)
            return e
        fpr, tpr, _ = roc_curve(df["label"].to_numpy(), df["score"].to_numpy())
        return float(auc(fpr, tpr))

    observed_diff = abs(_metric(scores_a) - _metric(scores_b))

    combined = pd.concat([scores_a, scores_b], ignore_index=True)
    n_a = len(scores_a)
    n_total = len(combined)
    count = 0
    for _ in range(n_permutations):
        perm_idx = rng.permutation(n_total)
        perm_a = combined.iloc[perm_idx[:n_a]]
        perm_b = combined.iloc[perm_idx[n_a:]]
        # Both permuted sets need at least two classes
        if (
            len(perm_a["label"].unique()) < 2
            or len(perm_b["label"].unique()) < 2
        ):
            continue
        try:
            diff = abs(_metric(perm_a) - _metric(perm_b))
            if diff >= observed_diff:
                count += 1
        except Exception:
            continue

    return count / n_permutations


def compute_ece(scores_df: pd.DataFrame, n_bins: int = 10) -> float:
    """Expected Calibration Error — measures how well confidence aligns with accuracy.

    A well-calibrated system has ECE ≈ 0. In biometrics, calibration determines
    whether score thresholds set at system deployment remain valid under operational
    conditions — a key Art.5(1)(f) integrity consideration.

    Args:
        scores_df: DataFrame with ``score`` and ``label`` columns.
        n_bins: Number of equal-width bins in [0, 1].

    Returns:
        ECE as a float in [0, 1].
    """
    scores = scores_df["score"].to_numpy(dtype=float)
    labels = scores_df["label"].to_numpy(dtype=float)
    n = len(scores)
    bins = np.linspace(0.0, 1.0, n_bins + 1)
    ece = 0.0
    for lo, hi in zip(bins[:-1], bins[1:]):
        mask = (scores >= lo) & (scores < hi)
        if not mask.any():
            continue
        bin_acc = float(labels[mask].mean())
        bin_conf = float(scores[mask].mean())
        bin_n = int(mask.sum())
        ece += (bin_n / n) * abs(bin_acc - bin_conf)
    return float(ece)
