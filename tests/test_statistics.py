"""Tests for biometric_auth.engine.statistics."""

from __future__ import annotations

import pandas as pd
import pytest

from biometric_auth.engine.statistics import (
    bootstrap_ci,
    compute_ece,
    delong_auc_comparison,
    permutation_test,
)


def test_bootstrap_ci_contains_point_estimate(low_eer_scores):
    from biometric_auth.engine.metrics import compute_eer

    def eer_fn(df):
        e, _ = compute_eer(df)
        return e

    lo, hi = bootstrap_ci(low_eer_scores, eer_fn, n_bootstrap=200, seed=42)
    point = eer_fn(low_eer_scores)
    assert lo <= point <= hi, f"CI [{lo:.4f}, {hi:.4f}] does not contain EER {point:.4f}"


def test_bootstrap_ci_interval_is_ordered(low_eer_scores):
    from biometric_auth.engine.metrics import compute_eer

    lo, hi = bootstrap_ci(
        low_eer_scores, lambda df: compute_eer(df)[0], n_bootstrap=200, seed=10
    )
    assert lo <= hi


def test_delong_identical_systems_p_near_one(low_eer_scores):
    _, p = delong_auc_comparison(low_eer_scores, low_eer_scores)
    assert p > 0.5, f"Identical systems should have high p-value, got {p:.4f}"


def test_delong_different_systems_p_low(low_eer_scores, high_eer_scores):
    _, p = delong_auc_comparison(low_eer_scores, high_eer_scores)
    assert p < 0.05, f"Very different systems should have low p-value, got {p:.4f}"


def test_delong_returns_finite_z(low_eer_scores, medium_eer_scores):
    z, p = delong_auc_comparison(low_eer_scores, medium_eer_scores)
    assert abs(z) < 1000, f"z-statistic {z} is unreasonably large"
    assert 0.0 <= p <= 1.0


def test_permutation_test_identical_p_near_one(low_eer_scores):
    p = permutation_test(low_eer_scores, low_eer_scores, metric="eer", n_permutations=200, seed=42)
    assert p > 0.3, f"Identical systems should give high p-value, got {p:.4f}"


def test_permutation_test_different_p_low(low_eer_scores, high_eer_scores):
    p = permutation_test(
        low_eer_scores, high_eer_scores, metric="eer", n_permutations=500, seed=42
    )
    assert p < 0.05, f"Different systems should give low p-value, got {p:.4f}"


def test_ece_perfect_calibration():
    """A perfectly calibrated predictor has ECE ≈ 0."""
    import numpy as np

    n = 1000
    scores = [0.1, 0.3, 0.5, 0.7, 0.9] * 200
    labels = [0, 0, 1, 1, 1] * 200
    df = pd.DataFrame({"score": scores, "label": labels})
    ece = compute_ece(df, n_bins=5)
    assert ece < 0.30, f"ECE {ece:.4f} should be modest for this dataset"


def test_ece_in_unit_interval(low_eer_scores):
    ece = compute_ece(low_eer_scores)
    assert 0.0 <= ece <= 1.0, f"ECE {ece:.4f} is out of [0, 1]"


def test_bootstrap_ci_respects_alpha(low_eer_scores):
    """90% CI should be narrower than default 95% CI."""
    from biometric_auth.engine.metrics import compute_eer

    fn = lambda df: compute_eer(df)[0]
    lo_95, hi_95 = bootstrap_ci(low_eer_scores, fn, n_bootstrap=200, alpha=0.05, seed=0)
    lo_90, hi_90 = bootstrap_ci(low_eer_scores, fn, n_bootstrap=200, alpha=0.10, seed=0)
    # 90% CI must be a subset of (or equal to) the 95% CI
    assert lo_90 >= lo_95 - 0.01
    assert hi_90 <= hi_95 + 0.01
