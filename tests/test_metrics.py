"""Tests for biometric_auth.engine.metrics."""

from __future__ import annotations

import pandas as pd
import pytest

from biometric_auth.engine.metrics import (
    compute_det_curve,
    compute_eer,
    compute_far_frr_at_threshold,
    compute_roc,
    run_evaluation,
)


def test_far_frr_at_threshold_all_genuine(low_eer_scores):
    far, frr = compute_far_frr_at_threshold(low_eer_scores, threshold=0.0)
    assert far == pytest.approx(1.0)
    assert frr == pytest.approx(0.0)


def test_far_frr_at_threshold_all_impostor(low_eer_scores):
    far, frr = compute_far_frr_at_threshold(low_eer_scores, threshold=1.01)
    assert far == pytest.approx(0.0)
    assert frr == pytest.approx(1.0)


def test_eer_low_accuracy_is_near_target(high_eer_scores):
    eer, _ = compute_eer(high_eer_scores)
    # Should be within 40% relative tolerance of the 15% target
    assert 0.05 < eer < 0.35, f"EER {eer:.3f} too far from 15% target"


def test_eer_high_accuracy_is_near_target(low_eer_scores):
    eer, _ = compute_eer(low_eer_scores)
    # Should be within 40% relative tolerance of the 1% target
    assert eer < 0.04, f"High-accuracy EER {eer:.3f} should be < 4%"


def test_eer_threshold_is_in_unit_interval(low_eer_scores):
    _, threshold = compute_eer(low_eer_scores)
    assert 0.0 <= threshold <= 1.0


def test_roc_auc_high_accuracy(low_eer_scores):
    _, _, _, auc_roc = compute_roc(low_eer_scores)
    assert auc_roc > 0.99, f"High-accuracy AUC {auc_roc:.4f} should be > 0.99"


def test_roc_auc_low_accuracy(high_eer_scores):
    _, _, _, auc_roc = compute_roc(high_eer_scores)
    assert auc_roc < 0.95, f"Low-accuracy AUC {auc_roc:.4f} should be < 0.95"


def test_roc_fpr_tpr_monotone(low_eer_scores):
    fpr, tpr, _, _ = compute_roc(low_eer_scores)
    # fpr and tpr from sklearn.roc_curve are monotonically non-decreasing
    assert all(b >= a for a, b in zip(fpr[:-1], fpr[1:]))
    assert all(b >= a for a, b in zip(tpr[:-1], tpr[1:]))


def test_det_curve_returns_two_arrays(low_eer_scores):
    fmr, fnmr = compute_det_curve(low_eer_scores)
    assert len(fmr) == len(fnmr)
    assert len(fmr) > 1


def test_run_evaluation_result_fields(low_eer_scores):
    result = run_evaluation(low_eer_scores, algorithm_name="test_algo", modality="face")
    assert result.algorithm_name == "test_algo"
    assert result.modality == "face"
    assert 0.0 <= result.eer <= 0.5
    assert 0.0 <= result.auc_roc <= 1.0
    assert result.n_genuine == 500
    assert result.n_impostor == 5000
    assert result.eer_ci_low <= result.eer <= result.eer_ci_high or (
        result.eer_ci_low <= result.eer_ci_high
    )


def test_run_evaluation_ci_ordering(low_eer_scores):
    result = run_evaluation(low_eer_scores)
    assert result.far_ci_low <= result.far_ci_high
    assert result.frr_ci_low <= result.frr_ci_high
    assert result.eer_ci_low <= result.eer_ci_high


def test_run_evaluation_to_dict_keys(low_eer_scores):
    result = run_evaluation(low_eer_scores)
    d = result.to_dict()
    for key in ("eer", "far", "frr", "auc_roc", "n_genuine", "n_impostor"):
        assert key in d, f"Missing key: {key}"


def test_missing_score_column_raises():
    df = pd.DataFrame({"label": [1, 0, 1], "other": [0.5, 0.3, 0.7]})
    with pytest.raises(ValueError, match="missing required columns"):
        compute_eer(df)


def test_missing_label_column_raises():
    df = pd.DataFrame({"score": [0.5, 0.3, 0.7]})
    with pytest.raises(ValueError, match="missing required columns"):
        compute_roc(df)
