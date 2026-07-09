"""Tests for biometric_auth.engine.bias."""

from __future__ import annotations

import pandas as pd
import pytest

from biometric_auth.engine.bias import (
    calibration_by_group,
    compute_group_metrics,
    demographic_parity_difference,
    disparate_impact_ratio,
    equal_opportunity_difference,
    equalised_odds_difference,
    run_bias_analysis,
)


def test_group_metrics_returns_all_groups(fair_scores):
    groups = compute_group_metrics(fair_scores)
    assert set(groups.keys()) == {"group_A", "group_B", "group_C"}


def test_group_metrics_far_in_unit_interval(fair_scores):
    groups = compute_group_metrics(fair_scores)
    for g in groups.values():
        assert 0.0 <= g.far <= 1.0
        assert 0.0 <= g.frr <= 1.0


def test_dpd_zero_for_identical_groups():
    """When both groups have identical score distributions, DPD should be 0."""
    from biometric_auth.data.synthetic import generate_synthetic_scores

    df_a = generate_synthetic_scores(n_genuine=300, n_impostor=3000, eer_target=0.05, seed=42)
    df_a["group"] = "A"
    df_b = generate_synthetic_scores(n_genuine=300, n_impostor=3000, eer_target=0.05, seed=42)
    df_b["group"] = "B"
    combined = pd.concat([df_a, df_b], ignore_index=True)
    groups = compute_group_metrics(combined)
    dpd = demographic_parity_difference(groups)
    assert dpd < 0.05, f"DPD {dpd:.4f} should be near-zero for identical distributions"


def test_biased_scores_give_biased_verdict(biased_scores):
    result = run_bias_analysis(biased_scores, algorithm_name="biased_system")
    assert result.fairness_verdict == "BIASED", (
        f"Expected BIASED, got {result.fairness_verdict}. "
        f"EqOdds={result.equalised_odds_difference:.3f}, DIR={result.disparate_impact_ratio:.3f}"
    )


def test_fair_scores_give_fair_verdict(fair_scores):
    result = run_bias_analysis(fair_scores, algorithm_name="fair_system")
    assert result.fairness_verdict in ("FAIR", "MARGINAL"), (
        f"Expected FAIR or MARGINAL, got {result.fairness_verdict}"
    )


def test_dir_one_for_equal_groups():
    from biometric_auth.data.synthetic import generate_synthetic_scores

    df_a = generate_synthetic_scores(n_genuine=300, n_impostor=3000, eer_target=0.05, seed=42)
    df_a["group"] = "A"
    df_b = generate_synthetic_scores(n_genuine=300, n_impostor=3000, eer_target=0.05, seed=42)
    df_b["group"] = "B"
    combined = pd.concat([df_a, df_b], ignore_index=True)
    groups = compute_group_metrics(combined)
    dir_val = disparate_impact_ratio(groups)
    assert dir_val > 0.90, f"DIR {dir_val:.4f} should be near 1.0 for equal groups"


def test_equialised_odds_gte_dpd_and_eod(biased_scores):
    groups = compute_group_metrics(biased_scores)
    dpd = demographic_parity_difference(groups)
    eod = equal_opportunity_difference(groups)
    eq_odds = equalised_odds_difference(groups)
    assert eq_odds >= dpd - 1e-9
    assert eq_odds >= eod - 1e-9


def test_bias_result_to_dict_keys(biased_scores):
    result = run_bias_analysis(biased_scores)
    d = result.to_dict()
    for key in (
        "algorithm_name",
        "groups_analysed",
        "group_results",
        "demographic_parity_difference",
        "equal_opportunity_difference",
        "equalised_odds_difference",
        "disparate_impact_ratio",
        "fairness_verdict",
    ):
        assert key in d, f"Missing key: {key}"


def test_calibration_by_group_all_positive(fair_scores):
    calibration = calibration_by_group(fair_scores)
    assert set(calibration.keys()) == {"group_A", "group_B", "group_C"}
    for g, ece in calibration.items():
        assert 0.0 <= ece <= 1.0, f"ECE for {g} = {ece:.4f} out of range"


def test_empty_dataframe_no_crash():
    result = run_bias_analysis(pd.DataFrame({"score": [], "label": [], "group": []}))
    assert result.fairness_verdict == "FAIR"
