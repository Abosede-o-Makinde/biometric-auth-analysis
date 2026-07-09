"""Demographic bias analysis for biometric authentication systems.

Measures fairness across synthetic demographic groups using metrics from:
- Hardt et al. (2016) — Equality of Opportunity in Supervised Learning
- NIST FRVT 2019 — Face Recognition Vendor Technology Evaluation
- UK Equality Act 2010 — 4/5ths disparate impact rule (EEOC, adapted for UK)

FAR disparity (DPD) = unequal security risk between groups.
FRR disparity (EOD) = unequal denial-of-service — the primary civil rights
concern in biometric deployments (some groups denied access more frequently).
"""

from __future__ import annotations

import numpy as np
import pandas as pd

from biometric_auth.engine.metrics import compute_eer, compute_far_frr_at_threshold, compute_roc
from biometric_auth.engine.statistics import compute_ece
from biometric_auth.models.results import BiasResult, DemographicGroup


def compute_group_metrics(
    scores_df: pd.DataFrame,
    threshold: float | None = None,
) -> dict[str, DemographicGroup]:
    """Compute per-group biometric metrics.

    If ``threshold`` is None, each group's EER threshold is used independently.
    Pass a common threshold to evaluate all groups at the same operating point.
    """
    if "group" not in scores_df.columns:
        raise ValueError("Score DataFrame must have a 'group' column for bias analysis.")

    groups = {}
    for group_name, group_df in scores_df.groupby("group"):
        if len(group_df["label"].unique()) < 2:
            continue
        try:
            eer, eer_threshold = compute_eer(group_df)
            t = threshold if threshold is not None else eer_threshold
            far, frr = compute_far_frr_at_threshold(group_df, t)
            _, _, _, auc_roc = compute_roc(group_df)
            genuine_n = int((group_df["label"] == 1).sum())
            impostor_n = int((group_df["label"] == 0).sum())
            groups[str(group_name)] = DemographicGroup(
                group_name=str(group_name),
                n_genuine=genuine_n,
                n_impostor=impostor_n,
                far=far,
                frr=frr,
                eer=eer,
                auc_roc=auc_roc,
            )
        except Exception:
            continue
    return groups


def demographic_parity_difference(group_results: dict[str, DemographicGroup]) -> float:
    """DPD = max(FAR_i) − min(FAR_i).

    Measures the spread of False Acceptance Rates across groups.
    A high DPD means some groups face greater identity-spoofing risk than others.
    """
    if not group_results:
        return 0.0
    fars = [g.far for g in group_results.values()]
    return float(max(fars) - min(fars))


def equal_opportunity_difference(group_results: dict[str, DemographicGroup]) -> float:
    """EOD = max(FRR_i) − min(FRR_i).

    Measures the spread of False Rejection Rates across groups.
    A high EOD is the primary civil rights indicator — some groups are denied
    access more frequently, which may engage Equality Act 2010 s.19 (indirect
    discrimination) and GDPR Art.22 automated decision rights.
    """
    if not group_results:
        return 0.0
    frrs = [g.frr for g in group_results.values()]
    return float(max(frrs) - min(frrs))


def equalised_odds_difference(group_results: dict[str, DemographicGroup]) -> float:
    """EqOdds = max(DPD, EOD). Per Hardt et al. (2016)."""
    return max(
        demographic_parity_difference(group_results),
        equal_opportunity_difference(group_results),
    )


def disparate_impact_ratio(group_results: dict[str, DemographicGroup]) -> float:
    """DIR = min(FAR_i) / max(FAR_i).

    DIR >= 0.80 satisfies the 4/5ths rule (EEOC Guidelines on Employee Selection
    Procedures, 29 C.F.R. § 1607.4(D), adopted as a benchmark in UK bias analysis).
    Returns 1.0 if all FAR values are 0 (perfect — no disparity).
    """
    if not group_results:
        return 1.0
    fars = [g.far for g in group_results.values()]
    max_far = max(fars)
    if max_far < 1e-9:
        return 1.0
    return float(min(fars) / max_far)


def calibration_by_group(scores_df: pd.DataFrame, n_bins: int = 10) -> dict[str, float]:
    """Expected Calibration Error per group."""
    if "group" not in scores_df.columns:
        return {}
    result = {}
    for group_name, group_df in scores_df.groupby("group"):
        if len(group_df) > 0:
            result[str(group_name)] = compute_ece(group_df, n_bins=n_bins)
    return result


def run_bias_analysis(
    scores_df: pd.DataFrame,
    algorithm_name: str = "unknown",
    threshold: float | None = None,
) -> BiasResult:
    """Run a full demographic bias analysis.

    Fairness verdicts:
        FAIR    — DPD < 0.05 AND EOD < 0.05 AND DIR >= 0.80
        BIASED  — EqOdds >= 0.10 OR DIR < 0.60
        MARGINAL — otherwise

    These thresholds are calibrated to produce actionable verdicts:
    - 5% DPD/EOD tolerance reflects operational noise in real deployments
    - DIR < 0.60 is a strong EEOC/UK-analogue red flag (well below 4/5ths)
    - EqOdds >= 0.10 means 10% performance gap — statistically and practically significant
    """
    group_results = compute_group_metrics(scores_df, threshold=threshold)

    if not group_results:
        return BiasResult(
            algorithm_name=algorithm_name,
            groups_analysed=[],
            group_results={},
            demographic_parity_difference=0.0,
            equal_opportunity_difference=0.0,
            equalised_odds_difference=0.0,
            disparate_impact_ratio=1.0,
            calibration_error_by_group={},
            fairness_verdict="FAIR",
        )

    dpd = demographic_parity_difference(group_results)
    eod = equal_opportunity_difference(group_results)
    eq_odds = equalised_odds_difference(group_results)
    dir_val = disparate_impact_ratio(group_results)
    calibration = calibration_by_group(scores_df)

    if eq_odds >= 0.10 or dir_val < 0.60:
        verdict = "BIASED"
    elif dpd < 0.05 and eod < 0.05 and dir_val >= 0.80:
        verdict = "FAIR"
    else:
        verdict = "MARGINAL"

    return BiasResult(
        algorithm_name=algorithm_name,
        groups_analysed=sorted(group_results.keys()),
        group_results=group_results,
        demographic_parity_difference=dpd,
        equal_opportunity_difference=eod,
        equalised_odds_difference=eq_odds,
        disparate_impact_ratio=dir_val,
        calibration_error_by_group=calibration,
        fairness_verdict=verdict,
    )
