"""Biometric performance metrics: FAR, FRR, EER, ROC, DET.

All functions are pure — they take a DataFrame and return a result.
DataFrame must have columns: ``score`` (float [0,1]) and ``label`` (int: 1=genuine, 0=impostor).

References:
    ISO/IEC 19795-1:2021 — Biometric performance testing and reporting
    NIST SP 800-76-2 — Biometric Specifications for Personal Identity Verification
"""

from __future__ import annotations

import numpy as np
import pandas as pd
from sklearn.metrics import auc, roc_curve

from biometric_auth.engine.statistics import bootstrap_ci
from biometric_auth.models.results import EvaluationResult


def _validate(scores_df: pd.DataFrame) -> None:
    missing = {"score", "label"} - set(scores_df.columns)
    if missing:
        raise ValueError(f"Score DataFrame missing required columns: {missing}")
    if scores_df.empty:
        raise ValueError("Score DataFrame is empty.")


def compute_far_frr_at_threshold(
    scores_df: pd.DataFrame, threshold: float
) -> tuple[float, float]:
    """Return (FAR, FRR) at a single decision threshold.

    FAR = impostor scores ≥ threshold / total impostors
    FRR = genuine scores <  threshold / total genuine
    """
    _validate(scores_df)
    genuine = scores_df[scores_df["label"] == 1]["score"]
    impostor = scores_df[scores_df["label"] == 0]["score"]
    far = float((impostor >= threshold).sum() / len(impostor)) if len(impostor) > 0 else 0.0
    frr = float((genuine < threshold).sum() / len(genuine)) if len(genuine) > 0 else 0.0
    return far, frr


def compute_eer(scores_df: pd.DataFrame) -> tuple[float, float]:
    """Return (EER, threshold) at the crossover point where FAR ≈ FRR.

    Uses the ROC curve and finds the threshold minimising |FAR - FRR|,
    which is equivalent to finding the EER per ISO/IEC 19795-1.
    """
    _validate(scores_df)
    labels = scores_df["label"].to_numpy()
    scores = scores_df["score"].to_numpy()

    fpr, tpr, thresholds = roc_curve(labels, scores)
    fnr = 1.0 - tpr  # FNR == FRR in biometric notation

    # Point on ROC where |FAR - FRR| is minimised
    idx = np.argmin(np.abs(fpr - fnr))
    eer = float((fpr[idx] + fnr[idx]) / 2.0)
    threshold = float(thresholds[idx]) if idx < len(thresholds) else 0.5
    return eer, threshold


def compute_roc(
    scores_df: pd.DataFrame,
) -> tuple[np.ndarray, np.ndarray, np.ndarray, float]:
    """Return (fpr, tpr, thresholds, auc_roc)."""
    _validate(scores_df)
    labels = scores_df["label"].to_numpy()
    scores = scores_df["score"].to_numpy()
    fpr, tpr, thresholds = roc_curve(labels, scores)
    auc_roc = float(auc(fpr, tpr))
    return fpr, tpr, thresholds, auc_roc


def compute_det_curve(scores_df: pd.DataFrame) -> tuple[np.ndarray, np.ndarray]:
    """Return (FMR, FNMR) for a Detection Error Tradeoff (DET) curve.

    FMR = False Match Rate = FAR; FNMR = False Non-Match Rate = FRR.
    The DET curve is plotted on probit (normal deviate) scale per ISO 19795.
    """
    _validate(scores_df)
    labels = scores_df["label"].to_numpy()
    scores = scores_df["score"].to_numpy()
    fpr, tpr, _ = roc_curve(labels, scores)
    fnmr = 1.0 - tpr
    return fpr, fnmr  # FMR, FNMR


def run_evaluation(
    scores_df: pd.DataFrame,
    algorithm_name: str = "unknown",
    modality: str = "unknown",
    n_bootstrap: int = 2000,
    bootstrap_seed: int = 42,
) -> EvaluationResult:
    """Run a full biometric evaluation and return an EvaluationResult.

    Computes EER, FAR/FRR at EER threshold, ROC, DET, and bootstrap
    confidence intervals (n=2000) for FAR, FRR, and EER.
    """
    _validate(scores_df)

    eer, eer_threshold = compute_eer(scores_df)
    far, frr = compute_far_frr_at_threshold(scores_df, eer_threshold)
    fpr, tpr, _, auc_roc = compute_roc(scores_df)
    fmr, fnmr = compute_det_curve(scores_df)

    genuine = scores_df[scores_df["label"] == 1]
    impostor = scores_df[scores_df["label"] == 0]

    def _far_fn(df: pd.DataFrame) -> float:
        f, _ = compute_far_frr_at_threshold(df, eer_threshold)
        return f

    def _frr_fn(df: pd.DataFrame) -> float:
        _, r = compute_far_frr_at_threshold(df, eer_threshold)
        return r

    def _eer_fn(df: pd.DataFrame) -> float:
        e, _ = compute_eer(df)
        return e

    far_lo, far_hi = bootstrap_ci(scores_df, _far_fn, n_bootstrap, seed=bootstrap_seed)
    frr_lo, frr_hi = bootstrap_ci(scores_df, _frr_fn, n_bootstrap, seed=bootstrap_seed + 1)
    eer_lo, eer_hi = bootstrap_ci(scores_df, _eer_fn, n_bootstrap, seed=bootstrap_seed + 2)

    # Subsample curve arrays to keep the result lightweight (~200 points)
    _max_pts = 200
    step = max(1, len(fpr) // _max_pts)

    return EvaluationResult(
        algorithm_name=algorithm_name,
        modality=modality,
        far=far,
        frr=frr,
        eer=eer,
        eer_threshold=eer_threshold,
        far_ci_low=far_lo,
        far_ci_high=far_hi,
        frr_ci_low=frr_lo,
        frr_ci_high=frr_hi,
        eer_ci_low=eer_lo,
        eer_ci_high=eer_hi,
        auc_roc=auc_roc,
        n_genuine=len(genuine),
        n_impostor=len(impostor),
        roc_fpr=fpr[::step].tolist(),
        roc_tpr=tpr[::step].tolist(),
        det_fmr=fmr[::step].tolist(),
        det_fnmr=fnmr[::step].tolist(),
    )
