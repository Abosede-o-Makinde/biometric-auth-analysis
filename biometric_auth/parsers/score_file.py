"""Score file parser — CSV or JSON to pandas DataFrame.

Expected CSV columns: score, label [, group, algorithm]
Expected JSON: list of objects with the same keys, or {scores: [...]} wrapper.
"""

from __future__ import annotations

import json
from pathlib import Path

import pandas as pd


_REQUIRED_COLS = {"score", "label"}
_OPTIONAL_COLS = {"group", "algorithm"}


def load_scores(path: str | Path) -> pd.DataFrame:
    """Load a biometric score file (CSV or JSON) into a validated DataFrame.

    Args:
        path: Path to a ``.csv`` or ``.json`` score file.

    Returns:
        DataFrame with at minimum columns ``score`` (float) and ``label`` (int).
        Optional columns ``group`` and ``algorithm`` are preserved if present;
        absent optional columns are filled with ``"overall"`` and ``"unknown"``.

    Raises:
        ValueError: If required columns are missing or the file is empty.
        FileNotFoundError: If the file does not exist.
    """
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Score file not found: {p}")

    suffix = p.suffix.lower()
    if suffix == ".csv":
        df = pd.read_csv(p)
    elif suffix == ".json":
        with open(p) as f:
            data = json.load(f)
        if isinstance(data, dict):
            # Handle {scores: [...]} wrapper
            data = data.get("scores", data)
        df = pd.DataFrame(data)
    else:
        raise ValueError(f"Unsupported score file format: {suffix}. Use .csv or .json")

    _validate(df)
    df = _normalise(df)
    return df


def _validate(df: pd.DataFrame) -> None:
    if df.empty:
        raise ValueError("Score file is empty.")
    missing = _REQUIRED_COLS - set(df.columns)
    if missing:
        raise ValueError(
            f"Score file is missing required columns: {missing}. "
            f"Required: {_REQUIRED_COLS}. Found: {set(df.columns)}"
        )
    invalid_labels = set(df["label"].dropna().unique()) - {0, 1, 0.0, 1.0}
    if invalid_labels:
        raise ValueError(
            f"Column 'label' must contain only 0 (impostor) or 1 (genuine). "
            f"Found unexpected values: {invalid_labels}"
        )


def _normalise(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()
    df["score"] = df["score"].astype(float)
    df["label"] = df["label"].astype(int)
    if "group" not in df.columns:
        df["group"] = "overall"
    if "algorithm" not in df.columns:
        df["algorithm"] = "unknown"
    # Drop any NaN scores/labels
    before = len(df)
    df = df.dropna(subset=["score", "label"])
    if len(df) < before:
        import warnings

        warnings.warn(
            f"Dropped {before - len(df)} rows with NaN score or label.", stacklevel=3
        )
    return df.reset_index(drop=True)
