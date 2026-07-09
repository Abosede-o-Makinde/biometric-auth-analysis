"""Tests for biometric_auth.parsers."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pandas as pd
import pytest

from biometric_auth.parsers.config_parser import emit_sample_config, load_config
from biometric_auth.parsers.score_file import load_scores


# ── Score file parser ─────────────────────────────────────────────────────────

def _write_csv(tmp_path: Path, data: dict) -> Path:
    p = tmp_path / "scores.csv"
    pd.DataFrame(data).to_csv(p, index=False)
    return p


def _write_json(tmp_path: Path, data) -> Path:
    p = tmp_path / "scores.json"
    with open(p, "w") as f:
        json.dump(data, f)
    return p


def test_load_scores_csv_minimal(tmp_path):
    p = _write_csv(tmp_path, {"score": [0.8, 0.3], "label": [1, 0]})
    df = load_scores(p)
    assert list(df.columns) >= ["score", "label"]
    assert "group" in df.columns
    assert "algorithm" in df.columns
    assert df["group"].iloc[0] == "overall"
    assert df["algorithm"].iloc[0] == "unknown"


def test_load_scores_csv_with_group(tmp_path):
    p = _write_csv(
        tmp_path,
        {"score": [0.8, 0.3], "label": [1, 0], "group": ["A", "B"]},
    )
    df = load_scores(p)
    assert set(df["group"]) == {"A", "B"}


def test_load_scores_json(tmp_path):
    data = [{"score": 0.7, "label": 1}, {"score": 0.2, "label": 0}]
    p = _write_json(tmp_path, data)
    df = load_scores(p)
    assert len(df) == 2
    assert "score" in df.columns


def test_load_scores_json_wrapped(tmp_path):
    data = {"scores": [{"score": 0.7, "label": 1}, {"score": 0.2, "label": 0}]}
    p = _write_json(tmp_path, data)
    df = load_scores(p)
    assert len(df) == 2


def test_missing_score_column_raises(tmp_path):
    p = _write_csv(tmp_path, {"label": [1, 0]})
    with pytest.raises(ValueError, match="missing required columns"):
        load_scores(p)


def test_missing_label_column_raises(tmp_path):
    p = _write_csv(tmp_path, {"score": [0.5, 0.3]})
    with pytest.raises(ValueError, match="missing required columns"):
        load_scores(p)


def test_invalid_label_values_raise(tmp_path):
    p = _write_csv(tmp_path, {"score": [0.5, 0.3], "label": [1, 99]})
    with pytest.raises(ValueError, match="label.*must contain"):
        load_scores(p)


def test_file_not_found_raises():
    with pytest.raises(FileNotFoundError):
        load_scores("/nonexistent/path/scores.csv")


def test_unsupported_format_raises(tmp_path):
    p = tmp_path / "scores.txt"
    p.write_text("score,label\n0.5,1\n")
    with pytest.raises(ValueError, match="Unsupported"):
        load_scores(p)


def test_empty_file_raises(tmp_path):
    p = tmp_path / "scores.csv"
    p.write_text("score,label\n")
    with pytest.raises(ValueError, match="empty"):
        load_scores(p)


# ── Config parser ─────────────────────────────────────────────────────────────

def test_load_config_minimal_yaml(tmp_path):
    p = tmp_path / "config.yaml"
    p.write_text("system_name: 'Test System'\n")
    config = load_config(p)
    assert config.system_name == "Test System"
    # All other fields should default without error
    assert config.deployment.dpia_completed is None


def test_load_config_empty_yaml_no_crash(tmp_path):
    p = tmp_path / "config.yaml"
    p.write_text("")
    config = load_config(p)
    assert config.system_name == "Unnamed Biometric System"


def test_load_config_missing_optional_fields(tmp_path):
    p = tmp_path / "config.yaml"
    p.write_text("deployment:\n  art9_basis: '9_2_b'\n")
    config = load_config(p)
    assert config.deployment.art9_basis == "9_2_b"
    assert config.deployment.dpia_completed is None  # not provided → None


def test_load_config_file_not_found():
    with pytest.raises(FileNotFoundError):
        load_config("/nonexistent/config.yaml")


def test_load_config_invalid_yaml(tmp_path):
    p = tmp_path / "config.yaml"
    p.write_text("system_name: [unclosed")
    with pytest.raises(ValueError, match="Invalid YAML"):
        load_config(p)


def test_load_config_full_sample(tmp_path):
    p = tmp_path / "sample.yaml"
    p.write_text(emit_sample_config())
    config = load_config(p)
    assert config.system_name == "My Biometric System"
    assert config.deployment.art9_basis == "9_2_b"
    assert config.security.encryption_at_rest is True
    assert config.security.template_protection == "cancelable"
    assert config.subject_rights.erasure_sla_days == 20


def test_emit_sample_config_is_valid_yaml():
    import yaml

    data = yaml.safe_load(emit_sample_config())
    assert isinstance(data, dict)
    assert "system_name" in data
