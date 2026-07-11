"""Tests for biometric_auth.reporters."""

from __future__ import annotations

import json

import pytest
from rich.console import Console

from biometric_auth.engine.attack import run_attack_simulation
from biometric_auth.engine.bias import run_bias_analysis
from biometric_auth.engine.gdpr import run_art9_assessment
from biometric_auth.engine.metrics import run_evaluation
from biometric_auth.reporters.console import (
    print_attack,
    print_bias,
    print_evaluation,
    print_gdpr,
)
from biometric_auth.reporters.json_rep import to_json
from biometric_auth.reporters.pdf_rep import generate_pdf


# ── Console reporter ──────────────────────────────────────────────────────────

def test_print_evaluation_no_exception(low_eer_scores, capsys):
    result = run_evaluation(low_eer_scores)
    print_evaluation(result)  # should not raise


def test_print_bias_no_exception(biased_scores):
    bias = run_bias_analysis(biased_scores)
    print_bias(bias)


def test_print_attack_no_exception(compliant_system):
    attack = run_attack_simulation(compliant_system)
    print_attack(attack)


def test_print_gdpr_no_exception(compliant_system, low_eer_scores):
    evaluation = run_evaluation(low_eer_scores)
    report = run_art9_assessment(compliant_system, evaluation_result=evaluation)
    print_gdpr(report)


def test_print_gdpr_non_compliant_no_exception(non_compliant_system):
    report = run_art9_assessment(non_compliant_system)
    print_gdpr(report)


# ── JSON reporter ─────────────────────────────────────────────────────────────

def test_json_evaluation_is_valid_json(low_eer_scores):
    result = run_evaluation(low_eer_scores)
    text = to_json(result)
    parsed = json.loads(text)
    assert "eer" in parsed


def test_json_bias_is_valid_json(biased_scores):
    bias = run_bias_analysis(biased_scores)
    text = to_json(bias)
    parsed = json.loads(text)
    assert "fairness_verdict" in parsed


def test_json_attack_is_valid_json(compliant_system):
    attack = run_attack_simulation(compliant_system)
    text = to_json(attack)
    parsed = json.loads(text)
    assert "attack_vectors" in parsed
    assert len(parsed["attack_vectors"]) == 7


def test_json_gdpr_is_valid_json(compliant_system):
    report = run_art9_assessment(compliant_system)
    text = to_json(report)
    parsed = json.loads(text)
    for key in ("overall_score", "overall_status", "risk_rating", "obligations"):
        assert key in parsed, f"Missing key: {key}"


def test_json_writes_to_file(compliant_system, tmp_path):
    report = run_art9_assessment(compliant_system)
    out = tmp_path / "report.json"
    to_json(report, path=out)
    assert out.exists()
    parsed = json.loads(out.read_text())
    assert "overall_score" in parsed


# ── PDF reporter ──────────────────────────────────────────────────────────────

def test_pdf_returns_bytes(compliant_system):
    report = run_art9_assessment(compliant_system)
    pdf_bytes = generate_pdf(report)
    assert isinstance(pdf_bytes, bytes)
    assert pdf_bytes[:4] == b"%PDF", "PDF bytes should start with %PDF magic number"


def test_pdf_non_compliant_no_exception(non_compliant_system):
    report = run_art9_assessment(non_compliant_system)
    pdf_bytes = generate_pdf(report)
    assert len(pdf_bytes) > 1000


def test_pdf_writes_to_file(compliant_system, tmp_path):
    report = run_art9_assessment(compliant_system)
    out = tmp_path / "report.pdf"
    generate_pdf(report, output=out)
    assert out.exists()
    assert out.stat().st_size > 1000
    assert out.read_bytes()[:4] == b"%PDF"


def test_pdf_with_evaluation_result(compliant_system, low_eer_scores):
    evaluation = run_evaluation(low_eer_scores)
    report = run_art9_assessment(compliant_system, evaluation_result=evaluation)
    pdf_bytes = generate_pdf(report, evaluation_result=evaluation)
    assert pdf_bytes[:4] == b"%PDF"
