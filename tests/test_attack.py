"""Tests for biometric_auth.engine.attack."""

from __future__ import annotations

import pytest

from biometric_auth.engine.attack import run_attack_simulation
from biometric_auth.models.config import SecurityControls, SystemConfig


def test_all_seven_vectors_present(compliant_system):
    result = run_attack_simulation(compliant_system)
    ids = {v.attack_id for v in result.attack_vectors}
    expected = {"PAD-001", "PAD-002", "PAD-003", "PAD-004", "DIG-001", "DIG-002", "DIG-003"}
    assert ids == expected


def test_cvss_scores_in_range(compliant_system):
    result = run_attack_simulation(compliant_system)
    for v in result.attack_vectors:
        assert 0.0 <= v.cvss_like_score <= 10.0, (
            f"{v.attack_id} CVSS score {v.cvss_like_score} out of range"
        )


def test_success_rates_in_range(compliant_system):
    result = run_attack_simulation(compliant_system)
    for v in result.attack_vectors:
        assert 0.0 <= v.attack_success_rate <= 1.0, (
            f"{v.attack_id} success rate {v.attack_success_rate} out of range"
        )


def test_active_liveness_reduces_print_attack(non_compliant_system, compliant_system):
    """Active liveness should dramatically reduce PAD-001 success rate."""
    result_no_pad = run_attack_simulation(non_compliant_system)
    result_pad = run_attack_simulation(compliant_system)

    no_pad_success = next(
        v.attack_success_rate for v in result_no_pad.attack_vectors if v.attack_id == "PAD-001"
    )
    pad_success = next(
        v.attack_success_rate for v in result_pad.attack_vectors if v.attack_id == "PAD-001"
    )
    # Active liveness should reduce print attack success by ~95%
    assert pad_success < no_pad_success * 0.20, (
        f"PAD reduction insufficient: {no_pad_success:.3f} → {pad_success:.3f}"
    )


def test_template_protection_reduces_dig002(compliant_system, non_compliant_system):
    """Cancelable biometrics should reduce DIG-002 (template injection) success."""
    result_protected = run_attack_simulation(compliant_system)
    result_unprotected = run_attack_simulation(non_compliant_system)

    protected = next(
        v.attack_success_rate
        for v in result_protected.attack_vectors
        if v.attack_id == "DIG-002"
    )
    unprotected = next(
        v.attack_success_rate
        for v in result_unprotected.attack_vectors
        if v.attack_id == "DIG-002"
    )
    assert protected < unprotected * 0.15, (
        f"Template protection insufficient: {unprotected:.3f} → {protected:.3f}"
    )


def test_tls_reduces_dig003(compliant_system, non_compliant_system):
    protected = next(
        v.attack_success_rate
        for v in run_attack_simulation(compliant_system).attack_vectors
        if v.attack_id == "DIG-003"
    )
    unprotected = next(
        v.attack_success_rate
        for v in run_attack_simulation(non_compliant_system).attack_vectors
        if v.attack_id == "DIG-003"
    )
    assert protected < unprotected * 0.15


def test_overall_vulnerability_score_in_range(compliant_system, non_compliant_system):
    assert 0.0 <= run_attack_simulation(compliant_system).overall_vulnerability_score <= 10.0
    assert 0.0 <= run_attack_simulation(non_compliant_system).overall_vulnerability_score <= 10.0


def test_non_compliant_higher_vulnerability_than_compliant(
    compliant_system, non_compliant_system
):
    compliant_score = run_attack_simulation(compliant_system).overall_vulnerability_score
    non_compliant_score = run_attack_simulation(non_compliant_system).overall_vulnerability_score
    assert non_compliant_score > compliant_score, (
        f"Non-compliant ({non_compliant_score:.1f}) should score higher "
        f"than compliant ({compliant_score:.1f})"
    )


def test_attack_result_to_dict_keys(compliant_system):
    result = run_attack_simulation(compliant_system)
    d = result.to_dict()
    for key in ("algorithm_name", "pad_enabled", "attack_vectors", "overall_vulnerability_score"):
        assert key in d


def test_mitigations_list_non_empty(compliant_system):
    result = run_attack_simulation(compliant_system)
    for v in result.attack_vectors:
        assert len(v.mitigations) > 0, f"{v.attack_id} has no mitigations listed"
