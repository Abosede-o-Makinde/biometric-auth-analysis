"""Tests for biometric_auth.engine.gdpr."""

from __future__ import annotations

import pytest

from biometric_auth.engine.attack import run_attack_simulation
from biometric_auth.engine.bias import run_bias_analysis
from biometric_auth.engine.gdpr import run_art9_assessment
from biometric_auth.engine.metrics import run_evaluation


def test_compliant_system_high_score(compliant_system):
    report = run_art9_assessment(compliant_system)
    assert report.overall_score >= 0.85, (
        f"Compliant system score {report.overall_score:.4f} should be ≥ 0.85"
    )


def test_non_compliant_system_low_score(non_compliant_system):
    report = run_art9_assessment(non_compliant_system)
    assert report.overall_score <= 0.45, (
        f"Non-compliant system score {report.overall_score:.4f} should be ≤ 0.45"
    )


def test_satisfied_threshold_always_090(compliant_system, non_compliant_system):
    for config in (compliant_system, non_compliant_system):
        report = run_art9_assessment(config)
        assert report.satisfied_threshold == 0.90, (
            f"satisfied_threshold should always be 0.90 for biometric data"
        )


def test_non_compliant_has_critical_gaps(non_compliant_system):
    report = run_art9_assessment(non_compliant_system)
    all_checks = [c for obl in report.obligations for c in obl.checks]
    critical_gaps = [c for c in all_checks if c.status == "GAP" and c.severity == "CRITICAL"]
    assert len(critical_gaps) >= 3, (
        f"Expected ≥3 CRITICAL GAPs for non-compliant system, found {len(critical_gaps)}"
    )


def test_dpia_false_gives_a9_020_gap(non_compliant_system):
    report = run_art9_assessment(non_compliant_system)
    all_checks = [c for obl in report.obligations for c in obl.checks]
    a9_020 = next((c for c in all_checks if c.check_id == "A9-020"), None)
    assert a9_020 is not None
    assert a9_020.status == "GAP"
    assert a9_020.severity == "CRITICAL"


def test_raw_images_true_gives_a9_030_gap(non_compliant_system):
    report = run_art9_assessment(non_compliant_system)
    all_checks = [c for obl in report.obligations for c in obl.checks]
    a9_030 = next((c for c in all_checks if c.check_id == "A9-030"), None)
    assert a9_030 is not None
    assert a9_030.status == "GAP"


def test_no_lawful_basis_gives_a9_001_gap(non_compliant_system):
    report = run_art9_assessment(non_compliant_system)
    all_checks = [c for obl in report.obligations for c in obl.checks]
    a9_001 = next((c for c in all_checks if c.check_id == "A9-001"), None)
    assert a9_001 is not None
    assert a9_001.status == "GAP"
    assert a9_001.severity == "CRITICAL"


def test_high_eer_gives_a9_022_gap(high_eer_scores, non_compliant_system):
    evaluation = run_evaluation(high_eer_scores, algorithm_name="low_accuracy")
    report = run_art9_assessment(non_compliant_system, evaluation_result=evaluation)
    all_checks = [c for obl in report.obligations for c in obl.checks]
    a9_022 = next((c for c in all_checks if c.check_id == "A9-022"), None)
    assert a9_022 is not None
    assert a9_022.status == "GAP", (
        f"High EER ({evaluation.eer:.2%}) should give A9-022 GAP"
    )


def test_low_eer_gives_a9_022_satisfied(low_eer_scores, compliant_system):
    evaluation = run_evaluation(low_eer_scores, algorithm_name="high_accuracy")
    report = run_art9_assessment(compliant_system, evaluation_result=evaluation)
    all_checks = [c for obl in report.obligations for c in obl.checks]
    a9_022 = next((c for c in all_checks if c.check_id == "A9-022"), None)
    assert a9_022 is not None
    assert a9_022.status == "SATISFIED"


def test_biased_system_gives_a9_061_gap(biased_scores, non_compliant_system):
    bias = run_bias_analysis(biased_scores)
    assert bias.equalised_odds_difference >= 0.10, (
        "Fixture must have EqOdds ≥ 0.10 for this test to be valid"
    )
    report = run_art9_assessment(non_compliant_system, bias_result=bias)
    all_checks = [c for obl in report.obligations for c in obl.checks]
    a9_061 = next((c for c in all_checks if c.check_id == "A9-061"), None)
    assert a9_061 is not None
    assert a9_061.status == "GAP"
    assert a9_061.severity == "CRITICAL"


def test_high_vulnerability_gives_a9_042_gap(non_compliant_system):
    attack = run_attack_simulation(non_compliant_system)
    report = run_art9_assessment(non_compliant_system, attack_result=attack)
    all_checks = [c for obl in report.obligations for c in obl.checks]
    a9_042 = next((c for c in all_checks if c.check_id == "A9-042"), None)
    assert a9_042 is not None
    assert a9_042.status == "GAP", (
        f"High vulnerability ({attack.overall_vulnerability_score:.1f}) should give GAP"
    )


def test_seven_obligations_present(compliant_system):
    report = run_art9_assessment(compliant_system)
    refs = {obl.obligation_ref for obl in report.obligations}
    expected = {"OBL-1", "OBL-2", "OBL-3", "OBL-4", "OBL-5", "OBL-6", "OBL-7"}
    assert refs == expected


def test_total_checks_count(compliant_system):
    report = run_art9_assessment(compliant_system)
    all_checks = [c for obl in report.obligations for c in obl.checks]
    assert len(all_checks) >= 22, f"Expected ≥22 checks, found {len(all_checks)}"


def test_to_dict_required_keys(compliant_system):
    report = run_art9_assessment(compliant_system)
    d = report.to_dict()
    for key in (
        "system_name",
        "overall_score",
        "overall_status",
        "risk_rating",
        "satisfied_threshold",
        "obligations",
        "generated_at",
    ):
        assert key in d, f"Missing key: {key}"


def test_risk_rating_low_for_compliant(compliant_system, low_eer_scores):
    evaluation = run_evaluation(low_eer_scores)
    report = run_art9_assessment(compliant_system, evaluation_result=evaluation)
    assert report.risk_rating in ("LOW", "MEDIUM"), (
        f"Compliant system should not be CRITICAL, got {report.risk_rating}"
    )


def test_risk_rating_critical_for_non_compliant(non_compliant_system):
    report = run_art9_assessment(non_compliant_system)
    assert report.risk_rating == "CRITICAL", (
        f"Non-compliant system should be CRITICAL, got {report.risk_rating}"
    )
