"""Shared pytest fixtures for biometric-auth-analysis tests."""

from __future__ import annotations

import pandas as pd
import pytest

from biometric_auth.data.synthetic import generate_synthetic_multigroup, generate_synthetic_scores
from biometric_auth.models.config import (
    AlgorithmInfo,
    DeploymentContext,
    RetentionConfig,
    SecurityControls,
    SubjectRightsConfig,
    SystemConfig,
    TransparencyConfig,
)


@pytest.fixture(scope="session")
def low_eer_scores() -> pd.DataFrame:
    """High-accuracy system: EER ≈ 1%."""
    return generate_synthetic_scores(
        n_genuine=500, n_impostor=5000, eer_target=0.01, seed=42, algorithm="high_accuracy"
    )


@pytest.fixture(scope="session")
def medium_eer_scores() -> pd.DataFrame:
    """Average system: EER ≈ 5%."""
    return generate_synthetic_scores(
        n_genuine=500, n_impostor=5000, eer_target=0.05, seed=100, algorithm="medium_accuracy"
    )


@pytest.fixture(scope="session")
def high_eer_scores() -> pd.DataFrame:
    """Legacy/degraded system: EER ≈ 15%."""
    return generate_synthetic_scores(
        n_genuine=500, n_impostor=5000, eer_target=0.15, seed=200, algorithm="low_accuracy"
    )


@pytest.fixture(scope="session")
def biased_scores() -> pd.DataFrame:
    """Multi-group scores with intentional bias: group_A EER=2%, group_B EER=15%."""
    return generate_synthetic_multigroup(
        groups=["group_A", "group_B"],
        eer_by_group={"group_A": 0.02, "group_B": 0.15},
        n_genuine_per_group=300,
        n_impostor_per_group=3000,
        seed=42,
        algorithm="biased_system",
    )


@pytest.fixture(scope="session")
def fair_scores() -> pd.DataFrame:
    """Multi-group scores with equal performance across groups."""
    return generate_synthetic_multigroup(
        groups=["group_A", "group_B", "group_C"],
        eer_by_group={"group_A": 0.05, "group_B": 0.052, "group_C": 0.051},
        n_genuine_per_group=300,
        n_impostor_per_group=3000,
        seed=99,
        algorithm="fair_system",
    )


@pytest.fixture(scope="session")
def compliant_system() -> SystemConfig:
    """Fully compliant biometric system configuration."""
    return SystemConfig(
        system_name="Compliant Face System",
        system_description="A well-configured biometric access control system",
        algorithm=AlgorithmInfo(
            name="ArcFace", modality="face", version="2.1.0", vendor="TestVendor"
        ),
        deployment=DeploymentContext(
            environment="production",
            use_case="access_control",
            data_subjects_count=800,
            art9_basis="9_2_b",
            consent_mechanism=None,
            dpia_completed=True,
            dpia_date="2026-01-10",
            dpo_consulted=True,
            transfers_outside_uk_eea=False,
        ),
        retention=RetentionConfig(
            raw_images_retained=False,
            biometric_templates_retained=True,
            retention_period_days=90,
            automated_deletion=True,
            deletion_audit_trail=True,
            data_minimisation_enforced=True,
            purpose_limitation_documented=True,
        ),
        security=SecurityControls(
            encryption_at_rest=True,
            encryption_algorithm="AES-256-GCM",
            tls_in_transit=True,
            template_protection="cancelable",
            anti_spoofing_pad=True,
            liveness_detection=True,
            liveness_detection_type="active",
            audit_logging=True,
        ),
        subject_rights=SubjectRightsConfig(
            erasure_process_documented=True,
            erasure_sla_days=20,
            verified_deletion=True,
            automated_decision_logic_documented=True,
        ),
        transparency=TransparencyConfig(
            privacy_notice_published=True,
            biometric_collection_notice=True,
            lawful_basis_documented=True,
            purpose_limitation_documented=True,
            notice_last_updated="2026-02-01",
        ),
    )


@pytest.fixture(scope="session")
def non_compliant_system() -> SystemConfig:
    """Non-compliant biometric system configuration — multiple CRITICAL gaps."""
    return SystemConfig(
        system_name="Non-Compliant System",
        system_description="A poorly configured biometric system",
        algorithm=AlgorithmInfo(name="OldAlgo", modality="face"),
        deployment=DeploymentContext(
            environment="production",
            use_case="access_control",
            art9_basis="none",       # CRITICAL: no lawful basis
            dpia_completed=False,    # CRITICAL: no DPIA
            dpo_consulted=False,
        ),
        retention=RetentionConfig(
            raw_images_retained=True,      # HIGH: raw images retained
            retention_period_days=1825,    # MEDIUM: 5 years — likely disproportionate
            automated_deletion=False,
            deletion_audit_trail=False,
            data_minimisation_enforced=False,
            purpose_limitation_documented=False,
        ),
        security=SecurityControls(
            encryption_at_rest=False,      # CRITICAL: no encryption
            tls_in_transit=False,
            template_protection="none",
            anti_spoofing_pad=False,
            audit_logging=False,
        ),
        subject_rights=SubjectRightsConfig(
            erasure_process_documented=False,
            erasure_sla_days=90,
            verified_deletion=False,
            automated_decision_logic_documented=False,
        ),
        transparency=TransparencyConfig(
            privacy_notice_published=False,
            biometric_collection_notice=False,
            lawful_basis_documented=False,
            purpose_limitation_documented=False,
        ),
    )
