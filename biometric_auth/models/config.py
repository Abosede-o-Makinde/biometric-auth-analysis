"""Pydantic v2 input models for biometric system configuration.

All fields are Optional — missing field = not assessed (PARTIAL), never a crash.
"""

from __future__ import annotations

from typing import Literal, Optional

from pydantic import BaseModel, Field


class AlgorithmInfo(BaseModel):
    name: str = "Unknown Algorithm"
    modality: Literal["face", "fingerprint", "iris", "voice", "multimodal", "unknown"] = "unknown"
    version: Optional[str] = None
    vendor: Optional[str] = None
    sdk_version: Optional[str] = None
    trained_on: Optional[str] = None


class DeploymentContext(BaseModel):
    environment: Literal["production", "staging", "development", "research", "unknown"] = "unknown"
    use_case: Literal[
        "access_control", "border_control", "banking", "healthcare", "research", "other"
    ] = "other"
    data_subjects_count: Optional[int] = None
    # Art.9 lawful basis — one of the Art.9(2) conditions
    art9_basis: Optional[Literal["9_2_a", "9_2_b", "9_2_g", "9_2_h", "9_2_i", "none"]] = None
    consent_mechanism: Optional[
        Literal["explicit_consent", "vital_interests", "employment_law", "none", "unknown"]
    ] = None
    dpia_completed: Optional[bool] = None
    dpia_date: Optional[str] = None  # ISO date string
    dpo_consulted: Optional[bool] = None
    transfers_outside_uk_eea: Optional[bool] = None
    adequacy_decision_or_sccs: Optional[bool] = None


class RetentionConfig(BaseModel):
    # raw images are themselves Art.9 biometric data — retaining them is highest risk
    raw_images_retained: Optional[bool] = None
    biometric_templates_retained: Optional[bool] = None
    retention_period_days: Optional[int] = None
    automated_deletion: Optional[bool] = None
    deletion_audit_trail: Optional[bool] = None
    data_minimisation_enforced: Optional[bool] = None
    purpose_limitation_documented: Optional[bool] = None


class SecurityControls(BaseModel):
    encryption_at_rest: Optional[bool] = None
    encryption_algorithm: Optional[str] = None
    tls_in_transit: Optional[bool] = None
    # Template protection is the primary Art.32 technical measure for biometric templates
    template_protection: Optional[
        Literal["cancelable", "homomorphic", "secure_sketch", "none", "unknown"]
    ] = None
    anti_spoofing_pad: Optional[bool] = None
    liveness_detection: Optional[bool] = None
    liveness_detection_type: Optional[
        Literal["active", "passive", "challenge_response", "none"]
    ] = None
    audit_logging: Optional[bool] = None
    intrusion_detection: Optional[bool] = None
    mfa_on_admin_access: Optional[bool] = None


class SubjectRightsConfig(BaseModel):
    erasure_process_documented: Optional[bool] = None
    erasure_sla_days: Optional[int] = None
    verified_deletion: Optional[bool] = None
    portability_supported: Optional[bool] = None
    automated_decision_logic_documented: Optional[bool] = None
    subject_access_request_process: Optional[bool] = None


class TransparencyConfig(BaseModel):
    privacy_notice_published: Optional[bool] = None
    biometric_collection_notice: Optional[bool] = None
    lawful_basis_documented: Optional[bool] = None
    purpose_limitation_documented: Optional[bool] = None
    notice_last_updated: Optional[str] = None  # ISO date string


class SystemConfig(BaseModel):
    """Root configuration model for a biometric authentication system."""

    system_name: str = "Unnamed Biometric System"
    system_description: str = ""
    algorithm: AlgorithmInfo = Field(default_factory=AlgorithmInfo)
    deployment: DeploymentContext = Field(default_factory=DeploymentContext)
    retention: RetentionConfig = Field(default_factory=RetentionConfig)
    security: SecurityControls = Field(default_factory=SecurityControls)
    subject_rights: SubjectRightsConfig = Field(default_factory=SubjectRightsConfig)
    transparency: TransparencyConfig = Field(default_factory=TransparencyConfig)
