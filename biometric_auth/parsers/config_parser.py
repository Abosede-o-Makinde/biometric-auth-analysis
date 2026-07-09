"""YAML config parser — YAML file to SystemConfig.

Missing fields are permitted (all fields are Optional in SystemConfig).
The parser never crashes on an incomplete config; it returns a SystemConfig
with defaults for any unspecified fields, which map to PARTIAL in assessment.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from biometric_auth.models.config import SystemConfig


def load_config(path: str | Path) -> SystemConfig:
    """Parse a YAML system configuration file into a SystemConfig.

    Args:
        path: Path to a ``.yaml`` or ``.yml`` system configuration file.

    Returns:
        SystemConfig instance. Missing fields default to None (PARTIAL assessment).

    Raises:
        FileNotFoundError: If the file does not exist.
        ValueError: If the YAML cannot be parsed or top-level is not a mapping.
    """
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Config file not found: {p}")

    with open(p) as f:
        try:
            data = yaml.safe_load(f)
        except yaml.YAMLError as exc:
            raise ValueError(f"Invalid YAML in {p}: {exc}") from exc

    if data is None:
        data = {}
    if not isinstance(data, dict):
        raise ValueError(f"Config file must be a YAML mapping (dict), got {type(data).__name__}")

    return SystemConfig.model_validate(data)


def emit_sample_config() -> str:
    """Return an annotated YAML template for a biometric system config."""
    return """\
# biometric-auth-analysis — System Configuration Template
# All fields are optional. Missing fields are assessed as PARTIAL.

system_name: "My Biometric System"
system_description: "Face recognition for staff building access"

algorithm:
  name: "VGGFace2 + ArcFace"
  modality: "face"         # face | fingerprint | iris | voice | multimodal | unknown
  version: "1.3.0"
  vendor: "Acme Biometrics Ltd"

deployment:
  environment: "production"  # production | staging | development | research | unknown
  use_case: "access_control" # access_control | border_control | banking | healthcare | research | other
  data_subjects_count: 1500
  art9_basis: "9_2_b"        # 9_2_a | 9_2_b | 9_2_g | 9_2_h | 9_2_i | none
  consent_mechanism: null    # explicit_consent | vital_interests | employment_law | none | unknown
  dpia_completed: true
  dpia_date: "2026-01-15"
  dpo_consulted: true
  transfers_outside_uk_eea: false
  adequacy_decision_or_sccs: null

retention:
  raw_images_retained: false
  biometric_templates_retained: true
  retention_period_days: 90
  automated_deletion: true
  deletion_audit_trail: true
  data_minimisation_enforced: true
  purpose_limitation_documented: true

security:
  encryption_at_rest: true
  encryption_algorithm: "AES-256-GCM"
  tls_in_transit: true
  template_protection: "cancelable"  # cancelable | homomorphic | secure_sketch | none | unknown
  anti_spoofing_pad: true
  liveness_detection: true
  liveness_detection_type: "active"  # active | passive | challenge_response | none
  audit_logging: true
  intrusion_detection: true
  mfa_on_admin_access: true

subject_rights:
  erasure_process_documented: true
  erasure_sla_days: 20
  verified_deletion: true
  portability_supported: false
  automated_decision_logic_documented: true
  subject_access_request_process: true

transparency:
  privacy_notice_published: true
  biometric_collection_notice: true
  lawful_basis_documented: true
  purpose_limitation_documented: true
  notice_last_updated: "2026-02-01"
"""
