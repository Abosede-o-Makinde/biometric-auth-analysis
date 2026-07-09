"""Biometric presentation attack and digital attack simulation.

Models 7 attack vectors across three categories, scoring each using a
CVSS v3.1-inspired formula adapted for biometric identity spoofing.

Base success rates are derived from:
    NIST FRVT PAD 2020 — Presentation Attack Detection for Facial Biometrics
    ISO/IEC 30107-3:2023 — Biometric presentation attack detection
    Faux et al. (2021)  — "Deepfakes and the 2020 US Election"

PAD mitigation factors reduce presentation attack success:
    Active liveness detection  → ~95% reduction
    Passive liveness detection → ~70% reduction
    Challenge-response         → ~90% reduction

Template protection (cancelable/homomorphic) mitigates DIG-002.
TLS-in-transit mitigates DIG-003.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from biometric_auth.models.config import SystemConfig
from biometric_auth.models.results import AttackResult, AttackVector


@dataclass(frozen=True)
class _AttackSpec:
    attack_id: str
    attack_type: str
    attack_category: str
    base_success_rate: float
    cvss_base: float  # unadjusted CVSS-like base (no mitigations)
    evidence: str


_ATTACK_SPECS: list[_AttackSpec] = [
    _AttackSpec(
        attack_id="PAD-001",
        attack_type="2D Print Attack",
        attack_category="presentation",
        base_success_rate=0.65,
        cvss_base=7.3,
        evidence=(
            "NIST FRVT PAD 2020: median impostor acceptance rate of 62-68% against systems "
            "lacking liveness detection (Category 1 systems). ISO/IEC 30107-3 §6.1."
        ),
    ),
    _AttackSpec(
        attack_id="PAD-002",
        attack_type="Video Replay Attack",
        attack_category="presentation",
        base_success_rate=0.55,
        cvss_base=7.5,
        evidence=(
            "NIST FRVT PAD 2020: video replay attacks achieve 50-60% success against "
            "non-PAD systems. Reduced vs print due to compression artefacts. ISO/IEC 30107-3 §6.2."
        ),
    ),
    _AttackSpec(
        attack_id="PAD-003",
        attack_type="3D Silicone Mask Attack",
        attack_category="presentation",
        base_success_rate=0.30,
        cvss_base=8.1,
        evidence=(
            "NIST FRVT PAD 2020: high-quality 3D masks achieve 25-35% success against "
            "non-PAD systems; require significant resources (£500-5000 per mask). "
            "ISO/IEC 30107-3 §6.3. CVSS elevated due to physical access requirement context."
        ),
    ),
    _AttackSpec(
        attack_id="PAD-004",
        attack_type="Adversarial Patch Attack",
        attack_category="digital",
        base_success_rate=0.40,
        cvss_base=7.8,
        evidence=(
            "Sharif et al. (2016): adversarial eyeglass patches achieve 90% targeted attack "
            "success in white-box setting, 40% black-box. Success rate used is conservative "
            "black-box estimate against deployed systems."
        ),
    ),
    _AttackSpec(
        attack_id="DIG-001",
        attack_type="Deepfake Injection Attack",
        attack_category="digital",
        base_success_rate=0.45,
        cvss_base=8.6,
        evidence=(
            "Korshunov & Marcel (2018): GAN-generated face images achieve 45-75% acceptance "
            "against commercial face verification APIs without PAD. "
            "Rate used: 45% (conservative for systems with basic input validation)."
        ),
    ),
    _AttackSpec(
        attack_id="DIG-002",
        attack_type="Template Database Injection",
        attack_category="infrastructure",
        base_success_rate=0.90,
        cvss_base=9.1,
        evidence=(
            "Direct template substitution achieves near-100% success without template protection "
            "(Ratha et al. 2001). Cancelable biometrics or homomorphic encryption renders "
            "stolen templates non-replayable. CVSS: AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:L."
        ),
    ),
    _AttackSpec(
        attack_id="DIG-003",
        attack_type="Score Tampering (MITM)",
        attack_category="infrastructure",
        base_success_rate=0.80,
        cvss_base=8.8,
        evidence=(
            "Without TLS or message integrity on the decision channel, score substitution "
            "trivially succeeds. TLS 1.2+ reduces this to near-zero (residual MITM risk). "
            "CVSS: AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N."
        ),
    ),
]

_SEVERITY_THRESHOLDS = [
    (9.0, "CRITICAL"),
    (7.0, "HIGH"),
    (4.0, "MEDIUM"),
    (0.0, "LOW"),
]


def _cvss_severity(score: float) -> str:
    for threshold, label in _SEVERITY_THRESHOLDS:
        if score >= threshold:
            return label
    return "LOW"


def _pad_mitigation_factor(spec: _AttackSpec, config: SystemConfig) -> float:
    """Return multiplicative reduction to base_success_rate from PAD controls."""
    if spec.attack_category != "presentation":
        return 1.0
    if not config.security.anti_spoofing_pad:
        return 1.0
    liveness_type = config.security.liveness_detection_type or "none"
    return {
        "active": 0.05,
        "challenge_response": 0.10,
        "passive": 0.30,
        "none": 0.85,
    }.get(liveness_type, 0.85)


def _template_protection_factor(spec: _AttackSpec, config: SystemConfig) -> float:
    """DIG-002 success rate is near-zero with proper template protection."""
    if spec.attack_id != "DIG-002":
        return 1.0
    tp = config.security.template_protection or "none"
    return {"cancelable": 0.05, "homomorphic": 0.02, "secure_sketch": 0.08}.get(tp, 1.0)


def _tls_mitigation_factor(spec: _AttackSpec, config: SystemConfig) -> float:
    """DIG-003 (score MITM) is near-zero with TLS in transit."""
    if spec.attack_id != "DIG-003":
        return 1.0
    return 0.05 if config.security.tls_in_transit else 1.0


def _mitigations_presentation(config: SystemConfig) -> list[str]:
    if config.security.anti_spoofing_pad:
        liveness = config.security.liveness_detection_type or "unknown"
        return [f"PAD enabled ({liveness} liveness)"]
    return [
        "Enable liveness detection (ISO/IEC 30107-3 Level 2)",
        "Deploy active challenge-response PAD for high-assurance contexts",
    ]


def _mitigations_dig001() -> list[str]:
    return [
        "Deploy input integrity checks to reject synthetic/GAN-generated images",
        "Use ISO/IEC 30107-3 conformant PAD to detect injected deepfakes",
        "Monitor enrolment and match pipelines for anomalous image statistics",
    ]


def _mitigations_dig002(config: SystemConfig) -> list[str]:
    tp = config.security.template_protection or "none"
    if tp in ("cancelable", "homomorphic", "secure_sketch"):
        return [f"Template protection active: {tp}"]
    return [
        "Implement cancelable biometrics or homomorphic encryption",
        "Ensure templates are irreversible — raw templates must not be stored",
    ]


def _mitigations_dig003(config: SystemConfig) -> list[str]:
    if not config.security.tls_in_transit:
        return [
            "Enable mutual TLS on all biometric score transmission channels",
            "Implement HMAC-signed decision tokens to prevent score substitution",
        ]
    return ["TLS in transit active"]


def _mitigations_pad004() -> list[str]:
    return [
        "Apply adversarial training or input preprocessing (feature squeezing)",
        "Monitor score distribution for statistical anomalies",
    ]


def _build_mitigations(spec: _AttackSpec, config: SystemConfig) -> list[str]:
    items: list[str] = []
    if spec.attack_category == "presentation":
        items.extend(_mitigations_presentation(config))
    if spec.attack_id == "DIG-001":
        items.extend(_mitigations_dig001())
    elif spec.attack_id == "DIG-002":
        items.extend(_mitigations_dig002(config))
    elif spec.attack_id == "DIG-003":
        items.extend(_mitigations_dig003(config))
    elif spec.attack_id == "PAD-004":
        items.extend(_mitigations_pad004())
    return items


def _simulate_vector(
    spec: _AttackSpec,
    config: SystemConfig,
    baseline_far: float,
) -> AttackVector:
    pad_factor = _pad_mitigation_factor(spec, config)
    tpl_factor = _template_protection_factor(spec, config)
    tls_factor = _tls_mitigation_factor(spec, config)

    effective_rate = spec.base_success_rate * pad_factor * tpl_factor * tls_factor
    effective_rate = max(0.0, min(1.0, effective_rate))

    # FAR under attack: success rate inflates the effective FAR
    impostor_far_under_attack = min(1.0, baseline_far + effective_rate * (1.0 - baseline_far))

    # CVSS adjustment: mitigations reduce exploitability sub-score by mitigation factor
    cvss_adjusted = max(0.0, min(10.0, spec.cvss_base * pad_factor * tpl_factor * tls_factor))

    return AttackVector(
        attack_id=spec.attack_id,
        attack_type=spec.attack_type,
        attack_category=spec.attack_category,
        impostor_far_under_attack=impostor_far_under_attack,
        attack_success_rate=effective_rate,
        cvss_like_score=cvss_adjusted,
        severity=_cvss_severity(cvss_adjusted),
        mitigations=_build_mitigations(spec, config),
        evidence=spec.evidence,
    )


def run_attack_simulation(
    config: SystemConfig,
    baseline_far: float = 0.05,
) -> AttackResult:
    """Simulate all 7 attack vectors against a system configuration.

    Args:
        config: SystemConfig describing the biometric system's controls.
        baseline_far: Operational FAR at chosen threshold (from EvaluationResult if available).

    Returns:
        AttackResult with per-vector results and aggregate vulnerability score.
    """
    vectors = [_simulate_vector(spec, config, baseline_far) for spec in _ATTACK_SPECS]

    # Overall vulnerability = weighted mean of CVSS-like scores
    # Infrastructure attacks weighted 1.5x (DIG-002, DIG-003 affect all users simultaneously)
    total_weight = 0.0
    total_score = 0.0
    for v in vectors:
        weight = 1.5 if v.attack_category == "infrastructure" else 1.0
        total_score += v.cvss_like_score * weight
        total_weight += weight
    overall = total_score / total_weight if total_weight > 0 else 0.0

    severity_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "NONE": 0}
    highest = max(vectors, key=lambda v: severity_order.get(v.severity, 0)).severity

    pad_enabled = bool(config.security.anti_spoofing_pad)
    liveness_type: Optional[str] = config.security.liveness_detection_type

    return AttackResult(
        algorithm_name=config.algorithm.name,
        pad_enabled=pad_enabled,
        liveness_type=liveness_type,
        attack_vectors=vectors,
        overall_vulnerability_score=overall,
        highest_severity=highest,
    )
