"""GDPR Article 9 compliance assessment engine for biometric systems.

Biometric data is ALWAYS Article 9 special category data (UK GDPR Art.9(1)).
All checks use satisfied_threshold = 0.90 — there is no lower-risk mode.

22 checks across 7 obligation clusters:

    OBL-1: Art.9(1) — Lawful Basis (2 checks)
    OBL-2: Art.5(1)(b) — Purpose Limitation & Data Minimisation (3 checks)
    OBL-3: Art.35 — DPIA (3 checks, including EER-linked metric check)
    OBL-4: Art.5(1)(e) — Storage Limitation (3 checks)
    OBL-5: Art.32 — Security Measures (5 checks, including attack-linked check)
    OBL-6: Art.17 / Art.22 — Erasure and Subject Rights (3 checks)
    OBL-7: Art.9 Bias & Non-Discrimination (3 checks, including bias-linked metric check)

References:
    ICO Biometric Data Guidance (2023)
    ICO DPIA Guidance — biometric systems always require DPIA (Art.35(3)(b))
    UK GDPR Art.9, Art.5, Art.32, Art.35, Art.17, Art.22
    Equality Act 2010 s.19 — indirect discrimination
"""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from biometric_auth.models.config import SystemConfig
from biometric_auth.models.results import (
    Art9CheckResult,
    Art9ObligationResult,
    AttackResult,
    BiasResult,
    EvaluationResult,
    GDPRReport,
)

# ──────────────────────────────────────────────────────────────────────────────
# OBL-1: Art.9(1) — Lawful Basis
# ──────────────────────────────────────────────────────────────────────────────

_OBL1_REF = "OBL-1"
_OBL1_TITLE = "Art.9(1) — Lawful Basis for Biometric Processing"


def _check_a9_001(config: SystemConfig, **_) -> Art9CheckResult:
    """A9-001: An Art.9(2) condition must be identified before processing begins."""
    basis = config.deployment.art9_basis
    if basis is None:
        status, finding, remediation = (
            "PARTIAL",
            "Art.9(2) lawful basis not documented in configuration.",
            "Identify and document the applicable Art.9(2) condition "
            "(e.g. 9_2_a explicit consent, 9_2_b employment law, 9_2_g substantial public interest).",
        )
    elif basis == "none":
        status, finding, remediation = (
            "GAP",
            "No Art.9(2) condition is identified. Processing biometric data without a lawful basis "
            "is prohibited under Art.9(1) UK GDPR.",
            "STOP processing until an applicable Art.9(2) condition is established and documented. "
            "Consult your DPO and consider whether biometric processing is necessary at all.",
        )
    else:
        status, finding, remediation = (
            "SATISFIED",
            f"Art.9(2) basis identified: {basis}.",
            "Ensure the basis remains valid and is reviewed at each DPIA cycle.",
        )
    return Art9CheckResult(
        check_id="A9-001",
        obligation_ref=_OBL1_REF,
        obligation_title=_OBL1_TITLE,
        description="Art.9(2) lawful basis documented and applicable",
        status=status,
        evidence=f"config.deployment.art9_basis = {basis}",
        finding=finding,
        remediation=remediation,
        severity="CRITICAL",
        weight=2.0,
    )


def _check_a9_002(config: SystemConfig, **_) -> Art9CheckResult:
    """A9-002: If basis is explicit consent (9_2_a), consent mechanism must be present."""
    basis = config.deployment.art9_basis
    mechanism = config.deployment.consent_mechanism
    if basis != "9_2_a":
        status, evidence, finding, remediation = (
            "N/A",
            f"Basis is {basis} — consent mechanism check not applicable.",
            "Not applicable.",
            "No action required.",
        )
    elif mechanism == "explicit_consent":
        status, evidence, finding, remediation = (
            "SATISFIED",
            "Explicit consent mechanism documented.",
            "Consent mechanism in place for Art.9(2)(a) basis.",
            "Ensure consent is freely given, specific, informed, and unambiguous (GDPR Art.7). "
            "Maintain consent records.",
        )
    else:
        status, evidence, finding, remediation = (
            "GAP",
            f"Basis is 9_2_a but consent_mechanism = {mechanism}.",
            "Art.9(2)(a) requires explicit consent (not just opt-in). "
            "The ICO requires a clear, affirmative act for special category data.",
            "Implement explicit consent collection compliant with Art.7 and ICO guidance. "
            "Record consent with timestamp and version of notice shown.",
        )
    return Art9CheckResult(
        check_id="A9-002",
        obligation_ref=_OBL1_REF,
        obligation_title=_OBL1_TITLE,
        description="Explicit consent mechanism present when basis is 9_2_a",
        status=status,
        evidence=evidence,
        finding=finding,
        remediation=remediation,
        severity="CRITICAL",
        weight=1.5,
    )


# ──────────────────────────────────────────────────────────────────────────────
# OBL-2: Art.5(1)(b) — Purpose Limitation & Data Minimisation
# ──────────────────────────────────────────────────────────────────────────────

_OBL2_REF = "OBL-2"
_OBL2_TITLE = "Art.5(1)(b)(c) — Purpose Limitation and Data Minimisation"


def _check_a9_010(config: SystemConfig, **_) -> Art9CheckResult:
    """A9-010: Processing purpose must be documented and limited."""
    documented = config.retention.purpose_limitation_documented
    if documented is True:
        status, finding = "SATISFIED", "Purpose limitation documented."
        remediation = "Review at each DPIA cycle to ensure purpose has not drifted."
    elif documented is False:
        status, finding = "GAP", "Purpose limitation not documented — scope creep risk."
        remediation = (
            "Document the specific purpose for biometric processing. "
            "Any further processing incompatible with the original purpose requires fresh lawful basis."
        )
    else:
        status, finding = "PARTIAL", "Purpose limitation documentation not assessed."
        remediation = "Complete a ROPA entry documenting the processing purpose and legal basis."
    return Art9CheckResult(
        check_id="A9-010",
        obligation_ref=_OBL2_REF,
        obligation_title=_OBL2_TITLE,
        description="Processing purpose documented and purpose limitation enforced",
        status=status,
        evidence=f"config.retention.purpose_limitation_documented = {documented}",
        finding=finding,
        remediation=remediation,
        severity="HIGH",
        weight=1.0,
    )


def _check_a9_011(config: SystemConfig, **_) -> Art9CheckResult:
    """A9-011: Data minimisation — only data necessary for the purpose is collected."""
    minimisation = config.retention.data_minimisation_enforced
    raw_retained = config.retention.raw_images_retained
    if minimisation is True and raw_retained is not True:
        status, finding = "SATISFIED", "Data minimisation enforced and raw images not retained."
        remediation = "Continue auditing to ensure only templates (not images) are stored."
    elif minimisation is False or raw_retained is True:
        status, finding = (
            "GAP",
            "Data minimisation not enforced or raw biometric images retained. "
            "Retaining raw images beyond the enrolment transaction is disproportionate "
            "and creates ongoing Art.9 risk.",
        )
        remediation = (
            "Delete raw biometric images after template extraction. "
            "Store only derived templates. Apply data minimisation policy across the pipeline."
        )
    else:
        status, finding = (
            "PARTIAL",
            "Data minimisation status not fully assessed.",
        )
        remediation = "Audit data flows to confirm only biometric templates are retained, not raw images."
    return Art9CheckResult(
        check_id="A9-011",
        obligation_ref=_OBL2_REF,
        obligation_title=_OBL2_TITLE,
        description="Data minimisation enforced; raw biometric images not retained",
        status=status,
        evidence=(
            f"data_minimisation_enforced={minimisation}, "
            f"raw_images_retained={raw_retained}"
        ),
        finding=finding,
        remediation=remediation,
        severity="HIGH",
        weight=1.2,
    )


def _check_a9_012(config: SystemConfig, **_) -> Art9CheckResult:
    """A9-012: Transparency — biometric collection notice provided to data subjects."""
    notice = config.transparency.biometric_collection_notice
    if notice is True:
        status, finding = "SATISFIED", "Biometric collection notice provided."
        remediation = "Ensure notice is updated whenever processing purpose or controls change."
    elif notice is False:
        status, finding = (
            "GAP",
            "No biometric collection notice provided. Art.13 requires information about "
            "the processing to be given at collection time.",
        )
        remediation = (
            "Implement an Art.13-compliant collection notice explaining: what biometric data "
            "is collected, why, lawful basis, retention period, subject rights, and DPO contact."
        )
    else:
        status, finding = "PARTIAL", "Biometric collection notice not assessed."
        remediation = "Verify that data subjects receive an Art.13 notice at or before biometric enrolment."
    return Art9CheckResult(
        check_id="A9-012",
        obligation_ref=_OBL2_REF,
        obligation_title=_OBL2_TITLE,
        description="Art.13 biometric collection notice provided to data subjects",
        status=status,
        evidence=f"config.transparency.biometric_collection_notice = {notice}",
        finding=finding,
        remediation=remediation,
        severity="MEDIUM",
        weight=0.8,
    )


# ──────────────────────────────────────────────────────────────────────────────
# OBL-3: Art.35 — DPIA
# ──────────────────────────────────────────────────────────────────────────────

_OBL3_REF = "OBL-3"
_OBL3_TITLE = "Art.35 — Data Protection Impact Assessment (DPIA)"


def _check_a9_020(config: SystemConfig, **_) -> Art9CheckResult:
    """A9-020: DPIA mandatory for biometric systems (ICO guidance — Art.35(3)(b))."""
    dpia = config.deployment.dpia_completed
    dpia_date = config.deployment.dpia_date
    if dpia is True:
        evidence = f"dpia_completed=True, dpia_date={dpia_date}"
        status, finding = "SATISFIED", f"DPIA completed (date: {dpia_date or 'not recorded'})."
        remediation = (
            "Review DPIA when: purpose changes, new algorithm deployed, or at least every 3 years."
        )
    elif dpia is False:
        evidence = "dpia_completed=False"
        status, finding = (
            "GAP",
            "DPIA not completed. Biometric systems always fall under Art.35(3)(b) "
            "(systematic processing of special category data at large scale). "
            "Processing without a DPIA is unlawful.",
        )
        remediation = (
            "Conduct a DPIA before or immediately after deployment. "
            "The ICO must be consulted under Art.36 if risks cannot be mitigated."
        )
    else:
        evidence = "dpia_completed not assessed"
        status, finding = (
            "PARTIAL",
            "DPIA completion status not documented.",
        )
        remediation = "Confirm and document DPIA completion status."
    return Art9CheckResult(
        check_id="A9-020",
        obligation_ref=_OBL3_REF,
        obligation_title=_OBL3_TITLE,
        description="DPIA completed (mandatory for biometric systems per Art.35(3)(b))",
        status=status,
        evidence=evidence,
        finding=finding,
        remediation=remediation,
        severity="CRITICAL",
        weight=2.0,
    )


def _check_a9_021(config: SystemConfig, **_) -> Art9CheckResult:
    """A9-021: DPO consulted during DPIA — required for special category processing."""
    dpo = config.deployment.dpo_consulted
    if dpo is True:
        status, finding = "SATISFIED", "DPO consulted."
        remediation = "Ensure DPO sign-off is obtained for each DPIA revision."
    elif dpo is False:
        status, finding = (
            "GAP",
            "DPO not consulted. Art.38 requires the DPO to be involved in DPIA for special "
            "category data. This is non-negotiable where a DPO is appointed.",
        )
        remediation = "Involve DPO immediately. Document DPO advice and any overrides with justification."
    else:
        status, finding = "PARTIAL", "DPO consultation not documented."
        remediation = "Confirm and document DPO involvement in DPIA."
    return Art9CheckResult(
        check_id="A9-021",
        obligation_ref=_OBL3_REF,
        obligation_title=_OBL3_TITLE,
        description="DPO consulted during DPIA",
        status=status,
        evidence=f"config.deployment.dpo_consulted = {dpo}",
        finding=finding,
        remediation=remediation,
        severity="HIGH",
        weight=1.0,
    )


def _check_a9_022(
    config: SystemConfig,
    evaluation_result: Optional[EvaluationResult] = None,
    **_,
) -> Art9CheckResult:
    """A9-022 (metric-linked): High EER creates high risk requiring DPIA attention.

    EER > 10% means 1 in 10 genuine users is rejected — this disproportionate
    impact on access must be addressed in the DPIA under Art.35(7)(c).
    """
    if evaluation_result is None:
        status, evidence, finding, remediation = (
            "PARTIAL",
            "EER not available — no score file provided.",
            "EER not evaluated. High EER creates high false-rejection risk that must be "
            "addressed in the DPIA.",
            "Run biometric-auth evaluate with a score file to obtain EER, "
            "then re-run the GDPR assessment.",
        )
    elif evaluation_result.eer > 0.10:
        status, evidence, finding, remediation = (
            "GAP",
            f"EER = {evaluation_result.eer:.2%} (>{10:.0%} threshold)",
            f"EER of {evaluation_result.eer:.2%} exceeds the 10% high-risk threshold. "
            "This level of false rejection means approximately 1 in "
            f"{1/evaluation_result.eer:.0f} genuine users is incorrectly denied access. "
            "DPIA must address this disproportionate impact and document mitigation.",
            "Consider algorithm replacement, threshold adjustment, or enrolment quality gates. "
            "EER below 5% should be the target for operational deployments.",
        )
    elif evaluation_result.eer > 0.02:
        status, evidence, finding, remediation = (
            "PARTIAL",
            f"EER = {evaluation_result.eer:.2%} (moderate, 2–10% range)",
            f"EER of {evaluation_result.eer:.2%} is moderate. DPIA should address residual "
            "false-rejection impact and define acceptable operating thresholds.",
            "Document EER and threshold in DPIA. Monitor for performance drift in production.",
        )
    else:
        status, evidence, finding, remediation = (
            "SATISFIED",
            f"EER = {evaluation_result.eer:.2%} (< 2% — low false-rejection risk)",
            f"EER of {evaluation_result.eer:.2%} is within acceptable range for operational deployment.",
            "Continue monitoring EER in production. Alert if EER drifts above 2%.",
        )
    return Art9CheckResult(
        check_id="A9-022",
        obligation_ref=_OBL3_REF,
        obligation_title=_OBL3_TITLE,
        description="EER within acceptable range for DPIA risk assessment (EER < 10%)",
        status=status,
        evidence=evidence,
        finding=finding,
        remediation=remediation,
        severity="HIGH",
        weight=1.5,
    )


# ──────────────────────────────────────────────────────────────────────────────
# OBL-4: Art.5(1)(e) — Storage Limitation
# ──────────────────────────────────────────────────────────────────────────────

_OBL4_REF = "OBL-4"
_OBL4_TITLE = "Art.5(1)(e) — Storage Limitation"


def _check_a9_030(config: SystemConfig, **_) -> Art9CheckResult:
    """A9-030: Raw biometric images must not be retained beyond enrolment."""
    raw = config.retention.raw_images_retained
    if raw is True:
        status, finding = (
            "GAP",
            "Raw biometric images retained. Raw images (face photos, fingerprint scans) are "
            "themselves Art.9 data. Retaining them beyond the enrolment transaction is "
            "disproportionate — only derived templates should be stored.",
        )
        remediation = (
            "Delete raw biometric images immediately after template extraction. "
            "Implement secure deletion with audit trail. "
            "This is a primary Art.32 and Art.5(1)(e) requirement."
        )
    elif raw is False:
        status, finding = "SATISFIED", "Raw biometric images not retained."
        remediation = "Confirm deletion is applied to all storage paths including caches and backups."
    else:
        status, finding = "PARTIAL", "Raw image retention policy not assessed."
        remediation = "Audit all data stores for raw biometric images and implement a deletion policy."
    return Art9CheckResult(
        check_id="A9-030",
        obligation_ref=_OBL4_REF,
        obligation_title=_OBL4_TITLE,
        description="Raw biometric images deleted after template extraction",
        status=status,
        evidence=f"config.retention.raw_images_retained = {raw}",
        finding=finding,
        remediation=remediation,
        severity="HIGH",
        weight=1.5,
    )


def _check_a9_031(config: SystemConfig, **_) -> Art9CheckResult:
    """A9-031: Retention period proportionate to processing purpose."""
    period = config.retention.retention_period_days
    use_case = config.deployment.use_case
    if period is None:
        status, finding = "PARTIAL", "Retention period not documented."
        remediation = "Define and document maximum retention periods per data category."
        evidence = "retention_period_days not set"
    else:
        # Border control contexts have ICO/Home Office approval for longer retention
        border = use_case == "border_control"
        high_period = 1095 if border else 365
        if period <= high_period:
            status = "SATISFIED"
            finding = f"Retention period {period} days is proportionate for {use_case}."
            remediation = "Review retention period at each DPIA cycle."
        else:
            status = "PARTIAL"
            finding = (
                f"Retention period {period} days may be disproportionate for {use_case} "
                f"(guidance: ≤{high_period} days). Justify in DPIA with specific necessity evidence."
            )
            remediation = (
                "Reduce retention period or document specific legal necessity for extended retention. "
                "ICO requires that retention periods be the minimum necessary for the purpose."
            )
        evidence = f"retention_period_days={period}, use_case={use_case}"
    return Art9CheckResult(
        check_id="A9-031",
        obligation_ref=_OBL4_REF,
        obligation_title=_OBL4_TITLE,
        description="Template retention period proportionate to processing purpose",
        status=status,
        evidence=evidence,
        finding=finding,
        remediation=remediation,
        severity="MEDIUM",
        weight=1.0,
    )


def _check_a9_032(config: SystemConfig, **_) -> Art9CheckResult:
    """A9-032: Automated deletion at end of retention period."""
    auto_del = config.retention.automated_deletion
    audit = config.retention.deletion_audit_trail
    if auto_del is True:
        status = "SATISFIED" if audit else "PARTIAL"
        finding = (
            "Automated deletion in place."
            if audit
            else "Automated deletion in place but no deletion audit trail."
        )
        remediation = (
            "Continue automated deletion. Regularly test deletion processes."
            if audit
            else "Implement a deletion audit trail to evidence compliance."
        )
    elif auto_del is False:
        status, finding = (
            "GAP",
            "No automated deletion. Manual processes are error-prone and "
            "create risk of retaining biometric data beyond the stated retention period.",
        )
        remediation = (
            "Implement automated deletion triggered by retention period expiry. "
            "Test deletion processes quarterly."
        )
    else:
        status, finding = "PARTIAL", "Automated deletion not assessed."
        remediation = "Implement and test automated deletion with audit trail."
    return Art9CheckResult(
        check_id="A9-032",
        obligation_ref=_OBL4_REF,
        obligation_title=_OBL4_TITLE,
        description="Automated deletion at retention period expiry with audit trail",
        status=status,
        evidence=f"automated_deletion={auto_del}, deletion_audit_trail={audit}",
        finding=finding,
        remediation=remediation,
        severity="HIGH",
        weight=1.0,
    )


# ──────────────────────────────────────────────────────────────────────────────
# OBL-5: Art.32 — Security Measures
# ──────────────────────────────────────────────────────────────────────────────

_OBL5_REF = "OBL-5"
_OBL5_TITLE = "Art.32 — Technical and Organisational Security Measures"


def _check_a9_040(config: SystemConfig, **_) -> Art9CheckResult:
    """A9-040: Encryption at rest for all biometric data stores."""
    enc = config.security.encryption_at_rest
    algo = config.security.encryption_algorithm
    if enc is True:
        status, finding = (
            "SATISFIED",
            f"Encryption at rest enabled (algorithm: {algo or 'not specified'}).",
        )
        remediation = (
            "Ensure AES-256 or equivalent. Rotate encryption keys annually. "
            "Confirm encryption covers all backup and archive stores."
        )
    elif enc is False:
        status, finding = (
            "GAP",
            "Biometric templates not encrypted at rest. Art.32(1)(a) requires appropriate "
            "technical measures including encryption for special category data.",
        )
        remediation = (
            "Implement AES-256 encryption at rest for all biometric template stores. "
            "This is a baseline requirement — non-negotiable for Art.9 data."
        )
    else:
        status, finding = "PARTIAL", "Encryption at rest not assessed."
        remediation = "Confirm encryption status for all biometric data stores."
    return Art9CheckResult(
        check_id="A9-040",
        obligation_ref=_OBL5_REF,
        obligation_title=_OBL5_TITLE,
        description="Encryption at rest for all biometric template stores",
        status=status,
        evidence=f"encryption_at_rest={enc}, algorithm={algo}",
        finding=finding,
        remediation=remediation,
        severity="CRITICAL",
        weight=1.5,
    )


def _check_a9_041(config: SystemConfig, **_) -> Art9CheckResult:
    """A9-041: Template protection (cancelable biometrics or equivalent).

    Template protection ensures that even if the database is breached,
    stolen templates cannot be replayed to a different system or used
    to reconstruct the raw biometric — critical for Art.32 proportionality.
    """
    tp = config.security.template_protection
    enc = config.security.encryption_at_rest
    if tp in ("cancelable", "homomorphic", "secure_sketch"):
        status, finding = (
            "SATISFIED",
            f"Template protection scheme: {tp}. Stolen templates are non-replayable.",
        )
        remediation = (
            f"Maintain and test the {tp} scheme. Ensure revocability is exercisable "
            "for each enrolled subject."
        )
    elif tp == "none" and enc is True:
        status, finding = (
            "PARTIAL",
            "No template protection scheme; encryption at rest partially mitigates. "
            "Encrypted templates are still replayable if the encryption key is compromised.",
        )
        remediation = (
            "Implement cancelable biometrics or homomorphic encryption for template protection. "
            "Encryption at rest is a necessary but insufficient control for Art.32 compliance."
        )
    else:
        status, finding = (
            "GAP",
            "No template protection and encryption at rest not confirmed. "
            "Biometric templates stored in cleartext are irreversible — a breach cannot be undone "
            "(unlike a password breach). This is a CRITICAL Art.32 deficiency.",
        )
        remediation = (
            "Immediately implement AES-256 encryption at rest as a minimum. "
            "Plan for cancelable biometrics deployment. "
            "Until implemented, biometric processing carries unacceptable Art.32 risk."
        )
    return Art9CheckResult(
        check_id="A9-041",
        obligation_ref=_OBL5_REF,
        obligation_title=_OBL5_TITLE,
        description="Template protection scheme (cancelable/homomorphic) to prevent template replay",
        status=status,
        evidence=f"template_protection={tp}, encryption_at_rest={enc}",
        finding=finding,
        remediation=remediation,
        severity="CRITICAL",
        weight=2.0,
    )


def _check_a9_042(
    config: SystemConfig,
    attack_result: Optional[AttackResult] = None,
    **_,
) -> Art9CheckResult:
    """A9-042 (attack-linked): Overall vulnerability must be below Art.32 threshold."""
    if attack_result is None:
        status, evidence, finding, remediation = (
            "PARTIAL",
            "Attack simulation not run.",
            "Vulnerability profile not assessed. Run attack simulation to evaluate Art.32 exposure.",
            "Run: biometric-auth attack --config <yaml> --scores <csv>",
        )
    elif attack_result.overall_vulnerability_score > 7.0:
        status, evidence, finding, remediation = (
            "GAP",
            f"Overall vulnerability score = {attack_result.overall_vulnerability_score:.1f} / 10",
            f"Vulnerability score of {attack_result.overall_vulnerability_score:.1f} exceeds the "
            "7.0 HIGH threshold. Specific high-severity vectors: "
            + ", ".join(
                v.attack_id
                for v in attack_result.attack_vectors
                if v.cvss_like_score >= 7.0
            ),
            "Address CRITICAL and HIGH vulnerability vectors before operational deployment. "
            "Prioritise template protection (DIG-002) and TLS (DIG-003) as immediate fixes.",
        )
    elif attack_result.overall_vulnerability_score > 4.0:
        status, evidence, finding, remediation = (
            "PARTIAL",
            f"Overall vulnerability score = {attack_result.overall_vulnerability_score:.1f} / 10",
            f"Moderate vulnerability exposure ({attack_result.overall_vulnerability_score:.1f}). "
            "Review MEDIUM-severity vectors and document residual risk in DPIA.",
            "Address MEDIUM-severity attack vectors per the recommended mitigations. "
            "Document residual risk acceptance in the DPIA.",
        )
    else:
        status, evidence, finding, remediation = (
            "SATISFIED",
            f"Overall vulnerability score = {attack_result.overall_vulnerability_score:.1f} / 10",
            f"Low vulnerability exposure ({attack_result.overall_vulnerability_score:.1f}). "
            "Security controls are effective against the modelled attack vectors.",
            "Maintain controls and re-run attack simulation after any system changes.",
        )
    return Art9CheckResult(
        check_id="A9-042",
        obligation_ref=_OBL5_REF,
        obligation_title=_OBL5_TITLE,
        description="Overall vulnerability score < 7.0 (Art.32 proportionality)",
        status=status,
        evidence=evidence,
        finding=finding,
        remediation=remediation,
        severity="HIGH",
        weight=1.5,
    )


def _check_a9_043(config: SystemConfig, **_) -> Art9CheckResult:
    """A9-043: Presentation Attack Detection (PAD / liveness) deployed."""
    pad = config.security.anti_spoofing_pad
    liveness = config.security.liveness_detection_type
    if pad is True:
        status, finding = (
            "SATISFIED",
            f"PAD enabled: {liveness or 'type not specified'}. "
            "ISO/IEC 30107-3 compliance should be verified by independent test.",
        )
        remediation = (
            "Periodically test PAD against new attack artefacts. "
            "Active liveness preferred for high-assurance contexts."
        )
    elif pad is False:
        status, finding = (
            "PARTIAL",
            "No presentation attack detection. Systems without PAD are highly vulnerable "
            "to 2D print and video replay attacks (65%+ success rate, see PAD-001/PAD-002).",
        )
        remediation = (
            "Deploy ISO/IEC 30107-3 compliant PAD. "
            "For high-assurance access control, active liveness detection is recommended."
        )
    else:
        status, finding = "PARTIAL", "PAD status not assessed."
        remediation = "Assess and document PAD controls for the deployed biometric modality."
    return Art9CheckResult(
        check_id="A9-043",
        obligation_ref=_OBL5_REF,
        obligation_title=_OBL5_TITLE,
        description="Presentation Attack Detection (PAD/liveness) deployed",
        status=status,
        evidence=f"anti_spoofing_pad={pad}, liveness_type={liveness}",
        finding=finding,
        remediation=remediation,
        severity="HIGH",
        weight=1.2,
    )


def _check_a9_044(config: SystemConfig, **_) -> Art9CheckResult:
    """A9-044: Audit logging of all biometric match decisions."""
    logging = config.security.audit_logging
    if logging is True:
        status, finding = "SATISFIED", "Audit logging enabled for biometric decisions."
        remediation = "Ensure logs are tamper-evident, retained per policy, and reviewed regularly."
    elif logging is False:
        status, finding = (
            "GAP",
            "No audit logging of biometric match decisions. Without an audit trail, "
            "breaches and misuse cannot be detected or attributed.",
        )
        remediation = (
            "Implement immutable audit logging for all biometric match events: "
            "timestamp, subject reference, outcome (accept/reject), threshold, score band. "
            "Do not log raw scores — log score bands to prevent template reconstruction."
        )
    else:
        status, finding = "PARTIAL", "Audit logging status not assessed."
        remediation = "Implement and verify audit logging for biometric decision events."
    return Art9CheckResult(
        check_id="A9-044",
        obligation_ref=_OBL5_REF,
        obligation_title=_OBL5_TITLE,
        description="Immutable audit logging of all biometric match decisions",
        status=status,
        evidence=f"config.security.audit_logging = {logging}",
        finding=finding,
        remediation=remediation,
        severity="MEDIUM",
        weight=1.0,
    )


# ──────────────────────────────────────────────────────────────────────────────
# OBL-6: Art.17 / Art.22 — Erasure and Subject Rights
# ──────────────────────────────────────────────────────────────────────────────

_OBL6_REF = "OBL-6"
_OBL6_TITLE = "Art.17 / Art.22 — Erasure and Automated Decision Rights"


def _check_a9_050(config: SystemConfig, **_) -> Art9CheckResult:
    """A9-050: Erasure process documented with SLA ≤ 30 days."""
    documented = config.subject_rights.erasure_process_documented
    sla = config.subject_rights.erasure_sla_days
    if documented is True and sla is not None:
        if sla <= 30:
            status, finding = (
                "SATISFIED",
                f"Erasure process documented. SLA: {sla} days (within 30-day UK GDPR limit).",
            )
            remediation = "Test erasure process quarterly. Ensure all backup stores are included."
        else:
            status, finding = (
                "PARTIAL",
                f"Erasure process documented but SLA is {sla} days — exceeds 30-day UK GDPR limit "
                "(Art.17(1): without undue delay, and at most one month).",
            )
            remediation = f"Reduce erasure SLA to ≤30 days. Current SLA of {sla} days may be non-compliant."
        evidence = f"process_documented={documented}, sla_days={sla}"
    elif documented is False:
        status, finding = (
            "GAP",
            "No erasure process documented. Data subjects have Art.17 rights to erasure "
            "of their biometric data. Absence of a process makes compliance impossible.",
        )
        remediation = (
            "Document and implement an erasure process covering all biometric data stores "
            "including backups, caches, and archives. SLA must be ≤30 days."
        )
        evidence = "erasure_process_documented=False"
    else:
        status, finding = "PARTIAL", "Erasure process not fully assessed."
        remediation = "Complete documentation of erasure process and set a compliant SLA."
        evidence = f"process_documented={documented}, sla_days={sla}"
    return Art9CheckResult(
        check_id="A9-050",
        obligation_ref=_OBL6_REF,
        obligation_title=_OBL6_TITLE,
        description="Erasure process documented with SLA ≤ 30 days (Art.17)",
        status=status,
        evidence=evidence,
        finding=finding,
        remediation=remediation,
        severity="HIGH",
        weight=1.2,
    )


def _check_a9_051(config: SystemConfig, **_) -> Art9CheckResult:
    """A9-051: Verified deletion — confirmation and audit trail."""
    verified = config.subject_rights.verified_deletion
    if verified is True:
        status, finding = "SATISFIED", "Deletion verified and audited."
        remediation = "Retain deletion audit records for the duration of the retention period + 12 months."
    elif verified is False:
        status, finding = (
            "PARTIAL",
            "Erasure is performed but not verified or audited. Without verification, "
            "data may persist in caches, logs, or backup stores.",
        )
        remediation = (
            "Implement deletion verification: scan data stores post-deletion, "
            "generate a deletion certificate, and retain audit evidence."
        )
    else:
        status, finding = "PARTIAL", "Deletion verification not assessed."
        remediation = "Implement verified deletion with audit trail for all biometric data stores."
    return Art9CheckResult(
        check_id="A9-051",
        obligation_ref=_OBL6_REF,
        obligation_title=_OBL6_TITLE,
        description="Deletion verified and audited across all stores including backups",
        status=status,
        evidence=f"config.subject_rights.verified_deletion = {verified}",
        finding=finding,
        remediation=remediation,
        severity="MEDIUM",
        weight=1.0,
    )


def _check_a9_052(config: SystemConfig, **_) -> Art9CheckResult:
    """A9-052: Art.22 — automated decision logic documented if biometrics used for access control."""
    logic_doc = config.subject_rights.automated_decision_logic_documented
    use_case = config.deployment.use_case
    # Art.22 is most relevant for access control and border control
    art22_relevant = use_case in ("access_control", "border_control", "banking")
    if not art22_relevant:
        return Art9CheckResult(
            check_id="A9-052",
            obligation_ref=_OBL6_REF,
            obligation_title=_OBL6_TITLE,
            description="Art.22 automated decision logic documented (where applicable)",
            status="N/A",
            evidence=f"use_case={use_case} — Art.22 not directly applicable",
            finding="Art.22 automated decision rights not directly applicable for this use case.",
            remediation="No action required for this use case.",
            severity="INFO",
            weight=0.5,
        )
    if logic_doc is True:
        status, finding = (
            "SATISFIED",
            "Automated biometric decision logic documented. Subjects can exercise Art.22 rights.",
        )
        remediation = "Ensure subjects can request human review of biometric access decisions."
    elif logic_doc is False:
        status, finding = (
            "GAP",
            f"Biometric system used for {use_case} but automated decision logic not documented. "
            "Art.22 requires that subjects can request human review of solely automated decisions "
            "with significant effects.",
        )
        remediation = (
            "Document the decision logic (threshold, algorithm, fallback process). "
            "Implement a process for subjects to request human review of biometric access decisions."
        )
    else:
        status, finding = (
            "PARTIAL",
            "Automated decision logic documentation not assessed for this access control system.",
        )
        remediation = "Document biometric decision logic and human override process per Art.22."
    return Art9CheckResult(
        check_id="A9-052",
        obligation_ref=_OBL6_REF,
        obligation_title=_OBL6_TITLE,
        description="Art.22 automated biometric decision logic documented (access control)",
        status=status,
        evidence=f"automated_decision_logic_documented={logic_doc}, use_case={use_case}",
        finding=finding,
        remediation=remediation,
        severity="HIGH",
        weight=1.0,
    )


# ──────────────────────────────────────────────────────────────────────────────
# OBL-7: Art.9 Bias & Non-Discrimination
# ──────────────────────────────────────────────────────────────────────────────

_OBL7_REF = "OBL-7"
_OBL7_TITLE = "Art.9 / Equality Act 2010 — Bias and Non-Discrimination"


def _check_a9_060(
    config: SystemConfig,
    bias_result: Optional[BiasResult] = None,
    **_,
) -> Art9CheckResult:
    """A9-060: Bias analysis conducted across demographic groups."""
    if bias_result is not None:
        groups = ", ".join(bias_result.groups_analysed)
        status, evidence, finding, remediation = (
            "SATISFIED",
            f"Bias analysis: groups=[{groups}], verdict={bias_result.fairness_verdict}",
            f"Bias analysis conducted across {len(bias_result.groups_analysed)} groups. "
            f"Fairness verdict: {bias_result.fairness_verdict}. "
            f"DPD={bias_result.demographic_parity_difference:.3f}, "
            f"EOD={bias_result.equal_opportunity_difference:.3f}, "
            f"DIR={bias_result.disparate_impact_ratio:.3f}.",
            "Schedule periodic bias re-evaluation as population demographics may shift. "
            "Document bias analysis results in DPIA.",
        )
    else:
        status, evidence, finding, remediation = (
            "PARTIAL",
            "Bias analysis not run — no score file with group labels provided.",
            "Demographic bias not evaluated. NIST FRVT 2019 found significant performance "
            "disparities across demographic groups in commercial face recognition systems. "
            "Undetected bias may constitute indirect discrimination under Equality Act 2010 s.19.",
            "Collect demographic group labels (synthetic proxies acceptable) and run: "
            "biometric-auth bias --scores <csv-with-group-col>",
        )
    return Art9CheckResult(
        check_id="A9-060",
        obligation_ref=_OBL7_REF,
        obligation_title=_OBL7_TITLE,
        description="Demographic bias analysis conducted across demographic groups",
        status=status,
        evidence=evidence,
        finding=finding,
        remediation=remediation,
        severity="HIGH",
        weight=1.5,
    )


def _check_a9_061(
    config: SystemConfig,
    bias_result: Optional[BiasResult] = None,
    **_,
) -> Art9CheckResult:
    """A9-061 (bias-linked): Equalised Odds < 0.10 across demographic groups.

    EqOdds ≥ 0.10 means a 10%+ performance gap — likely to constitute indirect
    discrimination under Equality Act 2010 s.19 if the groups correspond to
    protected characteristics.
    """
    if bias_result is None:
        status, evidence, finding, remediation = (
            "PARTIAL",
            "EqOdds not computed — no bias analysis run.",
            "Equalised Odds not evaluated — bias analysis required.",
            "Run bias analysis with group-labelled scores.",
        )
    elif bias_result.equalised_odds_difference >= 0.10:
        eqo = bias_result.equalised_odds_difference
        frr_disp = bias_result.equal_opportunity_difference
        far_disp = bias_result.demographic_parity_difference
        status, evidence, finding, remediation = (
            "GAP",
            f"EqOdds={eqo:.3f} (≥ 0.10 threshold), FRR disparity={frr_disp:.3f}, "
            f"FAR disparity={far_disp:.3f}",
            f"Equalised Odds difference of {eqo:.1%} indicates potential unlawful discriminatory "
            f"impact (Hardt et al. 2016). FRR disparity of {frr_disp:.1%} means some groups are "
            "denied access significantly more often. This may engage Equality Act 2010 s.19 "
            "(indirect discrimination) and GDPR Art.22 automated decision rights.",
            "Do not deploy or continue operating this system without bias mitigation. "
            "Options: re-train algorithm on balanced data, apply per-group threshold calibration, "
            "or replace the algorithm. Document in DPIA and consult DPO.",
        )
    else:
        eqo = bias_result.equalised_odds_difference
        status, evidence, finding, remediation = (
            "SATISFIED",
            f"EqOdds={eqo:.3f} (< 0.10 threshold)",
            f"Equalised Odds of {eqo:.1%} is within the acceptable range. "
            f"Fairness verdict: {bias_result.fairness_verdict}.",
            "Continue monitoring. EqOdds can increase with population shifts over time.",
        )
    return Art9CheckResult(
        check_id="A9-061",
        obligation_ref=_OBL7_REF,
        obligation_title=_OBL7_TITLE,
        description="Equalised Odds difference < 0.10 (non-discriminatory performance)",
        status=status,
        evidence=evidence,
        finding=finding,
        remediation=remediation,
        severity="CRITICAL",
        weight=2.0,
    )


def _check_a9_062(config: SystemConfig, **_) -> Art9CheckResult:
    """A9-062: Ongoing fairness monitoring in production documented."""
    # Inferred from DPIA + audit logging — no direct config field
    dpia = config.deployment.dpia_completed
    logging = config.security.audit_logging
    if dpia is True and logging is True:
        status, finding = (
            "SATISFIED",
            "DPIA completed and audit logging enabled — prerequisite infrastructure for "
            "ongoing fairness monitoring in place.",
        )
        remediation = (
            "Establish a periodic (quarterly) bias re-evaluation process using production "
            "audit data. Define KPIs: EqOdds < 0.10, DIR > 0.80, FRR by group."
        )
    elif dpia is False or logging is False:
        status, finding = (
            "GAP",
            "DPIA not completed or audit logging absent — ongoing fairness monitoring "
            "cannot be implemented without these prerequisites.",
        )
        remediation = (
            "Complete DPIA (A9-020) and enable audit logging (A9-044) first. "
            "Then establish a fairness monitoring programme with defined review cadence."
        )
    else:
        status, finding = (
            "PARTIAL",
            "Fairness monitoring prerequisites (DPIA, audit logging) not fully confirmed.",
        )
        remediation = "Confirm DPIA and audit logging status, then implement a monitoring schedule."
    return Art9CheckResult(
        check_id="A9-062",
        obligation_ref=_OBL7_REF,
        obligation_title=_OBL7_TITLE,
        description="Ongoing fairness monitoring programme documented and implemented",
        status=status,
        evidence=f"dpia_completed={dpia}, audit_logging={logging}",
        finding=finding,
        remediation=remediation,
        severity="MEDIUM",
        weight=1.0,
    )


# ──────────────────────────────────────────────────────────────────────────────
# Orchestrator
# ──────────────────────────────────────────────────────────────────────────────

_OBLIGATIONS: list[tuple[str, str, str, list]] = [
    (
        _OBL1_REF,
        _OBL1_TITLE,
        "Art.9(1) UK GDPR prohibits processing biometric data unless an Art.9(2) condition applies.",
        [_check_a9_001, _check_a9_002],
    ),
    (
        _OBL2_REF,
        _OBL2_TITLE,
        "Data minimisation and purpose limitation restrict collection and use to what is necessary.",
        [_check_a9_010, _check_a9_011, _check_a9_012],
    ),
    (
        _OBL3_REF,
        _OBL3_TITLE,
        "A DPIA is mandatory for biometric systems per Art.35(3)(b). DPO involvement required.",
        [_check_a9_020, _check_a9_021, _check_a9_022],
    ),
    (
        _OBL4_REF,
        _OBL4_TITLE,
        "Biometric data must not be retained longer than necessary for the processing purpose.",
        [_check_a9_030, _check_a9_031, _check_a9_032],
    ),
    (
        _OBL5_REF,
        _OBL5_TITLE,
        "Art.32 requires appropriate technical measures: encryption, template protection, PAD, audit logging.",
        [_check_a9_040, _check_a9_041, _check_a9_042, _check_a9_043, _check_a9_044],
    ),
    (
        _OBL6_REF,
        _OBL6_TITLE,
        "Data subjects have Art.17 erasure rights and Art.22 rights regarding automated biometric decisions.",
        [_check_a9_050, _check_a9_051, _check_a9_052],
    ),
    (
        _OBL7_REF,
        _OBL7_TITLE,
        "Biometric systems must not produce discriminatory outcomes. Bias must be measured and mitigated.",
        [_check_a9_060, _check_a9_061, _check_a9_062],
    ),
]


def run_art9_assessment(
    config: SystemConfig,
    evaluation_result: Optional[EvaluationResult] = None,
    bias_result: Optional[BiasResult] = None,
    attack_result: Optional[AttackResult] = None,
) -> GDPRReport:
    """Run the full GDPR Art.9 assessment and return a GDPRReport.

    Accepts optional EvaluationResult, BiasResult, AttackResult for
    metric-linked checks (A9-022, A9-042, A9-061). Without them, those
    checks return PARTIAL (not assessed) rather than failing.
    """
    obligations = []
    for obl_ref, obl_title, summary, check_fns in _OBLIGATIONS:
        checks = [
            fn(
                config,
                evaluation_result=evaluation_result,
                bias_result=bias_result,
                attack_result=attack_result,
            )
            for fn in check_fns
        ]
        obligations.append(
            Art9ObligationResult(
                obligation_ref=obl_ref,
                obligation_title=obl_title,
                summary=summary,
                checks=checks,
            )
        )

    return GDPRReport(
        system_name=config.system_name,
        system_description=config.system_description,
        generated_at=datetime.utcnow(),
        obligations=obligations,
        evaluation_result=evaluation_result,
        bias_result=bias_result,
        attack_result=attack_result,
        satisfied_threshold=0.90,
    )
