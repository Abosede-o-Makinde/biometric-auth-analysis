"""Result dataclasses for all evaluation outputs.

Dataclasses (not Pydantic) are used here because results are always fully
populated by engine code — partial/missing values do not arise mid-computation.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Literal, Optional


@dataclass
class EvaluationResult:
    algorithm_name: str
    modality: str
    far: float
    frr: float
    eer: float
    eer_threshold: float
    far_ci_low: float
    far_ci_high: float
    frr_ci_low: float
    frr_ci_high: float
    eer_ci_low: float
    eer_ci_high: float
    auc_roc: float
    n_genuine: int
    n_impostor: int
    roc_fpr: list[float] = field(default_factory=list)
    roc_tpr: list[float] = field(default_factory=list)
    det_fmr: list[float] = field(default_factory=list)
    det_fnmr: list[float] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "algorithm_name": self.algorithm_name,
            "modality": self.modality,
            "eer": round(self.eer, 6),
            "eer_threshold": round(self.eer_threshold, 6),
            "eer_ci": [round(self.eer_ci_low, 6), round(self.eer_ci_high, 6)],
            "far": round(self.far, 6),
            "far_ci": [round(self.far_ci_low, 6), round(self.far_ci_high, 6)],
            "frr": round(self.frr, 6),
            "frr_ci": [round(self.frr_ci_low, 6), round(self.frr_ci_high, 6)],
            "auc_roc": round(self.auc_roc, 6),
            "n_genuine": self.n_genuine,
            "n_impostor": self.n_impostor,
        }


@dataclass
class DemographicGroup:
    group_name: str
    n_genuine: int
    n_impostor: int
    far: float
    frr: float
    eer: float
    auc_roc: float

    def to_dict(self) -> dict:
        return {
            "group": self.group_name,
            "n_genuine": self.n_genuine,
            "n_impostor": self.n_impostor,
            "far": round(self.far, 6),
            "frr": round(self.frr, 6),
            "eer": round(self.eer, 6),
            "auc_roc": round(self.auc_roc, 6),
        }


@dataclass
class BiasResult:
    algorithm_name: str
    groups_analysed: list[str]
    group_results: dict[str, DemographicGroup]
    # DPD: max(FAR_i) − min(FAR_i) — security risk disparity
    demographic_parity_difference: float
    # EOD: max(FRR_i) − min(FRR_i) — denial-of-service disparity (primary civil rights metric)
    equal_opportunity_difference: float
    # EqOdds: max(DPD, EOD) per Hardt et al. (2016)
    equalised_odds_difference: float
    # DIR: min_FAR / max_FAR; 4/5ths rule threshold ≥ 0.80
    disparate_impact_ratio: float
    calibration_error_by_group: dict[str, float]
    fairness_verdict: Literal["FAIR", "MARGINAL", "BIASED"]

    def to_dict(self) -> dict:
        return {
            "algorithm_name": self.algorithm_name,
            "groups_analysed": self.groups_analysed,
            "group_results": {k: v.to_dict() for k, v in self.group_results.items()},
            "demographic_parity_difference": round(self.demographic_parity_difference, 6),
            "equal_opportunity_difference": round(self.equal_opportunity_difference, 6),
            "equalised_odds_difference": round(self.equalised_odds_difference, 6),
            "disparate_impact_ratio": round(self.disparate_impact_ratio, 6),
            "calibration_error_by_group": {
                k: round(v, 6) for k, v in self.calibration_error_by_group.items()
            },
            "fairness_verdict": self.fairness_verdict,
        }


@dataclass
class AttackVector:
    attack_id: str
    attack_type: str
    attack_category: Literal["presentation", "digital", "infrastructure"]
    impostor_far_under_attack: float
    attack_success_rate: float
    cvss_like_score: float
    severity: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    mitigations: list[str]
    evidence: str  # cites NIST FRVT PAD 2020 / ISO/IEC 30107-3

    def to_dict(self) -> dict:
        return {
            "attack_id": self.attack_id,
            "attack_type": self.attack_type,
            "attack_category": self.attack_category,
            "attack_success_rate": round(self.attack_success_rate, 4),
            "impostor_far_under_attack": round(self.impostor_far_under_attack, 6),
            "cvss_like_score": round(self.cvss_like_score, 1),
            "severity": self.severity,
            "mitigations": self.mitigations,
            "evidence": self.evidence,
        }


@dataclass
class AttackResult:
    algorithm_name: str
    pad_enabled: bool
    liveness_type: Optional[str]
    attack_vectors: list[AttackVector]
    overall_vulnerability_score: float
    highest_severity: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"]

    def to_dict(self) -> dict:
        return {
            "algorithm_name": self.algorithm_name,
            "pad_enabled": self.pad_enabled,
            "liveness_type": self.liveness_type,
            "attack_vectors": [v.to_dict() for v in self.attack_vectors],
            "overall_vulnerability_score": round(self.overall_vulnerability_score, 1),
            "highest_severity": self.highest_severity,
        }


@dataclass
class Art9CheckResult:
    check_id: str
    obligation_ref: str
    obligation_title: str
    description: str
    status: Literal["SATISFIED", "PARTIAL", "GAP", "N/A"]
    evidence: str
    finding: str
    remediation: str
    severity: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    weight: float = 1.0

    @property
    def score(self) -> float:
        return {"SATISFIED": 1.0, "PARTIAL": 0.5, "GAP": 0.0, "N/A": 1.0}.get(self.status, 0.0)

    def to_dict(self) -> dict:
        return {
            "check_id": self.check_id,
            "obligation_ref": self.obligation_ref,
            "description": self.description,
            "status": self.status,
            "evidence": self.evidence,
            "finding": self.finding,
            "remediation": self.remediation,
            "severity": self.severity,
            "weight": self.weight,
            "score": self.score,
        }


@dataclass
class Art9ObligationResult:
    obligation_ref: str
    obligation_title: str
    summary: str
    checks: list[Art9CheckResult] = field(default_factory=list)

    @property
    def score(self) -> float:
        total_weight = sum(c.weight for c in self.checks)
        if total_weight == 0:
            return 1.0
        return sum(c.score * c.weight for c in self.checks) / total_weight

    @property
    def status(self) -> str:
        s = self.score
        if s >= 0.90:
            return "SATISFIED"
        if s >= 0.45:
            return "PARTIAL"
        return "GAP"

    def to_dict(self) -> dict:
        return {
            "obligation_ref": self.obligation_ref,
            "obligation_title": self.obligation_title,
            "summary": self.summary,
            "score": round(self.score, 4),
            "status": self.status,
            "checks": [c.to_dict() for c in self.checks],
        }


@dataclass
class GDPRReport:
    system_name: str
    system_description: str
    generated_at: datetime
    obligations: list[Art9ObligationResult]
    evaluation_result: Optional[EvaluationResult] = None
    bias_result: Optional[BiasResult] = None
    attack_result: Optional[AttackResult] = None
    # Always 0.90 — biometric data is always Art.9 special category
    satisfied_threshold: float = 0.90

    @property
    def overall_score(self) -> float:
        total_weight = sum(c.weight for obl in self.obligations for c in obl.checks)
        if total_weight == 0:
            return 1.0
        return (
            sum(c.score * c.weight for obl in self.obligations for c in obl.checks) / total_weight
        )

    @property
    def overall_status(self) -> str:
        s = self.overall_score
        if s >= self.satisfied_threshold:
            return "SATISFIED"
        if s >= 0.45:
            return "PARTIAL"
        return "GAP"

    @property
    def risk_rating(self) -> Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]:
        all_checks = [c for obl in self.obligations for c in obl.checks]
        critical_gaps = sum(
            1 for c in all_checks if c.status == "GAP" and c.severity == "CRITICAL"
        )
        s = self.overall_score
        if s >= self.satisfied_threshold:
            return "LOW"
        if s >= 0.45:
            return "HIGH" if critical_gaps > 0 else "MEDIUM"
        return "CRITICAL"

    def to_dict(self) -> dict:
        return {
            "system_name": self.system_name,
            "system_description": self.system_description,
            "generated_at": self.generated_at.isoformat(),
            "overall_score": round(self.overall_score, 4),
            "overall_status": self.overall_status,
            "risk_rating": self.risk_rating,
            "satisfied_threshold": self.satisfied_threshold,
            "obligations": [o.to_dict() for o in self.obligations],
            "evaluation_result": self.evaluation_result.to_dict()
            if self.evaluation_result
            else None,
            "bias_result": self.bias_result.to_dict() if self.bias_result else None,
            "attack_result": self.attack_result.to_dict() if self.attack_result else None,
        }
