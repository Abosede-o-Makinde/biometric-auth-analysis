# Methodology

This document describes the statistical and analytical methods used in `biometric-auth-analysis`.
It is written to the standard expected of an MSc biometric authentication research appendix
(CETM44, University of Sunderland) and a Global Talent Visa portfolio artefact.

---

## 1. Biometric Performance Metrics

### 1.1 Score Model

Biometric comparison systems produce a **comparison score** _s_ ∈ [0, 1] for each pair of
biometric samples, where higher values indicate greater similarity. Following Daugman (2003),
genuine pair scores (same identity) and impostor pair scores (different identities) are modelled
as overlapping Gaussians:

```
genuine  scores ~ N(μ_G, σ²)
impostor scores ~ N(μ_I, σ²)  where μ_G > μ_I
```

The degree of overlap determines the Equal Error Rate.

### 1.2 FAR, FRR, and EER

Given a decision threshold _τ_:

- **FAR(τ)** = P(s ≥ τ | impostor) — False Acceptance Rate
- **FRR(τ)** = P(s < τ | genuine) — False Rejection Rate  
- **EER** = FAR(τ\*) = FRR(τ\*) — the threshold τ\* where FAR ≈ FRR

EER is computed by finding the minimum of |FAR(τ) − FRR(τ)| over the ROC curve,
per ISO/IEC 19795-1:2021 §7.3.

### 1.3 ROC and DET Curves

The **Receiver Operating Characteristic (ROC)** curve plots TPR = 1 − FRR vs FAR across all
thresholds. AUC-ROC = 1.0 indicates perfect separation; AUC-ROC = 0.5 indicates chance.

The **Detection Error Tradeoff (DET)** curve plots FMR (=FAR) vs FNMR (=FRR) on a normal
deviate (probit) scale, which linearises the typically curved tradeoff. DET curves are the
standard visualisation in biometric performance literature (ISO/IEC 19795-1:2021 §8.2).

---

## 2. Statistical Comparison Methods

### 2.1 Bootstrap Confidence Intervals

Bootstrap CI (Efron & Tibshirani 1993) is used for all metric uncertainty estimates:

1. Draw _B_ = 2000 resamples (with replacement) of size _n_ from the score set.
2. Compute the metric (EER, FAR, FRR) on each resample.
3. Report the (α/2, 1−α/2) percentiles as the (1−α) CI, with α = 0.05 by default.

Justification: the bootstrap makes no distributional assumptions, which is important when
score distributions are clipped at [0, 1] and not strictly Gaussian.

### 2.2 DeLong AUC Comparison

**Reference:** DeLong, E.R., DeLong, D.M., & Clarke-Pearson, D.L. (1988). Comparing the areas
under two or more correlated receiver operating characteristic curves: a nonparametric approach.
_Biometrics_, 44(3), 837–845.

DeLong's method computes placement values for genuine scores against impostor scores, derives
the AUC variance exactly (without simulation), and constructs a _z_-statistic for comparing
two AUCs. This is the standard method cited in ISO/IEC 19795-1:2021 for ROC comparison.

The implementation follows the variance formula from DeLong et al. (1988) Section 2:

```
Var(AUC) = S₁₀/m + S₀₁/n
```

where _m_ = genuine count, _n_ = impostor count, S₁₀ and S₀₁ are the sample variances of
the placement values V₁₀ and V₀₁.

### 2.3 Permutation Test

A non-parametric alternative to DeLong. Under the null hypothesis that both systems have
the same performance, labels (system A / system B) are randomly permuted across the combined
dataset. The observed |EER_A − EER_B| is compared against the permutation distribution.
p-value = fraction of permutations with |ΔE| ≥ observed |ΔE|.

### 2.4 Expected Calibration Error (ECE)

ECE measures whether biometric scores are well-calibrated — i.e., whether a score of 0.8
corresponds to genuineness with probability ≈ 0.8.

```
ECE = Σ_b (n_b / n) × |acc(b) − conf(b)|
```

where the sum is over equal-width bins, n_b is the bin count, acc(b) = fraction genuine in
bin, and conf(b) = mean score in bin. Low ECE is important for Art.5(1)(f) integrity:
calibrated scores allow operators to set thresholds with predictable outcomes.

---

## 3. Demographic Fairness Metrics

### 3.1 Metrics and Definitions

All metrics are computed over _K_ synthetic demographic groups.

| Metric | Formula | Reference |
|--------|---------|-----------|
| **DPD** (Demographic Parity Difference) | max_i(FAR_i) − min_i(FAR_i) | Statistical Parity, Dwork et al. (2012) |
| **EOD** (Equal Opportunity Difference) | max_i(FRR_i) − min_i(FRR_i) | Hardt et al. (2016) |
| **EqOdds** (Equalised Odds Difference) | max(DPD, EOD) | Hardt et al. (2016) |
| **DIR** (Disparate Impact Ratio) | min_i(FAR_i) / max_i(FAR_i) | EEOC 4/5ths rule |

### 3.2 Civil Rights Significance

FRR disparity (EOD) is the primary civil rights concern: groups with higher FRR are denied
access more frequently. If the groups correspond to protected characteristics under the UK
Equality Act 2010 (race, disability, sex, age, etc.), a statistically significant EOD may
constitute **indirect discrimination** under s.19 of that Act.

FAR disparity (DPD) reflects differential security risk: some groups face a higher probability
of identity spoofing by an attacker presenting their characteristics.

### 3.3 Fairness Thresholds

| Verdict | Condition |
|---------|-----------|
| **FAIR** | DPD < 0.05 AND EOD < 0.05 AND DIR ≥ 0.80 |
| **BIASED** | EqOdds ≥ 0.10 OR DIR < 0.60 |
| **MARGINAL** | otherwise |

The 5% DPD/EOD tolerance reflects operational noise; the DIR < 0.60 red flag is well below the
EEOC 4/5ths threshold. The EqOdds ≥ 0.10 threshold corresponds to a 10% performance gap,
which is both statistically and practically significant in real deployments.

**Reference:** Hardt, M., Price, E., & Srebro, N. (2016). Equality of Opportunity in Supervised
Learning. _NeurIPS 2016_.

---

## 4. Attack Simulation Model

### 4.1 CVSS v3.1 Adaptation for Biometrics

The CVSS v3.1 Base Score formula uses six metrics (AV, AC, PR, UI, S, C/I/A). For biometric
systems, the C/I/A impact triad is replaced with:

- **Identity Spoofing Likelihood** (analogous to Confidentiality impact)
- **Template Compromise Severity** (analogous to Integrity impact)
- **Data Subject Harm** (analogous to Availability impact, extended to privacy harm)

Base success rates are taken from NIST FRVT PAD 2020 and ISO/IEC 30107-3:2023.

### 4.2 Mitigation Reduction Factors

| Control | Attack | Reduction Factor |
|---------|--------|-----------------|
| Active liveness (challenge-response) | PAD-001, PAD-002, PAD-003 | ×0.05–0.10 |
| Passive liveness | PAD-001, PAD-002, PAD-003 | ×0.30 |
| Cancelable biometrics | DIG-002 | ×0.05 |
| Homomorphic encryption | DIG-002 | ×0.02 |
| Secure sketch | DIG-002 | ×0.08 |
| TLS in transit | DIG-003 | ×0.05 |

### 4.3 References

- NIST FRVT PAD 2020 — _Presentation Attack Detection for Facial Biometrics_ (Ngan et al.)
- ISO/IEC 30107-3:2023 — _Biometric presentation attack detection — Part 3: Testing and reporting_
- Sharif, M. et al. (2016). Accessorize to a crime: Real and stealthy attacks on state-of-the-art face recognition. _ACM CCS 2016_.
- Korshunov, P. & Marcel, S. (2018). DeepFakes: a New Threat to Face Recognition? _arXiv:1812.08685_.

---

## 5. GDPR Article 9 Assessment

See [GDPR_BIOMETRIC_REFERENCE.md](GDPR_BIOMETRIC_REFERENCE.md) for the full Art.9 framework.

The assessment uses a weighted scoring model identical to the gdpr-security-mapper project
(2026). The satisfied threshold is fixed at **0.90** for all biometric
systems — biometric data is always special category data under UK GDPR Art.9(1), with no lower
mode.

Risk rating maps: SATISFIED ≥ 90% → LOW; PARTIAL 45–89% → MEDIUM/HIGH; GAP < 45% → CRITICAL.

---

## 6. Synthetic Data Generation

Synthetic score distributions are generated using the standard two-Gaussian overlap model
(Daugman 2003). The separation between Gaussian means is calibrated to target a given EER:

```
separation = −2σ × Φ⁻¹(EER_target)
```

where Φ⁻¹ is the standard normal quantile function and σ = 0.10 (fixed variance).
Seeds are fixed (42, 100, 200) for full reproducibility.

This synthetic approach is itself a GDPR Art.5(1)(c) data minimisation demonstration: the
entire framework can be evaluated, published, and reproduced without holding any real biometric
data.
