# Key Findings — MSc Biometric Authentication Research (CETM44)

Plain-English summary of findings from the biometric authentication security and usability
analysis, with implications for organisations processing biometric data under UK GDPR
Article 9.

**Research scope:** Synthetic score distributions only — no real participant biometric data
(Art.5(1)(c) data minimisation).

---

## 1. Security effectiveness varies sharply by system quality

| System proxy | Approx. EER | Implication |
|--------------|-------------|-------------|
| High accuracy | ~1% | Suitable for high-assurance access control with appropriate controls |
| Medium accuracy | ~5% | Usable for low-risk use cases; DPIA must reflect residual impersonation risk |
| Low accuracy | ~15% | Unacceptable for production Art.9 processing without major remediation |

**Finding:** EER is not a standalone metric — it directly drives GDPR check **A9-022**
(DPIA residual risk). Organisations must link performance test results to their Article 35
DPIA, not treat them as purely technical benchmarks.

---

## 2. Usability and security are coupled through FRR

Higher false rejection rates (FRR) degrade user experience: legitimate users are denied
access. In workplace biometric access control, elevated FRR disproportionately affects
certain user groups and creates operational friction (help-desk load, workarounds).

**Finding:** Usability analysis is a security and compliance requirement, not a UX
afterthought. FRR disparity (Equalised Odds Difference) feeds GDPR check **A9-061**
(potential discrimination under Equality Act 2010 s.19).

---

## 3. Demographic bias can persist even in "accurate" systems

NIST FRVT 2019 demonstrated that commercial face recognition systems show significant
performance variation across demographic groups. This analysis confirms that unequal FAR/FRR
across groups creates both security risk (DPD) and civil-rights risk (EOD).

| Verdict | Meaning |
|---------|---------|
| FAIR | EqOdds < 10%, DIR ≥ 0.80 |
| MARGINAL | Borderline — requires monitoring and potential remediation |
| BIASED | EqOdds ≥ 10% or DIR < 0.80 — likely Art.9 and Equality Act concern |

**Finding:** Controllers must test fairness on deployment-representative populations, not
only aggregate accuracy. A low overall EER does not prove equitable treatment.

---

## 4. Attack resilience depends on architectural controls, not algorithm alone

Seven attack vectors (presentation attacks, digital spoofing, infrastructure compromise)
show that algorithm accuracy alone does not determine security posture:

- **PAD + liveness detection** reduces presentation attack success by ~95%
- **Cancelable biometrics** reduces template database injection from ~90% to ~5%
- **TLS in transit** reduces score tampering from ~80% to ~5%

**Finding:** Art.32 security measures are independently assessable. Attack vulnerability
scores feed GDPR check **A9-042**. Systems without PAD, template protection, or TLS fail
Art.32 checks regardless of EER.

---

## 5. GDPR Art.9 compliance is quantifiable and metric-linked

The three sample configurations illustrate a compliance spectrum:

| Configuration | Typical outcome | Primary gaps |
|---------------|-----------------|--------------|
| Face (compliant) | SATISFIED, LOW risk | Minor partial scores on subject rights |
| Fingerprint (partial) | PARTIAL, MEDIUM risk | Missing PAD, incomplete DPIA documentation |
| Iris (research) | GAP/CRITICAL | No lawful basis, no DPIA, high EER, no PAD |

**Finding:** Biometric data is **always** Art.9 special category data. The satisfied
threshold is fixed at **90%** — there is no "low-risk biometric" mode. Organisations
cannot rely on purpose limitation alone; lawful basis under Art.9(2) must be documented
and defensible.

---

## 6. Data minimisation is demonstrable

This repository analyses biometric *performance* using synthetic comparison scores only.
No biometric images, templates, or participant identifiers are stored.

**Finding:** Technical teams can conduct rigorous security and fairness analysis without
holding special category data — supporting Art.5(1)(c) data minimisation by design.

---

## Implications for practitioners

1. **Before deployment:** Complete DPIA (Art.35) with EER and attack assessment results
2. **During operation:** Monitor FRR disparity and EqOdds on production-representative data
3. **Architecture:** Implement PAD, cancelable templates, and TLS — not optional extras
4. **Documentation:** Map each control to a specific GDPR obligation cluster (see
   `docs/GDPR_BIOMETRIC_REFERENCE.md`)
5. **Lawful basis:** Document Art.9(2) condition explicitly — consent alone is rarely
   sufficient in employment contexts (ICO guidance)

---

*Full reproducible analysis: see `notebooks/` and `docs/METHODOLOGY.md`.*
