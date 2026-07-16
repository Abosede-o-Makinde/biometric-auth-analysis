# GDPR Biometric Reference

Quick reference for UK GDPR obligations applicable to biometric authentication systems,
aligned with the 7 obligation clusters assessed by `biometric-auth-analysis`.

**Primary source:** UK GDPR (retained EU law, Data Protection Act 2018)  
**ICO guidance:** [ico.org.uk/for-organisations/guide-to-data-protection/guide-to-the-general-data-protection-regulation-gdpr/](https://ico.org.uk/for-organisations/guide-to-data-protection/guide-to-the-general-data-protection-regulation-gdpr/)

---

## OBL-1: Art.9(1) — Lawful Basis

**Prohibition:** Processing biometric data for the purpose of uniquely identifying a natural
person is prohibited unless one of the Art.9(2) conditions applies.

| Basis | Condition | Notes |
|-------|-----------|-------|
| `9_2_a` | Explicit consent | Must be freely given, specific, informed, unambiguous. Higher bar than ordinary consent. |
| `9_2_b` | Employment / social security law obligation | Requires UK law authorisation. Common for workplace access control. |
| `9_2_g` | Substantial public interest | Requires UK law basis. Applicable to border control. |
| `9_2_h` | Health/medical purposes | Requires professional secrecy. |
| `9_2_i` | Public health | Must be necessary. |

**ICO position:** Controllers cannot choose a convenient basis — the basis must genuinely apply.
Consent is rarely appropriate where there is a power imbalance (e.g., employer/employee).

---

## OBL-2: Art.5(1)(b)(c) — Purpose Limitation & Data Minimisation

**Art.5(1)(b):** Biometric data collected for one purpose (access control) cannot be processed
for another (marketing, surveillance) without a fresh lawful basis.

**Art.5(1)(c):** Only biometric data adequate, relevant, and limited to what is necessary for
the processing purpose must be collected. This means:
- Derived templates preferred over raw images
- Only modalities necessary for the use case (iris for high-security; face for standard)
- Enrolment quality gates to avoid storing unnecessary retry images

---

## OBL-3: Art.35 — DPIA

**Mandatory for biometric systems:** Art.35(3)(b) requires a DPIA for systematic processing
of special category data at large scale. The ICO has confirmed this applies to most biometric
authentication deployments.

**DPIA must include (Art.35(7)):**
- Description of processing and purposes
- Assessment of necessity and proportionality
- Assessment of risks to data subjects
- Measures to address those risks

**DPO involvement (Art.38):** The DPO must be consulted if appointed. DPO advice must be
documented; if overridden, the reasons must be recorded.

**ICO consultation (Art.36):** If risks cannot be adequately mitigated, the ICO must be
consulted before processing begins. Expected response time: 8 weeks.

**EER and DPIA:** A high EER (> 10%) creates a disproportionate false-rejection risk that
must be addressed in the DPIA under Art.35(7)(c). This is why `biometric-auth-analysis`
check A9-022 is metric-linked.

---

## OBL-4: Art.5(1)(e) — Storage Limitation

**Core principle:** Biometric data must be kept no longer than necessary for the processing
purpose. Unlike ordinary personal data, biometric data cannot be changed if compromised —
this makes proportionate retention especially important.

| Data type | ICO guidance | Risk if retained longer |
|-----------|-------------|------------------------|
| Raw biometric images | Delete immediately after template extraction | Images are themselves Art.9 data; each retained image is an ongoing risk |
| Biometric templates | Delete on termination of relationship + short period | Risk of reuse, breach |
| Match decision logs | Standard data retention policy applies | Lower risk — no biometric content |

**Automated deletion:** Manual processes are error-prone. Automated deletion triggered by
retention period expiry is the expected standard.

---

## OBL-5: Art.32 — Security Measures

Art.32(1)(a) specifically mentions encryption as an appropriate technical measure.
For biometric systems, the expected measures include:

| Control | Level | Rationale |
|---------|-------|-----------|
| Encryption at rest (AES-256) | Baseline | Templates are Art.9 data |
| Cancelable biometrics / homomorphic encryption | Recommended | Stolen encrypted templates can still be replayed if the key is leaked; cancelable templates cannot |
| TLS 1.3 in transit | Baseline | Prevent score interception/substitution |
| ISO/IEC 30107-3 PAD | Required for high-assurance | Presentation attacks are the most common biometric attack vector |
| Immutable audit logging | Baseline | Required to detect misuse and evidence compliance |

**Template protection specifics:**

- **Cancelable biometrics:** The template is a transformed version of the biometric; the
  transform key can be revoked and a new enrolment created. Template is irreversible without key.
- **Homomorphic encryption:** Matching performed in encrypted domain; plaintext template never
  reconstructed during operation.
- **Secure sketch:** Error-tolerant cryptographic commitment; allows matching with privacy
  guarantees (Dodis et al. 2004).

---

## OBL-6: Art.17 / Art.22 — Erasure and Subject Rights

**Art.17 — Right to erasure:** Biometric data subjects can request erasure where:
- Processing was based on consent (Art.9(2)(a)) and consent is withdrawn
- Data is no longer necessary for the purpose
- Processing was unlawful

ICO expects erasure within **one calendar month** (~30 days). Extensions require notification.

**Art.22 — Automated decision-making:** Where biometric systems make or significantly affect
access decisions (building entry, banking, border control), Art.22 rights apply:
- Right to obtain human intervention
- Right to express their point of view
- Right to contest the decision

This is why check A9-052 requires automated decision logic to be documented for access control
use cases.

**Other subject rights:**
- Art.15 — Right of access: subjects can request their biometric template or proof of deletion
- Art.20 — Data portability: less applicable to derived templates (not portable in meaningful form)

---

## OBL-7: Art.9 Bias & Non-Discrimination

**Legal basis:** Art.9 requires proportionate processing. Where biometric systems produce
systematically worse outcomes for groups corresponding to protected characteristics under the
UK Equality Act 2010 (race, disability, sex, age, religion), this may constitute:
- **Indirect discrimination** under s.19 of the Equality Act 2010
- **Unlawful automated decision** under Art.22 where the disparity is systematic

**NIST FRVT 2019 findings:** Significant performance disparities across demographic groups
in commercial face recognition systems — some algorithms had false positive rates 10–100x higher
for certain groups. This is cited in ICO AI and data protection guidance.

**Bias quantification thresholds used in this tool:**

| Metric | FAIR | MARGINAL | BIASED |
|--------|------|----------|--------|
| DPD (FAR spread) | < 5% | 5–10% | > 10% |
| EOD (FRR spread) | < 5% | 5–10% | > 10% |
| EqOdds | < 10% | — | ≥ 10% |
| DIR | ≥ 0.80 | 0.60–0.80 | < 0.60 |

---

## Applicable Standards and Guidance

| Standard | Scope |
|----------|-------|
| UK GDPR (DPA 2018) | Primary legal framework |
| ICO Biometric Data Guidance (2023) | Authoritative ICO position |
| ISO/IEC 19795-1:2021 | Biometric performance testing |
| ISO/IEC 30107-3:2023 | Presentation attack detection |
| NIST SP 800-76-2 | Biometric specs for identity verification |
| NIST FRVT PAD 2020 | PAD benchmarking |
| Equality Act 2010 | Non-discrimination obligations |
| ICO AI and data protection (2022) | AI fairness guidance |
