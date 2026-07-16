# biometric-auth-analysis

[![CI](https://github.com/Abosede-o-Makinde/biometric-auth-analysis/actions/workflows/ci.yml/badge.svg)](https://github.com/Abosede-o-Makinde/biometric-auth-analysis/actions)
[![Python](https://img.shields.io/badge/python-3.11%20|%203.12-blue)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![GDPR Art.9](https://img.shields.io/badge/GDPR-Art.9%20biometric-red)](docs/GDPR_BIOMETRIC_REFERENCE.md)
[![Cite](https://img.shields.io/badge/cite-CITATION.cff-blue)](CITATION.cff)

**Biometric authentication security evaluation with GDPR Article 9 compliance assessment.**

Grounded in MSc biometric authentication research (CETM44, University of Sunderland).  
The first open-source framework to combine rigorous biometric security evaluation with
GDPR Art.9 compliance quantification.

---

## The problem this solves

| Existing tools | Gap |
|----------------|-----|
| ISO/IEC 19795 test frameworks | No GDPR integration; no bias measurement |
| NIST FRVT benchmarks | Government-only submissions; not reproducible for practitioners |
| GDPR compliance tools | No biometric-specific checks; no metric-linked assessment |
| Academic fairness libraries | No attack simulation; no GDPR output |

**This tool fills all four gaps in a single Python package.**

---

## What it contributes

**1. Metric-linked GDPR compliance:** Three GDPR checks are directly driven by computed metrics.
A high EER triggers `A9-022` (DPIA risk), a high vulnerability score triggers `A9-042` (Art.32),
and bias above threshold triggers `A9-061` (potential discrimination under Equality Act 2010).
No other tool connects biometric performance measurements to legal compliance scores.

**2. Complete security picture:** FAR/FRR/EER analysis, 95% bootstrap confidence intervals,
DeLong AUC comparison (cited in ISO/IEC 19795), demographic bias (Hardt et al. 2016),
and 7-vector attack simulation (NIST FRVT PAD 2020) in a single reproducible pipeline.

**3. GDPR-compliant by design:** The tool uses only synthetic score distributions — no real
biometric images. This is itself an Art.5(1)(c) data minimisation demonstration: all analysis
capabilities are shown without holding special category data.

---

## Research overview

This repository publishes the MSc biometric authentication research (CETM44, University of
Sunderland) as a reproducible, citable analysis toolkit.

**What was studied:** The technical security effectiveness and usability trade-offs of
biometric authentication systems, and how those measurements map to UK GDPR Article 9
obligations for special category biometric data.

**Method:** Synthetic comparison-score distributions (no real biometric images) evaluated
using ISO/IEC 19795-aligned metrics (FAR, FRR, EER, AUC), Hardt et al. (2016) fairness
measures, NIST FRVT PAD attack vectors, and a 22-check Art.9 compliance framework.

**Analysis notebooks** (run in order):

| Notebook | Domain |
|----------|--------|
| [`01_data_exploration.ipynb`](notebooks/01_data_exploration.ipynb) | Data loading and initial distribution analysis |
| [`02_usability_analysis.ipynb`](notebooks/02_usability_analysis.ipynb) | Usability scoring — FRR, false rejections, threshold trade-offs |
| [`03_security_effectiveness.ipynb`](notebooks/03_security_effectiveness.ipynb) | Technical security effectiveness (FAR/FRR/EER) and demographic fairness |
| [`04_gdpr_article9_mapping.ipynb`](notebooks/04_gdpr_article9_mapping.ipynb) | Maps findings to GDPR Article 9 requirements |

See [`docs/METHODOLOGY.md`](docs/METHODOLOGY.md) for full statistical methods and
[`docs/GDPR_BIOMETRIC_REFERENCE.md`](docs/GDPR_BIOMETRIC_REFERENCE.md) for the Art.9
obligation reference.

---

## Key findings

Summary of research conclusions — full plain-English write-up in [`findings/key_findings.md`](findings/key_findings.md):

1. **EER drives DPIA risk** — high error rates trigger GDPR check A9-022; performance testing must feed the Article 35 DPIA, not sit in isolation.
2. **Usability is compliance-relevant** — FRR disparity across groups links to Equality Act 2010 s.19 and GDPR Art.22 (check A9-061).
3. **Aggregate accuracy masks bias** — low overall EER does not prove equitable treatment; EqOdds and DIR must be measured per group.
4. **Architecture controls matter** — PAD, cancelable templates, and TLS determine Art.32 compliance (A9-042) independently of algorithm accuracy.
5. **Art.9 threshold is always 90%** — biometric data is always special category; compliant, partial, and non-compliant configurations are demonstrated in the sample YAML configs.
6. **Analysis without holding biometric data** — synthetic scores demonstrate that rigorous evaluation is possible under Art.5(1)(c) data minimisation.

**Article 9 implications for organisations:** Controllers processing biometric data must
document an Art.9(2) lawful basis, complete a DPIA before deployment, implement Art.32
technical measures (PAD, encryption, template protection), monitor fairness on
representative populations, and link performance metrics to compliance documentation —
not treat security testing and data protection as separate workflows.

---

## Installation

```bash
pip install biometric-auth-analysis
```

Or from source:

```bash
git clone https://github.com/Abosede-o-Makinde/biometric-auth-analysis
cd biometric-auth-analysis
pip install -e ".[dev]"
```

---

## Quick Start

### Demo (no data needed)

```bash
# Evaluate a pre-generated high-accuracy score file
biometric-auth evaluate --scores data/synthetic/scores_high_accuracy.csv

# Full GDPR Art.9 assessment with attack simulation
biometric-auth gdpr --config data/sample_configs/system_face_recognition.yaml \
                    --scores data/synthetic/scores_high_accuracy.csv

# Generate all reports (console + JSON + PDF)
biometric-auth report --config data/sample_configs/system_face_recognition.yaml \
                      --scores data/synthetic/scores_high_accuracy.csv \
                      --output-dir /tmp/bio-report

# Launch Streamlit dashboard
biometric-auth serve
```

### Sample terminal output — GDPR assessment

```
╭─────────────────────────────────────────────────────────────╮
│  GDPR Article 9 Compliance Assessment                       │
│                                                             │
│  CPS Face Recognition Access Control                        │
│  Overall score: 94.2%  |  Status: SATISFIED  |  Risk: LOW  │
│  Satisfied threshold: 90% (Art.9 special category — always) │
│  Generated: 2026-07-20 14:35 UTC                           │
╰─────────────────────────────────────────────────────────────╯

 Obligation  Title                                     Score   Status
 ─────────────────────────────────────────────────────────────────────
 OBL-1       Art.9(1) — Lawful Basis                  100%    SATISFIED
 OBL-2       Art.5(1)(b)(c) — Purpose Limitation      100%    SATISFIED
 OBL-3       Art.35 — DPIA                             93%    SATISFIED
 OBL-4       Art.5(1)(e) — Storage Limitation         100%    SATISFIED
 OBL-5       Art.32 — Security Measures                96%    SATISFIED
 OBL-6       Art.17/Art.22 — Erasure & Rights          88%    PARTIAL
 OBL-7       Art.9 Bias & Non-Discrimination          100%    SATISFIED
```

```
╭─────────────────────────────────────────────────────────────╮
│  Biometric Performance Evaluation                           │
│  ArcFace R100 — face                                        │
╰─────────────────────────────────────────────────────────────╯

 Metric                 Value        95% CI
 ──────────────────────────────────────────────────────
 EER                    0.89%        [0.71%, 1.09%]
 FAR @ EER threshold    0.89%        [0.72%, 1.08%]
 FRR @ EER threshold    0.89%        [0.73%, 1.07%]
 AUC-ROC                0.999821     —
 Genuine pairs          1,500        —
 Impostor pairs         15,000       —
```

---

## CLI Reference

```
biometric-auth evaluate   --scores <csv> [--algorithm <name>] [--output <json>]
biometric-auth compare    --scores <csv> --scores <csv> [--method delong|permutation]
biometric-auth bias       --scores <csv> [--group-col <col>] [--output <json>]
biometric-auth attack     --config <yaml> [--scores <csv>] [--output <json>]
biometric-auth gdpr       --config <yaml> [--scores <csv>] [--output <json>]
biometric-auth report     --config <yaml> --scores <csv> [--output-dir <dir>]
biometric-auth serve      [--port 8501]
biometric-auth sample     [--output <yaml>]
```

---

## YAML Configuration Schema

```yaml
system_name: "My Biometric System"
system_description: "Face recognition for staff access"

algorithm:
  name: "ArcFace R100"
  modality: face          # face | fingerprint | iris | voice | multimodal | unknown
  version: "2.1.0"
  vendor: "InsightFace"

deployment:
  environment: production
  use_case: access_control  # access_control | border_control | banking | healthcare | research
  data_subjects_count: 1200
  art9_basis: "9_2_b"       # 9_2_a | 9_2_b | 9_2_g | 9_2_h | 9_2_i | none
  dpia_completed: true
  dpia_date: "2026-01-20"
  dpo_consulted: true
  transfers_outside_uk_eea: false

retention:
  raw_images_retained: false      # Art.5(1)(e) — delete after template extraction
  retention_period_days: 90
  automated_deletion: true
  deletion_audit_trail: true
  data_minimisation_enforced: true

security:
  encryption_at_rest: true
  encryption_algorithm: "AES-256-GCM"
  tls_in_transit: true
  template_protection: "cancelable"  # cancelable | homomorphic | secure_sketch | none
  anti_spoofing_pad: true
  liveness_detection_type: "active"  # active | passive | challenge_response | none
  audit_logging: true

subject_rights:
  erasure_process_documented: true
  erasure_sla_days: 20
  verified_deletion: true
  automated_decision_logic_documented: true

transparency:
  privacy_notice_published: true
  biometric_collection_notice: true
  lawful_basis_documented: true
```

All fields are optional — missing fields map to PARTIAL (not assessed).

---

## GDPR Art.9 Assessment — 22 checks, 7 obligations

| Obligation | Cluster | Checks | Metric-linked |
|------------|---------|--------|---------------|
| OBL-1 | Art.9(1) — Lawful Basis | A9-001, A9-002 | No |
| OBL-2 | Art.5(1)(b)(c) — Purpose Limitation | A9-010, A9-011, A9-012 | No |
| OBL-3 | Art.35 — DPIA | A9-020, A9-021, A9-022 | **EER** → A9-022 |
| OBL-4 | Art.5(1)(e) — Storage Limitation | A9-030, A9-031, A9-032 | No |
| OBL-5 | Art.32 — Security Measures | A9-040–A9-044 | **Attack score** → A9-042 |
| OBL-6 | Art.17/Art.22 — Erasure & Rights | A9-050, A9-051, A9-052 | No |
| OBL-7 | Art.9 Bias & Non-Discrimination | A9-060, A9-061, A9-062 | **EqOdds** → A9-061 |

**Satisfied threshold:** Always **90%** for biometric systems — biometric data is always
Art.9 special category data. No lower mode.

**Risk rating:** SATISFIED ≥ 90% → LOW | PARTIAL 45–89% → MEDIUM/HIGH | GAP < 45% → CRITICAL

---

## Fairness Metrics

| Metric | Formula | Threshold | Civil rights significance |
|--------|---------|-----------|--------------------------|
| DPD | max(FAR_i) − min(FAR_i) | < 5% | Security risk disparity |
| EOD | max(FRR_i) − min(FRR_i) | < 5% | Denial-of-service disparity (primary concern) |
| EqOdds | max(DPD, EOD) | < 10% | Hardt et al. (2016) |
| DIR | min(FAR_i) / max(FAR_i) | ≥ 0.80 | 4/5ths rule (EEOC / UK equivalent) |

FRR disparity (EOD) is the primary civil rights indicator — groups denied access more
frequently may engage **Equality Act 2010 s.19** (indirect discrimination) and
**GDPR Art.22** automated decision rights.

---

## Attack Simulation

| ID | Attack Type | Category | Base Success |
|----|-------------|----------|-------------|
| PAD-001 | 2D Print Attack | Presentation | 65% |
| PAD-002 | Video Replay | Presentation | 55% |
| PAD-003 | 3D Silicone Mask | Presentation | 30% |
| PAD-004 | Adversarial Patch | Digital | 40% |
| DIG-001 | Deepfake Injection | Digital | 45% |
| DIG-002 | Template DB Injection | Infrastructure | 90% |
| DIG-003 | Score Tampering (MITM) | Infrastructure | 80% |

Active liveness detection reduces PAD-001/002/003 success by ~95%.
Cancelable biometrics reduces DIG-002 to ~5%. TLS reduces DIG-003 to ~5%.

---

## Synthetic Data

Three pre-generated CSV files are included (16,500 rows each, deterministic seeds):

| File | Target EER | Algorithm label |
|------|-----------|-----------------|
| `scores_high_accuracy.csv` | ~1% | `high_accuracy_system` |
| `scores_medium_accuracy.csv` | ~5% | `medium_accuracy_system` |
| `scores_low_accuracy.csv` | ~15% | `low_accuracy_system` |

Columns: `score, label, group, algorithm`. Real biometric images are not stored — this
is itself an Art.5(1)(c) data minimisation demonstration.

---

## Academic Use

This repository is citeable via `CITATION.cff`:

```bibtex
@software{makinde2026biometric,
  author = {Makinde, Abosede},
  title  = {biometric-auth-analysis: Biometric Authentication Security Evaluation
             with GDPR Article 9 Compliance Assessment},
  year   = {2026},
  url    = {https://github.com/Abosede-o-Makinde/biometric-auth-analysis},
  version = {1.0.0}
}
```

Key references implemented:
- **DeLong et al. (1988)** — AUC comparison (ISO/IEC 19795-1 standard method)
- **Hardt et al. (2016)** — Equalised Odds fairness metric
- **NIST FRVT PAD 2020** — Attack base success rates
- **ISO/IEC 30107-3:2023** — PAD testing and reporting
- **ISO/IEC 19795-1:2021** — Biometric performance testing

---

## Roadmap

| Priority | Item | Target |
|----------|------|--------|
| v1.1 | LFW dataset adapter (real-world face benchmark) | Q3 2026 |
| v1.1 | AT&T/ORL database adapter (classic fingerprint benchmark) | Q3 2026 |
| v1.2 | Multi-threshold operating point analysis (ROC operating points) | Q4 2026 |
| v1.2 | Intersectional bias (compound group analysis) | Q4 2026 |
| v2.0 | UK Equality Act 2010 impact assessment report section | 2027 |
| v2.0 | Automated DPIA template generation from assessment output | 2027 |

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Bug reports via [GitHub Issues](https://github.com/Abosede-o-Makinde/biometric-auth-analysis/issues).

For new GDPR checks, use the **New Art.9 check** issue template — all checks must cite
a specific GDPR provision and ICO guidance.

---

## Licence

MIT — see [LICENSE](LICENSE).

*Developed by Abosede Makinde (University of Sunderland).  
MSc biometric authentication research, CETM44.*
