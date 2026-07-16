# Changelog

All notable changes to this project will be documented in this file.
Format: [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
Versioning: [Semantic Versioning](https://semver.org/).

## [1.0.0] — 2026-07-20

Initial public release.

### Added

**Engine**
- `engine/metrics.py`: FAR, FRR, EER, ROC, DET — all pure functions
- `engine/statistics.py`: Bootstrap CI (n=2000), DeLong AUC comparison, permutation test, ECE
- `engine/bias.py`: DPD, EOD, EqOdds, DIR, calibration by group; fairness verdicts (FAIR/MARGINAL/BIASED)
- `engine/attack.py`: 7 attack vectors (PAD-001–003, PAD-004, DIG-001–003); CVSS-like scoring with PAD/TLS/template protection mitigations
- `engine/gdpr.py`: 22 Art.9 checks across 7 obligation clusters; metric-linked checks A9-022 (EER), A9-042 (vulnerability), A9-061 (EqOdds); `satisfied_threshold = 0.90` fixed

**Models**
- `models/config.py`: `SystemConfig` (Pydantic v2, all-Optional, 6 sub-models)
- `models/results.py`: `EvaluationResult`, `BiasResult`, `AttackResult`, `GDPRReport` (dataclasses)

**Data**
- 3 synthetic CSV files (16,500 rows each): high (EER≈1%), medium (EER≈5%), low (EER≈15%)
- 3 sample YAML configs: face_recognition (compliant), fingerprint (partial), iris (research/non-compliant)

**Interface**
- CLI: 7 subcommands (`evaluate`, `compare`, `bias`, `attack`, `gdpr`, `report`, `serve`, `sample`)
- Streamlit dashboard: 6 tabs (Overview, Performance, Algorithm Comparison, Demographic Bias, Attack Simulation, GDPR Art.9)
- Reporters: Rich console, JSON, ReportLab PDF

**Documentation**
- `docs/METHODOLOGY.md`: full statistical and GDPR methodology with academic citations
- `docs/GDPR_BIOMETRIC_REFERENCE.md`: Art.9 obligation reference table
- `docs/ARCHITECTURE.md`: module map, design principles, extension points
- `CITATION.cff`: CFF v1.2.0 for academic citability
- 4 Jupyter notebooks covering all evaluation domains (data exploration, usability, security effectiveness, GDPR Art.9 mapping)
