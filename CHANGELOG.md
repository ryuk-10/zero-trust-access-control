# Changelog

## v1.3.0
New features (continued development):
- **Step-up policy** (`config.STEP_UP_ON_HIGH_SEVERITY`): a single high-severity
  flag (privilege escalation or bulk export) now forces at least MFA even on a low
  score. This closes part of the low-and-slow evasion gap `analyze.py` surfaced:
  adversarial evasion detection improved from 0/400 to 240/400 (60%), and the main
  evaluation rose from 398/400 to **400/400** detection while precision and the
  false-positive rate stayed at 100% / 0% (normal traffic never raises these flags).
- **Audit dashboard** at `GET /dashboard`: a self-contained HTML page (no external
  assets) that polls `/audit/stats|logs|alerts` and shows live decisions and alerts.
  Delivers the report's stretch goal.
- **Model benchmark** (`benchmark_models.py`): puts Isolation Forest, Local Outlier
  Factor and One-Class SVM on the same one-class footing. Honest finding — on the
  features alone LOF/OC-SVM reach a higher ROC-AUC than IF (1.000 vs 0.937); the
  shipped system closes that gap with the rule boosters. Logged as future work.
- Added a `test_step_up_policy` unit test; tightened the reproducibility regression
  to the new 400/400 detection.

## v1.2.0
- Added `analyze.py`: ROC-AUC / PR-AUC, a threshold sweep, a composite-weight
  grid-search, and an adversarial "low-and-slow" evasion test (saves
  `analysis_roc_pr.png`).
- Added `Dockerfile`, `docker-compose.yml` and `.dockerignore` (Keycloak + app).
- Made `KEYCLOAK_URL` and the bind `HOST` environment-overridable.
- Added `ROADMAP.md`; expanded the README's continued-development section.
- No change to the shipped model or the reported numbers.

## v1.1.0
- Added `test_core.py`: unit tests for scoring/policy plus a reproducibility
  regression that guards the reported detection results (398/400, 100% precision, 0% FPR).
- Added GitHub Actions CI (`.github/workflows/ci.yml`) running the tests on every push.
- Pinned dependency versions in `requirements.txt` for reproducible installs.
- Expanded README (results, architecture, project structure, reproducibility, limitations).
- Added MIT LICENSE and this changelog; tidied `.gitignore`.
- No change to the model, scoring, thresholds, features, or reported numbers.

## v1.0.0
- Initial release: single Flask app (config, db, engine, app) implementing a
  NIST SP 800-207 PEP/PDP with an unsupervised Isolation Forest + rule boosters,
  three-tier decisions, live demo (`demo.sh`), and reproducible evaluation (`evaluate.py`).
