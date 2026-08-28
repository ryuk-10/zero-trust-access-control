# Changelog

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
