# Changelog

## v1.7.0
New features (continued development) - Track C: robustness & evaluation:
- **More attack types** (`engine.make_attack`): `session_hijack` (stolen token reused
  from a new device, otherwise blending in) and `api_enumeration` (scraping at an
  elevated, sometimes sub-threshold rate). The default training/eval mix is unchanged,
  so the reported headline numbers stay stable.
- **`robustness.py`** with a `zt.py robustness` sub-command, in three parts:
  - Extended per-type detection over the full attack suite. Honest finding:
    `session_hijack` is caught 0% (only a new-device tell), `api_enumeration` ~54%.
  - A session-level **velocity detector** that catches flagless low-and-slow harvests
    the per-request engine misses entirely (100% of sustained campaigns), at a measured
    ~13% false-positive cost on the heaviest legitimate users. A single perfectly
    mimicked request remains fundamentally uncatchable at the request level.
  - **Cost-based threshold selection**: sweeps the ALLOW cut and picks the threshold
    minimising expected cost for several false-negative : false-positive ratios.
- Added `test_new_attack_types` and `test_velocity_detector` (13 tests total).

## v1.6.0
New features (continued development) - one-command stack:
- **Keycloak realm auto-import** (`keycloak/realm-export.json`): the `zerotrust`
  realm, the public `zt-app` client (direct access grants + an audience mapper so
  tokens carry `aud: zt-app`), and a test user `alice` / `password123` are created
  automatically on startup.
- **`docker compose up --build` now works end-to-end**: Keycloak imports the realm
  (`start-dev --import-realm`), a tool-free TCP healthcheck gates startup, and the
  app waits for Keycloak to be healthy before starting. The JWT-protected routes
  work with no manual Keycloak configuration.
- Completes the Track A Docker/Keycloak item.

## v1.5.0
New features (continued development) - observability & hardening:
- **Structured JSON logging** (`observability.py`): every scored request is logged
  as a one-line JSON `access_decision` event (request id, user, endpoint, decision,
  risk score, flags, latency), ready to ship to a log aggregator. Dependency-free.
- **Request-level tracing**: each request gets an `X-Request-ID` (honouring an
  incoming one from a load balancer, or minting a fresh one), echoed on the
  response and included in the structured log.
- **Basic hardening**: standard security headers on every response
  (`X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, `Cache-Control`,
  and a `Content-Security-Policy` that blocks external sources while allowing the
  dashboard's own inline assets).
- Added `test_security_headers_and_request_id`; completes the Track A
  logging / tracing / hardening item.

## v1.4.0
New features (continued development):
- **Real geolocation on the live path** (`geoip.py`): the running app previously
  sent `geo_lat/geo_lon = 0.0`, so the two geographic features were inert in
  production. A dependency-free, offline country-centroid resolver now turns a
  country hint (or a private/loopback IP) into real coordinates, wired into the PEP
  context builder. Pluggable so a real GeoIP database can slot in later.
- **`/metrics` endpoint**: Prometheus-style plaintext metrics (request totals by
  decision, alert count, mean scoring latency) for scraping by Prometheus/Grafana.
- **Unified CLI** (`zt.py`): one entry point with sub-commands `evaluate`,
  `analyze`, `benchmark`, `train`, `test`, `serve`.
- Added `test_geoip_resolver`.

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
