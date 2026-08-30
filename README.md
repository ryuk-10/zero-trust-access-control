# Adaptive Zero-Trust Access Control

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

Behaviour-based Zero-Trust access control that scores **every HTTP request** in real time and
returns **ALLOW**, step-up **MFA**, or **DENY**. An unsupervised Isolation Forest learns each
user's normal behaviour and is combined with six rule-based boosters and a time-of-day factor
into a single 0–1 risk score. It implements the NIST SP 800-207 Policy Enforcement Point /
Policy Decision Point split in a single lightweight Flask app, with Keycloak for identity and
SQLite for storage.

> MEng Cybersecurity project, University of Limerick — Ishaan Shanbhag.

## Results (reproducible synthetic evaluation)

Measured on 2,400 requests (2,000 legitimate + 400 attacks, across 20 users):

| Metric | Value |
|---|---|
| Detection rate (recall) | **100%** (400 / 400 attacks) |
| Precision | **100%** |
| False-positive rate | **0%** (0 / 2,000 legitimate) |
| F1 score | **1.000** |
| Per-request scoring latency | **~6–8 ms** (well inside the 50 ms budget) |

Per-attack-type detection: credential stuffing 100% · insider threat 100% · impossible travel
100% · data exfiltration 100% · privilege escalation 100%.

*The dissertation baseline was 99.5% (398/400) — tag `v1.1.0`. The v1.3.0 step-up policy
(a single high-severity flag forces MFA) catches the two previously-missed privilege-escalation
attacks, taking detection to 400/400 with no change to precision or the false-positive rate.
These figures come from a controlled synthetic evaluation; a diverse, real deployment would be
expected to show a higher (non-zero) false-positive rate.*

## How it decides

Each request becomes **13 behavioural features** (time, request rates, geolocation, device,
endpoint type, latency). The risk score blends three parts:

```
risk = 0.40 · anomaly(model) + 0.35 · boosters(rules) + 0.25 · time-of-day
```

and maps to three tiers, with a deterministic override:

- **ALLOW** — score < 0.45
- **MFA_REQUIRED** — 0.45 ≤ score ≤ 0.70
- **DENY** — score > 0.70, **or** four or more red flags on a single request

The six rule boosters: new device, new location, abnormal hour, bulk data access,
privilege escalation, high request rate.

## Project structure

| File | Role |
|---|---|
| `config.py` | All tuneable settings (thresholds, weights, booster values, feature list) |
| `db.py` | SQLite layer (access logs, per-user baselines, audit alerts, model versions) |
| `engine.py` | Feature extraction, risk scoring, the ALLOW/MFA/DENY decision, and the synthetic-data generators |
| `app.py` | Flask web layer + Policy Enforcement Point (`require_auth`) |
| `evaluate.py` | Reproducible offline accuracy + latency evaluation over 2,400 requests |
| `analyze.py` | Deeper analysis: ROC/PR-AUC, threshold sweep, weight grid-search, evasion test |
| `benchmark_models.py` | Compares Isolation Forest vs Local Outlier Factor vs One-Class SVM |
| `geoip.py` | Offline, dependency-free country -> coordinates resolver for the live path |
| `zt.py` | Unified CLI: `evaluate` / `analyze` / `benchmark` / `train` / `test` / `serve` |
| `demo.sh` | Live demo: 5 normal + 5 attack requests through the running system |
| `run.sh` / `stop.sh` | Start / stop Keycloak and the Flask app |
| `test_core.py` | Unit tests + a reproducibility regression |

The Flask app also serves a live audit dashboard at **`/dashboard`** and
Prometheus-style metrics at **`/metrics`** (both no-auth, no external assets).

## Quick start

```bash
pip install -r requirements.txt

# Unified CLI (v1.4.0):
python zt.py evaluate    # reproducible accuracy + latency (writes evaluation_results.csv)
python zt.py analyze     # ROC/PR-AUC, threshold sweep, evasion test
python zt.py benchmark   # Isolation Forest vs LOF vs One-Class SVM
python zt.py test        # run the tests
python zt.py serve       # start the service (dashboard at /dashboard, metrics at /metrics)

# Live demo through Keycloak + Flask:
./run.sh && ./demo.sh && ./stop.sh
```

## Reproducibility

`evaluate.py` fixes the random seed and scores the same 2,400-request dataset through the exact
pipeline the live guard uses, so anyone can reproduce the numbers above from a single command.
`test_core.py` includes a regression test that asserts the detection results have not drifted.

## Limitations & future work

The evaluation uses synthetic, fairly homogeneous users and self-generated attacks, and accuracy
relies on each user first having an established baseline. Future work: evaluate on diverse and
real user populations, validate on real access logs, adapt thresholds per role, and integrate
alerts with enterprise SIEM tooling.

## Continued development (post-submission)

The as-submitted version is tagged `v1.1.0`. Ongoing work lives on `main`; see [`ROADMAP.md`](ROADMAP.md).

- **`analyze.py`** — deeper evaluation: ROC-AUC / PR-AUC, a threshold sweep, a weight
  grid-search, and an adversarial "low-and-slow" evasion test. Run `python analyze.py`
  (writes `analysis_roc_pr.png`).
- **`Dockerfile` + `docker-compose.yml`** — bring the stack up locally with
  `docker compose up --build` (app on :5001, Keycloak on :8080). You still need to create
  the Keycloak realm/client/user for the JWT-protected routes.
- **Step-up policy (v1.3.0)** — `config.STEP_UP_ON_HIGH_SEVERITY` makes a single
  high-severity flag (privilege escalation / bulk export) force at least MFA. This lifted
  adversarial evasion detection from 0/400 to 240/400 and main detection to 400/400, with no
  effect on the false-positive rate.
- **Audit dashboard (v1.3.0)** — `GET /dashboard`, a self-contained live view of decisions
  and alerts.
- **Real geolocation (v1.4.0)** — `geoip.py` resolves a country hint / IP to real coordinates
  on the live path (previously hard-coded to 0,0); pluggable for a real GeoIP database.
- **`/metrics` + unified CLI (v1.4.0)** — Prometheus-style metrics at `GET /metrics`, and a
  single `zt.py` entry point for every task.
- **`benchmark_models.py` (v1.3.0)** — model comparison. Honest finding: on the features
  alone, LOF and One-Class SVM reach a higher ROC-AUC than Isolation Forest (1.000 vs 0.937);
  the shipped system closes that gap with its rule boosters. Flagged as future work.

Remaining honest gap: evasive attacks that raise *no* flag at all (mimicking a normal endpoint)
still slip through — closing that needs behavioural sequence / velocity modelling (roadmap).

## License

MIT — see [LICENSE](LICENSE).
