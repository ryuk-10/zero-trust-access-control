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
| Detection rate (recall) | **99.5%** (398 / 400 attacks) |
| Precision | **100%** |
| False-positive rate | **0%** (0 / 2,000 legitimate) |
| F1 score | **0.997** |
| Per-request scoring latency | **~6–8 ms** (well inside the 50 ms budget) |

Per-attack-type detection: credential stuffing 100% · insider threat 100% · impossible travel
100% · data exfiltration 100% · privilege escalation 97.5%.

*These figures come from a controlled synthetic evaluation; a diverse, real deployment would be
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
| `demo.sh` | Live demo: 5 normal + 5 attack requests through the running system |
| `run.sh` / `stop.sh` | Start / stop Keycloak and the Flask app |
| `test_core.py` | Unit tests + a reproducibility regression |

## Quick start

```bash
pip install -r requirements.txt

python evaluate.py     # reproducible accuracy + latency (writes evaluation_results.csv)
pytest -q              # run the tests

python app.py          # start the service (trains a model on first run)
./run.sh               # start Keycloak + Flask, then:
./demo.sh              # live demo through the running system
./stop.sh              # stop everything
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

Honest finding from `analyze.py`: attacks that mimic a user's normal behaviour and only trip a
single endpoint flag currently evade detection — closing that gap is on the roadmap.

## License

MIT — see [LICENSE](LICENSE).
