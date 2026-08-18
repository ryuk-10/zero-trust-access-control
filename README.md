# Adaptive Zero-Trust Access Control

Behaviour-based Zero-Trust access control that scores every HTTP request in real time and returns ALLOW, step-up MFA, or DENY. An unsupervised Isolation Forest learns each user's normal behaviour and is combined with six rule-based boosters and a time-of-day factor into a single 0-1 risk score. It implements the NIST SP 800-207 Policy Enforcement Point / Policy Decision Point split in a single lightweight Flask app, with Keycloak for identity and SQLite for storage.

## Files

- config.py  - all tuneable settings (thresholds, weights, feature list)
- db.py      - SQLite layer (access logs, user baselines, alerts, model versions)
- engine.py  - feature extraction, risk scoring, the ALLOW/MFA/DENY decision, data generators
- app.py     - Flask web layer and Policy Enforcement Point
- evaluate.py - reproducible accuracy and latency evaluation over 2,400 requests
- demo.sh    - live demo: 5 normal and 5 attack requests through the running app

## Decision tiers

- ALLOW: score below 0.45
- MFA_REQUIRED: score 0.45 to 0.70
- DENY: score above 0.70, or four or more red flags on one request

## Run

    pip install -r requirements.txt
    python app.py        # start the service (trains a model on first run)
    python evaluate.py   # reproducible accuracy and latency evaluation
    ./demo.sh            # live demo through the running app
