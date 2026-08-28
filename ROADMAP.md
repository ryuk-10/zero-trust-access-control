# Roadmap — continued development

The dissertation version is preserved at tag **v1.1.0**. Everything below is
post-submission work. The guiding aim: move beyond a synthetic proof-of-concept
toward something defensible on real data and runnable end-to-end.

## Done
- **v1.1.0** — tests, pinned deps, MIT license, docs (submission baseline).
- **v1.2.0** — `analyze.py` (ROC/PR-AUC, threshold sweep, weight grid-search,
  adversarial low-and-slow test), Dockerfile + docker-compose, env-overridable
  Keycloak URL / bind host. *No change to the model or reported numbers.*
- **v1.3.0** — step-up policy (single high-severity flag forces MFA; evasion
  detection 0/400 -> 240/400, main detection 398/400 -> 400/400 at 0% FPR),
  audit dashboard at `/dashboard`, and `benchmark_models.py` (IF vs LOF vs OC-SVM).

## Track A — Make it real (engineering / product)
- [ ] Real geolocation on the live path (IP -> country / lat-lon); today the live
      app sends 0,0 so the geo features are inert in production.
- [ ] Finish the Docker stack: auto-import a Keycloak realm/client/user so the
      protected routes work with `docker compose up` and nothing else.
- [x] Small audit dashboard (recent decisions + alerts) — done in v1.3.0 (`/dashboard`).
- [ ] Structured logging, `/metrics`, request-level tracing, basic hardening.

## Track B — Improve the detection (ML / research)
- [ ] Tune the composite weights and thresholds from data instead of hand-setting
      (the grid-search in `analyze.py` already hints model=0.50/rules=0.25/time=0.25
      reaches F1=1.0 on the synthetic set — validate before adopting).
- [~] Compare models (`benchmark_models.py`, v1.3.0): on features alone LOF and
      OC-SVM beat IF on ROC-AUC (1.000 vs 0.937) — evaluate augmenting/replacing IF,
      or feeding the rule flags into the model. Also try Extended Isolation Forest
      and per-role / per-user models.
- [ ] Baseline decay / concept-drift handling (schema needs per-item timestamps).
- [ ] **Validate on a real public dataset** — the biggest credibility jump.

## Track C — Robustness & evaluation
- [~] Low-and-slow evasion gap (v1.3.0): step-up on high-severity flags took
      adversarial detection from 0/400 to 240/400. Remaining gap: evasions that
      raise no flag at all (mimicking a normal endpoint) still slip through —
      needs behavioural sequence / velocity modelling.
- [ ] More attack types; cost-based threshold selection; calibration.
- [~] Expand the benchmark suite and CI coverage (`benchmark_models.py` added v1.3.0).
