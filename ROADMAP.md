# Roadmap — continued development

The dissertation version is preserved at tag **v1.1.0**. Everything below is
post-submission work. The guiding aim: move beyond a synthetic proof-of-concept
toward something defensible on real data and runnable end-to-end.

## Done
- **v1.1.0** — tests, pinned deps, MIT license, docs (submission baseline).
- **v1.2.0** — `analyze.py` (ROC/PR-AUC, threshold sweep, weight grid-search,
  adversarial low-and-slow test), Dockerfile + docker-compose, env-overridable
  Keycloak URL / bind host. *No change to the model or reported numbers.*

## Track A — Make it real (engineering / product)
- [ ] Real geolocation on the live path (IP -> country / lat-lon); today the live
      app sends 0,0 so the geo features are inert in production.
- [ ] Finish the Docker stack: auto-import a Keycloak realm/client/user so the
      protected routes work with `docker compose up` and nothing else.
- [ ] Small audit dashboard (recent decisions + alerts) — the report's stretch goal.
- [ ] Structured logging, `/metrics`, request-level tracing, basic hardening.

## Track B — Improve the detection (ML / research)
- [ ] Tune the composite weights and thresholds from data instead of hand-setting
      (the grid-search in `analyze.py` already hints model=0.50/rules=0.25/time=0.25
      reaches F1=1.0 on the synthetic set — validate before adopting).
- [ ] Try Extended Isolation Forest; consider per-role or per-user models.
- [ ] Baseline decay / concept-drift handling (schema needs per-item timestamps).
- [ ] **Validate on a real public dataset** — the biggest credibility jump.

## Track C — Robustness & evaluation
- [ ] Address the low-and-slow evasion gap surfaced by `analyze.py` (e.g. make
      certain sensitive endpoints always require step-up, or weight single
      high-severity flags more).
- [ ] More attack types; cost-based threshold selection; calibration.
- [ ] Expand the benchmark suite and CI coverage.
