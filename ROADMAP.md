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
- **v1.4.0** — offline geolocation on the live path (`geoip.py`), Prometheus-style
  `/metrics` endpoint, and a unified `zt.py` CLI.
- **v1.5.0** — structured JSON logging (`observability.py`), request-level tracing
  (`X-Request-ID`), and basic hardening (security headers / CSP).
- **v1.6.0** — one-command stack: Keycloak realm/client/user auto-import
  (`keycloak/realm-export.json`), so `docker compose up --build` runs end-to-end
  with the JWT-protected routes working out of the box.
- **v1.7.0** — Track C robustness: two more attack types (`session_hijack`,
  `api_enumeration`), a session-level velocity detector for flagless low-and-slow
  harvests, and cost-based threshold selection (`robustness.py`).

## Track A — Make it real (engineering / product)
- [~] Real geolocation on the live path (v1.4.0): `geoip.py` resolves country/IP to
      coordinates offline; still to do is a real GeoIP (MaxMind/GeoLite2) database
      for IP-level accuracy instead of country centroids.
- [x] Finish the Docker stack: auto-import a Keycloak realm/client/user so the
      protected routes work with `docker compose up` and nothing else — done in v1.6.0.
- [x] Small audit dashboard (recent decisions + alerts) — done in v1.3.0 (`/dashboard`).
- [x] Structured logging, `/metrics`, request-level tracing, basic hardening —
      done: `/metrics` (v1.4.0), JSON logging + `X-Request-ID` + security headers (v1.5.0).

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
- [x] Low-and-slow evasion gap: step-up (v1.3.0) took adversarial detection from
      0/400 to 240/400; the flagless residual is now addressed at the session level
      by the velocity detector in `robustness.py` (v1.7.0), which catches sustained
      harvests the per-request engine cannot. Documented residual: a single perfectly
      mimicked request is fundamentally uncatchable at the request level.
- [x] More attack types; cost-based threshold selection — done in v1.7.0
      (`session_hijack`, `api_enumeration`; cost-based threshold sweep in `robustness.py`).
- [x] Expand the benchmark suite (`benchmark_models.py` v1.3.0, `robustness.py` v1.7.0).
      CI workflow is written (`.github/workflows/ci.yml`) but not yet pushed — the
      current token lacks the `workflow` scope; enable via the GitHub UI or a scoped token.
