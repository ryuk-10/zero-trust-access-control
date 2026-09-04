"""
Unit tests + a reproducibility regression for the Zero-Trust engine.

Run either way:
    python test_core.py      # standalone
    pytest -q                # CI

The reproducibility test protects the headline numbers reported in the
dissertation: 398/400 attacks detected (99.5%), 100% precision, 0% FPR.
"""
import os
import evaluate                 # sets config.DB_PATH to a throwaway file, imports engine + db
engine = evaluate.engine
db = evaluate.db
config = evaluate.config


def _fresh_db():
    for suf in ("", "-wal", "-shm"):
        p = config.DB_PATH + suf
        if os.path.exists(p):
            os.remove(p)
    db.init_db()


# ---- policy / scoring logic -------------------------------------------------
def test_thresholds():
    assert engine.decide(0.30)["action"] == "ALLOW"
    assert engine.decide(0.55)["action"] == "MFA_REQUIRED"
    assert engine.decide(0.80)["action"] == "DENY"


def test_critical_flag_override():
    flags = ["NEW_DEVICE", "NEW_LOCATION", "ABNORMAL_HOUR", "PRIVILEGE_ESCALATION"]
    assert engine.decide(0.30, flags)["action"] == "DENY"   # 4+ flags -> deny


def test_step_up_policy():
    # v1.3.0: a single high-severity flag forces at least MFA even on a low score.
    d = engine.decide(0.30, ["PRIVILEGE_ESCALATION"])
    assert d["action"] == "MFA_REQUIRED" and d["rule"] == "STEP_UP_HIGH_SEVERITY"
    assert engine.decide(0.30, ["BULK_DATA_ACCESS"])["action"] == "MFA_REQUIRED"
    # A non-high-severity flag on a low score stays ALLOW (no over-blocking).
    assert engine.decide(0.30, ["ABNORMAL_HOUR"])["action"] == "ALLOW"
    assert engine.decide(0.30, [])["action"] == "ALLOW"


def test_boosters_add_up_and_cap():
    assert engine.booster_total([]) == 0.0
    assert engine.booster_total(["NEW_DEVICE"]) == 0.25
    assert engine.booster_total(
        ["NEW_DEVICE", "NEW_LOCATION", "PRIVILEGE_ESCALATION",
         "BULK_DATA_ACCESS", "HIGH_REQUEST_RATE", "ABNORMAL_HOUR"]) <= 1.0


def test_time_factor():
    assert engine.time_factor(14) == 0.1   # business hours
    assert engine.time_factor(7) == 0.3    # edge
    assert engine.time_factor(3) == 0.6    # night


def test_score_weights_sum_to_one():
    assert round(config.W_ANOMALY + config.W_RULES + config.W_DECAY, 6) == 1.0


def test_feature_extraction_and_flags():
    _fresh_db()
    db.update_user_baseline("u-test", "known-device", "IE", 14)
    ctx = {"keycloak_id": "u-test", "hour_of_day": 3, "endpoint": "/api/admin/users",
           "geo_country": "RU", "device_fingerprint": "evil", "requests_last_1m": 2}
    feats, flags = engine.extract_features(ctx)
    assert len(feats) == 13
    for f in ("NEW_DEVICE", "NEW_LOCATION", "ABNORMAL_HOUR", "PRIVILEGE_ESCALATION"):
        assert f in flags


def test_security_headers_and_request_id():
    # v1.5.0: every response carries hardening headers and a request id.
    import app as A
    A.start_up()
    client = A.app.test_client()
    r = client.get("/health")
    assert r.headers.get("X-Content-Type-Options") == "nosniff"
    assert r.headers.get("X-Frame-Options") == "DENY"
    assert "Content-Security-Policy" in r.headers
    assert r.headers.get("X-Request-ID")                      # one was minted
    # An incoming request id is honoured (end-to-end tracing).
    r2 = client.get("/health", headers={"X-Request-ID": "trace-abc"})
    assert r2.headers.get("X-Request-ID") == "trace-abc"


def test_external_dataset_rows():
    # v1.8.0: the independent benchmark generator yields well-formed rows.
    # (Import is side-effect-free; it does not touch config paths.)
    import make_external_dataset as mk
    normal = mk.normal_rows(20)
    attacks = mk.attack_rows("insider_threat", 5)
    assert all(len(r) == 8 for r in normal + attacks)       # 8-column schema
    assert all(r[7] == 0 for r in normal)                   # label column
    assert all(r[7] == 1 for r in attacks)


def test_new_attack_types():
    # v1.7.0: the extra attack generators produce valid, labelled 13-feature rows.
    for kind in ("session_hijack", "api_enumeration"):
        rec = engine.make_attack(kind, engine.NORMAL_USERS[0])
        assert rec["label"] == 1
        feats, _flags = engine.extract_features(rec)
        assert len(feats) == 13


def test_velocity_detector():
    # v1.7.0: a sustained single-account request volume trips the session detector,
    # while a short burst does not.
    import robustness
    det = robustness.VelocityDetector(window=40, max_requests=30)
    flagged = any(det.observe("u1") for _ in range(50))
    assert flagged
    calm = robustness.VelocityDetector(window=40, max_requests=30)
    assert not any(calm.observe("u2") for _ in range(10))


def test_geoip_resolver():
    import geoip
    # A country hint resolves to that country's centroid (not 0,0).
    ru = geoip.resolve(country_hint="RU")
    assert ru["country"] == "RU" and ru["lat"] != 0.0 and ru["lon"] != 0.0
    # Case-insensitive.
    assert geoip.resolve(country_hint="ie")["country"] == "IE"
    # A private / loopback IP falls back to the service's own country.
    assert geoip.resolve(ip="127.0.0.1")["country"] == geoip.DEFAULT_COUNTRY
    # An unknown public IP with no hint stays unresolved (0,0).
    unk = geoip.resolve(ip="8.8.8.8")
    assert unk["country"] == "" and unk["lat"] == 0.0 and unk["lon"] == 0.0


def test_synthetic_counts_and_labels():
    normal = engine.generate_normal(100)
    attacks = engine.generate_attacks(20)
    assert len(normal) == 100 and all(r["label"] == 0 for r in normal)
    assert len(attacks) == 20 and all(r["label"] == 1 for r in attacks)


# ---- reproducibility regression (guards the reported results) ---------------
def test_reproducible_detection():
    _fresh_db()
    evaluate.ensure_model()
    evaluate.setup_baselines()
    ds = evaluate.build_dataset(2000, 80)
    tp = fp = fn = tn = 0
    for rec in ds:
        dec, _flags, _ms = evaluate.score(rec)
        detected = dec["action"] != "ALLOW"
        if rec["label"] == 1:
            tp += detected; fn += (not detected)
        else:
            fp += detected; tn += (not detected)
    recall = tp / (tp + fn)
    precision = tp / (tp + fp)
    fpr = fp / (fp + tn)
    print(f"recall={recall:.4f} precision={precision:.4f} fpr={fpr:.4f} "
          f"(tp={tp} fp={fp} fn={fn} tn={tn})")
    # v1.3.0 step-up policy catches the two privilege-escalation attacks that
    # previously slipped through, taking detection from 398/400 to 400/400.
    assert tp >= 398 and fn <= 2     # 400/400 with a small margin
    assert precision == 1.0          # no false positives -> 100% precision
    assert fpr == 0.0                # 0% false-positive rate


if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items())
             if k.startswith("test_") and callable(v)]
    for t in tests:
        t(); print("PASS", t.__name__)
    print(f"\n{len(tests)}/{len(tests)} tests passed")
