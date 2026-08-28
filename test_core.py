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
    assert tp >= 397 and fn <= 3     # ~398/400 = 99.5% detection
    assert precision == 1.0          # no false positives -> 100% precision
    assert fpr == 0.0                # 0% false-positive rate


if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items())
             if k.startswith("test_") and callable(v)]
    for t in tests:
        t(); print("PASS", t.__name__)
    print(f"\n{len(tests)}/{len(tests)} tests passed")
