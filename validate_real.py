#!/usr/bin/env python3
"""
validate_real.py -- validate the engine on an external dataset (v1.8.0).

Reads a CSV of real (or independently-generated) access events, maps the columns
onto the subset of the 13 features they can fill, retrains the Isolation Forest on
the NORMAL training split, and reports detection quality on a held-out test split.
Because it is schema-driven, the same command validates the bundled independent
benchmark today and a real dataset (RBA, CERT, ...) the moment you provide one in
the same schema.

Expected CSV columns:
    timestamp,user_id,country,device,endpoint,request_size_bytes,success,label
(`success` is optional/unused for scoring; `label` is 1 for attack, 0 for normal.)

It does NOT touch the shipped model or database (uses temp paths).

Run:  python validate_real.py [--csv datasets/external_benchmark.csv]
"""
import argparse
import csv as csvmod
import os
import random
from datetime import datetime

import config
# Use throwaway paths so the shipped model/DB are never modified.
config.DB_PATH = "/tmp/ztac_validate.db"
config.MODEL_PATH = "/tmp/ztac_validate_model.pkl"
import db
import engine
import geoip
import numpy as np

# Which of the 13 features an event log like this can and cannot fill.
MAPPED = ["hour_of_day", "day_of_week", "requests_last_1m", "requests_last_5m",
          "requests_last_1h", "request_size_bytes", "geo_lat", "geo_lon",
          "is_new_device", "is_new_location", "is_bulk_access", "is_privilege_escalation"]
UNAVAILABLE = {"response_latency_ms": "no timing column in an access log; set to 0"}


def _epoch(ts):
    try:
        return datetime.fromisoformat(ts).timestamp()
    except ValueError:
        return 0.0


def _load(csv_path):
    """Read the CSV and compute per-user rolling request rates from timestamps."""
    rows = []
    with open(csv_path, newline="") as f:
        for r in csvmod.DictReader(f):
            rows.append({
                "t": _epoch(r["timestamp"]),
                "user": r["user_id"],
                "country": (r.get("country") or "").strip().upper(),
                "device": r.get("device") or "",
                "endpoint": r.get("endpoint") or "",
                "size": int(float(r.get("request_size_bytes") or 0)),
                "label": int(r.get("label") or 0),
            })
    # Rolling rates per user (counts of that user's events in the trailing window).
    by_user = {}
    for r in rows:
        by_user.setdefault(r["user"], []).append(r["t"])
    for u in by_user:
        by_user[u].sort()
    for r in rows:
        times = by_user[r["user"]]
        t = r["t"]
        r["r1m"] = sum(1 for x in times if t - 60 < x <= t)
        r["r5m"] = sum(1 for x in times if t - 300 < x <= t)
        r["r1h"] = sum(1 for x in times if t - 3600 < x <= t)
    return rows


def _context(r):
    """Build the request-context dict engine.extract_features() expects."""
    lat, lon = geoip.country_centroid(r["country"])
    dt = datetime.fromtimestamp(r["t"]) if r["t"] else datetime(2026, 1, 1)
    return {
        "keycloak_id": r["user"],
        "hour_of_day": dt.hour,
        "day_of_week": dt.weekday(),
        "requests_last_1m": r["r1m"], "requests_last_5m": r["r5m"], "requests_last_1h": r["r1h"],
        "request_size_bytes": r["size"],
        "geo_lat": lat, "geo_lon": lon, "geo_country": r["country"],
        "device_fingerprint": r["device"], "endpoint": r["endpoint"],
        "response_latency_ms": 0,          # not available in an access log
    }


def main():
    ap = argparse.ArgumentParser(description="Validate the engine on an external CSV.")
    ap.add_argument("--csv", default=os.path.join(os.path.dirname(__file__),
                    "datasets", "external_benchmark.csv"))
    ap.add_argument("--contamination", type=float, default=0.08)
    args = ap.parse_args()

    if not os.path.exists(args.csv):
        raise SystemExit("No CSV at %s -- run make_external_dataset.py first." % args.csv)

    for suffix in ("", "-wal", "-shm"):
        p = config.DB_PATH + suffix
        if os.path.exists(p):
            os.remove(p)
    db.init_db()

    rows = _load(args.csv)
    normal = [r for r in rows if r["label"] == 0]
    attacks = [r for r in rows if r["label"] == 1]
    random.seed(42)
    random.shuffle(normal)
    cut = int(0.7 * len(normal))
    train_normal, test_normal = normal[:cut], normal[cut:]
    test = test_normal + attacks

    print("=" * 70)
    print("  EXTERNAL DATASET VALIDATION  -  %s" % os.path.basename(args.csv))
    print("=" * 70)
    print("  train (normal): %d   test: %d normal + %d attacks"
          % (len(train_normal), len(test_normal), len(attacks)))

    # Seed baselines from the TRAINING normal only (learn each user's normal).
    for r in train_normal:
        c = _context(r)
        db.update_user_baseline(c["keycloak_id"], c["device_fingerprint"],
                                c["geo_country"], c["hour_of_day"])

    # Retrain the Isolation Forest on the training-normal feature vectors.
    train_vectors = np.array([engine.extract_features(_context(r))[0] for r in train_normal],
                             dtype=float)
    engine.build_and_save(train_vectors, "real-validate", args.contamination)
    engine.load_model()

    # Evaluate on the held-out test split through the real scoring pipeline.
    tp = fp = fn = tn = 0
    per_type_note = {}
    for r in test:
        feats, flags = engine.extract_features(_context(r))
        risk = engine.score_risk(feats, flags)
        detected = engine.decide(risk, flags)["action"] != "ALLOW"
        if r["label"] == 1:
            tp += detected; fn += (not detected)
        else:
            fp += detected; tn += (not detected)

    recall = tp / (tp + fn) if (tp + fn) else 0.0
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0

    print("-" * 70)
    print("  Detection rate (recall) : %5.1f%%   (%d/%d attacks)" % (100 * recall, tp, tp + fn))
    print("  Precision               : %5.1f%%" % (100 * precision))
    print("  False-positive rate     : %5.1f%%   (%d/%d normal)" % (100 * fpr, fp, fp + tn))
    print("  F1 score                : %.3f" % f1)
    print("-" * 70)
    print("  Feature mapping (log -> 13-feature model):")
    print("    mapped (%d): %s" % (len(MAPPED), ", ".join(MAPPED)))
    for k, why in UNAVAILABLE.items():
        print("    not available: %s  (%s)" % (k, why))
    print("-" * 70)
    print("  This benchmark is an INDEPENDENT synthetic distribution (different")
    print("  generator/users/noise from training), so it tests cross-distribution")
    print("  generalisation. Point --csv at a real dataset in the same schema for")
    print("  a true real-world result.")


if __name__ == "__main__":
    main()
