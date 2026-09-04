#!/usr/bin/env python3
"""
make_external_dataset.py -- build an INDEPENDENT held-out benchmark (v1.8.0).

The point of this file is honesty about generalisation. The model is trained on
engine.py's synthetic generator; testing on that same generator risks flattering
results. This script produces a *separately constructed* dataset -- different
users, countries, hour patterns, noise, and deliberately overlapping/ambiguous
cases -- written to a plain CSV. It is NOT real data, but it is a different
distribution, so it tests cross-distribution generalisation, and it is written in
the exact schema `validate_real.py` expects, so a real dataset can replace it
later with no code change.

Schema (one row per request):
    timestamp,user_id,country,device,endpoint,request_size_bytes,success,label

Run:  python make_external_dataset.py   ->   datasets/external_benchmark.csv
"""
import csv
import os
import random
from datetime import datetime, timedelta

SEED = 123                      # deliberately different from engine.py's 42
random.seed(SEED)

OUT = os.path.join(os.path.dirname(__file__), "datasets", "external_benchmark.csv")

NORMAL_ENDPOINTS = ["/api/documents", "/api/profile", "/api/reports", "/api/search", "/api/orders"]
SENSITIVE_ENDPOINTS = ["/api/admin/users", "/api/documents/export", "/api/system/backup", "/api/config"]

# A different user population from engine.NORMAL_USERS (names, countries, hours).
USERS = []
_countries = ["IE", "GB", "DE", "FR", "ES", "IN", "US"]
for i in range(15):
    home = random.choice(_countries)
    # Some users are 9-to-5, some are shift workers (late hours are normal for them).
    if random.random() < 0.3:
        hours = list(range(22, 24)) + list(range(0, 6))
    else:
        hours = list(range(8, 19))
    USERS.append({
        "id": "u%02d" % i,
        "country": home,
        "devices": ["dev-%02d-a" % i] + (["dev-%02d-b" % i] if random.random() < 0.5 else []),
        "hours": hours,
    })

BASE_TIME = datetime(2026, 1, 1, 12, 0, 0)


def _ts(offset_seconds):
    return (BASE_TIME + timedelta(seconds=offset_seconds)).isoformat()


def _size_normal():
    # Lognormal-ish small sizes with a long tail.
    return int(min(20000, max(100, random.lognormvariate(7.0, 1.0))))


def normal_rows(n):
    rows = []
    for _ in range(n):
        u = random.choice(USERS)
        hour = random.choice(u["hours"])
        # ~3% legitimately use a new device, ~2% travel: real noise that creates
        # overlap with attacks and a non-trivial false-positive challenge.
        device = random.choice(u["devices"])
        if random.random() < 0.03:
            device = "dev-new-%d" % random.randint(1000, 9999)
        country = u["country"]
        if random.random() < 0.02:
            country = random.choice(_countries)
        # ~5% of normal traffic legitimately touches a sensitive endpoint.
        endpoint = random.choice(SENSITIVE_ENDPOINTS) if random.random() < 0.05 else random.choice(NORMAL_ENDPOINTS)
        t = _ts(random.randint(0, 60 * 60 * 24 * 30) + hour * 3600)
        rows.append([t, u["id"], country, device, endpoint, _size_normal(), 1, 0])
    return rows


def attack_rows(kind, n):
    rows = []
    for _ in range(n):
        u = random.choice(USERS)
        base = random.randint(0, 60 * 60 * 24 * 30)
        if kind == "credential_stuffing":
            # A tight burst from a new device / foreign country (high rate).
            dev = "atk-%d" % random.randint(1000, 9999)
            ctry = random.choice(["RU", "CN", "BR", "NG"])
            for b in range(random.randint(15, 40)):
                rows.append([_ts(base + b), u["id"], ctry, dev,
                             random.choice(NORMAL_ENDPOINTS), 150, 0, 1])
        elif kind == "impossible_travel":
            rows.append([_ts(base + 8 * 3600), u["id"], random.choice(["US", "JP", "AU"]),
                         "atk-tr-%d" % random.randint(1000, 9999),
                         random.choice(NORMAL_ENDPOINTS), 800, 1, 1])
        elif kind == "insider_threat":
            rows.append([_ts(base + random.choice([1, 2, 3, 23]) * 3600), u["id"], u["country"],
                         random.choice(u["devices"]), random.choice(SENSITIVE_ENDPOINTS),
                         random.randint(2000, 60000), 1, 1])
        elif kind == "data_exfiltration":
            rows.append([_ts(base + random.choice([0, 1, 2, 3]) * 3600), u["id"], u["country"],
                         random.choice(u["devices"]), "/api/documents/export",
                         random.randint(80000, 800000), 1, 1])
        elif kind == "privilege_escalation":
            dev = random.choice(u["devices"]) if random.random() < 0.5 else "atk-pe-%d" % random.randint(1000, 9999)
            rows.append([_ts(base + random.randint(0, 23) * 3600), u["id"],
                         random.choice([u["country"], "RU", "US"]), dev,
                         random.choice(SENSITIVE_ENDPOINTS), 800, 1, 1])
        elif kind == "session_hijack":
            # Subtle: new device, otherwise blends in (business hours, home country).
            rows.append([_ts(base + random.randint(9, 17) * 3600), u["id"], u["country"],
                         "atk-sh-%d" % random.randint(1000, 9999),
                         random.choice(NORMAL_ENDPOINTS), _size_normal(), 1, 1])
        elif kind == "low_and_slow":
            # Flagless harvest: normal endpoint, own device, home country, business
            # hour, spread out. Deliberately overlaps with normal (the hard residual).
            rows.append([_ts(base + random.randint(9, 17) * 3600), u["id"], u["country"],
                         random.choice(u["devices"]), random.choice(NORMAL_ENDPOINTS),
                         _size_normal(), 1, 1])
    return rows


def main():
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    rows = normal_rows(3000)
    for kind, n in [("credential_stuffing", 12), ("impossible_travel", 100),
                    ("insider_threat", 100), ("data_exfiltration", 100),
                    ("privilege_escalation", 100), ("session_hijack", 100),
                    ("low_and_slow", 150)]:
        rows += attack_rows(kind, n)
    random.shuffle(rows)
    with open(OUT, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["timestamp", "user_id", "country", "device", "endpoint",
                    "request_size_bytes", "success", "label"])
        w.writerows(rows)
    n_attack = sum(1 for r in rows if r[7] == 1)
    print("Wrote %s" % OUT)
    print("  %d rows: %d normal + %d attack events" % (len(rows), len(rows) - n_attack, n_attack))


if __name__ == "__main__":
    main()
