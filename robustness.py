#!/usr/bin/env python3
"""
robustness.py -- Track C: robustness & evaluation (continued development).

Three parts, all reproducible (seed 42) and read-only (throwaway DB, no model change):

  1. MORE ATTACK TYPES -- runs the engine against an extended suite (the original
     five plus session_hijack and api_enumeration) and reports per-type detection.

  2. BEHAVIOURAL VELOCITY DETECTOR -- addresses the "low-and-slow" gap that the
     per-request engine cannot close. A perfectly mimicked single request is, by
     definition, indistinguishable from a legitimate one; the signal only appears
     ACROSS requests. We simulate low-and-slow campaigns (many sensitive accesses,
     each individually normal-looking, spread just under the rate limit) and show a
     simple per-user velocity detector catches them while the per-request engine
     does not -- and we measure its false-positive rate on normal users.

  3. COST-BASED THRESHOLD SELECTION -- sweeps the ALLOW threshold and picks the one
     that minimises expected cost for several false-negative : false-positive cost
     ratios, since in security a missed attack usually costs far more than a
     false alarm.

Run:  python robustness.py     (or: python zt.py ... once wired)
"""
import os
import random
from collections import defaultdict, deque

import config
config.DB_PATH = "/tmp/ztac_robustness.db"
import db
import engine

SEED = 42
ORIGINAL_ATTACKS = ["credential_stuffing", "insider_threat", "impossible_travel",
                    "data_exfiltration", "privilege_escalation"]
NEW_ATTACKS = ["session_hijack", "api_enumeration"]
ALL_ATTACKS = ORIGINAL_ATTACKS + NEW_ATTACKS


def _fresh_db():
    for suffix in ("", "-wal", "-shm"):
        p = config.DB_PATH + suffix
        if os.path.exists(p):
            os.remove(p)
    db.init_db()


def _ensure_model():
    if os.path.exists(config.MODEL_PATH):
        engine.load_model()
    else:
        engine.train_on_synthetic()
        engine.load_model()


def _seed_baselines():
    for u in engine.NORMAL_USERS:
        for d in u["devices"]:
            db.update_user_baseline(u["keycloak_id"], d, u["country"], 12)
        for h in u["hours"]:
            db.update_user_baseline(u["keycloak_id"], u["devices"][0], u["country"], h)


def _score(record):
    """Run one record through the real engine; return (detected?, decision, flags)."""
    feats, flags = engine.extract_features(record)
    risk = engine.score_risk(feats, flags)
    decision = engine.decide(risk, flags)
    return decision["action"] != "ALLOW", decision["action"], flags


# ---------------------------------------------------------------------------
# PART 1 -- more attack types
# ---------------------------------------------------------------------------
def part1_more_attacks(n_per=80):
    print("=" * 74)
    print("  PART 1  -  EXTENDED ATTACK SUITE (per-type detection)")
    print("=" * 74)
    random.seed(SEED)
    for kind in ALL_ATTACKS:
        detected = 0
        for _ in range(n_per):
            user = random.choice(engine.NORMAL_USERS)
            hit, _dec, _flags = _score(engine.make_attack(kind, user))
            detected += hit
        tag = "" if kind in ORIGINAL_ATTACKS else "  (new)"
        print("  %-22s %5.1f%%   (%d/%d)%s" %
              (kind, 100.0 * detected / n_per, detected, n_per, tag))
    print()


# ---------------------------------------------------------------------------
# PART 2 -- behavioural velocity detector for low-and-slow
# ---------------------------------------------------------------------------
class VelocityDetector:
    """A session-level signal the per-request engine cannot provide: it flags an
    account that issues an unusually high VOLUME of requests within a rolling
    window. A single request reveals nothing; sustained harvesting does. This is a
    deliberately blunt instrument -- Part 3 then formalises the coverage/cost
    trade-off it implies."""

    def __init__(self, window=40, max_requests=30):
        self.window = window
        self.max_requests = max_requests
        self._recent = defaultdict(lambda: deque(maxlen=window))

    def observe(self, user_id):
        self._recent[user_id].append(1)
        return sum(self._recent[user_id]) > self.max_requests   # True == flag


def _low_and_slow_request(user):
    """One request in a flagless low-and-slow harvest: a NORMAL endpoint with
    everything else normal too (known device, home country, business hour, low
    instantaneous rate). Individually indistinguishable from legitimate traffic,
    so the per-request engine allows it -- this is the residual gap step-up left."""
    return engine.one_row(
        user, hour=random.randint(9, 17),
        req_1m=random.randint(1, 4), req_5m=random.randint(2, 8), req_1h=random.randint(5, 25),
        size=random.randint(200, 1500), lat=user["lat"], lon=user["lon"],
        endpoint=random.choice(engine.NORMAL_ENDPOINTS),
        country=user["country"], device=random.choice(user["devices"]))


def part2_velocity(n_campaigns=40, campaign_len=50, n_normal_users=60):
    print("=" * 74)
    print("  PART 2  -  LOW-AND-SLOW: per-request engine vs velocity detector")
    print("=" * 74)
    random.seed(SEED)

    # --- attacker campaigns: sustained flagless harvesting from one account ---
    engine_hits = 0
    total_requests = 0
    campaigns_caught = 0
    for c in range(n_campaigns):
        user = random.choice(engine.NORMAL_USERS)
        det = VelocityDetector()
        uid = "attacker-%d" % c
        caught = False
        for _ in range(campaign_len):
            rec = _low_and_slow_request(user)
            hit, _dec, _flags = _score(rec)
            engine_hits += hit
            total_requests += 1
            if det.observe(uid):
                caught = True
        campaigns_caught += caught

    # --- legitimate users with realistic, variable activity (FPR of the detector) ---
    fp_users = 0
    for n in range(n_normal_users):
        det = VelocityDetector()
        # Most people browse lightly; a minority are heavy "power users".
        length = random.randint(20, 45) if random.random() < 0.25 else random.randint(3, 18)
        flagged = False
        for _ in range(length):
            if det.observe("normal-%d" % n):
                flagged = True
        fp_users += flagged

    print("  Low-and-slow campaigns : %d (x%d flagless requests each)" % (n_campaigns, campaign_len))
    print("  Per-request engine     : %d/%d requests flagged (%.1f%%)"
          % (engine_hits, total_requests, 100.0 * engine_hits / total_requests))
    print("  Velocity detector      : %d/%d campaigns caught (%.1f%%)"
          % (campaigns_caught, n_campaigns, 100.0 * campaigns_caught / n_campaigns))
    print("  Velocity detector FPR  : %d/%d legitimate users flagged (%.1f%%)"
          % (fp_users, n_normal_users, 100.0 * fp_users / n_normal_users))
    print("  So the per-request engine misses flagless harvests almost entirely,")
    print("  while a volume-based session detector catches the sustained ones -- at")
    print("  the cost of flagging the heaviest legitimate users. A single, perfectly")
    print("  mimicked request stays fundamentally uncatchable at the request level.")
    print()


# ---------------------------------------------------------------------------
# PART 3 -- cost-based threshold selection
# ---------------------------------------------------------------------------
def _labelled_scores(n_normal=2000, n_per=80, n_low_slow=200):
    """Composite risk score for a labelled mix of normal + all attack types, PLUS
    a batch of flagless low-and-slow requests (label 1). Those deliberately overlap
    with normal traffic, which is what creates a real false-negative / false-positive
    trade-off for the threshold sweep to resolve."""
    random.seed(SEED)
    scored = []                                  # (score, label)
    for rec in engine.generate_normal(n_normal):
        feats, flags = engine.extract_features(rec)
        scored.append((engine.score_risk(feats, flags), 0))
    for kind in ALL_ATTACKS:
        for _ in range(n_per):
            rec = engine.make_attack(kind, random.choice(engine.NORMAL_USERS))
            feats, flags = engine.extract_features(rec)
            scored.append((engine.score_risk(feats, flags), 1))
    for _ in range(n_low_slow):                  # the hard, overlapping residual
        rec = _low_and_slow_request(random.choice(engine.NORMAL_USERS))
        feats, flags = engine.extract_features(rec)
        scored.append((engine.score_risk(feats, flags), 1))
    return scored


def part3_cost_thresholds():
    print("=" * 74)
    print("  PART 3  -  COST-BASED THRESHOLD SELECTION")
    print("=" * 74)
    scored = _labelled_scores()
    n_attack = sum(1 for _s, y in scored if y == 1)
    n_normal = sum(1 for _s, y in scored if y == 0)
    thresholds = [round(0.20 + 0.02 * i, 2) for i in range(36)]   # 0.20 .. 0.90

    print("  dataset: %d normal + %d attacks" % (n_normal, n_attack))
    print("  A request is treated as 'blocked' when its score >= threshold.")
    print("  Expected cost = C_fn * false_negatives + C_fp * false_positives.")
    print("-" * 74)
    print("  %-14s %-12s %-10s %-10s" % ("cost ratio", "best thr", "missed", "false alarms"))
    for c_fn, c_fp in [(1, 1), (5, 1), (10, 1), (20, 1)]:
        best = None
        for t in thresholds:
            fn = sum(1 for s, y in scored if y == 1 and s < t)
            fp = sum(1 for s, y in scored if y == 0 and s >= t)
            cost = c_fn * fn + c_fp * fp
            if best is None or cost < best[0]:
                best = (cost, t, fn, fp)
        print("  %-14s %-12s %-10s %-10s" %
              ("%d:%d" % (c_fn, c_fp), best[1], best[2], best[3]))
    print("-" * 74)
    print("  Higher FN cost pushes the optimal threshold DOWN (block more, tolerate")
    print("  more false alarms) -- letting the bank tune the ALLOW cut to its risk")
    print("  appetite rather than hard-coding 0.45.")
    print()


def main():
    _fresh_db()
    _ensure_model()
    _seed_baselines()
    part1_more_attacks()
    part2_velocity()
    part3_cost_thresholds()


if __name__ == "__main__":
    main()
