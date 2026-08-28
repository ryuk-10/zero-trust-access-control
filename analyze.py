#!/usr/bin/env python3
"""
analyze.py — deeper evaluation for continued development (post-submission).

Uses the same synthetic dataset as evaluate.py, but goes further:
  1. ROC-AUC and PR-AUC of the composite risk score.
  2. A threshold sweep (recall / FPR trade-off as the ALLOW cut moves).
  3. A weight grid-search — is the hand-set 0.40/0.35/0.25 near-optimal?
  4. An adversarial "low-and-slow" test — attacks that mimic normal behaviour.
Saves a ROC + PR chart to analysis_roc_pr.png. Does NOT change the model.

Run:  python analyze.py
"""
import os, random
import numpy as np
import config
config.DB_PATH = "/tmp/ztac_analyze.db"
import db, engine
from sklearn.metrics import (roc_auc_score, average_precision_score,
                             roc_curve, precision_recall_curve)

ATTACKS = ["credential_stuffing", "insider_threat", "impossible_travel",
           "data_exfiltration", "privilege_escalation"]

def _fresh():
    for s in ("", "-wal", "-shm"):
        p = config.DB_PATH + s
        if os.path.exists(p): os.remove(p)
    db.init_db()

def _ensure_model():
    if os.path.exists(config.MODEL_PATH): engine.load_model()
    else: engine.train_on_synthetic(); engine.load_model()

def _baselines():
    for u in engine.NORMAL_USERS:
        for d in u["devices"]: db.update_user_baseline(u["keycloak_id"], d, u["country"], 12)
        for h in u["hours"]: db.update_user_baseline(u["keycloak_id"], u["devices"][0], u["country"], h)

def _dataset(n_normal=2000, n_per=80, seed=42):
    random.seed(seed); ds = []
    for r in engine.generate_normal(n_normal):
        r["_type"] = "normal"; ds.append(r)
    for k in ATTACKS:
        for _ in range(n_per):
            u = random.choice(engine.NORMAL_USERS)
            rec = engine.make_attack(k, u); rec["label"] = 1; rec["_type"] = k; ds.append(rec)
    return ds

def _components(rec):
    feats, flags = engine.extract_features(rec)
    return engine.anomaly_score(feats), engine.booster_total(flags), engine.time_factor(feats[0]), flags

def main():
    _fresh(); _ensure_model(); _baselines()
    ds = _dataset()
    y = np.array([r["label"] for r in ds])
    comp = [_components(r) for r in ds]
    A = np.array([c[0] for c in comp]); R = np.array([c[1] for c in comp]); T = np.array([c[2] for c in comp])
    nflags = np.array([len(c[3]) for c in comp])
    score = np.clip(config.W_ANOMALY*A + config.W_RULES*R + config.W_DECAY*T, 0, 1)

    line = "="*64
    print("\n"+line+"\n  DEEPER ANALYSIS — Adaptive Zero-Trust\n"+line)

    # 1. AUCs
    roc = roc_auc_score(y, score); pr = average_precision_score(y, score)
    print(f"  ROC-AUC = {roc:.4f}      PR-AUC = {pr:.4f}   (on the continuous risk score)")

    # 2. threshold sweep
    print("\n  Threshold sweep (flag if score >= t, or 4+ flags):")
    print("    t      recall   FPR     precision")
    for t in [0.35, 0.40, 0.45, 0.50, 0.55, 0.60, 0.70]:
        det = (score >= t) | (nflags >= config.CRITICAL_FLAG_COUNT)
        tp = int(((y==1)&det).sum()); fn = int(((y==1)&~det).sum())
        fp = int(((y==0)&det).sum()); tn = int(((y==0)&~det).sum())
        rec = tp/(tp+fn); fpr = fp/(fp+tn); prec = tp/(tp+fp) if tp+fp else 1.0
        star = "  <- current ALLOW cut" if abs(t-config.ALLOW_THRESHOLD)<1e-9 else ""
        print(f"    {t:.2f}   {rec:.3f}    {fpr:.3f}   {prec:.3f}{star}")

    # 3. weight grid-search
    print("\n  Weight grid-search (step 0.05, weights sum to 1, current tiers + override):")
    best = None
    grid = [x/20 for x in range(21)]
    for wa in grid:
        for wr in grid:
            wd = round(1 - wa - wr, 4)
            if wd < -1e-9 or wd > 1+1e-9: continue
            sc = np.clip(wa*A + wr*R + wd*T, 0, 1)
            det = (sc >= config.ALLOW_THRESHOLD) | (nflags >= config.CRITICAL_FLAG_COUNT)
            tp = int(((y==1)&det).sum()); fn = int(((y==1)&~det).sum()); fp = int(((y==0)&det).sum())
            rec = tp/(tp+fn); prec = tp/(tp+fp) if tp+fp else 1.0
            f1 = 2*prec*rec/(prec+rec) if prec+rec else 0.0
            if best is None or f1 > best[0]: best = (f1, wa, wr, wd, rec, prec)
    print(f"    best   F1={best[0]:.4f}  at model={best[1]:.2f} rules={best[2]:.2f} time={best[3]:.2f}"
          f"  (recall={best[4]:.3f} precision={best[5]:.3f})")
    det = (score >= config.ALLOW_THRESHOLD) | (nflags >= config.CRITICAL_FLAG_COUNT)
    tp = int(((y==1)&det).sum()); fn = int(((y==1)&~det).sum()); fp = int(((y==0)&det).sum())
    rec = tp/(tp+fn); prec = tp/(tp+fp) if tp+fp else 1.0; f1 = 2*prec*rec/(prec+rec)
    print(f"    current  F1={f1:.4f}  at model=0.40 rules=0.35 time=0.25  (recall={rec:.3f} precision={prec:.3f})")

    # 4. adversarial low-and-slow
    print("\n  Adversarial 'low-and-slow' evasion (attacks disguised as normal):")
    random.seed(7); evasive = []
    for k in ATTACKS:
        for _ in range(80):
            u = random.choice(engine.NORMAL_USERS)
            rec = engine.make_attack(k, u)
            rec["device_fingerprint"] = u["devices"][0]     # known device
            rec["geo_country"] = u["country"]; rec["geo_lat"] = u["lat"]; rec["geo_lon"] = u["lon"]
            rec["hour_of_day"] = 14                          # business hour
            rec["requests_last_1m"], rec["requests_last_5m"], rec["requests_last_1h"] = 3, 10, 30
            rec["request_size_bytes"] = 800
            evasive.append(rec)
    det = 0
    for rec in evasive:
        f, fl = engine.extract_features(rec); s = engine.score_risk(f, fl)
        if engine.decide(s, fl)["action"] != "ALLOW": det += 1
    print(f"    evasive attacks caught: {det}/{len(evasive)} ({100*det/len(evasive):.1f}%)")
    print("    -> honest weak spot: an attacker who mimics a user's normal behaviour and only")
    print("       trips an endpoint flag is far harder to catch. Motivates the roadmap (real")
    print("       baselines, sequence models, adaptive thresholds).")

    # chart
    try:
        import matplotlib; matplotlib.use("Agg"); import matplotlib.pyplot as plt
        fprc, tprc, _ = roc_curve(y, score); prc, recc, _ = precision_recall_curve(y, score)
        fig, ax = plt.subplots(1, 2, figsize=(10, 4))
        ax[0].plot(fprc, tprc, color="#00B140", lw=2); ax[0].plot([0,1],[0,1],"--",color="#cccccc")
        ax[0].set_title(f"ROC  (AUC = {roc:.3f})"); ax[0].set_xlabel("False positive rate"); ax[0].set_ylabel("True positive rate")
        ax[1].plot(recc, prc, color="#034638", lw=2)
        ax[1].set_title(f"Precision-Recall  (AP = {pr:.3f})"); ax[1].set_xlabel("Recall"); ax[1].set_ylabel("Precision")
        for a in ax: a.grid(alpha=0.2); a.set_xlim(-0.02,1.02); a.set_ylim(-0.02,1.02)
        fig.tight_layout(); fig.savefig("analysis_roc_pr.png", dpi=130)
        print(f"\n  Saved chart: analysis_roc_pr.png")
    except Exception as e:
        print(f"\n  (chart skipped: {e})")

    for s in ("", "-wal", "-shm"):
        p = config.DB_PATH + s
        if os.path.exists(p): os.remove(p)
    print(line+"\n")

if __name__ == "__main__":
    main()
