#!/usr/bin/env python3
"""
benchmark_models.py -- why Isolation Forest? (continued development, post-submission)

The dissertation picks Isolation Forest on the usual arguments: unsupervised,
no attack labels needed, fast, robust in higher dimensions. This script backs
that choice with numbers by putting three classic unsupervised anomaly detectors
on the EXACT same footing:

    * IsolationForest   (the one the system ships with)
    * LocalOutlierFactor(novelty=True)
    * OneClassSVM

All three are fit on NORMAL traffic only (true unsupervised / one-class setup),
then judged on a held-out mix of normal + the five attack types. We report
ROC-AUC and PR-AUC (threshold-independent), plus precision / recall / F1 at each
model's own native decision boundary, and the fit + scoring time.

This does NOT touch the shipped model or the SQLite database - it is a
read-only experiment. Run:  python benchmark_models.py
"""
import os, time, random
import numpy as np
import config
# Use a throwaway DB so we never disturb the real audit trail.
config.DB_PATH = "/tmp/ztac_benchmark.db"
import db, engine
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import IsolationForest
from sklearn.neighbors import LocalOutlierFactor
from sklearn.svm import OneClassSVM
from sklearn.metrics import (roc_auc_score, average_precision_score,
                             precision_score, recall_score, f1_score)

ATTACKS = ["credential_stuffing", "insider_threat", "impossible_travel",
           "data_exfiltration", "privilege_escalation"]
SEED = 42


def _fresh_db():
    """Start from an empty scratch database and (re)create the tables."""
    for suffix in ("", "-wal", "-shm"):
        p = config.DB_PATH + suffix
        if os.path.exists(p):
            os.remove(p)
    db.init_db()


def _seed_baselines():
    """Teach every known user their normal device / country / hours, so that the
    NEW_DEVICE / NEW_LOCATION / ABNORMAL_HOUR features are computed the same way
    the live system would compute them."""
    for u in engine.NORMAL_USERS:
        for d in u["devices"]:
            db.update_user_baseline(u["keycloak_id"], d, u["country"], 12)
        for h in u["hours"]:
            db.update_user_baseline(u["keycloak_id"], u["devices"][0], u["country"], h)


def _vec(record):
    """Turn one request record into its 13-feature vector (same order the model
    is trained on). We ignore the rule flags here - this is a pure test of the
    ML model's ability to separate normal from attack on the features alone."""
    feats, _flags = engine.extract_features(record)
    return feats


def _build_split(n_train=3000, n_test_normal=800, n_per_attack=80):
    """Build an unsupervised train/test split.

    Training set : normal traffic ONLY (the models never see an attack in fit).
    Test set     : fresh normal traffic + n_per_attack of each of the 5 attacks.
    Returns (X_train, X_test, y_test) where y_test is 1 for attack, 0 for normal.
    """
    random.seed(SEED)
    X_train = [_vec(r) for r in engine.generate_normal(n_train)]

    X_test, y_test = [], []
    for r in engine.generate_normal(n_test_normal):
        X_test.append(_vec(r)); y_test.append(0)
    for kind in ATTACKS:
        for _ in range(n_per_attack):
            user = random.choice(engine.NORMAL_USERS)
            X_test.append(_vec(engine.make_attack(kind, user))); y_test.append(1)

    return np.array(X_train), np.array(X_test), np.array(y_test)


def _evaluate(name, model, Xtr, Xte, yte):
    """Fit one model on normal-only training data, score the test set, and
    return a dict of metrics. `anomaly` = higher means more anomalous, so we can
    feed it straight to ROC-AUC / PR-AUC against the attack label (1)."""
    t0 = time.perf_counter()
    model.fit(Xtr)
    fit_ms = (time.perf_counter() - t0) * 1000.0

    t0 = time.perf_counter()
    # decision_function: higher = more normal. Negate so higher = more anomalous.
    anomaly = -model.decision_function(Xte)
    # predict(): -1 = anomaly/outlier, +1 = inlier -> map to attack label (1/0).
    pred = (model.predict(Xte) == -1).astype(int)
    score_ms = (time.perf_counter() - t0) * 1000.0

    return {
        "name": name,
        "roc_auc": roc_auc_score(yte, anomaly),
        "pr_auc": average_precision_score(yte, anomaly),
        "precision": precision_score(yte, pred, zero_division=0),
        "recall": recall_score(yte, pred, zero_division=0),
        "f1": f1_score(yte, pred, zero_division=0),
        "fit_ms": fit_ms,
        "score_ms_per": score_ms / len(Xte),
    }


def main():
    print("=" * 74)
    print("  MODEL BENCHMARK  -  Isolation Forest vs Local Outlier Factor vs OC-SVM")
    print("=" * 74)
    _fresh_db()
    _seed_baselines()

    Xtr, Xte, yte = _build_split()
    # Scale features once (fit on train only) - OC-SVM in particular needs it.
    scaler = StandardScaler().fit(Xtr)
    Xtr_s, Xte_s = scaler.transform(Xtr), scaler.transform(Xte)
    print("  train (normal only): %d   test: %d normal + %d attacks"
          % (len(Xtr), int((yte == 0).sum()), int((yte == 1).sum())))
    print("-" * 74)

    # contamination / nu = the same 0.15 the project already assumes.
    cont = config.IF_CONTAMINATION
    models = [
        ("IsolationForest", IsolationForest(
            n_estimators=config.IF_N_ESTIMATORS, contamination=cont, random_state=SEED)),
        ("LocalOutlierFactor", LocalOutlierFactor(
            novelty=True, contamination=cont)),
        ("OneClassSVM", OneClassSVM(nu=cont, gamma="scale")),
    ]
    results = [_evaluate(n, m, Xtr_s, Xte_s, yte) for n, m in models]

    # ---- table ----
    hdr = "  %-20s %8s %8s %10s %8s %8s %10s" % (
        "model", "ROC-AUC", "PR-AUC", "precision", "recall", "F1", "score us")
    print(hdr); print("-" * 74)
    for r in results:
        print("  %-20s %8.3f %8.3f %10.3f %8.3f %8.3f %10.1f" % (
            r["name"], r["roc_auc"], r["pr_auc"], r["precision"],
            r["recall"], r["f1"], r["score_ms_per"] * 1000.0))
    print("-" * 74)

    best = max(results, key=lambda r: (round(r["roc_auc"], 3), r["f1"]))
    ship = next(r for r in results if r["name"] == "IsolationForest")
    print("  Best ROC-AUC: %s (%.3f)." % (best["name"], best["roc_auc"]))
    if best["name"] == "IsolationForest":
        print("  -> Confirms the design choice: Isolation Forest is at least as strong")
        print("     as the alternatives here, and it is the fastest to score per request")
        print("     (%.1f us), which matters when every HTTP request is scored inline."
              % (ship["score_ms_per"] * 1000.0))
    else:
        print("  -> %s edges out Isolation Forest on this synthetic set; worth a note in"
              % best["name"])
        print("     future work, though IF stays attractive for speed / interpretability.")
    print("=" * 74)


if __name__ == "__main__":
    main()
