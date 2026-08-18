#!/usr/bin/env python3
# =============================================================================
# evaluate.py  -  Measures how good the risk engine is (the "exam").
# =============================================================================
#
# WHAT THIS FILE IS FOR
# ---------------------
# This is the script that produces the numbers you see in the report and the
# slides (detection rate, false positives, latency, and so on). Think of it as
# the "exam" for the risk engine: it feeds the engine thousands of requests
# whose correct answer we already know (some genuinely normal, some attacks),
# then checks how often the engine got it right, and how fast it was.
#
# It runs completely OFFLINE. It never starts the web server and never touches
# the real database (ztac.db). Instead it uses a throwaway database in /tmp that
# it deletes at the end, so running the exam can never pollute your live data.
#
# WHAT IT DOES
# ------------
# It scores 2,400 labelled requests (2,000 normal + 400 attacks), writes every
# single result to evaluation_results.csv, then prints the overall accuracy
# (recall / precision / false-positive rate / F1), a per-attack-type breakdown,
# and the per-request scoring latency.
#
# THE PIPELINE EACH REQUEST GOES THROUGH (the same one the live guard uses):
#       extract_features()  ->  score_risk()  ->  decide()
#   A request counts as "DETECTED" when the decision is NOT "ALLOW" - i.e. the
#   system either challenged it with MFA or denied it, instead of letting it
#   through silently.
#
# HOW TO RUN IT
# -------------
#   python evaluate.py                              # the standard 2,400-request run
#   python evaluate.py --normal 2000 --per-attack 80   # change the dataset size
# =============================================================================

# ---- Standard-library imports (these all ship with Python) ------------------
import os        # for deleting the throwaway database files and building paths
import csv       # to write the per-request results file (evaluation_results.csv)
import time      # to measure how long scoring one request takes (latency)
import random    # to pick random users/attacks so the test set is varied
import argparse  # to read the command-line options (--normal, --per-attack)

# ---- Our own modules --------------------------------------------------------
# IMPORTANT ORDERING NOTE:
# We import `config` FIRST and immediately repoint its DB_PATH at a throwaway
# file. `db` opens its database connection lazily (only when first used), and it
# reads config.DB_PATH at that moment - so as long as we change the path BEFORE
# anything touches the database, every read/write in this whole script goes to
# /tmp/ztac_eval.db and the real ztac.db is left completely untouched.
import config
config.DB_PATH = "/tmp/ztac_eval.db"

import db        # the SQLite layer (init_db, user baselines, ...)
import engine    # the brain: feature extraction, scoring, the decision, and the
                 # synthetic-data generators (generate_normal, make_attack, ...)


# ---- Constants --------------------------------------------------------------
# The five attack types the system knows how to generate and recognise. We keep
# them in a list so we can loop over them and report a breakdown per type.
ATTACK_KINDS = [
    "credential_stuffing",
    "insider_threat",
    "impossible_travel",
    "data_exfiltration",
    "privilege_escalation",
]

# HERE = the folder this evaluate.py lives in. We compute it so the results CSV
# is written next to the script no matter what directory you run it from.
HERE     = os.path.dirname(os.path.abspath(__file__))
CSV_PATH = os.path.join(HERE, "evaluation_results.csv")

# Just some cosmetic strings for drawing tidy lines in the printed report.
LINE = "=" * 68
SUB  = "-" * 68


# =============================================================================
# SETUP HELPERS  -  get the engine and the database ready before any scoring
# =============================================================================

# FUNCTION 1/6: ensure_model() -> load the ML model (train it first if missing).
def ensure_model():
    """
    Make sure a trained Isolation Forest is loaded into memory.

    The engine scores anomalies with a machine-learning model saved on disk
    (model/isolation_forest.pkl). If that file already exists we just load it.
    If it does NOT exist yet (e.g. a fresh copy of the project), we train one on
    synthetic data first, then load it - so this script always works, even from
    a clean checkout with no model.
    """
    if os.path.exists(config.MODEL_PATH):
        engine.load_model()
    else:
        print("No trained model found - training one on synthetic data first...\n")
        engine.train_on_synthetic()   # builds + saves model/isolation_forest.pkl
        engine.load_model()


# FUNCTION 2/6: setup_baselines() -> teach the 20 users their "normal" so the
#               NEW_DEVICE / NEW_LOCATION / ABNORMAL_HOUR flags can work.
def setup_baselines():
    """
    Give every one of the 20 simulated users a "normal behaviour" profile.

    WHY THIS MATTERS: three of the red flags - NEW_DEVICE, NEW_LOCATION and
    ABNORMAL_HOUR - work by comparing a request against what that user normally
    does. If a user has no baseline yet, there is nothing to compare against, so
    those flags can never fire and attacks would look deceptively normal.

    In a real deployment the baseline is learned slowly from ALLOWED requests
    over time. Here we simply seed each user with their two known devices, their
    country (IE), and their full working-hour range (8-18), which mirrors the
    state of a system that has been running for a while.
    """
    for user in engine.NORMAL_USERS:
        # Teach the system each of this user's known devices (seen at hour 12).
        for device in user["devices"]:
            db.update_user_baseline(user["keycloak_id"], device, user["country"], 12)
        # Teach the system each of this user's normal working hours.
        for hour in user["hours"]:
            db.update_user_baseline(user["keycloak_id"], user["devices"][0],
                                    user["country"], hour)


# FUNCTION 3/6: score() -> the core. Run ONE request through
#               extract_features -> score_risk -> decide, and time it.
def score(record):
    """
    Run ONE request through the real pipeline and time it.

    This is the heart of the whole evaluation. It does exactly what the live
    Policy Decision Point does, in three steps:
        1. extract_features -> turn the request into 13 numbers + a list of flags
        2. score_risk       -> combine model + flags + time into one 0..1 score
        3. decide           -> map that score (and flags) to ALLOW / MFA / DENY

    We wrap those three steps in a stopwatch (time.perf_counter) so we can report
    how many milliseconds a single decision takes.

    Returns a tuple: (decision_dict, flags_list, elapsed_milliseconds).
    """
    start = time.perf_counter()                      # stopwatch: start
    features, flags = engine.extract_features(record)
    risk = engine.score_risk(features, flags)
    decision = engine.decide(risk, flags)
    elapsed_ms = (time.perf_counter() - start) * 1000.0   # seconds -> milliseconds
    return decision, flags, elapsed_ms


# =============================================================================
# FULL EVALUATION  -  2,400 labelled requests -> accuracy + latency
# =============================================================================

# FUNCTION 4/6: build_dataset() -> make the big labelled test set
#               (2,000 normal + 80 of each of the 5 attack types = 2,400).
def build_dataset(n_normal, n_per_attack):
    """
    Build the big labelled test set the engine will be graded on.

    It contains n_normal normal requests plus n_per_attack of EACH of the five
    attack types (so 5 * n_per_attack attacks in total). Every record is tagged
    with an extra "_type" key ("normal" or the attack name) so we can later
    report how well each attack type was detected.
    """
    random.seed(42)     # fixed seed -> the exact same test set on every run (reproducible)
    dataset = []

    # 1) The normal requests. generate_normal() already labels each one with 0.
    for rec in engine.generate_normal(n_normal):
        rec["_type"] = "normal"
        dataset.append(rec)

    # 2) The attacks: n_per_attack of each type, each aimed at a random user.
    for kind in ATTACK_KINDS:
        for _ in range(n_per_attack):                 # "_" = we don't need the counter
            user = random.choice(engine.NORMAL_USERS) # pick a random victim
            rec = engine.make_attack(kind, user)      # build one attack of this kind
            rec["label"] = 1                          # 1 = attack (make sure it's set)
            rec["_type"] = kind                       # remember which type, for the breakdown
            dataset.append(rec)

    return dataset


# FUNCTION 5/6: run_evaluation() -> score all 2,400 requests, log each to CSV,
#               tally the confusion matrix, and print accuracy + latency.
def run_evaluation(n_normal, n_per_attack):
    """
    Score the whole dataset, log every result to CSV, then print the metrics.

    The core idea is the "confusion matrix" - four running counters that classify
    every request into one of four boxes:
        tp (true positive)  : an ATTACK that we correctly DETECTED
        fn (false negative) : an ATTACK that we MISSED (let through as ALLOW)
        fp (false positive) : a NORMAL request we wrongly flagged (MFA/DENY)
        tn (true negative)  : a NORMAL request we correctly ALLOWED
    All the headline metrics are just simple fractions of these four numbers.
    """
    dataset = build_dataset(n_normal, n_per_attack)
    n_norm = sum(1 for r in dataset if r["label"] == 0)   # count the normals
    n_att  = sum(1 for r in dataset if r["label"] == 1)   # count the attacks

    # The four confusion-matrix counters, all starting at zero.
    tp = fp = fn = tn = 0
    # per_type maps an attack name -> [how_many_detected, how_many_total].
    per_type = {k: [0, 0] for k in ATTACK_KINDS}
    latencies = []                                         # every request's timing, in ms

    # Open the results CSV for writing. Using "with" guarantees the file is
    # closed properly even if something goes wrong midway.
    with open(CSV_PATH, "w", newline="") as f:
        writer = csv.writer(f)
        # The header row of the spreadsheet.
        writer.writerow(["index", "keycloak_id", "type", "label",
                         "risk_score", "decision", "detected", "flags", "latency_ms"])

        # enumerate(dataset, 1) walks the list giving (1, first), (2, second), ...
        for i, record in enumerate(dataset, 1):
            decision, flags, ms = score(record)           # run the real pipeline + time it
            latencies.append(ms)
            detected = decision["action"] != "ALLOW"      # caught = not ALLOW

            # Write this single request's full result as one row of the CSV.
            writer.writerow([i, record.get("keycloak_id", ""), record["_type"],
                             record["label"], decision["risk_score"],
                             decision["action"], int(detected),
                             "|".join(flags), round(ms, 3)])

            # Update the confusion-matrix counters.
            if record["label"] == 1:                      # this request really IS an attack
                per_type[record["_type"]][1] += 1         # count it under its type's total
                if detected:
                    tp += 1                               # caught an attack  -> true positive
                    per_type[record["_type"]][0] += 1     # and tally it as detected
                else:
                    fn += 1                               # missed an attack  -> false negative
            else:                                         # this request is NORMAL
                if detected:
                    fp += 1                               # false alarm       -> false positive
                else:
                    tn += 1                               # correctly allowed -> true negative

    # ---- Turn the four counters into the headline metrics --------------------
    # recall / detection rate: of all real attacks, what fraction did we catch?
    recall    = tp / (tp + fn) if (tp + fn) else 0.0
    # precision: of everything we flagged, what fraction were really attacks?
    precision = tp / (tp + fp) if (tp + fp) else 1.0
    # false-positive rate: of all normal requests, what fraction did we wrongly flag?
    fpr       = fp / (fp + tn) if (fp + tn) else 0.0
    # F1: a single score that balances precision and recall (their harmonic mean).
    f1        = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0

    # ---- Latency statistics -------------------------------------------------
    latencies.sort()                                      # sorting makes percentiles easy
    mean_ms = sum(latencies) / len(latencies)             # average time per request
    # 95th percentile: 95% of requests were at least this fast (a "typical worst case").
    p95_ms  = latencies[int(0.95 * len(latencies)) - 1]
    max_ms  = latencies[-1]                               # the single slowest request

    # ---- Print the report ---------------------------------------------------
    print(LINE)
    print("  ADAPTIVE ZERO-TRUST ACCESS CONTROL  -  FULL EVALUATION")
    print(LINE)
    print(f"  Dataset          : {len(dataset)} requests "
          f"({n_norm} normal, {n_att} attack) across {len(engine.NORMAL_USERS)} users")
    print(f"  Model            : {engine.get_model_version()}")
    print(f"  Per-request log  : {CSV_PATH}")
    print("  " + SUB)
    print("  DETECTION ACCURACY")
    print(f"    Detection rate (recall) : {recall*100:5.1f}%   ({tp}/{tp+fn} attacks caught)")
    print(f"    Precision               : {precision*100:5.1f}%")
    print(f"    False-positive rate     : {fpr*100:5.1f}%   ({fp}/{fp+tn} normal flagged)")
    print(f"    F1 score                : {f1:.3f}")
    print(f"    Confusion matrix        : tp={tp} fp={fp} fn={fn} tn={tn}")
    print("  " + SUB)
    print("  DETECTION BY ATTACK TYPE")
    for kind in ATTACK_KINDS:
        caught, total = per_type[kind]
        rate = (caught / total * 100) if total else 0.0
        print(f"    {kind:22}: {rate:5.1f}%   ({caught}/{total})")
    print("  " + SUB)
    print("  PER-REQUEST SCORING LATENCY")
    print(f"    Mean : {mean_ms:.2f} ms     95th pct : {p95_ms:.2f} ms     Max : {max_ms:.2f} ms")
    print("    (authorisation budget from the literature: 50 ms)")
    print(LINE + "\n")


# =============================================================================
# MAIN  -  wire everything together and handle the command-line options
# =============================================================================

# FUNCTION 6/6: main() -> read the command-line flags, set up the DB + model +
#               baselines, run the evaluation, then clean up.
def main():
    # argparse reads the options the user typed after "python evaluate.py".
    parser = argparse.ArgumentParser(description="Full evaluation of the Zero-Trust engine.")
    parser.add_argument("--normal", type=int, default=2000, help="number of normal test requests")
    parser.add_argument("--per-attack", type=int, default=80, help="requests per attack type (x5)")
    args = parser.parse_args()

    # Start from a clean, throwaway database every time. SQLite can leave two
    # side-files (-wal and -shm), so we delete all three if they exist.
    for suffix in ("", "-wal", "-shm"):
        p = config.DB_PATH + suffix
        if os.path.exists(p):
            os.remove(p)

    db.init_db()          # create the empty tables
    ensure_model()        # load (or train) the Isolation Forest
    setup_baselines()     # give the 20 users their "normal behaviour" profiles

    print()               # blank line before the report banner
    run_evaluation(args.normal, args.per_attack)

    # Clean up: delete the throwaway database so nothing is left behind.
    for suffix in ("", "-wal", "-shm"):
        p = config.DB_PATH + suffix
        if os.path.exists(p):
            os.remove(p)


# This standard Python idiom means "only run main() if this file was launched
# directly (python evaluate.py), not if it was imported by another file".
if __name__ == "__main__":
    main()
