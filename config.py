# =============================================================================
# config.py  -  Every tuneable setting for the whole system, in one place.
# =============================================================================
# Nothing here "does" anything; it just defines values that the other files
# import (e.g. "config.ALLOW_THRESHOLD"). Change a number here and it takes
# effect everywhere, so this is the one file you edit to re-tune the system.
# =============================================================================
import os

# ---- Decision thresholds: where ALLOW ends and DENY begins ------------------
ALLOW_THRESHOLD = 0.45      # score below this  -> ALLOW
DENY_THRESHOLD = 0.7        # score above this  -> DENY  (in between -> MFA)

# ---- Isolation Forest (the anomaly-detection model) settings ----------------
IF_N_ESTIMATORS = 200       # how many trees in the forest (more = steadier score)
IF_CONTAMINATION = 0.15     # rough fraction of data assumed to be anomalies

# ---- File locations ---------------------------------------------------------
MODEL_PATH = os.path.join(os.path.dirname(__file__), 'model', 'isolation_forest.pkl')  # trained model on disk
DB_PATH = os.path.join(os.path.dirname(__file__), 'ztac.db')                            # the SQLite database file

# ---- Keycloak (the identity provider that issues login tokens) --------------
KEYCLOAK_URL = os.getenv('KEYCLOAK_URL', 'http://localhost:8080')
KEYCLOAK_REALM = 'zerotrust'
KEYCLOAK_CLIENT_ID = 'zt-app'
# JWKS = the URL where Keycloak publishes its public keys, used to verify tokens.
JWKS_URL = KEYCLOAK_URL + '/realms/' + KEYCLOAK_REALM + '/protocol/openid-connect/certs'

# ---- Composite-score weights: how the final risk score is mixed -------------
# These three must add up to 1.0. score = 0.40*model + 0.35*rules + 0.25*time.
W_ANOMALY = 0.4     # weight of the ML model's anomaly score
W_RULES = 0.35      # weight of the rule-based red flags (boosters)
W_DECAY = 0.25      # weight of the time-of-day factor

# ---- Booster weights: how many "points" each red flag is worth --------------
# A new device AND a new country together (0.25 + 0.25) is the classic
# account-takeover signature and pushes a request from ALLOW into MFA.
BOOSTER_WEIGHTS = {'NEW_DEVICE': 0.25, 'NEW_LOCATION': 0.25, 'BULK_DATA_ACCESS': 0.2, 'PRIVILEGE_ESCALATION': 0.25, 'ABNORMAL_HOUR': 0.05, 'HIGH_REQUEST_RATE': 0.15}

# ---- Hard override: this many flags at once = automatic DENY -----------------
CRITICAL_FLAG_COUNT = 4     # 4+ independent red flags -> DENY, whatever the score

# ---- Step-up policy (v1.3.0): a single high-severity flag forces at least MFA ----
# Closes part of the 'low-and-slow' evasion gap: an attacker who mimics normal
# behaviour but still touches a sensitive endpoint (admin / bulk export) no longer
# slips through on a low score. Normal traffic never raises these flags, so the
# false-positive rate is unaffected.
STEP_UP_ON_HIGH_SEVERITY = True
STEP_UP_FLAGS = ['PRIVILEGE_ESCALATION', 'BULK_DATA_ACCESS']
MAX_REQUESTS_PER_MINUTE = 30  # above this, the HIGH_REQUEST_RATE flag fires

# ---- Keyword lists used to classify an endpoint from its URL ----------------
BULK_ENDPOINTS = ['/bulk', '/export', '/download', '/dump', '/backup']   # -> BULK_DATA_ACCESS
PRIV_ENDPOINTS = ['/admin', '/internal', '/config', '/system', '/users'] # -> PRIVILEGE_ESCALATION

# ---- The 13 behavioural features the model reads, in fixed order -------------
# This order MUST match the order used in engine.extract_features().
FEATURE_COLUMNS = ['hour_of_day', 'day_of_week', 'requests_last_1m', 'requests_last_5m', 'requests_last_1h', 'request_size_bytes', 'geo_lat', 'geo_lon', 'is_new_device', 'is_new_location', 'is_bulk_access', 'is_privilege_escalation', 'response_latency_ms']

# ---- Web server port (override with the PORT environment variable) -----------
PORT = int(os.getenv('PORT', '5001'))
