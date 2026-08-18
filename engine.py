# =============================================================================
# engine.py  -  The BRAIN (Policy Decision Point). Turns a request into a score
#               and a decision, and also generates the synthetic training data.
# =============================================================================
# Reading order (grouped below):
#   PART A - extract_features(): request  -> 13 numbers + red-flag list
#   PART B - score_risk():       numbers + flags -> one 0..1 risk score
#            (built from anomaly_score + booster_total + time_factor)
#   PART C - decide():           score + flags   -> ALLOW / MFA / DENY
#   PART D - synthetic data generators (normal users + 5 attack types)
#   PART E - model training + saving
#   PART F - self-tests (run:  python engine.py)
# =============================================================================
import os
import pickle
import random
from datetime import datetime
import numpy
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline
import config
import db

# Helper: True if the URL contains any keyword in the list (spots bulk/admin endpoints).
def endpoint_contains_any(endpoint, word_list):
    endpoint = endpoint.lower()
    for word in word_list:
        if word in endpoint:
            return True
    return False

# PART A. Turn one request into (a) the 13-number feature vector and (b) a list of red flags.
# Flags come from comparing to the user's baseline (new device/location/hour) and the URL/rate.
def extract_features(context):
    flags = []
    keycloak_id = context.get('keycloak_id', '')
    hour = int(context.get('hour_of_day', 12))
    endpoint = context.get('endpoint', '')
    device = context.get('device_fingerprint', '')
    country = context.get('geo_country', '')
    baseline = db.get_user_baseline(keycloak_id)
    is_new_device = 0
    is_new_location = 0
    if baseline is not None:
        if device and device not in baseline['known_devices']:
            is_new_device = 1
            flags.append('NEW_DEVICE')
        if country and country not in baseline['known_countries']:
            is_new_location = 1
            flags.append('NEW_LOCATION')
        if baseline['typical_hours'] and hour not in baseline['typical_hours']:
            flags.append('ABNORMAL_HOUR')
    is_bulk_access = 0
    if endpoint_contains_any(endpoint, config.BULK_ENDPOINTS):
        is_bulk_access = 1
        flags.append('BULK_DATA_ACCESS')
    is_privilege_escalation = 0
    if endpoint_contains_any(endpoint, config.PRIV_ENDPOINTS):
        is_privilege_escalation = 1
        flags.append('PRIVILEGE_ESCALATION')
    requests_1m = int(context.get('requests_last_1m', 0))
    if requests_1m > config.MAX_REQUESTS_PER_MINUTE:
        flags.append('HIGH_REQUEST_RATE')
    feature_vector = [hour, int(context.get('day_of_week', 0)), requests_1m, int(context.get('requests_last_5m', 0)), int(context.get('requests_last_1h', 0)), int(context.get('request_size_bytes', 0)), float(context.get('geo_lat', 0.0)), float(context.get('geo_lon', 0.0)), is_new_device, is_new_location, is_bulk_access, is_privilege_escalation, float(context.get('response_latency_ms', 0.0))]
    return (feature_vector, flags)
_model = {'pipeline': None, 'version': 'none'}

# Helper: force a number to stay within 0.0 .. 1.0.
def clamp(value):
    if value < 0.0:
        return 0.0
    if value > 1.0:
        return 1.0
    return value

# Time-of-day risk: 0.1 in business hours (8-18), 0.3 at the edges, 0.6 at night.
def time_factor(hour):
    if 8 <= hour <= 18:
        return 0.1
    elif 6 <= hour <= 20:
        return 0.3
    else:
        return 0.6

# Add up the point value of each red flag that fired (capped at 1.0).
def booster_total(flags):
    total = 0.0
    for flag in flags:
        total = total + config.BOOSTER_WEIGHTS.get(flag, 0.0)
    if total > 1.0:
        total = 1.0
    return total

# Ask the Isolation Forest how unusual this request is; rescale to 0 (normal) .. 1 (very odd).
def anomaly_score(features):
    one_row = numpy.array(features, dtype=float).reshape(1, -1)
    raw = _model['pipeline'].decision_function(one_row)[0]
    score = (0.6 - raw) / 1.2
    return clamp(score)

# Load the trained model pipeline from disk (model/isolation_forest.pkl) into memory.
def load_model():
    with open(config.MODEL_PATH, 'rb') as f:
        saved = pickle.load(f)
    _model['pipeline'] = saved['pipeline']
    _model['version'] = saved.get('version', 'unknown')
    print('Model loaded:', _model['version'])

# Reload the model from disk - used to hot-swap it after retraining.
def reload_model():
    load_model()

# True if a model is currently loaded in memory.
def is_model_loaded():
    return _model['pipeline'] is not None

# Return the version string of the loaded model.
def get_model_version():
    return _model['version']

# PART B. The composite score = 0.40*model + 0.35*rules + 0.25*time, clamped to 0..1.
def score_risk(features, flags):
    part_model = anomaly_score(features)
    part_rules = booster_total(flags)
    part_time = time_factor(features[0])
    score = config.W_ANOMALY * part_model + config.W_RULES * part_rules + config.W_DECAY * part_time
    return round(clamp(score), 4)

# PART C. Map the score to ALLOW (<0.45) / MFA (0.45-0.70) / DENY (>0.70),
# with a hard override: 4+ red flags at once = DENY no matter the score.
def decide(risk_score, flags=None):
    if flags is None:
        flags = []
    if len(flags) >= config.CRITICAL_FLAG_COUNT:
        return {'action': 'DENY', 'risk_level': 'HIGH', 'risk_score': round(risk_score, 4), 'rule': 'CRITICAL_MULTI_SIGNAL'}
    if risk_score < config.ALLOW_THRESHOLD:
        return {'action': 'ALLOW', 'risk_level': 'LOW', 'risk_score': round(risk_score, 4)}
    elif risk_score <= config.DENY_THRESHOLD:
        return {'action': 'MFA_REQUIRED', 'risk_level': 'MEDIUM', 'risk_score': round(risk_score, 4)}
    else:
        return {'action': 'DENY', 'risk_level': 'HIGH', 'risk_score': round(risk_score, 4)}
random.seed(42)
NORMAL_USERS = []
for i in range(1, 21):
    NORMAL_USERS.append({'keycloak_id': 'user-' + str(i).zfill(3), 'country': 'IE', 'lat': 52.67, 'lon': -8.63, 'devices': ['fp-' + str(i).zfill(3) + '-a', 'fp-' + str(i).zfill(3) + '-b'], 'hours': list(range(8, 19))})
NORMAL_ENDPOINTS = ['/api/documents', '/api/profile', '/api/reports', '/api/search']
SENSITIVE_ENDPOINTS = ['/api/admin/users', '/api/documents/export', '/api/system/backup']

# PART D. Make N fake NORMAL requests (business hours, known device, IE); each labelled 0.
def generate_normal(how_many=2000):
    rows = []
    for _ in range(how_many):
        user = random.choice(NORMAL_USERS)
        rows.append({'keycloak_id': user['keycloak_id'], 'hour_of_day': random.choice(user['hours']), 'day_of_week': random.randint(0, 4), 'requests_last_1m': random.randint(0, 8), 'requests_last_5m': random.randint(0, 25), 'requests_last_1h': random.randint(5, 80), 'request_size_bytes': random.randint(100, 5000), 'geo_lat': user['lat'], 'geo_lon': user['lon'], 'is_new_device': 0, 'is_new_location': 0, 'is_bulk_access': 0, 'is_privilege_escalation': 0, 'response_latency_ms': random.randint(30, 90), 'endpoint': random.choice(NORMAL_ENDPOINTS), 'geo_country': user['country'], 'device_fingerprint': random.choice(user['devices']), 'label': 0})
    return rows

# Helper: build one attack record from the given field values (always labelled 1).
def one_row(user, hour, req_1m, req_5m, req_1h, size, lat, lon, endpoint, country, device, new_device=0, new_loc=0, bulk=0, priv=0):
    return {'keycloak_id': user['keycloak_id'], 'hour_of_day': hour, 'day_of_week': random.randint(0, 6), 'requests_last_1m': req_1m, 'requests_last_5m': req_5m, 'requests_last_1h': req_1h, 'request_size_bytes': size, 'geo_lat': lat, 'geo_lon': lon, 'is_new_device': new_device, 'is_new_location': new_loc, 'is_bulk_access': bulk, 'is_privilege_escalation': priv, 'response_latency_ms': random.randint(50, 250), 'endpoint': endpoint, 'geo_country': country, 'device_fingerprint': device, 'label': 1}

# Build one attack of a given kind (credential_stuffing / insider_threat / impossible_travel /
# data_exfiltration / privilege_escalation) aimed at the given user.
def make_attack(kind, user):
    if kind == 'credential_stuffing':
        return one_row(user, hour=random.randint(0, 23), req_1m=random.randint(40, 120), req_5m=random.randint(150, 500), req_1h=random.randint(500, 2000), size=200, lat=user['lat'] + 5, lon=user['lon'] + 5, new_device=1, new_loc=1, endpoint=random.choice(NORMAL_ENDPOINTS), country=random.choice(['RU', 'CN', 'BR']), device='fp-attack-' + str(random.randint(1000, 9999)))
    if kind == 'insider_threat':
        return one_row(user, hour=random.choice([1, 2, 3, 22, 23]), req_1m=random.randint(5, 15), req_5m=random.randint(15, 40), req_1h=random.randint(30, 80), size=random.randint(1000, 50000), lat=user['lat'], lon=user['lon'], priv=1, endpoint=random.choice(SENSITIVE_ENDPOINTS), country=user['country'], device=random.choice(user['devices']))
    if kind == 'impossible_travel':
        return one_row(user, hour=random.randint(8, 18), req_1m=random.randint(1, 5), req_5m=random.randint(2, 10), req_1h=random.randint(5, 30), size=800, lat=user['lat'] + 30, lon=user['lon'] + 40, new_device=1, new_loc=1, endpoint=random.choice(NORMAL_ENDPOINTS), country=random.choice(['US', 'JP', 'AU']), device='fp-travel-' + str(random.randint(1000, 9999)))
    if kind == 'data_exfiltration':
        return one_row(user, hour=random.choice([0, 1, 2, 3, 22, 23]), req_1m=random.randint(10, 30), req_5m=random.randint(30, 80), req_1h=random.randint(100, 300), size=random.randint(50000, 500000), lat=user['lat'], lon=user['lon'], bulk=1, endpoint='/api/documents/export', country=user['country'], device=random.choice(user['devices']))
    return one_row(user, hour=random.randint(0, 23), req_1m=random.randint(5, 20), req_5m=random.randint(15, 50), req_1h=random.randint(30, 100), size=800, lat=user['lat'], lon=user['lon'], new_device=random.choice([0, 1]), priv=1, endpoint=random.choice(SENSITIVE_ENDPOINTS), country=random.choice(['IE', 'US', 'RU']), device='fp-priv-' + str(random.randint(1000, 9999)))

# Make N random attacks of mixed types; each labelled 1.
def generate_attacks(how_many=100):
    kinds = ['credential_stuffing', 'insider_threat', 'impossible_travel', 'data_exfiltration', 'privilege_escalation']
    rows = []
    for _ in range(how_many):
        kind = random.choice(kinds)
        user = random.choice(NORMAL_USERS)
        rows.append(make_attack(kind, user))
    return rows

# Convert a list of request dicts into a numeric numpy table (features only) for training.
def rows_to_numbers(rows):
    table = []
    for row in rows:
        one_row = []
        for column_name in config.FEATURE_COLUMNS:
            one_row.append(float(row.get(column_name, 0)))
        table.append(one_row)
    return numpy.array(table, dtype=float)

# PART E. Train the Scaler+IsolationForest pipeline, save it to disk, record the version.
def build_and_save(numbers, version, contamination):
    print('Training the Isolation Forest on', len(numbers), 'examples...')
    pipeline = Pipeline([('scaler', StandardScaler()), ('iforest', IsolationForest(n_estimators=config.IF_N_ESTIMATORS, contamination=contamination, random_state=42))])
    pipeline.fit(numbers)
    saved = {'pipeline': pipeline, 'feature_columns': config.FEATURE_COLUMNS, 'version': version, 'trained_at': datetime.utcnow().isoformat()}
    os.makedirs(os.path.dirname(config.MODEL_PATH), exist_ok=True)
    with open(config.MODEL_PATH, 'wb') as f:
        pickle.dump(saved, f)
    db.record_model_version(version, len(numbers), contamination)
    print('Saved model:', version)
    return {'version': version, 'samples': len(numbers), 'contamination': round(contamination, 4)}

# Bootstrap training: generate fake normal+attack data, then train a model on it.
def train_on_synthetic(n_normal=2000, n_attack=100):
    normal = generate_normal(n_normal)
    attacks = generate_attacks(n_attack)
    all_rows = normal + attacks
    numbers = rows_to_numbers(all_rows)
    contamination = n_attack / len(all_rows)
    version = 'synthetic-' + datetime.utcnow().strftime('%Y%m%d%H%M')
    return build_and_save(numbers, version, contamination)

# Production training: train on real ALLOWED requests from the DB (needs 50+ rows).
def train_on_logs(contamination=0.15, days_lookback=30):
    rows = db.get_training_data(days_lookback)
    if len(rows) < 50:
        raise ValueError('Not enough data to train on: ' + str(len(rows)) + ' rows (need 50+).')
    numbers = rows_to_numbers(rows)
    version = 'logs-' + datetime.utcnow().strftime('%Y%m%d%H%M')
    return build_and_save(numbers, version, contamination)

# PART F self-test: the ALLOW/MFA/DENY score boundaries are correct.
def test_thresholds():
    print('Testing the ALLOW / MFA / DENY thresholds...')
    assert decide(0.3)['action'] == 'ALLOW'
    assert decide(0.55)['action'] == 'MFA_REQUIRED'
    assert decide(0.8)['action'] == 'DENY'
    print('  PASS')

# Self-test: four red flags force a DENY regardless of the score.
def test_critical_rule():
    print("Testing the 'four red flags = DENY' rule...")
    four = ['NEW_DEVICE', 'NEW_LOCATION', 'ABNORMAL_HOUR', 'PRIVILEGE_ESCALATION']
    assert decide(0.3, four)['action'] == 'DENY'
    print('  PASS')

# Self-test: booster point values add up and cap at 1.0.
def test_boosters():
    print('Testing that red-flag points add up correctly...')
    assert booster_total([]) == 0.0
    assert booster_total(['NEW_DEVICE']) == 0.25
    assert booster_total(['NEW_DEVICE', 'NEW_LOCATION', 'PRIVILEGE_ESCALATION', 'BULK_DATA_ACCESS', 'HIGH_REQUEST_RATE', 'ABNORMAL_HOUR']) <= 1.0
    print('  PASS')

# Self-test: time-of-day risk returns the expected values.
def test_time_factor():
    print('Testing the time-of-day risk...')
    assert time_factor(14) == 0.1
    assert time_factor(3) == 0.6
    print('  PASS')

# Self-test: feature extraction returns 13 numbers and the right flags for an attack.
def test_features():
    print('Testing feature extraction and flags...')
    db.init_db()
    db.update_user_baseline('test-user', 'known-device', 'IE', 14)
    attack = {'keycloak_id': 'test-user', 'hour_of_day': 3, 'endpoint': '/api/admin/users', 'geo_country': 'RU', 'device_fingerprint': 'evil-device', 'requests_last_1m': 2}
    features, flags = extract_features(attack)
    assert len(features) == 13
    assert 'NEW_DEVICE' in flags
    assert 'NEW_LOCATION' in flags
    assert 'PRIVILEGE_ESCALATION' in flags
    print('  PASS')

# Self-test: the data generator produces the right counts and labels.
def test_synthetic_data():
    print('Testing the fake data generator...')
    normal = generate_normal(100)
    attacks = generate_attacks(20)
    assert len(normal) == 100
    assert len(attacks) == 20
    assert all((row['label'] == 0 for row in normal))
    assert all((row['label'] == 1 for row in attacks))
    print('  PASS')
if __name__ == '__main__':
    import tempfile
    config.DB_PATH = os.path.join(tempfile.gettempdir(), 'test_ztac.db')
    print('=' * 55)
    test_thresholds()
    test_critical_rule()
    test_boosters()
    test_time_factor()
    test_features()
    test_synthetic_data()
    print('=' * 55)
    print('ALL TESTS PASSED')
    if os.path.exists(config.DB_PATH):
        os.unlink(config.DB_PATH)
