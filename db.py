# =============================================================================
# db.py  -  The system's MEMORY. A thin SQLite layer (no ORM, plain sqlite3).
# =============================================================================
# It manages four tables:
#   access_logs     - one row per scored request (every request ever seen)
#   user_baselines  - each user's learned "normal" (known devices/countries/hours)
#   audit_alerts    - one row per DENY (security incidents)
#   model_versions  - training history (which model, when, how many samples)
# Each function opens a connection, does its work, commits, and closes.
# =============================================================================
import sqlite3
import json
import config

# Open a fresh SQLite connection; row_factory lets us read columns by name.
def get_conn():
    conn = sqlite3.connect(config.DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

# Create the four tables if they don't already exist. Safe to call every startup.
def init_db():
    conn = get_conn()
    conn.execute('\n        CREATE TABLE IF NOT EXISTS access_logs (\n            id                      INTEGER PRIMARY KEY AUTOINCREMENT,\n            timestamp               TEXT DEFAULT CURRENT_TIMESTAMP,\n            keycloak_id             TEXT,\n            username                TEXT,\n            ip_address              TEXT,\n            endpoint                TEXT,\n            http_method             TEXT,\n            hour_of_day             INTEGER,\n            day_of_week             INTEGER,\n            requests_last_1m        INTEGER,\n            requests_last_5m        INTEGER,\n            requests_last_1h        INTEGER,\n            request_size_bytes      INTEGER,\n            geo_lat                 REAL,\n            geo_lon                 REAL,\n            geo_country             TEXT,\n            device_fingerprint      TEXT,\n            is_new_device           INTEGER,\n            is_new_location         INTEGER,\n            is_bulk_access          INTEGER,\n            is_privilege_escalation INTEGER,\n            response_latency_ms     REAL,\n            risk_score              REAL,\n            risk_level              TEXT,\n            policy_decision         TEXT,\n            anomaly_flags           TEXT,\n            model_version           TEXT\n        )\n    ')
    conn.execute("\n        CREATE TABLE IF NOT EXISTS user_baselines (\n            keycloak_id     TEXT PRIMARY KEY,\n            known_devices   TEXT DEFAULT '[]',\n            known_countries TEXT DEFAULT '[]',\n            typical_hours   TEXT DEFAULT '[]',\n            total_requests  INTEGER DEFAULT 0,\n            last_seen       TEXT DEFAULT CURRENT_TIMESTAMP\n        )\n    ")
    conn.execute("\n        CREATE TABLE IF NOT EXISTS audit_alerts (\n            id           INTEGER PRIMARY KEY AUTOINCREMENT,\n            timestamp    TEXT DEFAULT CURRENT_TIMESTAMP,\n            log_id       INTEGER,\n            keycloak_id  TEXT,\n            alert_type   TEXT,\n            severity     TEXT DEFAULT 'HIGH',\n            details      TEXT,\n            acknowledged INTEGER DEFAULT 0\n        )\n    ")
    conn.execute('\n        CREATE TABLE IF NOT EXISTS model_versions (\n            id            INTEGER PRIMARY KEY AUTOINCREMENT,\n            version       TEXT,\n            trained_at    TEXT DEFAULT CURRENT_TIMESTAMP,\n            samples       INTEGER,\n            contamination REAL,\n            active        INTEGER DEFAULT 1\n        )\n    ')
    conn.commit()
    conn.close()

# Return one user's learned 'normal' profile (devices/countries/hours), or None if unseen.
def get_user_baseline(keycloak_id):
    conn = get_conn()
    row = conn.execute('SELECT * FROM user_baselines WHERE keycloak_id = ?', (keycloak_id,)).fetchone()
    conn.close()
    if row is None:
        return None
    return {'known_devices': json.loads(row['known_devices']), 'known_countries': json.loads(row['known_countries']), 'typical_hours': json.loads(row['typical_hours'])}

# Add a new device/country/hour to a user's profile (creates the row if new).
# IMPORTANT: called only after an ALLOW, so a blocked attacker can't poison the baseline.
def update_user_baseline(keycloak_id, device, country, hour):
    baseline = get_user_baseline(keycloak_id)
    if baseline is None:
        baseline = {'known_devices': [], 'known_countries': [], 'typical_hours': []}
    if device and device not in baseline['known_devices']:
        baseline['known_devices'].append(device)
    if country and country not in baseline['known_countries']:
        baseline['known_countries'].append(country)
    if hour not in baseline['typical_hours']:
        baseline['typical_hours'].append(hour)
    conn = get_conn()
    conn.execute('\n        INSERT OR REPLACE INTO user_baselines\n        (keycloak_id, known_devices, known_countries, typical_hours, last_seen)\n        VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)\n    ', (keycloak_id, json.dumps(baseline['known_devices']), json.dumps(baseline['known_countries']), json.dumps(baseline['typical_hours'])))
    conn.commit()
    conn.close()

# Save one fully-scored request to access_logs; returns the new row's id.
def insert_access_log(log):
    conn = get_conn()
    cursor = conn.execute('\n        INSERT INTO access_logs (\n            keycloak_id, username, ip_address, endpoint, http_method,\n            hour_of_day, day_of_week, requests_last_1m, requests_last_5m, requests_last_1h,\n            request_size_bytes, geo_lat, geo_lon, geo_country, device_fingerprint,\n            is_new_device, is_new_location, is_bulk_access, is_privilege_escalation,\n            response_latency_ms, risk_score, risk_level, policy_decision,\n            anomaly_flags, model_version\n        ) VALUES (\n            ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?\n        )\n    ', (log.get('keycloak_id'), log.get('username'), log.get('ip_address'), log.get('endpoint'), log.get('http_method'), log.get('hour_of_day'), log.get('day_of_week'), log.get('requests_last_1m'), log.get('requests_last_5m'), log.get('requests_last_1h'), log.get('request_size_bytes'), log.get('geo_lat'), log.get('geo_lon'), log.get('geo_country'), log.get('device_fingerprint'), log.get('is_new_device'), log.get('is_new_location'), log.get('is_bulk_access'), log.get('is_privilege_escalation'), log.get('response_latency_ms'), log.get('risk_score'), log.get('risk_level'), log.get('policy_decision'), json.dumps(log.get('anomaly_flags', [])), log.get('model_version')))
    conn.commit()
    new_id = cursor.lastrowid
    conn.close()
    return new_id

# Record a security incident (called when a request is DENIED).
def insert_audit_alert(log_id, keycloak_id, alert_type, details):
    conn = get_conn()
    conn.execute('\n        INSERT INTO audit_alerts (log_id, keycloak_id, alert_type, details)\n        VALUES (?, ?, ?, ?)\n    ', (log_id, keycloak_id, alert_type, json.dumps(details)))
    conn.commit()
    conn.close()

# Log a training event (version, sample count, contamination) into model_versions.
def record_model_version(version, samples, contamination):
    conn = get_conn()
    conn.execute('\n        INSERT INTO model_versions (version, samples, contamination)\n        VALUES (?, ?, ?)\n    ', (version, samples, contamination))
    conn.commit()
    conn.close()

# Fetch past ALLOWED requests as feature dicts, used to retrain on real traffic.
def get_training_data(days=30):
    conn = get_conn()
    rows = conn.execute("\n        SELECT hour_of_day, day_of_week, requests_last_1m, requests_last_5m,\n               requests_last_1h, request_size_bytes, geo_lat, geo_lon,\n               is_new_device, is_new_location, is_bulk_access,\n               is_privilege_escalation, response_latency_ms\n        FROM access_logs\n        WHERE policy_decision = 'ALLOW'\n    ").fetchall()
    conn.close()
    return [dict(row) for row in rows]
