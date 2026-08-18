# =============================================================================
# app.py  -  The WEB LAYER + Policy Enforcement Point (PEP).
# =============================================================================
# This is the Flask application. The key piece is the @require_auth decorator:
# every protected route runs through it, so each request is (1) token-verified,
# (2) turned into a context, (3) scored by the engine, (4) logged, and (5)
# enforced - ALLOW runs the page, MFA returns 401, DENY returns 403 + an alert.
# The un-protected /health, /train, /evaluate and /audit/* routes exist for
# bootstrapping, batch testing, and the dashboard.
# =============================================================================
import os
import time
import hashlib
import functools
from datetime import datetime
from collections import defaultdict
from flask import Flask, request, jsonify, g
import jwt
import requests as http
import config
import db
import engine
from engine import extract_features, score_risk, decide
_key_cache = {'keys': None, 'fetched_at': 0}
_request_times = defaultdict(list)

# Fetch Keycloak's public signing keys (JWKS), cached for 5 minutes to avoid re-fetching.
def _get_keycloak_keys():
    now = time.time()
    still_fresh = _key_cache['keys'] is not None and now - _key_cache['fetched_at'] < 300
    if still_fresh:
        return _key_cache['keys']
    response = http.get(config.JWKS_URL, timeout=5)
    response.raise_for_status()
    _key_cache['keys'] = response.json()['keys']
    _key_cache['fetched_at'] = now
    return _key_cache['keys']

# Verify a login token's signature, expiry and audience using Keycloak's key; return its claims.
def _verify_jwt(token):
    header = jwt.get_unverified_header(token)
    key_id = header.get('kid')
    matching_key = None
    for key in _get_keycloak_keys():
        if key['kid'] == key_id:
            matching_key = key
            break
    if matching_key is None:
        raise jwt.InvalidTokenError('No matching Keycloak key for this token.')
    public_key = jwt.algorithms.RSAAlgorithm.from_jwk(matching_key)
    contents = jwt.decode(token, public_key, algorithms=['RS256'], audience=config.KEYCLOAK_CLIENT_ID)
    return contents

# Track this user's request timestamps and count how many in the last 1m / 5m / 1h.
def _get_request_rates(keycloak_id):
    now = time.time()
    times = _request_times[keycloak_id]
    times.append(now)
    times = [t for t in times if t > now - 3600]
    _request_times[keycloak_id] = times
    last_1m = 0
    last_5m = 0
    for t in times:
        if t > now - 60:
            last_1m += 1
        if t > now - 300:
            last_5m += 1
    return {'requests_last_1m': last_1m, 'requests_last_5m': last_5m, 'requests_last_1h': len(times)}

# Assemble the request context (user, endpoint, device fingerprint, geo, time, rates) for scoring.
def _build_context(user):
    user_agent = request.headers.get('User-Agent', '')
    device_fingerprint = hashlib.sha256(user_agent.encode()).hexdigest()[:16]
    now = datetime.utcnow()
    rates = _get_request_rates(user['keycloak_id'])
    context = {'keycloak_id': user['keycloak_id'], 'username': user['username'], 'ip_address': request.headers.get('X-Forwarded-For', request.remote_addr or '127.0.0.1'), 'endpoint': request.path, 'http_method': request.method, 'device_fingerprint': request.headers.get('X-Device', device_fingerprint), 'geo_country': request.headers.get('X-Geo-Country', ''), 'geo_lat': 0.0, 'geo_lon': 0.0, 'request_size_bytes': int(request.headers.get('Content-Length', 0)), 'hour_of_day': int(request.headers.get('X-Demo-Hour', now.hour)), 'day_of_week': now.weekday()}
    context.update(rates)
    return context

# Pick a human-readable alert name based on which flags fired (for the audit log).
def _alert_type_for(flags):
    if 'BULK_DATA_ACCESS' in flags:
        return 'BULK_DOWNLOAD_DETECTED'
    if 'PRIVILEGE_ESCALATION' in flags:
        return 'PRIVILEGE_ESCALATION_ATTEMPT'
    if 'NEW_LOCATION' in flags:
        return 'ANOMALOUS_LOCATION'
    if 'HIGH_REQUEST_RATE' in flags:
        return 'CREDENTIAL_MISUSE_SUSPECTED'
    return 'ANOMALOUS_BEHAVIOUR'

# The DECORATOR = the Policy Enforcement Point. Wrap a route so every request to it is
# verified, scored, logged, and enforced before the page code ever runs.
def require_auth(page_function):

    @functools.wraps(page_function)
    # The wrapper that runs on each request: verify token -> build context -> score -> decide,
    # log it, then ALLOW (run page + learn baseline) / MFA (401) / DENY (403 + alert).
    def guarded_page(*args, **kwargs):
        start_time = time.perf_counter()
        auth_header = request.headers.get('Authorization', '')
        if not auth_header.startswith('Bearer '):
            return (jsonify({'error': 'Missing login token'}), 401)
        token = auth_header[len('Bearer '):]
        try:
            token_contents = _verify_jwt(token)
        except Exception:
            return (jsonify({'error': 'Invalid or expired login token'}), 401)
        user = {'keycloak_id': token_contents['sub'], 'username': token_contents.get('preferred_username', token_contents['sub'])}
        context = _build_context(user)
        features, flags = extract_features(context)
        risk = score_risk(features, flags)
        decision = decide(risk, flags)
        latency_ms = round((time.perf_counter() - start_time) * 1000, 2)
        log_row = dict(context)
        log_row['is_new_device'] = 1 if 'NEW_DEVICE' in flags else 0
        log_row['is_new_location'] = 1 if 'NEW_LOCATION' in flags else 0
        log_row['is_bulk_access'] = 1 if 'BULK_DATA_ACCESS' in flags else 0
        log_row['is_privilege_escalation'] = 1 if 'PRIVILEGE_ESCALATION' in flags else 0
        log_row['response_latency_ms'] = latency_ms
        log_row['risk_score'] = risk
        log_row['risk_level'] = decision['risk_level']
        log_row['policy_decision'] = decision['action']
        log_row['anomaly_flags'] = flags
        log_row['model_version'] = 'current'
        log_id = db.insert_access_log(log_row)
        if decision['action'] == 'ALLOW':
            db.update_user_baseline(context['keycloak_id'], context['device_fingerprint'], context['geo_country'], context['hour_of_day'])
            g.user = user
            g.decision = decision
            return page_function(*args, **kwargs)
        elif decision['action'] == 'MFA_REQUIRED':
            return (jsonify({'error': 'Extra login (MFA) required - this request looks unusual', 'risk_score': risk, 'flags': flags}), 401)
        else:
            db.insert_audit_alert(log_id, user['keycloak_id'], _alert_type_for(flags), {'risk_score': risk, 'flags': flags})
            return (jsonify({'error': 'Access denied - this request looks like an attack', 'risk_score': risk, 'flags': flags, 'alert_id': log_id}), 403)
    return guarded_page
app = Flask(__name__)

# On server start: create the DB tables and load the model (training one first if none exists).
def start_up():
    db.init_db()
    if not os.path.exists(config.MODEL_PATH):
        from engine import train_on_synthetic
        print('No model found. Training one from synthetic data...')
        train_on_synthetic()
    engine.load_model()

@app.route('/health')
# GET /health (no auth): report model status and the current thresholds.
def health():
    return jsonify({'status': 'ok' if engine.is_model_loaded() else 'degraded', 'model_version': engine.get_model_version(), 'thresholds': {'allow_below': config.ALLOW_THRESHOLD, 'deny_above': config.DENY_THRESHOLD}})

@app.route('/train', methods=['POST'])
# POST /train (no auth): retrain the model (synthetic or on logs) and hot-swap it in.
def train():
    from engine import train_on_synthetic, train_on_logs
    body = request.get_json(force=True) if request.data else {}
    try:
        if body.get('synthetic'):
            result = train_on_synthetic(int(body.get('n_normal', 2000)), int(body.get('n_attack', 100)))
        else:
            result = train_on_logs()
        engine.reload_model()
        return jsonify({'status': 'trained', **result})
    except ValueError as error:
        return (jsonify({'error': str(error)}), 400)

# Helper: divide two numbers, returning 0.0 instead of crashing on divide-by-zero.
def safe_divide(top, bottom):
    if bottom == 0:
        return 0.0
    return top / bottom

# From scored+labelled results, compute precision / recall / F1 / false-positive rate.
def compute_metrics(results):
    labelled = []
    for r in results:
        if r['label'] is not None:
            labelled.append(r)
    if not labelled:
        return None
    true_positive = 0
    false_positive = 0
    false_negative = 0
    true_negative = 0
    for r in labelled:
        flagged = r['risk_level'] in ('MEDIUM', 'HIGH')
        if r['label'] == 1 and flagged:
            true_positive += 1
        elif r['label'] == 0 and flagged:
            false_positive += 1
        elif r['label'] == 1 and (not flagged):
            false_negative += 1
        else:
            true_negative += 1
    precision = safe_divide(true_positive, true_positive + false_positive)
    recall = safe_divide(true_positive, true_positive + false_negative)
    f1 = safe_divide(2 * precision * recall, precision + recall)
    false_positive_rate = safe_divide(false_positive, false_positive + true_negative)
    return {'precision': round(precision, 4), 'recall': round(recall, 4), 'f1_score': round(f1, 4), 'false_positive_rate': round(false_positive_rate, 4), 'total': len(labelled)}

@app.route('/evaluate', methods=['POST'])
# POST /evaluate (no auth): score a batch of records; if labels are given, also return metrics.
def evaluate():
    body = request.get_json(force=True)
    records = body.get('records', [])
    if not records:
        return (jsonify({'error': 'no records given'}), 400)
    results = []
    for record in records:
        features, flags = extract_features(record)
        score = engine.score_risk(features, flags)
        decision = decide(score, flags)
        results.append({'risk_score': score, 'risk_level': decision['risk_level'], 'policy_decision': decision['action'], 'flags': flags, 'label': record.get('label')})
    metrics = compute_metrics(results)
    return jsonify({'results': results, 'metrics': metrics})

@app.route('/audit/logs')
# GET /audit/logs (no auth): most recent scored requests, for the dashboard.
def audit_logs():
    limit = int(request.args.get('limit', 50))
    rows = db.get_conn().execute('SELECT id, timestamp, username, endpoint, risk_score, policy_decision, anomaly_flags FROM access_logs ORDER BY id DESC LIMIT ?', (limit,)).fetchall()
    return jsonify({'logs': [dict(r) for r in rows]})

@app.route('/audit/alerts')
# GET /audit/alerts (no auth): most recent security alerts.
def audit_alerts():
    rows = db.get_conn().execute('SELECT id, timestamp, keycloak_id, alert_type, details FROM audit_alerts ORDER BY id DESC LIMIT 20').fetchall()
    return jsonify({'alerts': [dict(r) for r in rows]})

@app.route('/audit/stats')
# GET /audit/stats (no auth): totals and the ALLOW/MFA/DENY breakdown.
def audit_stats():
    conn = db.get_conn()
    total = conn.execute('SELECT COUNT(*) FROM access_logs').fetchone()[0]
    counts = {'ALLOW': 0, 'MFA_REQUIRED': 0, 'DENY': 0}
    for row in conn.execute('SELECT policy_decision, COUNT(*) AS n FROM access_logs GROUP BY policy_decision'):
        counts[row['policy_decision']] = row['n']
    return jsonify({'total_requests': total, 'decisions': counts})

@app.route('/api/documents')
@require_auth
# GET /api/documents (PROTECTED): a normal endpoint - should be ALLOWED for genuine users.
def list_documents():
    return jsonify({'documents': ['Q1 Report', 'HR Policy', 'Org Chart'], 'decision': g.decision})

@app.route('/api/documents/<int:doc_id>')
@require_auth
# GET /api/documents/<id> (PROTECTED): fetch one document.
def get_document(doc_id):
    return jsonify({'id': doc_id, 'title': 'Sample Document', 'decision': g.decision})

@app.route('/api/documents/export', methods=['POST', 'GET'])
@require_auth
# GET/POST /api/documents/export (PROTECTED): triggers the BULK_DATA_ACCESS flag.
def export_documents():
    return jsonify({'message': 'Bulk export started', 'decision': g.decision})

@app.route('/api/admin/users')
@require_auth
# GET /api/admin/users (PROTECTED): triggers the PRIVILEGE_ESCALATION flag.
def admin_users():
    return jsonify({'users': ['alice', 'bob'], 'decision': g.decision})
if __name__ == '__main__':
    start_up()
    print('Starting the web server on http://localhost:' + str(config.PORT))
    app.run(host='127.0.0.1', port=config.PORT)
