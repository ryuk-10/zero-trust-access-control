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
import uuid
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
import geoip
import observability
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
    ip = request.headers.get('X-Forwarded-For', request.remote_addr or '127.0.0.1')
    # v1.4.0: resolve real coordinates from the country hint / IP instead of 0,0,
    # so the geo features carry signal on the live path (see geoip.py).
    geo = geoip.resolve(ip=ip, country_hint=request.headers.get('X-Geo-Country', ''))
    context = {'keycloak_id': user['keycloak_id'], 'username': user['username'], 'ip_address': ip, 'endpoint': request.path, 'http_method': request.method, 'device_fingerprint': request.headers.get('X-Device', device_fingerprint), 'geo_country': geo['country'], 'geo_lat': geo['lat'], 'geo_lon': geo['lon'], 'request_size_bytes': int(request.headers.get('Content-Length', 0)), 'hour_of_day': int(request.headers.get('X-Demo-Hour', now.hour)), 'day_of_week': now.weekday()}
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
        # Structured, traceable log line for this decision (JSON to stdout).
        observability.log_request(
            request_id=getattr(g, 'request_id', None),
            username=user['username'], endpoint=context['endpoint'],
            method=context['http_method'], decision=decision['action'],
            risk_score=risk, flags=flags, latency_ms=latency_ms,
            ip=context.get('ip_address'))
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


# ---- Request tracing (v1.5.0) ----------------------------------------------
# Give every request a unique id so it can be traced across the logs. Honour an
# incoming X-Request-ID (e.g. from a load balancer) or mint a fresh one.
@app.before_request
def _assign_request_id():
    g.request_id = request.headers.get('X-Request-ID') or uuid.uuid4().hex[:16]
    g.start_time = time.perf_counter()


# ---- Basic hardening (v1.5.0) ----------------------------------------------
# Standard security headers on every response, plus the request id echoed back.
_SECURITY_HEADERS = {
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'Referrer-Policy': 'no-referrer',
    'Cache-Control': 'no-store',
    # Allow the dashboard's own inline script/style; block all external sources.
    'Content-Security-Policy': "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'",
}


@app.after_request
def _security_headers(response):
    for header, value in _SECURITY_HEADERS.items():
        response.headers.setdefault(header, value)
    if getattr(g, 'request_id', None):
        response.headers['X-Request-ID'] = g.request_id
    return response


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

@app.route('/metrics')
# GET /metrics (no auth): Prometheus-style plaintext metrics for ops dashboards.
# Exposes request totals by decision, alert count and average scoring latency, so
# the service can be scraped by Prometheus / Grafana without any extra dependency.
def metrics():
    conn = db.get_conn()
    total = conn.execute('SELECT COUNT(*) FROM access_logs').fetchone()[0]
    counts = {'ALLOW': 0, 'MFA_REQUIRED': 0, 'DENY': 0}
    for row in conn.execute('SELECT policy_decision, COUNT(*) AS n FROM access_logs GROUP BY policy_decision'):
        if row['policy_decision'] in counts:
            counts[row['policy_decision']] = row['n']
    alerts = conn.execute('SELECT COUNT(*) FROM audit_alerts').fetchone()[0]
    avg_latency = conn.execute('SELECT AVG(response_latency_ms) FROM access_logs').fetchone()[0] or 0.0
    lines = [
        '# HELP ztac_requests_total Total requests scored by the PEP.',
        '# TYPE ztac_requests_total counter',
        'ztac_requests_total %d' % total,
        '# HELP ztac_decisions_total Requests by policy decision.',
        '# TYPE ztac_decisions_total counter',
        'ztac_decisions_total{decision="allow"} %d' % counts['ALLOW'],
        'ztac_decisions_total{decision="mfa_required"} %d' % counts['MFA_REQUIRED'],
        'ztac_decisions_total{decision="deny"} %d' % counts['DENY'],
        '# HELP ztac_alerts_total Security alerts raised.',
        '# TYPE ztac_alerts_total counter',
        'ztac_alerts_total %d' % alerts,
        '# HELP ztac_scoring_latency_ms_avg Mean per-request scoring latency.',
        '# TYPE ztac_scoring_latency_ms_avg gauge',
        'ztac_scoring_latency_ms_avg %.3f' % avg_latency,
    ]
    return app.response_class('\n'.join(lines) + '\n', mimetype='text/plain; version=0.0.4')


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


# -----------------------------------------------------------------------------
# Audit dashboard (v1.3.0): a single self-contained HTML page that visualises the
# audit trail. It has NO external dependencies (no CDN, no build step) - the page
# just polls the existing /audit/stats, /audit/logs and /audit/alerts JSON
# endpoints every few seconds and redraws. Open http://localhost:5001/dashboard.
# -----------------------------------------------------------------------------
_DASHBOARD_HTML = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Zero-Trust Audit Dashboard</title>
<style>
  :root{--bg:#0f1420;--card:#171e2e;--line:#26304a;--fg:#e7ecf5;--mut:#8a97b1;
        --allow:#2ecc71;--mfa:#f1c40f;--deny:#e74c3c;--accent:#4aa3ff}
  *{box-sizing:border-box} body{margin:0;background:var(--bg);color:var(--fg);
    font:14px/1.5 -apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif}
  header{padding:18px 24px;border-bottom:1px solid var(--line);display:flex;
    align-items:baseline;gap:12px} header h1{font-size:18px;margin:0;font-weight:600}
  header .sub{color:var(--mut);font-size:12px} main{padding:20px 24px;max-width:1100px;margin:0 auto}
  .cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:14px;margin-bottom:22px}
  .card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:16px}
  .card .n{font-size:28px;font-weight:700} .card .k{color:var(--mut);font-size:12px;text-transform:uppercase;letter-spacing:.04em}
  .allow .n{color:var(--allow)} .mfa .n{color:var(--mfa)} .deny .n{color:var(--deny)}
  h2{font-size:13px;text-transform:uppercase;letter-spacing:.05em;color:var(--mut);margin:26px 0 10px}
  table{width:100%;border-collapse:collapse} th,td{text-align:left;padding:8px 10px;border-bottom:1px solid var(--line);font-size:13px}
  th{color:var(--mut);font-weight:600} td.mono{font-variant-numeric:tabular-nums}
  .pill{padding:2px 9px;border-radius:20px;font-size:12px;font-weight:600;display:inline-block}
  .p-ALLOW{background:rgba(46,204,113,.15);color:var(--allow)}
  .p-MFA_REQUIRED{background:rgba(241,196,15,.15);color:var(--mfa)}
  .p-DENY{background:rgba(231,76,60,.15);color:var(--deny)}
  .flags{color:var(--mut);font-size:12px} .empty{color:var(--mut);padding:14px 10px}
  footer{color:var(--mut);font-size:12px;padding:10px 24px 30px}
</style></head>
<body>
<header><h1>Zero-Trust Audit Dashboard</h1>
  <span class="sub">live view of every scored request &middot; refreshes every 4s</span></header>
<main>
  <div class="cards">
    <div class="card"><div class="k">Total requests</div><div class="n" id="c-total">-</div></div>
    <div class="card allow"><div class="k">Allowed</div><div class="n" id="c-allow">-</div></div>
    <div class="card mfa"><div class="k">Step-up (MFA)</div><div class="n" id="c-mfa">-</div></div>
    <div class="card deny"><div class="k">Denied</div><div class="n" id="c-deny">-</div></div>
  </div>
  <h2>Recent requests</h2>
  <table><thead><tr><th>#</th><th>Time</th><th>User</th><th>Endpoint</th>
    <th>Score</th><th>Decision</th><th>Flags</th></tr></thead>
    <tbody id="logs"><tr><td colspan="7" class="empty">loading&hellip;</td></tr></tbody></table>
  <h2>Security alerts</h2>
  <table><thead><tr><th>#</th><th>Time</th><th>User</th><th>Type</th></tr></thead>
    <tbody id="alerts"><tr><td colspan="4" class="empty">loading&hellip;</td></tr></tbody></table>
</main>
<footer>Adaptive Zero-Trust Access Control &middot; no external assets &middot; data from /audit/*</footer>
<script>
  const $=id=>document.getElementById(id);
  const esc=s=>String(s==null?'':s).replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]));
  const t=s=>{if(!s)return '';const d=new Date(s.replace(' ','T')+'Z');
    return isNaN(d)?esc(s):d.toLocaleTimeString();};
  async function j(u){try{const r=await fetch(u);return await r.json();}catch(e){return null;}}
  async function tick(){
    const s=await j('/audit/stats');
    if(s){$('c-total').textContent=s.total_requests;
      $('c-allow').textContent=(s.decisions.ALLOW||0);
      $('c-mfa').textContent=(s.decisions.MFA_REQUIRED||0);
      $('c-deny').textContent=(s.decisions.DENY||0);}
    const l=await j('/audit/logs?limit=25');
    if(l&&l.logs){$('logs').innerHTML = l.logs.length? l.logs.map(r=>{
      let f=r.anomaly_flags; try{f=JSON.parse(f||'[]').join(', ');}catch(e){f=r.anomaly_flags||'';}
      const sc=r.risk_score==null?'':Number(r.risk_score).toFixed(3);
      return `<tr><td class=mono>${r.id}</td><td>${t(r.timestamp)}</td><td>${esc(r.username)}</td>
        <td>${esc(r.endpoint)}</td><td class=mono>${sc}</td>
        <td><span class="pill p-${esc(r.policy_decision)}">${esc(r.policy_decision)}</span></td>
        <td class=flags>${esc(f)}</td></tr>`;}).join('')
      : '<tr><td colspan=7 class=empty>no requests yet - run demo.sh or evaluate.py</td></tr>';}
    const a=await j('/audit/alerts');
    if(a&&a.alerts){$('alerts').innerHTML = a.alerts.length? a.alerts.map(r=>
      `<tr><td class=mono>${r.id}</td><td>${t(r.timestamp)}</td>
        <td>${esc(r.keycloak_id)}</td><td>${esc(r.alert_type)}</td></tr>`).join('')
      : '<tr><td colspan=4 class=empty>no alerts</td></tr>';}
  }
  tick(); setInterval(tick,4000);
</script>
</body></html>"""


@app.route('/dashboard')
# GET /dashboard (no auth): human-readable audit dashboard for the demo.
def dashboard():
    return app.response_class(_DASHBOARD_HTML, mimetype='text/html')


if __name__ == '__main__':
    start_up()
    print('Starting the web server on http://localhost:' + str(config.PORT))
    app.run(host=os.getenv('HOST', '127.0.0.1'), port=config.PORT)
