#!/usr/bin/env bash
# =============================================================================
# demo.sh  -  LIVE demo of the running system.
# =============================================================================
# Unlike evaluate.py (which scores requests offline), this drives the REAL Flask
# app over HTTP with a REAL Keycloak login token, so every request goes through
# the Policy Enforcement Point (@require_auth) and gets a real ALLOW / MFA / DENY
# response, exactly as it would in production.
#
# It does three things:
#   1. Makes sure the system is up (starts it with run.sh if it isn't).
#   2. Gets a login token for the test user 'alice' (creates her if missing).
#   3. Sends 5 NORMAL requests, then 5 ATTACK requests, printing each verdict.
#
# The 5 normal requests come first on purpose: as they are ALLOWED, the system
# LEARNS alice's baseline (her device, country IE, working hour). The 5 attacks
# that follow then look abnormal against that baseline and get caught.
#
# Usage:  ./demo.sh
# =============================================================================

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ---- Settings (match config.py / run.sh) ------------------------------------
APP="http://localhost:5001"          # the Flask app
KC="http://localhost:8080"           # Keycloak
REALM="zerotrust"
CLIENT="zt-app"
USER="alice"
PASS="password123"
ADMIN_USER="admin"                   # Keycloak bootstrap admin (from run.sh)
ADMIN_PASS="admin"

# Reuse the project's Python for tiny JSON parsing (falls back to system python3).
PY="$DIR/../app/.venv/bin/python"
[ -x "$PY" ] || PY="python3"

# Tiny helper: read JSON from stdin and print the value of a Python expression
# over the parsed dict 'd'.  e.g.  echo "$json" | jget "d.get('access_token','')"
jget() { "$PY" -c "import sys,json
try:
    d=json.load(sys.stdin)
except Exception:
    sys.exit(0)
print($1)" 2>/dev/null; }

line() { printf '%s\n' "======================================================================"; }
sub()  { printf '%s\n' "----------------------------------------------------------------------"; }


# ---- Best-effort: create the 'alice' user if the token request fails --------
ensure_alice() {
    local at
    at=$(curl -s -d "grant_type=password&client_id=admin-cli&username=$ADMIN_USER&password=$ADMIN_PASS" \
         "$KC/realms/master/protocol/openid-connect/token" | jget "d.get('access_token','')")
    if [ -z "$at" ]; then
        echo "  (could not get a Keycloak admin token - create '$USER' manually)"
        return
    fi
    # Create the user (harmless if it already exists).
    curl -s -o /dev/null -X POST -H "Authorization: Bearer $at" -H "Content-Type: application/json" \
        -d "{\"username\":\"$USER\",\"enabled\":true}" \
        "$KC/admin/realms/$REALM/users"
    # Look up the user's id.
    local uid
    uid=$(curl -s -H "Authorization: Bearer $at" \
          "$KC/admin/realms/$REALM/users?username=$USER" | jget "d[0]['id']")
    if [ -z "$uid" ]; then
        echo "  (could not find or create '$USER')"
        return
    fi
    # Set a permanent password.
    curl -s -o /dev/null -X PUT -H "Authorization: Bearer $at" -H "Content-Type: application/json" \
        -d "{\"type\":\"password\",\"value\":\"$PASS\",\"temporary\":false}" \
        "$KC/admin/realms/$REALM/users/$uid/reset-password"
    echo "  ensured user '$USER' exists with password '$PASS'."
}

get_token() {
    curl -s -d "grant_type=password&client_id=$CLIENT&username=$USER&password=$PASS" \
        "$KC/realms/$REALM/protocol/openid-connect/token" | jget "d.get('access_token','')"
}

# ---- Wipe alice's learned baseline so the demo starts from a clean slate -----
# WHY: the system only "knows" a device/country/hour after it has ALLOWED it.
# If a previous run left attacker values in her baseline, the NEW_DEVICE /
# NEW_LOCATION flags would not fire and attacks would look normal. Clearing the
# one row makes every run deterministic: the 5 normal requests rebuild her
# baseline from scratch, and the 5 attacks are then genuinely abnormal.
reset_baseline() {
    local sub
    sub=$("$PY" - "$TOKEN" <<'PYEOF'
import sys, base64, json
try:
    p = sys.argv[1].split(".")[1]; p += "=" * (-len(p) % 4)
    print(json.loads(base64.urlsafe_b64decode(p)).get("sub", ""))
except Exception:
    print("")
PYEOF
)
    if [ -z "$sub" ]; then
        echo "  (could not decode token; skipping baseline reset)"
        return
    fi
    "$PY" - "$DIR/ztac.db" "$sub" <<'PYEOF'
import sys, sqlite3
try:
    c = sqlite3.connect(sys.argv[1])
    c.execute("DELETE FROM user_baselines WHERE keycloak_id=?", (sys.argv[2],))
    c.commit(); c.close()
    print("  cleared this user's baseline - starting fresh.")
except Exception as e:
    print("  (baseline reset skipped:", e, ")")
PYEOF
}


# ---- send one authenticated request and print a one-line verdict ------------
# args: <label> <method> <path> <device> <country> <hour>
send() {
    local tag="$1" method="$2" path="$3" device="$4" country="$5" hour="$6"
    local resp code body verdict score flags err

    # -w appends the HTTP status code on its own final line so we can split it off.
    resp=$(curl -s -w $'\n%{http_code}' -X "$method" \
        -H "Authorization: Bearer $TOKEN" \
        -H "X-Device: $device" \
        -H "X-Geo-Country: $country" \
        -H "X-Demo-Hour: $hour" \
        "$APP$path")
    code=$(printf '%s' "$resp" | tail -n1)      # last line = HTTP code
    body=$(printf '%s' "$resp" | sed '$d')      # everything except the last line

    score=$(printf '%s' "$body" | jget "d.get('risk_score', (d.get('decision') or {}).get('risk_score',''))")
    flags=$(printf '%s' "$body" | jget "','.join(d.get('flags',[]))")
    err=$(printf '%s'   "$body" | jget "d.get('error','')")

    # Turn the HTTP status into the policy decision (200=ALLOW, 401=MFA, 403=DENY).
    case "$code" in
        200) verdict="ALLOW" ;;
        401) if printf '%s' "$err" | grep -qi "token"; then verdict="AUTH-FAIL"; else verdict="MFA_REQUIRED"; fi ;;
        403) verdict="DENY" ;;
        *)   verdict="HTTP $code" ;;
    esac

    printf "  %-48s -> %-13s score=%-6s %s\n" \
        "$tag" "$verdict" "${score:-?}" "${flags:+[flags: $flags]}"
}


# =============================================================================
# 1. MAKE SURE THE SYSTEM IS RUNNING
# =============================================================================
line
echo "  ADAPTIVE ZERO-TRUST ACCESS CONTROL  -  LIVE DEMO"
line
if curl -sf "$APP/health" >/dev/null 2>&1; then
    echo "System: already running."
else
    echo "System: not running - starting it with run.sh (this can take a moment)..."
    "$DIR/run.sh"
fi
# Final check that the app really answered.
if ! curl -sf "$APP/health" >/dev/null 2>&1; then
    echo "ERROR: the app is not responding on $APP. Check /tmp/ztac_simple.log."
    exit 1
fi
echo "Health : $(curl -s "$APP/health" | jget "d.get('status','?')+' (model '+str(d.get('model_version','?'))+')'")"

# =============================================================================
# 2. GET A LOGIN TOKEN FOR alice
# =============================================================================
TOKEN="$(get_token)"
if [ -z "$TOKEN" ]; then
    echo "Login : no token for '$USER' yet - attempting to create the user..."
    ensure_alice
    TOKEN="$(get_token)"
fi
if [ -z "$TOKEN" ]; then
    echo "ERROR: could not obtain a login token."
    echo "       Make sure Keycloak is up, realm '$REALM' and client '$CLIENT' exist,"
    echo "       and that client '$CLIENT' has 'Direct access grants' enabled."
    exit 1
fi
echo "Login : got a token for '$USER'."
reset_baseline
echo

# =============================================================================
# 3a. FIVE NORMAL REQUESTS  (these ALLOW and teach alice's baseline)
# =============================================================================
echo "PART A - 5 NORMAL requests (known laptop, Ireland, business hours)"
sub
send "Normal 1: list documents"            GET  "/api/documents"     "alice-laptop" "IE" 14
send "Normal 2: open document 1"           GET  "/api/documents/1"   "alice-laptop" "IE" 14
send "Normal 3: open document 2"           GET  "/api/documents/2"   "alice-laptop" "IE" 14
send "Normal 4: open document 3"           GET  "/api/documents/3"   "alice-laptop" "IE" 14
send "Normal 5: list documents again"      GET  "/api/documents"     "alice-laptop" "IE" 14
echo

# =============================================================================
# 3b. FIVE ATTACK REQUESTS  (abnormal vs the baseline just learned)
# =============================================================================
echo "PART B - 5 ATTACK requests (new devices, foreign country, odd hours, sensitive endpoints)"
sub
# Each attack uses a UNIQUE new device (and mostly a new country) so they stay
# independent. 2-3 flags -> MFA_REQUIRED; 4 flags -> critical override -> DENY.
send "Attack 1: 2am login, new device, from RU"     GET  "/api/documents"        "attacker-1" "RU" 2
send "Attack 2: 3am bulk export (insider, own PC)"  GET  "/api/documents/export" "alice-laptop" "IE" 3
send "Attack 3: 3am admin access, new device"       GET  "/api/admin/users"      "attacker-3" "IE" 3
# 4 flags each (new device + new country + odd hour + sensitive endpoint) -> DENY:
send "Attack 4: 3am admin, new device, from CN"     GET  "/api/admin/users"      "attacker-4" "CN" 3
send "Attack 5: 2am bulk export, new device, from BR" GET "/api/documents/export" "attacker-5" "BR" 2
echo

line
echo "  Demo complete. Normal traffic was ALLOWED; attacks were challenged (MFA) or DENIED."
echo "  See the audit trail:   curl -s $APP/audit/alerts | $PY -m json.tool"
line
