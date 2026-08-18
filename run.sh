#!/usr/bin/env bash
# run.sh  -  Start Keycloak (the login server) and the Flask app.
# Usage:  ./run.sh
set -e

APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KEYCLOAK="$HOME/keycloak-26.6.3/bin/kc.sh"
JAVA_HOME_DIR="/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home"
PYTHON="$APP_DIR/../app/.venv/bin/python"   # reuse the main project's Python

# --- 1. Keycloak on port 8080 ---
if curl -s -o /dev/null http://localhost:8080/realms/zerotrust; then
  echo "Keycloak: already running"
else
  echo "Keycloak: starting (log: /tmp/keycloak.log)..."
  JAVA_HOME="$JAVA_HOME_DIR" KC_BOOTSTRAP_ADMIN_USERNAME=admin KC_BOOTSTRAP_ADMIN_PASSWORD=admin \
    nohup "$KEYCLOAK" start-dev > /tmp/keycloak.log 2>&1 &
  for i in $(seq 1 60); do
    curl -s -o /dev/null http://localhost:8080/realms/zerotrust && { echo "  up"; break; }
    sleep 1
  done
fi

# --- 2. The Flask app on port 5001 ---
if lsof -nP -tiTCP:5001 -sTCP:LISTEN >/dev/null 2>&1; then
  echo "App: already running on 5001 (run ./stop.sh first to restart)"
else
  echo "App: starting (log: /tmp/ztac_simple.log)..."
  ( cd "$APP_DIR" && nohup "$PYTHON" app.py > /tmp/ztac_simple.log 2>&1 & )
  for i in $(seq 1 30); do
    curl -s -o /dev/null http://localhost:5001/health && { echo "  up"; break; }
    sleep 1
  done
fi

echo
echo "Ready:"
echo "  Keycloak admin : http://localhost:8080  (admin/admin)"
echo "  App health     : http://localhost:5001/health"
echo "  Stop everything: ./stop.sh"
