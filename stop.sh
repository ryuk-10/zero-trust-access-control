#!/usr/bin/env bash
# stop.sh  -  Stop the Flask app (5001) and Keycloak (8080).
for port in 5001 8080; do
  pids="$(lsof -nP -tiTCP:$port -sTCP:LISTEN 2>/dev/null || true)"
  if [ -n "$pids" ]; then
    echo "stopping whatever is on port $port (PID $pids)"
    kill $pids 2>/dev/null || true
  else
    echo "nothing running on port $port"
  fi
done
