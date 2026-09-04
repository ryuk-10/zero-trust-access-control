#!/usr/bin/env python3
"""
observability.py -- structured logging and request tracing (v1.5.0).

Before this, the app only printed ad-hoc messages and stored decisions in SQLite.
This module adds machine-readable (JSON) logging so the service can be shipped to
a log aggregator (ELK, Loki, CloudWatch) and each request can be traced end to
end by a single request id.

It is dependency-free (standard library `logging` + `json`) and does two things:
  * get_logger()      -> a logger that emits one JSON object per line to stdout.
  * log_request(...)  -> log a single access decision as a structured event.

Nothing here changes how requests are scored; it only records what happened.
"""
import json
import logging
import sys
import time

_LOGGER = None


class _JsonFormatter(logging.Formatter):
    """Render each log record as a compact one-line JSON object."""

    def format(self, record):
        payload = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(record.created)),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        # Anything passed via logger.info(..., extra={"event": {...}}) is merged in.
        if hasattr(record, "event") and isinstance(record.event, dict):
            payload.update(record.event)
        return json.dumps(payload, default=str)


def get_logger(name="ztac"):
    """Return a process-wide singleton JSON logger writing to stdout."""
    global _LOGGER
    if _LOGGER is not None:
        return _LOGGER
    logger = logging.getLogger(name)
    logger.setLevel(logging.INFO)
    logger.propagate = False          # don't double-log through the root logger
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(_JsonFormatter())
        logger.addHandler(handler)
    _LOGGER = logger
    return logger


def log_request(request_id, username, endpoint, method, decision,
                risk_score, flags, latency_ms, ip=None):
    """Emit one structured 'access_decision' event for a scored request.

    All the fields a security team would want to filter or alert on live at the
    top level of the JSON object, so queries like `policy_decision = "DENY"` work
    directly in a log aggregator.
    """
    get_logger().info("access_decision", extra={"event": {
        "event_type": "access_decision",
        "request_id": request_id,
        "username": username,
        "endpoint": endpoint,
        "method": method,
        "policy_decision": decision,
        "risk_score": risk_score,
        "flags": flags,
        "latency_ms": latency_ms,
        "ip": ip,
    }})


if __name__ == "__main__":
    # Tiny self-check.
    log_request("req-demo-1", "alice", "/api/admin/users", "GET",
                "DENY", 0.83, ["NEW_DEVICE", "PRIVILEGE_ESCALATION"], 6.1, "203.0.113.7")
