#!/usr/local/bin/python3
# SPDX-License-Identifier: BSD-2-Clause
#
# NetShield - get_stats.py
# Called by configd to return a statistics summary.
# Outputs a single JSON object to stdout.

import sys
import os
import json
import logging
import logging.handlers
import traceback
from datetime import datetime

_SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))
sys.path.insert(0, _SCRIPT_DIR)

from lib import db, policy_engine, dns_filter

LOG_DIR  = "/var/log/netshield"
LOG_FILE = os.path.join(LOG_DIR, "netshield.log")
PID_FILE = "/var/run/netshield.pid"


def _setup_logging() -> logging.Logger:
    os.makedirs(LOG_DIR, exist_ok=True)
    logger = logging.getLogger("netshield.get_stats")
    logger.setLevel(logging.WARNING)
    if logger.handlers:
        return logger
    handler = logging.handlers.RotatingFileHandler(
        LOG_FILE, maxBytes=5 * 1024 * 1024, backupCount=3
    )
    handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s"))
    logger.addHandler(handler)
    return logger


log = _setup_logging()


def _service_status() -> str:
    try:
        with open(PID_FILE) as fh:
            pid = int(fh.read().strip())
        os.kill(pid, 0)
        return "running"
    except (FileNotFoundError, ValueError, OSError):
        return "stopped"


def main() -> None:
    today = datetime.utcnow().date().isoformat()
    result: dict = {
        "alerts_today": 0,
        "alerts_by_type": {},
        "top_devices": [],
        "recent_alerts": [],
        "devices_total": 0,
        "policies_active": 0,
        "blocked_domains": 0,
        "service_status": "stopped",
    }

    try:
        result["alerts_today"] = db.count_alerts_today(today)
    except Exception as exc:
        log.error("stats — alerts_today: %s", exc)

    try:
        result["alerts_by_type"] = db.alert_counts_by_type(date=today)
    except Exception as exc:
        log.error("stats — alerts_by_type: %s", exc)

    try:
        result["top_devices"] = db.top_devices_by_alert_count(limit=10, date=today)
    except Exception as exc:
        log.error("stats — top_devices: %s", exc)

    try:
        result["recent_alerts"] = db.get_alerts(limit=10)
    except Exception as exc:
        log.error("stats — recent_alerts: %s", exc)

    try:
        result["devices_total"] = db.count_devices()
    except Exception as exc:
        log.error("stats — devices_total: %s", exc)

    try:
        result["policies_active"] = len(policy_engine.get_active_policies())
    except Exception as exc:
        log.error("stats — policies_active: %s", exc)

    try:
        result["blocked_domains"] = dns_filter.count_blocked_domains()
    except Exception as exc:
        log.error("stats — blocked_domains: %s", exc)

    result["service_status"] = _service_status()

    print(json.dumps(result, default=str))


if __name__ == "__main__":
    main()
