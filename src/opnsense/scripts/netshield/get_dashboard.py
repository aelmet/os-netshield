#!/usr/local/bin/python3
# SPDX-License-Identifier: BSD-2-Clause
#
# NetShield - get_dashboard.py
# Called by configd to supply the frontend dashboard with a comprehensive
# snapshot of current NetShield state.
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

from lib import db, policy_engine, dns_filter, enforcement, app_signatures

LOG_DIR  = "/var/log/netshield"
LOG_FILE = os.path.join(LOG_DIR, "netshield.log")
PID_FILE = "/var/run/netshield.pid"


def _setup_logging() -> logging.Logger:
    os.makedirs(LOG_DIR, exist_ok=True)
    logger = logging.getLogger("netshield.get_dashboard")
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

    dashboard: dict = {
        "summary": {
            "alerts_today": 0,
            "devices_total": 0,
            "policies_active": 0,
            "blocked_domains": 0,
            "service_status": "stopped",
            "generated_at": datetime.utcnow().isoformat() + "Z",
        },
        "top_apps": [],
        "top_devices": [],
        "recent_alerts": [],
        "enforcement_status": {
            "pf_rules_loaded": 0,
            "dns_rules_loaded": 0,
            "quarantined_count": 0,
        },
        "vpn_detections": 0,
        "category_blocks": 0,
    }

    # --- summary ---
    try:
        dashboard["summary"]["alerts_today"] = db.count_alerts_today(today)
    except Exception as exc:
        log.error("dashboard — alerts_today: %s", exc)

    try:
        dashboard["summary"]["devices_total"] = db.count_devices()
    except Exception as exc:
        log.error("dashboard — devices_total: %s", exc)

    try:
        dashboard["summary"]["policies_active"] = len(policy_engine.get_active_policies())
    except Exception as exc:
        log.error("dashboard — policies_active: %s", exc)

    try:
        dashboard["summary"]["blocked_domains"] = dns_filter.count_blocked_domains()
    except Exception as exc:
        log.error("dashboard — blocked_domains: %s", exc)

    dashboard["summary"]["service_status"] = _service_status()

    # --- top apps ---
    try:
        dashboard["top_apps"] = app_signatures.top_detected_apps(limit=10, date=today)
    except Exception as exc:
        log.error("dashboard — top_apps: %s", exc)

    # --- top devices ---
    try:
        dashboard["top_devices"] = db.top_devices_by_alert_count(limit=10, date=today)
    except Exception as exc:
        log.error("dashboard — top_devices: %s", exc)

    # --- recent alerts ---
    try:
        dashboard["recent_alerts"] = db.get_alerts(limit=20)
    except Exception as exc:
        log.error("dashboard — recent_alerts: %s", exc)

    # --- enforcement status ---
    try:
        enf_status = enforcement.get_status()
        dashboard["enforcement_status"]["pf_rules_loaded"]  = enf_status.get("pf_rules_loaded", 0)
        dashboard["enforcement_status"]["dns_rules_loaded"] = enf_status.get("dns_rules_loaded", 0)
        dashboard["enforcement_status"]["quarantined_count"]= enf_status.get("quarantined_count", 0)
    except Exception as exc:
        log.error("dashboard — enforcement_status: %s", exc)

    # --- VPN detections today ---
    try:
        vpn_types = ["vpn_detected", "proxy_detected", "tor_detected", "tunnel_detected"]
        counts = db.alert_counts_by_type(date=today)
        dashboard["vpn_detections"] = sum(counts.get(t, 0) for t in vpn_types)
    except Exception as exc:
        log.error("dashboard — vpn_detections: %s", exc)

    # --- category blocks today ---
    try:
        dashboard["category_blocks"] = db.count_alerts_by_type_prefix(
            prefix="category_block", date=today
        )
    except Exception as exc:
        log.error("dashboard — category_blocks: %s", exc)

    print(json.dumps(dashboard, default=str))


if __name__ == "__main__":
    main()
