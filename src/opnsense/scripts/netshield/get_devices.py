#!/usr/local/bin/python3
# SPDX-License-Identifier: BSD-2-Clause
#
# NetShield - get_devices.py
# Called by configd to list devices and manage quarantine/approval state.
# Usage (first positional arg is action):
#   get_devices.py list
#   get_devices.py quarantine   <MAC>
#   get_devices.py unquarantine <MAC>
#   get_devices.py approve      <MAC>

import sys
import os
import json
import re
import logging
import logging.handlers
import traceback

_SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))
sys.path.insert(0, _SCRIPT_DIR)

from lib import db, device_tracker, enforcement

LOG_DIR  = "/var/log/netshield"
LOG_FILE = os.path.join(LOG_DIR, "netshield.log")

_MAC_RE = re.compile(r"^([0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}$")


def _setup_logging() -> logging.Logger:
    os.makedirs(LOG_DIR, exist_ok=True)
    logger = logging.getLogger("netshield.get_devices")
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


def _output(data) -> None:
    print(json.dumps(data, default=str))


def _validate_mac(mac: str) -> bool:
    return bool(_MAC_RE.match(mac))


def action_list() -> None:
    try:
        devices = db.get_all_devices()
        _output(devices)
    except Exception as exc:
        log.error("get_devices list error: %s\n%s", exc, traceback.format_exc())
        _output({"error": str(exc)})


def action_quarantine(mac: str) -> None:
    if not _validate_mac(mac):
        _output({"error": "Invalid MAC address format"})
        return
    try:
        mac = mac.upper()
        db.set_device_quarantine(mac, quarantined=True)
        # Generate and apply a pf block rule for this MAC
        enforcement.add_quarantine_rule(mac)
        _output({"result": "quarantined", "mac": mac})
    except Exception as exc:
        log.error("quarantine error for %s: %s\n%s", mac, exc, traceback.format_exc())
        _output({"error": str(exc)})


def action_unquarantine(mac: str) -> None:
    if not _validate_mac(mac):
        _output({"error": "Invalid MAC address format"})
        return
    try:
        mac = mac.upper()
        db.set_device_quarantine(mac, quarantined=False)
        enforcement.remove_quarantine_rule(mac)
        _output({"result": "unquarantined", "mac": mac})
    except Exception as exc:
        log.error("unquarantine error for %s: %s\n%s", mac, exc, traceback.format_exc())
        _output({"error": str(exc)})


def action_approve(mac: str) -> None:
    if not _validate_mac(mac):
        _output({"error": "Invalid MAC address format"})
        return
    try:
        mac = mac.upper()
        db.set_device_approved(mac, approved=True)
        _output({"result": "approved", "mac": mac})
    except Exception as exc:
        log.error("approve error for %s: %s\n%s", mac, exc, traceback.format_exc())
        _output({"error": str(exc)})


def main() -> None:
    if len(sys.argv) < 2:
        _output({"error": "No action specified. Use: list | quarantine | unquarantine | approve"})
        return

    action = sys.argv[1].lower()

    if action == "list":
        action_list()

    elif action == "quarantine":
        if len(sys.argv) < 3:
            _output({"error": "quarantine requires a MAC address argument"})
            return
        action_quarantine(sys.argv[2])

    elif action == "unquarantine":
        if len(sys.argv) < 3:
            _output({"error": "unquarantine requires a MAC address argument"})
            return
        action_unquarantine(sys.argv[2])

    elif action == "approve":
        if len(sys.argv) < 3:
            _output({"error": "approve requires a MAC address argument"})
            return
        action_approve(sys.argv[2])

    else:
        _output({"error": f"Unknown action: {action}. Use: list | quarantine | unquarantine | approve"})


if __name__ == "__main__":
    main()
