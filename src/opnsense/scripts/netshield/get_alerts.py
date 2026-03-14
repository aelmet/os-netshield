#!/usr/local/bin/python3
# Copyright (c) 2025-2026, NetShield Contributors
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice,
#    this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright notice,
#    this list of conditions and the following disclaimer in the documentation
#    and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
# SPDX-License-Identifier: BSD-2-Clause

"""configd script: return alerts as JSON.

Called by OPNsense configd via netshield.conf action definitions.

Usage:
    get_alerts.py [--limit N] [--type ALERT_TYPE] [--flush]

Options:
    --limit N          Return at most N alerts (default: 100)
    --type ALERT_TYPE  Filter by alert type
    --flush            Delete alerts older than retention days and output result
"""

import argparse
import json
import os
import sys

# ---------------------------------------------------------------------------
# Ensure lib/ is on the path regardless of cwd
# ---------------------------------------------------------------------------
_SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))
if _SCRIPT_DIR not in sys.path:
    sys.path.insert(0, _SCRIPT_DIR)

from lib import db as _db
from lib.config import load_config
from urllib.parse import unquote

def _classify_alert(alert_type, detail=''):
    """Classify alert into security category."""
    type_lower = (alert_type or '').lower()
    if 'dns' in type_lower or 'block' in type_lower:
        return 'DNS Security'
    if 'threat' in type_lower or 'malware' in type_lower:
        return 'Threat Detection'
    if 'phish' in type_lower:
        return 'Phishing'
    if 'new_device' in type_lower or 'device' in type_lower:
        return 'Device Discovery'
    if 'policy' in type_lower:
        return 'Policy Enforcement'
    if 'ids' in type_lower or 'intrusion' in type_lower:
        return 'Intrusion Detection'
    if 'geo' in type_lower:
        return 'GeoIP Blocking'
    if 'doh' in type_lower:
        return 'DNS-over-HTTPS'
    if 'tor' in type_lower:
        return 'Tor Prevention'
    if 'vpn' in type_lower:
        return 'VPN Prevention'
    if 'web' in type_lower or 'category' in type_lower:
        return 'Web Category'
    if 'app' in type_lower:
        return 'Application Control'
    if 'bandwidth' in type_lower:
        return 'Bandwidth'
    if 'brute' in type_lower:
        return 'Brute Force'
    if 'scan' in type_lower or 'port' in type_lower:
        return 'Port Scan'
    return 'General'


def _classify_alert(alert_type, detail=''):
    """Classify alert into security category."""
    type_map = {
        'dns_block': 'DNS Security',
        'threat_detected': 'Threat Detection',
        'malware': 'Malware',
        'phishing': 'Phishing',
        'new_device': 'Device Discovery',
        'policy_violation': 'Policy Enforcement',
        'ids_alert': 'Intrusion Detection',
        'geoip_block': 'GeoIP Blocking',
        'doh_block': 'DNS-over-HTTPS',
        'tor_block': 'Tor Prevention',
        'vpn_block': 'VPN Prevention',
        'web_block': 'Web Category',
        'app_block': 'Application Control',
        'bandwidth_alert': 'Bandwidth',
        'brute_force': 'Brute Force',
        'port_scan': 'Port Scan',
    }
    for key, cat in type_map.items():
        if key in alert_type.lower():
            return cat
    return 'General'



def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="NetShield: retrieve alerts as JSON"
    )
    sub = parser.add_subparsers(dest="cmd")

    # list [limit] [alert_type]
    p_list = sub.add_parser("list", help="List alerts")
    p_list.add_argument("limit", nargs="?", type=int, default=100,
                        help="Maximum number of alerts to return (default: 100)")
    p_list.add_argument("alert_type", nargs="?", default=None,
                        help="Filter alerts by type (e.g. 'New Device')")

    # get <alert_id>
    p_get = sub.add_parser("get", help="Get a single alert by ID")
    p_get.add_argument("alert_id", help="Alert ID to retrieve")

    # flush
    sub.add_parser("flush", help="Flush alerts older than retention days")

    # ack <alert_id>
    p_ack = sub.add_parser("ack", help="Acknowledge an alert by ID")
    p_ack.add_argument("alert_id", help="Alert ID to acknowledge")

    # Default: no subcommand = list with defaults (backward compat for bare call)
    return parser.parse_args()


def main() -> None:
    # configd passes all parameters as a single comma-delimited token
    if len(sys.argv) == 2:
        arg = sys.argv[1]
        parts = arg.replace(',', ' ').split()
        sys.argv = [sys.argv[0]] + [unquote(p.strip("'\"")) for p in parts]
    args = _parse_args()

    try:
        _db.init_db()

        if args.cmd == "flush":
            cfg = load_config()
            days = cfg.getint("general", "alert_retention_days", fallback=30)
            result = _db.flush_old_alerts(days=days)
            print(json.dumps(result, indent=2))
            return

        if args.cmd == "get":
            alert = _db.get_alert_by_id(args.alert_id)
            if alert:
                # Transform to match frontend expectations
                result = {
                    "id": alert.get("id"),
                    "timestamp": alert.get("timestamp", ""),
                    "device": alert.get("device_name", "") or alert.get("device_ip", "") or alert.get("device_mac", ""),
                    "device_mac": alert.get("device_mac", ""),
                    "device_ip": alert.get("device_ip", ""),
                    "device_name": alert.get("device_name", ""),
                    "type": alert.get("alert_type", "other"),
                    "alert_type": alert.get("alert_type", ""),
                    "severity": alert.get("severity", "medium"),
                    "detail": alert.get("detail", ""),
                    "acknowledged": alert.get("acknowledged", 0),
                    "category": _classify_alert(alert.get("alert_type", ""), alert.get("detail", "")),
                }
                print(json.dumps(result, indent=2))
            else:
                print(json.dumps({"status": "error", "message": "Alert not found"}))
            return

        if args.cmd == "ack":
            result = _db.ack_alert(args.alert_id)
            print(json.dumps({"result": "ok" if result else "failed"}))
            return

        # "list" or no subcommand → return alerts
        limit = getattr(args, "limit", 100) or 100
        alert_type = getattr(args, "alert_type", None)
        raw_alerts = _db.get_alerts(limit=limit, alert_type=alert_type)
        
        # Transform field names to match frontend expectations
        # Frontend expects: timestamp, device, type, severity, detail, acknowledged, id,
        # Database has: timestamp, device_name, alert_type, severity, detail, acknowledged, id
        alerts = []
        for a in raw_alerts:
            alerts.append({
                "id": a.get("id"),
                "timestamp": a.get("timestamp", ""),
                "device": a.get("device_name", "") or a.get("device_ip", "") or a.get("device_mac", ""),
                "type": a.get("alert_type", "other"),
                "severity": a.get("severity", "medium"),
                "detail": a.get("detail", ""),
                "acknowledged": a.get("acknowledged", 0),
                "category": _classify_alert(a.get("alert_type", ""), a.get("detail", "")),
                # Keep original fields too for compatibility
                "device_mac": a.get("device_mac", ""),
                "device_ip": a.get("device_ip", ""),
                "device_name": a.get("device_name", ""),
                "alert_type": a.get("alert_type", ""),
            })
        print(json.dumps(alerts, indent=2))

    except Exception as exc:
        error = {"error": str(exc)}
        print(json.dumps(error), file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
