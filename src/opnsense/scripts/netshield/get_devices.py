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

"""configd script: return device list as JSON.

Called by OPNsense configd via netshield.conf action definitions.

Usage:
    get_devices.py [--search TERM] [--quarantined]

Options:
    --search TERM   Filter devices by MAC, IP, hostname, or vendor substring
    --quarantined   Return only quarantined devices
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
from urllib.parse import unquote
import subprocess as _arp_sp


def _get_arp_hostnames():
    result = {}
    try:
        out = _arp_sp.run(["arp", "-a"], capture_output=True, text=True, timeout=5)
        for line in out.stdout.strip().split("\n"):
            parts = line.split()
            if len(parts) >= 4 and parts[1].startswith("(") and parts[3] != "(incomplete)":
                hostname = parts[0]
                mac = parts[3]
                if hostname != "?" and hostname != "":
                    if "." in hostname:
                        hostname = hostname.split(".")[0]
                    result[mac] = hostname
    except Exception:
        pass
    return result


arp_hostnames = _get_arp_hostnames()


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="NetShield: retrieve device list as JSON"
    )
    sub = parser.add_subparsers(dest="cmd")

    # list [search]
    p_list = sub.add_parser("list", help="List devices")
    p_list.add_argument("search", nargs="?", default=None,
                        help="Filter by MAC, IP, hostname, or vendor (substring match)")

    # quarantined
    sub.add_parser("quarantined", help="Return only quarantined devices")

    # quarantine <mac_or_uuid>
    p_q = sub.add_parser("quarantine", help="Quarantine a device by MAC/UUID")
    p_q.add_argument("identifier", help="Device MAC or UUID")

    # unquarantine <mac_or_uuid>
    p_uq = sub.add_parser("unquarantine", help="Unquarantine a device by MAC/UUID")
    p_uq.add_argument("identifier", help="Device MAC or UUID")

    # approve <mac_or_uuid>
    p_ap = sub.add_parser("approve", help="Approve a new device by MAC/UUID")
    p_ap.add_argument("identifier", help="Device MAC or UUID")

    # set_category <mac> <category>
    p_sc = sub.add_parser("set_category", help="Set device category")
    p_sc.add_argument("identifier", help="Device MAC")
    p_sc.add_argument("category", help="Device category")

    # get_categories
    sub.add_parser("get_categories", help="Get device category summary")

    return parser.parse_args()


def main() -> None:
    # configd passes parameters - either comma-delimited or space-separated
    if len(sys.argv) == 2:
        arg = sys.argv[1]
        parts = arg.replace(',', ' ').split()
        sys.argv = [sys.argv[0]] + [unquote(p.strip("'\"")) for p in parts]
    elif len(sys.argv) > 2:
        # Space-separated args from configd - still need URL-decoding
        sys.argv = [sys.argv[0]] + [unquote(p.strip("'\"")) for p in sys.argv[1:]]
    args = _parse_args()

    try:
        _db.init_db()

        if args.cmd == "quarantine":
            result = _db.quarantine_device(args.identifier)
            if result:
                # Create alert for quarantine event
                dev = _db.get_device_by_mac(args.identifier)
                if dev:
                    _db.add_alert(
                        device_mac=dev.get("mac", args.identifier),
                        device_ip=dev.get("ip", ""),
                        device_name=dev.get("hostname", ""),
                        alert_type="Device Quarantined",
                        severity="high",
                        detail="Device {} quarantined by admin".format(args.identifier),
                    )
                import subprocess as _sp
                _sp.Popen(["configctl", "filter", "reload"], stdout=_sp.DEVNULL, stderr=_sp.DEVNULL)
            print(json.dumps(result, indent=2))
            return

        if args.cmd == "unquarantine":
            result = _db.unquarantine_device(args.identifier)
            if result:
                import subprocess as _sp
                _sp.Popen(["configctl", "filter", "reload"], stdout=_sp.DEVNULL, stderr=_sp.DEVNULL)
            print(json.dumps(result, indent=2))
            return

        if args.cmd == "approve":
            result = _db.approve_device(args.identifier)
            print(json.dumps(result, indent=2))
            return

        if args.cmd == "quarantined":
            devices = _db.get_devices(search=None, quarantined=True)
            for dev in devices:
                if not dev.get("hostname") and dev.get("mac") in arp_hostnames:
                    dev["hostname"] = arp_hostnames[dev["mac"]]
            print(json.dumps(devices, indent=2))
            return

        if args.cmd == "set_category":
            import sqlite3
            db_path = "/var/db/netshield/netshield.db"
            conn = sqlite3.connect(db_path)
            conn.execute(
                "UPDATE devices SET category = ?, category_source = 'manual' WHERE mac = ?",
                (args.category, args.identifier)
            )
            conn.commit()
            changed = conn.total_changes
            conn.close()
            print(json.dumps({"status": "ok", "updated": changed}))
            return

        if args.cmd == "get_categories":
            import sqlite3
            db_path = "/var/db/netshield/netshield.db"
            conn = sqlite3.connect(db_path)
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                "SELECT category, COUNT(*) as count FROM devices GROUP BY category ORDER BY count DESC"
            ).fetchall()
            cats = [{"category": r["category"], "count": r["count"]} for r in rows]
            total = sum(r["count"] for r in rows)
            conn.close()
            print(json.dumps({"status": "ok", "categories": cats, "total": total}))
            return

        # "list" or no subcommand
        search = getattr(args, "search", None)
        devices = _db.get_devices(search=search, quarantined=None)
        # Enrich devices with ARP hostnames where DB hostname is empty
        for dev in devices:
            if not dev.get("hostname") and dev.get("mac") in arp_hostnames:
                dev["hostname"] = arp_hostnames[dev["mac"]]
        print(json.dumps(devices, indent=2))

    except Exception as exc:
        error = {"error": str(exc)}
        print(json.dumps(error), file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
