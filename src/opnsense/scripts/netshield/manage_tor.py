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

"""
manage_tor.py — configd script for Tor/anonymizer blocking management.
Called by OPNsense configd via actions_netshield.conf.
All output is JSON on stdout.
"""

import argparse
import json
import logging
import os
import sys

# Ensure the lib directory is importable when called from configd
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, SCRIPT_DIR)

from lib.db import Database  # noqa: E402
from lib.tor_blocker import TorBlocker  # noqa: E402

logging.basicConfig(
    filename="/var/log/netshield/manage_tor.log",
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
log = logging.getLogger("manage_tor")


def output(data):
    print(json.dumps(data, default=str))


def main():
    parser = argparse.ArgumentParser(
        description="NetShield Tor/anonymizer blocking management",
    )
    sub = parser.add_subparsers(dest="action")

    # enable — Enable all Tor blocking layers
    sub.add_parser("enable", help="Enable Tor blocking (all layers)")

    # disable — Disable all Tor blocking layers
    sub.add_parser("disable", help="Disable Tor blocking")

    # update — Update Tor IP lists and regenerate rules
    sub.add_parser("update", help="Update Tor node IP lists")

    # status — Get current status and stats
    sub.add_parser("status", help="Get Tor blocker status and statistics")

    # toggle-layer <layer> <enabled>
    p_toggle = sub.add_parser("toggle-layer", help="Toggle a specific blocking layer")
    p_toggle.add_argument("layer", choices=["block_ips", "block_ports", "block_dns", "alert_on_attempt"])
    p_toggle.add_argument("enabled", choices=["0", "1"])

    # check-ip <ip>
    p_check = sub.add_parser("check-ip", help="Check if an IP is a known Tor node")
    p_check.add_argument("ip", help="IP address to check")

    # list-ips [limit] [offset]
    p_list = sub.add_parser("list-ips", help="List blocked Tor IPs")
    p_list.add_argument("limit", nargs="?", type=int, default=100)
    p_list.add_argument("offset", nargs="?", type=int, default=0)

    # purge-stale [days]
    p_purge = sub.add_parser("purge-stale", help="Remove Tor IPs not seen recently")
    p_purge.add_argument("days", nargs="?", type=int, default=7)

    # port-rules — Output pf port blocking rules (for anchor generation)
    sub.add_parser("port-rules", help="Generate pf port blocking rules")

    args = parser.parse_args()

    if not args.action:
        parser.print_help()
        output({"result": "failed", "message": "no action specified"})
        return

    try:
        db = Database()
        tor = TorBlocker(db)
    except Exception as exc:
        output({"result": "failed", "message": "Failed to initialise Tor blocker: {}".format(exc)})
        sys.exit(1)

    try:
        if args.action == "enable":
            result = tor.enable()
            output(result)

        elif args.action == "disable":
            result = tor.disable()
            output(result)

        elif args.action == "update":
            result = tor.update()
            output(result)

        elif args.action == "status":
            result = tor.get_status()
            output(result)

        elif args.action == "toggle-layer":
            enabled = args.enabled == "1"
            result = tor.toggle_layer(args.layer, enabled)
            output(result)

        elif args.action == "check-ip":
            result = tor.check_ip(args.ip)
            output(result)

        elif args.action == "list-ips":
            result = tor.get_blocked_ips_list(limit=args.limit, offset=args.offset)
            output(result)

        elif args.action == "purge-stale":
            result = tor.purge_stale_ips(days=args.days)
            output(result)

        elif args.action == "port-rules":
            rules = tor.generate_port_rules()
            print(rules)

        else:
            output({"result": "failed", "message": "unknown action: {}".format(args.action)})

    except Exception as exc:
        log.exception("Unhandled error in manage_tor")
        output({"result": "failed", "message": str(exc)})
        sys.exit(1)


if __name__ == "__main__":
    main()
