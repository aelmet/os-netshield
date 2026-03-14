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

"""configd script — Returns bandwidth data as JSON.

Usage:
  get_bandwidth.py --current
  get_bandwidth.py --history [--mac MAC] [--hours N]
  get_bandwidth.py --top-devices [--hours N] [--limit N]
  get_bandwidth.py --by-app [--hours N] [--limit N]
"""

import argparse
import json
import logging
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from urllib.parse import unquote
from lib.bandwidth_tracker import (
    get_bandwidth_by_app,
    get_bandwidth_history,
    get_current_bandwidth,
    get_top_devices,
    init_bandwidth_tables,
)

log = logging.getLogger("netshield.get_bandwidth")


def _error(message: str, code: int = 1) -> None:
    print(json.dumps({"error": message}))
    sys.exit(code)


def main() -> None:
    # configd passes all parameters as a single comma-delimited token
    if len(sys.argv) == 2:
        arg = sys.argv[1]
        parts = arg.replace(',', ' ').split()
        sys.argv = [sys.argv[0]] + [unquote(p.strip("'\"")) for p in parts]

    logging.basicConfig(
        level=logging.WARNING,
        format="%(levelname)s %(name)s: %(message)s",
        stream=sys.stderr,
    )

    parser = argparse.ArgumentParser(
        description="NetShield bandwidth data query tool",
        add_help=True,
    )
    sub = parser.add_subparsers(dest="cmd")

    # current [window_minutes]
    p_current = sub.add_parser("current",
                               help="Return current bandwidth rates per device")
    p_current.add_argument("window", nargs="?", type=int, default=5,
                           help="Window in minutes (default: 5)")

    # history [hours] [mac]
    p_history = sub.add_parser("history", help="Return time-series bandwidth data")
    p_history.add_argument("hours", nargs="?", type=int, default=24,
                           help="Look-back window in hours (default: 24)")
    p_history.add_argument("mac", nargs="?", default=None,
                           help="Filter to a specific device MAC address")

    # top-devices [hours] [limit]
    p_top = sub.add_parser("top-devices", help="Return top devices by total bytes")
    p_top.add_argument("hours", nargs="?", type=int, default=24,
                       help="Look-back window in hours (default: 24)")
    p_top.add_argument("limit", nargs="?", type=int, default=10,
                       help="Maximum number of results (default: 10)")

    # by-app [hours] [limit]
    p_app = sub.add_parser("by-app", help="Return bandwidth breakdown by application")
    p_app.add_argument("hours", nargs="?", type=int, default=24,
                       help="Look-back window in hours (default: 24)")
    p_app.add_argument("limit", nargs="?", type=int, default=10,
                       help="Maximum number of results (default: 10)")

    # realtime - returns current bandwidth rates in bps
    sub.add_parser("realtime", help="Return real-time bandwidth rates (bps)")

    # device [mac] - returns bandwidth for a specific device
    p_dev = sub.add_parser("device", help="Return bandwidth for a specific device")
    p_dev.add_argument("mac", help="Device MAC address")

    args = parser.parse_args()

    if not args.cmd:
        parser.print_help()
        _error("no action specified")

    # Ensure tables exist (no-op if already created)
    try:
        init_bandwidth_tables()
    except Exception as exc:  # pylint: disable=broad-except
        log.warning("Could not init bandwidth tables: %s", exc)

    try:
        if args.cmd == "current":
            window = max(1, args.window)
            data = get_current_bandwidth(window_minutes=window)
            result = sorted(data.values(), key=lambda x: x.get("bytes_total", 0), reverse=True)
            print(json.dumps({"mode": "current", "window_minutes": window, "devices": result}, indent=2))

        elif args.cmd == "history":
            hours = max(1, args.hours)
            data = get_bandwidth_history(device_mac=args.mac, hours=hours)
            print(json.dumps({
                "mode":       "history",
                "hours":      hours,
                "device_mac": args.mac,
                "data":       data,
            }, indent=2))

        elif args.cmd == "top-devices":
            hours = max(1, args.hours)
            limit = max(1, args.limit)
            data = get_top_devices(hours=hours, limit=limit)
            print(json.dumps({
                "mode":    "top_devices",
                "hours":   hours,
                "limit":   limit,
                "devices": data,
            }, indent=2))

        elif args.cmd == "by-app":
            hours = max(1, args.hours)
            limit = max(1, args.limit)
            data = get_bandwidth_by_app(hours=hours, limit=limit)
            print(json.dumps({
                "mode":  "by_app",
                "hours": hours,
                "limit": limit,
                "apps":  data,
            }, indent=2))

        elif args.cmd == "realtime":
            from datetime import datetime
            # Get current bandwidth snapshot and calculate rates
            data = get_current_bandwidth(window_minutes=1)
            total_down = sum(d.get("bytes_in", 0) for d in data.values())
            total_up = sum(d.get("bytes_out", 0) for d in data.values())
            # Convert to approximate bytes per second (data is from 1 min window)
            print(json.dumps({
                "download_bps": int(total_down / 60),
                "upload_bps":   int(total_up / 60),
                "timestamp":    datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
            }, indent=2))

        elif args.cmd == "device":
            mac = args.mac.lower()
            # Get bandwidth for specific device
            data = get_current_bandwidth(window_minutes=1440)  # 24 hours
            device_data = data.get(mac, {})
            print(json.dumps({
                "mac":           mac,
                "bytes_down":    device_data.get("bytes_in", 0),
                "bytes_up":      device_data.get("bytes_out", 0),
                "download_today": device_data.get("bytes_in", 0),
                "upload_today":  device_data.get("bytes_out", 0),
            }, indent=2))

    except Exception as exc:  # pylint: disable=broad-except
        log.exception("Unhandled error in get_bandwidth")
        _error(f"Internal error: {exc}")


if __name__ == "__main__":
    main()
