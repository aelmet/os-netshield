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
manage_syslog.py — configd script for syslog/SIEM export management.
Called by OPNsense configd via actions_netshield.conf.
All output is JSON on stdout.

Subcommands:
    test   — send a test message to the configured syslog/SIEM target
    stats  — return JSON with per-event-type export counts
"""

import argparse
import json
import logging
import os
import sys
from datetime import datetime

# Ensure the lib directory is importable when called from configd
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, SCRIPT_DIR)

from lib.config import load_config, get_section  # noqa: E402
from lib.syslog_export import SyslogExporter  # noqa: E402
from urllib.parse import unquote

logging.basicConfig(
    filename="/var/log/netshield/manage_syslog.log",
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
log = logging.getLogger("manage_syslog")

# Path to the persistent stats file written by the daemon
STATS_FILE = "/var/db/netshield/syslog_stats.json"


def output(data: object) -> None:
    print(json.dumps(data, default=str))


def _load_syslog_settings():
    """Load syslog connection settings from NetShield configuration."""
    try:
        cfg = load_config()
        syslog = get_section(cfg, "syslog")
        return {
            "enabled": syslog.get("enabled", "0") == "1",
            "host": syslog.get("host", ""),
            "port": int(syslog.get("port", 514)),
            "protocol": syslog.get("protocol", "udp"),
        }
    except Exception as exc:
        log.warning("Failed to load syslog settings: %s", exc)
        return {"enabled": False, "host": "", "port": 514, "protocol": "udp"}


def cmd_test(_args) -> None:
    """Send a test syslog message to the configured remote host."""
    cfg = _load_syslog_settings()

    if not cfg["host"]:
        output({"result": "error", "message": "No syslog host configured"})
        return

    # Force enabled=True so the test fires regardless of the enabled flag
    exporter = SyslogExporter(
        host=cfg["host"],
        port=cfg["port"],
        protocol=cfg["protocol"],
        enabled=True,
    )

    test_payload = {
        "event_type": "test",
        "message": "NetShield syslog test message",
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "host": cfg["host"],
        "port": cfg["port"],
        "protocol": cfg["protocol"],
    }

    ok = exporter.export_alert({
        "alert_type": "test",
        "device_mac": "00:00:00:00:00:00",
        "device_name": "netshield-test",
        "severity": "info",
        "message": "NetShield syslog connectivity test",
        "timestamp": datetime.utcnow().isoformat() + "Z",
    })
    exporter.close()

    if ok:
        output({
            "result": "ok",
            "message": f"Test message sent to {cfg['host']}:{cfg['port']} ({cfg['protocol'].upper()})",
            "details": test_payload,
        })
    else:
        output({
            "result": "error",
            "message": f"Failed to send test message to {cfg['host']}:{cfg['port']} ({cfg['protocol'].upper()}). "
                       "Check host/port and firewall rules.",
        })


def cmd_stats(_args) -> None:
    """Return export count statistics from the stats file."""
    try:
        if os.path.exists(STATS_FILE):
            with open(STATS_FILE, "r") as fh:
                stats = json.load(fh)
        else:
            stats = {
                "alerts_exported": 0,
                "flows_exported": 0,
                "threats_exported": 0,
                "device_events_exported": 0,
                "send_errors": 0,
                "last_export": None,
            }
        output({"result": "ok", "stats": stats})
    except Exception as exc:
        log.error("Failed to read syslog stats: %s", exc)
        output({"result": "error", "message": str(exc)})


def main() -> None:
    # configd passes all parameters as a single comma-delimited token
    if len(sys.argv) == 2:
        arg = sys.argv[1]
        parts = arg.replace(',', ' ').split()
        sys.argv = [sys.argv[0]] + [unquote(p.strip("'\"")) for p in parts]
    parser = argparse.ArgumentParser(
        description="NetShield syslog/SIEM export management",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    subparsers = parser.add_subparsers(dest="command", metavar="COMMAND")

    # test subcommand
    subparsers.add_parser("test", help="Send a test syslog message")

    # stats subcommand
    subparsers.add_parser("stats", help="Show syslog export statistics")

    args = parser.parse_args()

    if args.command == "test":
        cmd_test(args)
    elif args.command == "stats":
        cmd_stats(args)
    else:
        parser.print_help(sys.stderr)
        output({"result": "error", "message": "Unknown or missing subcommand"})
        sys.exit(1)


if __name__ == "__main__":
    main()
