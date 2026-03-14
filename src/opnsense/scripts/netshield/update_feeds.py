#!/usr/local/bin/python3

# Copyright (c) 2025-2026, NetShield Contributors
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice,
#    this list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
# SPDX-License-Identifier: BSD-2-Clause

"""
update_feeds.py — configd script for threat intelligence feed management.
All output is JSON for OPNsense API consumption.
"""

import argparse
import json
import sys
import os

# Ensure lib/ is importable when invoked from configd
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "lib"))

try:
    from db_module import get_db  # type: ignore  # project-provided helper
except ImportError:
    # Minimal fallback for environments where db_module is not yet wired
    class _FakeDB:
        def execute(self, *a, **k): pass
        def fetchone(self, *a, **k): return None
        def fetchall(self, *a, **k): return []
        def commit(self): pass

    def get_db():
        return _FakeDB()

from threat_intel import ThreatIntelManager


def _ok(data):
    print(json.dumps({"status": "ok", **data}))


def _err(msg):
    print(json.dumps({"status": "error", "message": msg}))
    sys.exit(1)


def main():
    # configd passes all parameters as a single comma-delimited token
    if len(sys.argv) == 2:
        arg = sys.argv[1]
        parts = arg.replace(',', ' ').split()
        sys.argv = [sys.argv[0]] + [p.strip("'\"") for p in parts]
    parser = argparse.ArgumentParser(description="NetShield Threat Feed Manager")
    sub = parser.add_subparsers(dest="cmd")

    # update-all
    sub.add_parser("update-all", help="Download all enabled feeds")

    # list
    sub.add_parser("list", help="List feeds with status")

    # enable <name>
    p_enable = sub.add_parser("enable", help="Enable a feed by name")
    p_enable.add_argument("name", help="Feed name")

    # disable <name>
    p_disable = sub.add_parser("disable", help="Disable a feed by name")
    p_disable.add_argument("name", help="Feed name")

    # check-ip <ip>
    p_check_ip = sub.add_parser("check-ip", help="Check IP against loaded IoCs")
    p_check_ip.add_argument("ip", help="IP address to check")

    # check-domain <domain>
    p_check_domain = sub.add_parser("check-domain", help="Check domain against IoCs")
    p_check_domain.add_argument("domain", help="Domain to check")

    # stats
    sub.add_parser("stats", help="Show aggregate statistics")

    args = parser.parse_args()

    if not args.cmd:
        parser.print_help()
        _err("no action specified")

    db = get_db()
    mgr = ThreatIntelManager(db)

    if args.cmd == "update-all":
        try:
            mgr.update_all_feeds()
            _ok({"message": "All feeds updated", "feed_status": mgr.get_feed_status()})
        except Exception as exc:
            _err(str(exc))

    elif args.cmd == "list":
        _ok({"feeds": mgr.get_feed_status()})

    elif args.cmd == "enable":
        try:
            mgr.enable_feed(args.name)
            _ok({"message": f"Feed '{args.name}' enabled"})
        except Exception as exc:
            _err(str(exc))

    elif args.cmd == "disable":
        try:
            mgr.disable_feed(args.name)
            _ok({"message": f"Feed '{args.name}' disabled"})
        except Exception as exc:
            _err(str(exc))

    elif args.cmd == "check-ip":
        result = mgr.check_ip(args.ip)
        _ok({"ip": args.ip, "result": result})

    elif args.cmd == "check-domain":
        result = mgr.check_domain(args.domain)
        _ok({"domain": args.domain, "result": result})

    elif args.cmd == "stats":
        _ok({"stats": mgr.get_stats()})


if __name__ == "__main__":
    main()
