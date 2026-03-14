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
manage_geoip.py — configd script for GeoIP management.
All output is JSON for OPNsense API consumption.
"""

import argparse
import json
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "lib"))

try:
    from db_module import get_db  # type: ignore
except ImportError:
    class _FakeDB:
        def execute(self, *a, **k): pass
        def fetchone(self, *a, **k): return None
        def fetchall(self, *a, **k): return []
        def commit(self): pass

    def get_db():
        return _FakeDB()

from geoip import GeoIPManager
from urllib.parse import unquote


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
        sys.argv = [sys.argv[0]] + [unquote(p.strip("'\"")) for p in parts]
    parser = argparse.ArgumentParser(description="NetShield GeoIP Manager")
    sub = parser.add_subparsers(dest="cmd")

    # lookup <ip>
    p_lookup = sub.add_parser("lookup", help="Lookup country for an IP")
    p_lookup.add_argument("ip", help="IP address to look up")

    # list-rules
    sub.add_parser("list-rules", help="List all country rules")

    # add-rule <country> <rule_action>
    p_add = sub.add_parser("add-rule", help="Add/update a country rule")
    p_add.add_argument("country", help="ISO 3166-1 alpha-2 country code")
    p_add.add_argument("rule_action", choices=["allow", "block", "log"],
                       help="Rule action: allow, block, or log")

    # remove-rule <country>
    p_remove = sub.add_parser("remove-rule", help="Remove a country rule")
    p_remove.add_argument("country", help="ISO 3166-1 alpha-2 country code")

    # stats
    sub.add_parser("stats", help="Show GeoIP statistics")

    # apply
    sub.add_parser("apply", help="Generate and apply pf rules")

    args = parser.parse_args()

    if not args.cmd:
        parser.print_help()
        _err("no action specified")

    db = get_db()
    mgr = GeoIPManager(db)

    if args.cmd == "lookup":
        result = mgr.lookup(args.ip)
        _ok({"ip": args.ip, "geo": result})

    elif args.cmd == "list-rules":
        _ok({"rules": mgr.get_rules()})

    elif args.cmd == "add-rule":
        try:
            mgr.add_rule(args.country, args.rule_action)
            _ok({"message": f"Rule added: {args.country.upper()} -> {args.rule_action}"})
        except ValueError as exc:
            _err(str(exc))

    elif args.cmd == "remove-rule":
        mgr.remove_rule(args.country)
        _ok({"message": f"Rule removed: {args.country.upper()}"})

    elif args.cmd == "stats":
        _ok({"stats": mgr.get_stats()})

    elif args.cmd == "apply":
        try:
            mgr.generate_pf_rules()
            _ok({"message": "GeoIP pf rules applied"})
        except Exception as exc:
            _err(str(exc))


if __name__ == "__main__":
    main()
