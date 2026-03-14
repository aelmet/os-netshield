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
manage_dns.py — configd script for DNS filtering management.
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
from lib.dns_filter import DNSFilter  # noqa: E402

_log_dir = "/var/log/netshield"
if not os.path.isdir(_log_dir):
    os.makedirs(_log_dir, exist_ok=True)
logging.basicConfig(
    filename=os.path.join(_log_dir, "manage_dns.log"),
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
log = logging.getLogger("manage_dns")


def output(data: object) -> None:
    print(json.dumps(data, default=str))


def main() -> None:
    # configd passes all parameters as a single comma-delimited token
    if len(sys.argv) == 2:
        arg = sys.argv[1]
        parts = arg.replace(',', ' ').split()
        sys.argv = [sys.argv[0]] + [p.strip("'\"") for p in parts]
    parser = argparse.ArgumentParser(
        description="NetShield DNS filtering management",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = parser.add_subparsers(dest="action")

    # update-blocklists
    sub.add_parser("update-blocklists", help="Download and apply all enabled blocklists")

    # list-blocklists
    sub.add_parser("list-blocklists", help="List configured blocklists")

    # enable-blocklist <name>
    p_enable = sub.add_parser("enable-blocklist", help="Enable a blocklist by name")
    p_enable.add_argument("name", help="Blocklist name")

    # disable-blocklist <name>
    p_disable = sub.add_parser("disable-blocklist", help="Disable a blocklist by name")
    p_disable.add_argument("name", help="Blocklist name")

    # list-rules [search]
    p_list_rules = sub.add_parser("list-rules", help="List custom DNS rules")
    p_list_rules.add_argument("search", nargs="?", default=None, help="Search term")

    # add-rule <domain> [action]
    p_add_rule = sub.add_parser("add-rule", help="Add a custom DNS rule")
    p_add_rule.add_argument("domain", help="Domain for the rule")
    p_add_rule.add_argument(
        "rule_action", nargs="?", default="block",
        choices=["block", "allow", "redirect"],
        help="Rule action (default: block)",
    )

    # remove-rule <domain>
    p_remove_rule = sub.add_parser("remove-rule", help="Remove a custom DNS rule")
    p_remove_rule.add_argument("domain", help="Domain to remove")

    # stats
    sub.add_parser("stats", help="Show DNS filter statistics")

    # query-log [limit]
    p_query_log = sub.add_parser("query-log", help="Show recent DNS query log")
    p_query_log.add_argument("limit", nargs="?", type=int, default=100,
                             help="Number of log entries to return (default: 100)")

    # safe-search-on
    sub.add_parser("safe-search-on", help="Enable safe search DNS overrides")

    # safe-search-off
    sub.add_parser("safe-search-off", help="Disable safe search DNS overrides")

    # list-categories
    sub.add_parser("list-categories", help="List web filter categories")

    # toggle-category <name> <enabled>
    p_tog_cat = sub.add_parser("toggle-category", help="Enable or disable a web category")
    p_tog_cat.add_argument("name", help="Category name")
    p_tog_cat.add_argument("enabled", choices=["0", "1"], help="1=enable, 0=disable")

    args = parser.parse_args()

    if not args.action:
        parser.print_help()
        output({"result": "failed", "message": "no action specified"})
        return

    try:
        db = Database()
        dns = DNSFilter(db)
    except Exception as exc:
        output({"result": "failed", "message": "Failed to initialise DNS filter: {}".format(exc)})
        sys.exit(1)

    try:
        if args.action == "update-blocklists":
            result = dns.update_all_blocklists()
            output({"result": "ok", **result})

        elif args.action == "list-blocklists":
            rows = db.query("SELECT * FROM dns_blocklists ORDER BY name")
            output({"blocklists": [dict(r) for r in rows]})

        elif args.action in ("enable-blocklist", "disable-blocklist"):
            enabled = 1 if args.action == "enable-blocklist" else 0
            db.execute(
                "UPDATE dns_blocklists SET enabled = ? WHERE name = ?",
                (enabled, args.name),
            )
            db.commit()
            # Regenerate Unbound config and reload so the change takes effect
            dns.generate_unbound_overrides()
            dns.reload_unbound()
            output({
                "result": "ok",
                "name": args.name,
                "enabled": bool(enabled),
            })

        elif args.action == "list-rules":
            rules = dns.get_rules(search=args.search)
            output({"rules": rules, "total": len(rules)})

        elif args.action == "add-rule":
            result = dns.add_custom_rule(args.domain, args.rule_action)
            output(result)

        elif args.action == "remove-rule":
            result = dns.remove_custom_rule(args.domain)
            output(result)

        elif args.action == "stats":
            stats = dns.get_stats()
            output(stats)

        elif args.action == "query-log":
            logs = dns.get_query_log(limit=args.limit)
            output({"log": logs, "count": len(logs)})

        elif args.action == "safe-search-on":
            result = dns.enable_safe_search()
            output(result)

        elif args.action == "safe-search-off":
            result = dns.disable_safe_search()
            output(result)

        elif args.action == "list-categories":
            rows = db.query(
                "SELECT category, COUNT(*) as domain_count, "
                "SUM(CASE WHEN enabled=1 THEN 1 ELSE 0 END) as enabled_lists "
                "FROM dns_blocklists WHERE category IS NOT NULL AND category != '' "
                "GROUP BY category ORDER BY category"
            )
            cats = []
            for r in rows:
                cats.append({
                    "name": r["category"],
                    "domain_count": r["domain_count"],
                    "enabled": r["enabled_lists"] > 0,
                })
            output({"categories": cats})

        elif args.action == "toggle-category":
            enabled = 1 if args.enabled == "1" else 0
            db.execute(
                "UPDATE dns_blocklists SET enabled = ? WHERE category = ?",
                (enabled, args.name),
            )
            db.commit()
            dns.generate_unbound_overrides()
            dns.reload_unbound()
            output({"result": "ok", "category": args.name, "enabled": bool(enabled)})

        else:
            output({"result": "failed", "message": "unknown action: {}".format(args.action)})

    except Exception as exc:
        log.exception("Unhandled error in manage_dns")
        output({"result": "failed", "message": str(exc)})
        sys.exit(1)


if __name__ == "__main__":
    main()
