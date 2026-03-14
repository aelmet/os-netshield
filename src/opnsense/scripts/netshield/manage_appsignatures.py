#!/usr/local/bin/python3
# Copyright (c) 2025-2026, NetShield Project
# Application Signatures Management CLI

"""
CLI for application signatures management.

Usage:
    manage_appsignatures.py list [category=<c>]
    manage_appsignatures.py categories
    manage_appsignatures.py match-domain <domain>
    manage_appsignatures.py match-port <port> [protocol=<p>]
    manage_appsignatures.py search query=<q>
    manage_appsignatures.py apps-by-category <category>
    manage_appsignatures.py add-custom id=<id> name=<n> category=<c> domains=<d1,d2,...> [ports=<p1,p2,...>] [risk=<r>]
    manage_appsignatures.py remove-custom <app_id>
    manage_appsignatures.py stats
"""

import json
import os
import sys

# Add lib to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'lib'))

from app_signatures import AppSignaturesEngine


def parse_args():
    """Parse key=value arguments."""
    args = {}
    for arg in sys.argv[2:]:
        if '=' in arg:
            key, value = arg.split('=', 1)
            args[key] = value
        else:
            args[arg] = True
    return args


def main():
    if len(sys.argv) < 2:
        print(json.dumps({"status": "error", "message": "No command specified"}))
        return

    command = sys.argv[1]
    args = parse_args()

    engine = AppSignaturesEngine()

    try:
        if command == "list":
            category = args.get("category")
            all_apps = engine.get_all_apps()
            if category:
                all_apps = [a for a in all_apps if a["category"] == category]
            print(json.dumps({"apps": all_apps, "total": len(all_apps)}))

        elif command == "categories":
            result = engine.get_categories()
            print(json.dumps(result))

        elif command == "match-domain":
            if len(sys.argv) < 3:
                print(json.dumps({"status": "error", "message": "domain required"}))
                return
            domain = sys.argv[2]
            match = engine.match_domain(domain)
            if match:
                print(json.dumps({"matched": True, **match.to_dict()}))
            else:
                print(json.dumps({"matched": False, "domain": domain}))

        elif command == "match-port":
            if len(sys.argv) < 3:
                print(json.dumps({"status": "error", "message": "port required"}))
                return
            port = int(sys.argv[2])
            protocol = args.get("protocol", "tcp")
            matches = engine.match_port(port, protocol)
            print(json.dumps({
                "port": port,
                "protocol": protocol,
                "matches": [m.to_dict() for m in matches],
            }))

        elif command == "search":
            query = args.get("query")
            if not query:
                print(json.dumps({"status": "error", "message": "query required"}))
                return
            results = engine.search_apps(query)
            print(json.dumps({"results": results, "total": len(results)}))

        elif command == "apps-by-category":
            if len(sys.argv) < 3:
                print(json.dumps({"status": "error", "message": "category required"}))
                return
            category = sys.argv[2]
            apps = engine.get_apps_by_category(category)
            print(json.dumps({"category": category, "apps": apps, "total": len(apps)}))

        elif command == "add-custom":
            app_id = args.get("id")
            name = args.get("name")
            category = args.get("category")
            domains_str = args.get("domains", "")
            ports_str = args.get("ports", "")
            risk = args.get("risk", "low")

            if not all([app_id, name, category]):
                print(json.dumps({"status": "error", "message": "id, name, and category required"}))
                return

            domains = [d.strip() for d in domains_str.split(",") if d.strip()]
            ports = [int(p.strip()) for p in ports_str.split(",") if p.strip()]

            success = engine.add_custom_signature(app_id, name, category, domains, ports, risk)
            print(json.dumps({"status": "ok" if success else "error"}))

        elif command == "remove-custom":
            if len(sys.argv) < 3:
                print(json.dumps({"status": "error", "message": "app_id required"}))
                return
            app_id = sys.argv[2]
            success = engine.remove_custom_signature(app_id)
            print(json.dumps({"status": "ok" if success else "error"}))

        elif command == "stats":
            result = engine.get_stats()
            print(json.dumps(result))

        else:
            print(json.dumps({"status": "error", "message": f"Unknown command: {command}"}))

    except Exception as e:
        print(json.dumps({"status": "error", "message": str(e)}))


if __name__ == "__main__":
    main()
