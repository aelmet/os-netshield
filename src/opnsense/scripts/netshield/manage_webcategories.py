#!/usr/local/bin/python3
# Copyright (c) 2025-2026, NetShield Project
# Web Categories Management CLI

"""
CLI for web categories management.

Usage:
    manage_webcategories.py list
    manage_webcategories.py groups
    manage_webcategories.py enable <category>
    manage_webcategories.py disable <category>
    manage_webcategories.py classify <domain>
    manage_webcategories.py add-override domain=<d> category=<c>
    manage_webcategories.py remove-override <domain>
    manage_webcategories.py overrides
    manage_webcategories.py set-device-policy mac=<m> category=<c> action=<a>
    manage_webcategories.py device-policies <mac>
    manage_webcategories.py update-db [source]
    manage_webcategories.py stats
    manage_webcategories.py search query=<q> [category=<c>] [limit=N]
"""

import json
import os
import sys

# Add lib to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'lib'))

from web_categories import WebCategoriesEngine


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

    engine = WebCategoriesEngine()

    try:
        if command == "list":
            categories = engine.get_categories()
            result = [c.to_dict() for c in categories]
            print(json.dumps(result))

        elif command == "groups":
            result = engine.get_category_groups()
            print(json.dumps(result))

        elif command == "enable":
            if len(sys.argv) < 3:
                print(json.dumps({"status": "error", "message": "category required"}))
                return
            category = sys.argv[2]
            result = engine.enable_category(category)
            print(json.dumps(result))

        elif command == "disable":
            if len(sys.argv) < 3:
                print(json.dumps({"status": "error", "message": "category required"}))
                return
            category = sys.argv[2]
            result = engine.disable_category(category)
            print(json.dumps(result))

        elif command == "classify":
            if len(sys.argv) < 3:
                print(json.dumps({"status": "error", "message": "domain required"}))
                return
            domain = sys.argv[2]
            classification = engine.classify(domain)
            print(json.dumps(classification.to_dict()))

        elif command == "add-override":
            domain = args.get("domain")
            category = args.get("category")
            if not domain or not category:
                print(json.dumps({"status": "error", "message": "domain and category required"}))
                return
            result = engine.add_override(domain, category)
            print(json.dumps(result))

        elif command == "remove-override":
            if len(sys.argv) < 3:
                print(json.dumps({"status": "error", "message": "domain required"}))
                return
            domain = sys.argv[2]
            result = engine.remove_override(domain)
            print(json.dumps(result))

        elif command == "overrides":
            result = engine.get_overrides()
            print(json.dumps(result))

        elif command == "set-device-policy":
            mac = args.get("mac")
            category = args.get("category")
            action = args.get("action", "block")
            if not mac or not category:
                print(json.dumps({"status": "error", "message": "mac and category required"}))
                return
            result = engine.set_device_policy(mac, category, action)
            print(json.dumps(result))

        elif command == "device-policies":
            if len(sys.argv) < 3:
                print(json.dumps({"status": "error", "message": "mac required"}))
                return
            mac = sys.argv[2]
            result = engine.get_device_policies(mac)
            print(json.dumps(result))

        elif command == "update-db":
            source = sys.argv[2] if len(sys.argv) > 2 else "shalla"
            result = engine.update_database(source)
            print(json.dumps(result))

        elif command == "stats":
            result = engine.get_stats()
            print(json.dumps(result))

        elif command == "search":
            query = args.get("query")
            if not query:
                print(json.dumps({"status": "error", "message": "query required"}))
                return
            category = args.get("category")
            limit = int(args.get("limit", 100))
            result = engine.search_domains(query, category, limit)
            print(json.dumps(result))

        else:
            print(json.dumps({"status": "error", "message": f"Unknown command: {command}"}))

    except Exception as e:
        print(json.dumps({"status": "error", "message": str(e)}))


if __name__ == "__main__":
    main()
