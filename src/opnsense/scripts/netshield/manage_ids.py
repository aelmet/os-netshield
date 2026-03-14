#!/usr/local/bin/python3
# Copyright (c) 2025-2026, NetShield Project
# IDS Management CLI

"""
CLI for IDS/IPS management.

Usage:
    manage_ids.py status
    manage_ids.py start
    manage_ids.py stop
    manage_ids.py reload-rules
    manage_ids.py alerts [options]
    manage_ids.py alert-stats
    manage_ids.py acknowledge <alert_id>
    manage_ids.py signatures [options]
    manage_ids.py enable-sig <sid>
    manage_ids.py disable-sig <sid>
    manage_ids.py add-rule [options]
    manage_ids.py delete-rule <sid>
    manage_ids.py categories
    manage_ids.py top-signatures [limit=N]
    manage_ids.py top-attackers [limit=N]
"""

import json
import os
import sys

# Add lib to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'lib'))

from db import Database
from ids_engine import IDSEngine, SuricataController, SignatureManager, AlertProcessor
from urllib.parse import unquote


def parse_args():
    """Parse key=value arguments."""
    argv = sys.argv[2:]
    if len(argv) == 1:
        arg = argv[0]
        argv = [unquote(p.strip("'\"")) for p in arg.replace(',', ' ').split()]
    args = {}
    for arg in argv:
        if '=' in arg:
            key, value = arg.split('=', 1)
            args[key] = value
        else:
            args[arg] = True
    return args


def main():
    # configd passes all parameters as a single comma-delimited token
    if len(sys.argv) == 2 and ',' in sys.argv[1]:
        parts = [unquote(p.strip("'\"")) for p in sys.argv[1].replace(',', ' ').split()]
        sys.argv = [sys.argv[0]] + parts

    if len(sys.argv) < 2:
        print(json.dumps({"status": "error", "message": "No command specified"}))
        return

    command = sys.argv[1]
    args = parse_args()

    db = Database()
    engine = IDSEngine(db)

    try:
        if command == "status":
            result = engine.get_status()
            print(json.dumps(result))

        elif command == "start":
            result = engine.start()
            print(json.dumps(result))

        elif command == "stop":
            result = engine.stop()
            print(json.dumps(result))

        elif command == "reload-rules":
            result = SuricataController.reload_rules()
            print(json.dumps(result))

        elif command == "alerts":
            limit = int(args.get("limit", 20))
            offset = int(args.get("offset", 0))
            severity = int(args["severity"]) if "severity" in args else None
            src_ip = args.get("src_ip")

            result = engine.get_alerts(
                limit=limit,
                offset=offset,
                severity=severity,
                src_ip=src_ip,
            )
            print(json.dumps(result))

        elif command == "alert-stats":
            result = engine.get_alert_stats()
            print(json.dumps(result))

        elif command == "acknowledge":
            if len(sys.argv) < 3:
                print(json.dumps({"status": "error", "message": "alert_id required"}))
                return
            alert_id = int(sys.argv[2])
            result = engine.acknowledge_alert(alert_id)
            print(json.dumps(result))

        elif command == "signatures":
            limit = int(args.get("limit", 50))
            offset = int(args.get("offset", 0))
            category = args.get("category")
            search = args.get("search")
            enabled_only = args.get("enabled_only") == "1"

            result = engine.list_signatures(
                limit=limit,
                offset=offset,
                category=category,
                search=search,
                enabled_only=enabled_only,
            )
            print(json.dumps(result))

        elif command == "enable-sig":
            if len(sys.argv) < 3:
                print(json.dumps({"status": "error", "message": "sid required"}))
                return
            sid = int(sys.argv[2])
            result = engine.enable_signature(sid)
            print(json.dumps(result))

        elif command == "disable-sig":
            if len(sys.argv) < 3:
                print(json.dumps({"status": "error", "message": "sid required"}))
                return
            sid = int(sys.argv[2])
            result = engine.disable_signature(sid)
            print(json.dumps(result))

        elif command == "add-rule":
            action = args.get("action", "alert")
            protocol = args.get("protocol", "tcp")
            src = args.get("src", "any any")
            dst = args.get("dst", "any any")
            msg = args.get("msg", "Custom rule")
            classtype = args.get("classtype", "misc-activity")
            priority = int(args.get("priority", 3))

            result = engine.add_custom_rule(
                action=action,
                protocol=protocol,
                src=src,
                dst=dst,
                msg=msg,
                classtype=classtype,
                priority=priority,
            )
            print(json.dumps(result))

        elif command == "delete-rule":
            if len(sys.argv) < 3:
                print(json.dumps({"status": "error", "message": "sid required"}))
                return
            sid = int(sys.argv[2])
            result = engine.delete_custom_rule(sid)
            print(json.dumps(result))

        elif command == "categories":
            result = engine.get_categories()
            print(json.dumps(result))

        elif command == "top-signatures":
            limit = int(args.get("limit", 10))
            result = engine.get_top_signatures(limit)
            print(json.dumps(result))

        elif command == "top-attackers":
            limit = int(args.get("limit", 10))
            result = engine.get_top_attackers(limit)
            print(json.dumps(result))

        else:
            print(json.dumps({"status": "error", "message": f"Unknown command: {command}"}))

    except Exception as e:
        print(json.dumps({"status": "error", "message": str(e)}))


if __name__ == "__main__":
    main()
