#!/usr/local/bin/python3
# Copyright (c) 2025-2026, NetShield Project
# Target Lists Management CLI

"""
CLI for target lists management (Firewalla-style).

Usage:
    manage_targetlists.py list
    manage_targetlists.py get <id>
    manage_targetlists.py create name=<n> [description=<d>] [type=<t>]
    manage_targetlists.py delete <id>
    manage_targetlists.py update id=<id> [name=<n>] [description=<d>]
    manage_targetlists.py entries list_id=<id> [limit=N] [offset=N] [search=<s>]
    manage_targetlists.py add-entry list_id=<id> value=<v> [comment=<c>]
    manage_targetlists.py remove-entry <entry_id>
    manage_targetlists.py check-domain <domain>
    manage_targetlists.py check-ip <ip>
    manage_targetlists.py add-policy list_id=<id> action=<a> [direction=<d>] [priority=<p>]
    manage_targetlists.py policies <list_id>
    manage_targetlists.py mute-alarms list_id=<id> [alarm_type=<t>]
    manage_targetlists.py unmute-alarms list_id=<id> [alarm_type=<t>]
    manage_targetlists.py export <list_id>
    manage_targetlists.py import <file_path>
    manage_targetlists.py stats
"""

import json
import os
import sys

# Add lib to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'lib'))

from target_lists import TargetListsManager


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
    # configd passes all params as a single comma-delimited token
    # e.g. sys.argv = ['script.py', 'entries,list_id=1,limit=100,offset=0']
    if len(sys.argv) == 2 and ',' in sys.argv[1]:
        parts = sys.argv[1].split(',')
        sys.argv = [sys.argv[0]] + parts

    if len(sys.argv) < 2:
        print(json.dumps({"status": "error", "message": "No command specified"}))
        return

    command = sys.argv[1]
    args = parse_args()

    manager = TargetListsManager()

    try:
        if command == "list":
            lists = manager.get_all_lists()
            result = [l.to_dict() for l in lists]
            print(json.dumps(result))

        elif command == "get":
            if len(sys.argv) < 3:
                print(json.dumps({"status": "error", "message": "id required"}))
                return
            list_id = int(sys.argv[2])
            target_list = manager.get_list(list_id)
            if target_list:
                print(json.dumps(target_list.to_dict()))
            else:
                print(json.dumps({"status": "error", "message": "List not found"}))

        elif command == "create":
            name = args.get("name")
            description = args.get("description", "")
            list_type = args.get("type", "domain")
            if not name:
                print(json.dumps({"status": "error", "message": "name required"}))
                return
            list_id = manager.create_list(name, description, list_type)
            if list_id:
                print(json.dumps({"status": "ok", "id": list_id}))
            else:
                print(json.dumps({"status": "error", "message": "Failed to create list"}))

        elif command == "delete":
            if len(sys.argv) < 3:
                print(json.dumps({"status": "error", "message": "id required"}))
                return
            list_id = int(sys.argv[2])
            success = manager.delete_list(list_id)
            print(json.dumps({"status": "ok" if success else "error"}))

        elif command == "update":
            list_id = int(args.get("id", 0))
            if not list_id:
                print(json.dumps({"status": "error", "message": "id required"}))
                return
            name = args.get("name")
            description = args.get("description")
            success = manager.update_list(list_id, name, description)
            print(json.dumps({"status": "ok" if success else "error"}))

        elif command == "entries":
            list_id = int(args.get("list_id", 0))
            if not list_id:
                print(json.dumps({"status": "error", "message": "list_id required"}))
                return
            limit = int(args.get("limit", 100))
            offset = int(args.get("offset", 0))
            search = args.get("search")
            entries, total = manager.get_entries(list_id, limit, offset, search)
            print(json.dumps({
                "entries": [e.to_dict() for e in entries],
                "total": total,
            }))

        elif command == "add-entry":
            list_id = int(args.get("list_id", 0))
            value = args.get("value")
            comment = args.get("comment", "")
            if not list_id or not value:
                print(json.dumps({"status": "error", "message": "list_id and value required"}))
                return
            entry_id = manager.add_entry(list_id, value, comment)
            if entry_id:
                print(json.dumps({"status": "ok", "id": entry_id}))
            else:
                print(json.dumps({"status": "error", "message": "Failed to add entry"}))

        elif command == "remove-entry":
            if len(sys.argv) < 3:
                print(json.dumps({"status": "error", "message": "entry_id required"}))
                return
            entry_id = int(sys.argv[2])
            success = manager.remove_entry(entry_id)
            print(json.dumps({"status": "ok" if success else "error"}))

        elif command == "check-domain":
            if len(sys.argv) < 3:
                print(json.dumps({"status": "error", "message": "domain required"}))
                return
            domain = sys.argv[2]
            matches = manager.check_domain(domain)
            print(json.dumps({
                "domain": domain,
                "matches": [m.to_dict() for m in matches],
                "matched": len(matches) > 0,
            }))

        elif command == "check-ip":
            if len(sys.argv) < 3:
                print(json.dumps({"status": "error", "message": "ip required"}))
                return
            ip = sys.argv[2]
            matches = manager.check_ip(ip)
            print(json.dumps({
                "ip": ip,
                "matches": [m.to_dict() for m in matches],
                "matched": len(matches) > 0,
            }))

        elif command == "add-policy":
            list_id = int(args.get("list_id", 0))
            action = args.get("action", "block")
            direction = args.get("direction", "both")
            priority = int(args.get("priority", 100))
            if not list_id:
                print(json.dumps({"status": "error", "message": "list_id required"}))
                return
            policy_id = manager.add_policy(list_id, action, direction, priority)
            if policy_id:
                print(json.dumps({"status": "ok", "id": policy_id}))
            else:
                print(json.dumps({"status": "error", "message": "Failed to add policy"}))

        elif command == "policies":
            if len(sys.argv) < 3:
                print(json.dumps({"status": "error", "message": "list_id required"}))
                return
            list_id = int(sys.argv[2])
            policies = manager.get_policies(list_id)
            print(json.dumps(policies))

        elif command == "mute-alarms":
            list_id = int(args.get("list_id", 0))
            alarm_type = args.get("alarm_type")
            if not list_id:
                print(json.dumps({"status": "error", "message": "list_id required"}))
                return
            success = manager.mute_alarms(list_id, alarm_type)
            print(json.dumps({"status": "ok" if success else "error"}))

        elif command == "unmute-alarms":
            list_id = int(args.get("list_id", 0))
            alarm_type = args.get("alarm_type")
            if not list_id:
                print(json.dumps({"status": "error", "message": "list_id required"}))
                return
            success = manager.unmute_alarms(list_id, alarm_type)
            print(json.dumps({"status": "ok" if success else "error"}))

        elif command == "export":
            if len(sys.argv) < 3:
                print(json.dumps({"status": "error", "message": "list_id required"}))
                return
            list_id = int(sys.argv[2])
            result = manager.export_list(list_id)
            print(json.dumps(result))

        elif command == "import":
            if len(sys.argv) < 3:
                print(json.dumps({"status": "error", "message": "file_path required"}))
                return
            file_path = sys.argv[2]
            with open(file_path, 'r') as f:
                data = json.load(f)
            list_id = manager.import_list(data)
            if list_id:
                print(json.dumps({"status": "ok", "id": list_id}))
            else:
                print(json.dumps({"status": "error", "message": "Failed to import"}))

        elif command == "toggle-block":
            list_id = int(args.get("list_id", 0))
            if not list_id:
                print(json.dumps({"status": "error", "message": "list_id required"}))
                return
            # Read current block state
            import os as _os
            state_file = "/var/db/netshield/targetlists_blocked.json"
            blocked_ids = []
            if _os.path.exists(state_file):
                with open(state_file, "r") as f:
                    blocked_ids = json.load(f)
            list_id_str = str(list_id)
            if list_id_str in blocked_ids:
                blocked_ids.remove(list_id_str)
                new_state = False
            else:
                blocked_ids.append(list_id_str)
                new_state = True
            with open(state_file, "w") as f:
                json.dump(blocked_ids, f)
            # Trigger enforcement
            import subprocess
            subprocess.run(["/usr/local/opnsense/scripts/netshield/lib/unbound_enforcer.py", "targetlists"],
                         capture_output=True, timeout=30)
            print(json.dumps({"status": "ok", "list_id": list_id, "blocked": new_state}))

        elif command == "stats":
            result = manager.get_stats()
            print(json.dumps(result))

        else:
            print(json.dumps({"status": "error", "message": f"Unknown command: {command}"}))

    except Exception as e:
        print(json.dumps({"status": "error", "message": str(e)}))


if __name__ == "__main__":
    main()
