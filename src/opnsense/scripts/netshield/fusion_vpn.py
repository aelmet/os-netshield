#!/usr/local/bin/python3
# Copyright (c) 2025-2026, NetShield Project
# Fusion VPN CLI - configd script

"""
CLI for Fusion VPN management (Asus VPN Fusion style).

Usage:
    fusion_vpn.py status
    fusion_vpn.py profiles
    fusion_vpn.py profile <id>
    fusion_vpn.py create name=<n> protocol=<p> [config_file=<f>] [username=<u>] [password=<p>]
    fusion_vpn.py update id=<id> [name=<n>] [username=<u>] [password=<p>] [apply_to_all=<0|1>] [kill_switch=<0|1>]
    fusion_vpn.py delete <id>
    fusion_vpn.py connect <id>
    fusion_vpn.py disconnect <id>
    fusion_vpn.py assignments [profile_id=<id>]
    fusion_vpn.py assign profile_id=<id> device_mac=<mac> [device_name=<name>]
    fusion_vpn.py unassign <assignment_id>
    fusion_vpn.py exceptions
    fusion_vpn.py add-exception device_mac=<mac> [device_name=<name>] [reason=<r>]
    fusion_vpn.py remove-exception <exception_id>
    fusion_vpn.py import-config <file_path>
"""

import base64
import json
import os
import sys

# Add lib to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'lib'))

from fusion_vpn_engine import FusionVpnEngine
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

    engine = FusionVpnEngine()

    try:
        # ========== Status & Profiles ==========

        if command == "status":
            result = engine.get_status()
            print(json.dumps(result))

        elif command == "profiles":
            profiles = engine.get_profiles()
            print(json.dumps([p.to_dict() for p in profiles]))

        elif command == "profile":
            if len(sys.argv) < 3:
                print(json.dumps({"status": "error", "message": "profile_id required"}))
                return
            profile_id = int(sys.argv[2])
            profile = engine.get_profile(profile_id)
            if profile:
                print(json.dumps(profile.to_dict()))
            else:
                print(json.dumps({"status": "error", "message": "Profile not found"}))

        # ========== Profile Management ==========

        elif command == "create":
            name = args.get("name")
            protocol = args.get("protocol", "openvpn")
            config_file = args.get("config_file")
            config_content = args.get("config_content", "")

            # If config_content is base64 encoded
            if args.get("config_base64"):
                try:
                    config_content = base64.b64decode(args["config_base64"]).decode("utf-8")
                except Exception:
                    print(json.dumps({"status": "error", "message": "Invalid base64 config"}))
                    return

            # If config_file provided, read it
            if config_file and os.path.exists(config_file):
                with open(config_file, "r") as f:
                    config_content = f.read()

            if not name:
                print(json.dumps({"status": "error", "message": "name required"}))
                return

            if not config_content:
                print(json.dumps({"status": "error", "message": "config_content or config_file required"}))
                return

            result = engine.create_profile(
                name=name,
                protocol=protocol,
                config_content=config_content,
                username=args.get("username"),
                password=args.get("password"),
                apply_to_all=args.get("apply_to_all", "1") == "1",
                kill_switch=args.get("kill_switch", "0") == "1",
            )
            print(json.dumps(result))

        elif command == "update":
            profile_id = int(args.get("id", 0))
            if not profile_id:
                print(json.dumps({"status": "error", "message": "id required"}))
                return

            update_args = {}
            if "name" in args:
                update_args["name"] = args["name"]
            if "username" in args:
                update_args["username"] = args["username"]
            if "password" in args:
                update_args["password"] = args["password"]
            if "apply_to_all" in args:
                update_args["apply_to_all"] = int(args["apply_to_all"])
            if "kill_switch" in args:
                update_args["kill_switch"] = int(args["kill_switch"])
            if "enabled" in args:
                update_args["enabled"] = int(args["enabled"])

            result = engine.update_profile(profile_id, **update_args)
            print(json.dumps(result))

        elif command == "delete":
            if len(sys.argv) < 3:
                print(json.dumps({"status": "error", "message": "profile_id required"}))
                return
            profile_id = int(sys.argv[2])
            result = engine.delete_profile(profile_id)
            print(json.dumps(result))

        # ========== Connection Management ==========

        elif command == "connect":
            if len(sys.argv) < 3:
                print(json.dumps({"status": "error", "message": "profile_id required"}))
                return
            profile_id = int(sys.argv[2])
            result = engine.connect_profile(profile_id)
            print(json.dumps(result))

        elif command == "disconnect":
            if len(sys.argv) < 3:
                print(json.dumps({"status": "error", "message": "profile_id required"}))
                return
            profile_id = int(sys.argv[2])
            result = engine.disconnect_profile(profile_id)
            print(json.dumps(result))

        # ========== Device Assignments ==========

        elif command == "assignments":
            profile_id = int(args.get("profile_id", 0)) if "profile_id" in args else None
            assignments = engine.get_device_assignments(profile_id)
            print(json.dumps([a.to_dict() for a in assignments]))

        elif command == "assign":
            profile_id = int(args.get("profile_id", 0))
            device_mac = args.get("device_mac")
            device_name = args.get("device_name")

            if not profile_id or not device_mac:
                print(json.dumps({"status": "error", "message": "profile_id and device_mac required"}))
                return

            result = engine.assign_device(profile_id, device_mac, device_name)
            print(json.dumps(result))

        elif command == "unassign":
            if len(sys.argv) < 3:
                print(json.dumps({"status": "error", "message": "assignment_id required"}))
                return
            assignment_id = int(sys.argv[2])
            result = engine.unassign_device(assignment_id)
            print(json.dumps(result))

        # ========== Exception Devices ==========

        elif command == "exceptions":
            exceptions = engine.get_exception_devices()
            print(json.dumps([e.to_dict() for e in exceptions]))

        elif command == "add-exception":
            device_mac = args.get("device_mac")
            if not device_mac:
                print(json.dumps({"status": "error", "message": "device_mac required"}))
                return
            result = engine.add_exception_device(
                device_mac=device_mac,
                device_name=args.get("device_name"),
                reason=args.get("reason"),
            )
            print(json.dumps(result))

        elif command == "remove-exception":
            if len(sys.argv) < 3:
                print(json.dumps({"status": "error", "message": "exception_id required"}))
                return
            exception_id = int(sys.argv[2])
            result = engine.remove_exception_device(exception_id)
            print(json.dumps(result))

        # ========== Config Import ==========

        elif command == "import-config":
            if len(sys.argv) < 3:
                print(json.dumps({"status": "error", "message": "file_path required"}))
                return
            file_path = sys.argv[2]
            if not os.path.exists(file_path):
                print(json.dumps({"status": "error", "message": "File not found"}))
                return

            # Detect protocol from extension
            if file_path.endswith(".ovpn"):
                protocol = "openvpn"
            elif file_path.endswith(".conf"):
                protocol = "wireguard"
            else:
                protocol = args.get("protocol", "openvpn")

            name = args.get("name", os.path.basename(file_path).rsplit(".", 1)[0])

            with open(file_path, "r") as f:
                config_content = f.read()

            result = engine.create_profile(
                name=name,
                protocol=protocol,
                config_content=config_content,
                username=args.get("username"),
                password=args.get("password"),
            )
            print(json.dumps(result))

        else:
            print(json.dumps({"status": "error", "message": f"Unknown command: {command}"}))

    except Exception as e:
        print(json.dumps({"status": "error", "message": str(e)}))


if __name__ == "__main__":
    main()
