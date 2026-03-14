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
manage_parental.py — configd script for parental controls management.
Called by OPNsense configd via actions_netshield.conf.
All output is JSON on stdout.
"""

import argparse
import json
import logging
import os
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, SCRIPT_DIR)

from lib.db import Database  # noqa: E402
from lib.parental_engine import ParentalEngine  # noqa: E402
from urllib.parse import unquote

logging.basicConfig(
    filename="/var/log/netshield/manage_parental.log",
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
log = logging.getLogger("manage_parental")


def output(data: object) -> None:
    print(json.dumps(data, default=str))


def main() -> None:
    # configd passes all parameters as a single comma-delimited token
    if len(sys.argv) == 2:
        arg = sys.argv[1]
        parts = arg.replace(',', ' ').split()
        sys.argv = [sys.argv[0]] + [unquote(p.strip("'\"")) for p in parts]
    parser = argparse.ArgumentParser(
        description="NetShield parental controls management",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = parser.add_subparsers(dest="action")

    # list
    sub.add_parser("list", help="List all parental profiles")

    # add <name> [time_limit] [bedtime_start] [bedtime_end] [blocked_categories] [allowed_categories] [enabled]
    p_add = sub.add_parser("add", help="Add a new parental profile")
    p_add.add_argument("name", help="Profile name")
    p_add.add_argument("time_limit", nargs="?", type=int, default=0,
                       help="Daily time limit in minutes (default: 0 = unlimited)")
    p_add.add_argument("bedtime_start", nargs="?", default=None, help="Bedtime start HH:MM")
    p_add.add_argument("bedtime_end", nargs="?", default=None, help="Bedtime end HH:MM")
    p_add.add_argument("blocked_categories", nargs="?", default=None,
                       help="Comma-separated blocked categories")
    p_add.add_argument("allowed_categories", nargs="?", default=None,
                       help="Comma-separated allowed categories")
    p_add.add_argument("enabled", nargs="?", default="1", help="1 or 0 (default: 1)")

    # update <id> [name] [time_limit] [bedtime_start] [bedtime_end] [blocked_categories] [allowed_categories] [enabled]
    p_update = sub.add_parser("update", help="Update an existing profile")
    p_update.add_argument("id", type=int, help="Profile ID")
    p_update.add_argument("name", nargs="?", default=None, help="Profile name")
    p_update.add_argument("time_limit", nargs="?", default=None,
                          help="Daily time limit in minutes")
    p_update.add_argument("bedtime_start", nargs="?", default=None, help="Bedtime start HH:MM")
    p_update.add_argument("bedtime_end", nargs="?", default=None, help="Bedtime end HH:MM")
    p_update.add_argument("blocked_categories", nargs="?", default=None,
                          help="Comma-separated blocked categories")
    p_update.add_argument("allowed_categories", nargs="?", default=None,
                          help="Comma-separated allowed categories")
    p_update.add_argument("enabled", nargs="?", default=None, help="1 or 0")

    # delete <id>
    p_delete = sub.add_parser("delete", help="Delete a profile by ID")
    p_delete.add_argument("id", type=int, help="Profile ID")

    # assign-device <id> <mac>
    p_assign = sub.add_parser("assign-device", help="Assign a device MAC to a profile")
    p_assign.add_argument("id", type=int, help="Profile ID")
    p_assign.add_argument("mac", help="Device MAC address")

    # unassign-device <mac>
    p_unassign = sub.add_parser("unassign-device", help="Unassign a device MAC from its profile")
    p_unassign.add_argument("mac", help="Device MAC address")

    # usage <id> [days]
    p_usage = sub.add_parser("usage", help="Show usage for a profile")
    p_usage.add_argument("id", type=int, help="Profile ID")
    p_usage.add_argument("days", nargs="?", type=int, default=7,
                         help="Number of days (default: 7)")

    args = parser.parse_args()

    if not args.action:
        parser.print_help()
        output({"result": "failed", "message": "no action specified"})
        return

    try:
        db = Database()
        engine = ParentalEngine(db)
    except Exception as exc:
        output({"result": "failed", "message": "Failed to initialise parental engine: {}".format(exc)})
        sys.exit(1)

    try:
        if args.action == "list":
            profiles = engine.get_profiles()
            output({"profiles": profiles, "total": len(profiles)})

        elif args.action == "add":
            blocked = (
                [c.strip() for c in args.blocked_categories.split(",") if c.strip()]
                if args.blocked_categories else []
            )
            allowed = (
                [c.strip() for c in args.allowed_categories.split(",") if c.strip()]
                if args.allowed_categories else []
            )
            enabled = args.enabled != "0"
            result = engine.add_profile(
                name=args.name,
                time_limit_daily_min=args.time_limit or 0,
                bedtime_start=args.bedtime_start,
                bedtime_end=args.bedtime_end,
                blocked_categories=blocked,
                allowed_categories=allowed,
                enabled=enabled,
            )
            output(result)

        elif args.action == "update":
            # Normalize: empty strings from positional args are treated as absent
            name = args.name if args.name else None
            bedtime_start = args.bedtime_start if args.bedtime_start else None
            bedtime_end = args.bedtime_end if args.bedtime_end else None
            time_limit_str = args.time_limit if args.time_limit else None
            blocked_cat = args.blocked_categories if args.blocked_categories else None
            allowed_cat = args.allowed_categories if args.allowed_categories else None
            enabled_str = args.enabled if args.enabled else None

            blocked = (
                [c.strip() for c in blocked_cat.split(",") if c.strip()]
                if blocked_cat is not None else None
            )
            allowed = (
                [c.strip() for c in allowed_cat.split(",") if c.strip()]
                if allowed_cat is not None else None
            )
            enabled = None
            if enabled_str is not None:
                enabled = enabled_str != "0"
            time_limit = int(time_limit_str) if time_limit_str is not None else None
            result = engine.update_profile(
                profile_id=args.id,
                name=name,
                time_limit_daily_min=time_limit,
                bedtime_start=bedtime_start,
                bedtime_end=bedtime_end,
                blocked_categories=blocked,
                allowed_categories=allowed,
                enabled=enabled,
            )
            output(result)

        elif args.action == "delete":
            result = engine.delete_profile(args.id)
            output(result)

        elif args.action == "assign-device":
            result = engine.assign_device(args.id, args.mac)
            output(result)

        elif args.action == "unassign-device":
            result = engine.unassign_device(args.mac)
            output(result)

        elif args.action == "usage":
            usage = engine.get_usage(args.id, days=args.days)
            output({"profile_id": args.id, "days": args.days, "usage": usage})

        else:
            output({"result": "failed", "message": "unknown action: {}".format(args.action)})

    except Exception as exc:
        log.exception("Unhandled error in manage_parental")
        output({"result": "failed", "message": str(exc)})
        sys.exit(1)


if __name__ == "__main__":
    main()
