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
JWT Helper CLI — Command-line wrapper for JWT operations used by configd actions.

Usage:
  jwt_helper_cli.py --generate --username NAME [--device-name NAME] [--device-id ID]
  jwt_helper_cli.py --validate --token TOKEN
  jwt_helper_cli.py --revoke --jti JTI

All output is JSON to stdout. Exit code 0 = success, 1 = error.
"""

import argparse
import json
import os
import sys
from urllib.parse import unquote

# Ensure lib/ is importable when run from scripts/netshield/
sys.path.insert(0, os.path.join(os.path.dirname(__file__)))

from lib.jwt_helper import JWTManager


def cmd_generate(args, manager: JWTManager) -> dict:
    """Generate an access + refresh token pair for the given username."""
    username = args.username
    access_token = manager.generate_access_token(username)
    refresh_token = manager.generate_refresh_token(username)

    # Extract JTI from refresh token payload for session registration
    payload = manager.validate_token(refresh_token)
    jti = payload.get("jti", "") if payload else ""

    manager.register_session(
        username=username,
        jti=jti,
        device_name=getattr(args, "device_name", "") or "",
        device_id=getattr(args, "device_id", "") or "",
    )

    return {
        "status": "ok",
        "access_token": access_token,
        "refresh_token": refresh_token,
        "expires_in": 900,
        "token_type": "Bearer",
    }


def cmd_validate(args, manager: JWTManager) -> dict:
    """Validate a token and return its payload."""
    token = args.token
    if not token:
        return {"status": "error", "message": "No token provided"}

    payload = manager.validate_token(token)
    if payload is None:
        return {"status": "error", "message": "Token is invalid or expired"}

    return {
        "status": "ok",
        "payload": payload,
        "username": payload.get("sub", ""),
        "type": payload.get("type", ""),
        "permissions": payload.get("permissions", []),
    }


def cmd_revoke(args, manager: JWTManager) -> dict:
    """Revoke a token by its JTI."""
    jti = args.jti
    if not jti:
        return {"status": "error", "message": "No JTI provided"}

    manager.revoke_token(jti)
    return {"status": "ok", "revoked": jti}


def main() -> None:
    # configd passes all parameters as a single comma-delimited token
    if len(sys.argv) == 2:
        parts = sys.argv[1].split(',')
        sys.argv = [sys.argv[0]] + [unquote(p.strip("'\"")) for p in parts]
    parser = argparse.ArgumentParser(
        description="NetShield JWT Helper CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = parser.add_subparsers(dest="cmd")

    # generate <username> [device_name] [device_id]
    p_gen = sub.add_parser("generate", help="Generate token pair")
    p_gen.add_argument("username", help="Username for token generation")
    p_gen.add_argument("device_name", nargs="?", default="", help="Device name")
    p_gen.add_argument("device_id", nargs="?", default="", help="Device ID")

    # validate <token>
    p_val = sub.add_parser("validate", help="Validate a token")
    p_val.add_argument("token", help="JWT token string")

    # revoke <jti>
    p_rev = sub.add_parser("revoke", help="Revoke a token by JTI")
    p_rev.add_argument("jti", help="JTI (token ID) to revoke")

    args = parser.parse_args()

    if not args.cmd:
        parser.print_help()
        print(json.dumps({"status": "error", "message": "No operation specified"}))
        sys.exit(0)

    try:
        manager = JWTManager()
    except Exception as exc:
        print(json.dumps({"status": "error", "message": f"JWTManager init failed: {exc}"}))
        sys.exit(0)

    try:
        if args.cmd == "generate":
            result = cmd_generate(args, manager)
        elif args.cmd == "validate":
            result = cmd_validate(args, manager)
        elif args.cmd == "revoke":
            result = cmd_revoke(args, manager)
        else:
            result = {"status": "error", "message": "No operation specified"}

        print(json.dumps(result))
        if result.get("status") != "ok":
            sys.exit(0)

    except Exception as exc:
        print(json.dumps({"status": "error", "message": str(exc)}))
        sys.exit(0)


if __name__ == "__main__":
    main()
