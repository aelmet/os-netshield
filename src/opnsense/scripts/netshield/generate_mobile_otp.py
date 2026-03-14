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

"""Generate a one-time password (OTP) for mobile app pairing.

This script generates a 6-digit OTP that expires after 5 minutes.
The OTP is stored in the database and can be validated by the mobile app
during the pairing process.

Usage:
    generate_mobile_otp.py

Output:
    JSON with OTP and expiration timestamp.
"""

import json
import os
import secrets
import sys
from datetime import datetime, timedelta

# Ensure lib/ is on the path
_SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))
if _SCRIPT_DIR not in sys.path:
    sys.path.insert(0, _SCRIPT_DIR)

from lib.config import DB_PATH
from lib import db as _db

# OTP settings
OTP_LENGTH = 6
OTP_EXPIRY_MINUTES = 5


def generate_otp() -> str:
    """Generate a cryptographically secure numeric OTP."""
    return ''.join(str(secrets.randbelow(10)) for _ in range(OTP_LENGTH))


def store_otp(otp: str, expiry: datetime) -> bool:
    """Store OTP in database for later validation."""
    try:
        _db.init_db()
        conn = _db.get_db()

        # Create OTP table if not exists
        conn.execute("""
            CREATE TABLE IF NOT EXISTS mobile_otp (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                otp TEXT NOT NULL,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                used INTEGER DEFAULT 0
            )
        """)

        # Invalidate any existing unused OTPs
        conn.execute("UPDATE mobile_otp SET used = 1 WHERE used = 0")

        # Store new OTP
        now = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
        expiry_str = expiry.strftime("%Y-%m-%dT%H:%M:%SZ")

        conn.execute(
            "INSERT INTO mobile_otp (otp, created_at, expires_at) VALUES (?, ?, ?)",
            (otp, now, expiry_str)
        )
        conn.commit()
        conn.close()
        return True
    except Exception as exc:
        print(json.dumps({"error": str(exc)}), file=sys.stderr)
        return False


def main() -> None:
    """Generate and output OTP as JSON."""
    otp = generate_otp()
    expiry = datetime.utcnow() + timedelta(minutes=OTP_EXPIRY_MINUTES)

    if store_otp(otp, expiry):
        result = {
            "status": "ok",
            "otp": otp,
            "expires_at": expiry.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "expires_in_seconds": OTP_EXPIRY_MINUTES * 60
        }
    else:
        result = {
            "status": "error",
            "message": "Failed to generate OTP"
        }

    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
