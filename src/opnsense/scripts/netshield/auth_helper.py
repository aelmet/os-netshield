#!/usr/local/bin/python3
# Copyright (c) 2025, NetShield Project
# All rights reserved.
#
# Validate username+password against OPNsense local users OR NetShield OTP.

import sys
import json
import hashlib
import sqlite3
import time
import xml.etree.ElementTree as ET
from urllib.parse import unquote

DB_PATH = "/var/db/netshield/netshield.db"


def validate_otp(username: str, password: str) -> bool:
    """Check if credentials match a valid (unexpired, unused) OTP."""
    try:
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        now = int(time.time())
        password_hash = hashlib.sha256(password.encode()).hexdigest()

        cur.execute("""
            SELECT id FROM mobile_otp
            WHERE username = ?
              AND password_hash = ?
              AND expires_at > ?
              AND used = 0
            LIMIT 1
        """, (username, password_hash, now))

        row = cur.fetchone()
        if row:
            # Mark OTP as used
            cur.execute("UPDATE mobile_otp SET used = 1 WHERE id = ?", (row[0],))
            conn.commit()
            conn.close()
            return True
        conn.close()
        return False
    except Exception:
        return False


def _crypt_verify(password: str, stored_hash: str) -> bool:
    """Verify password using FreeBSD's native libcrypt (supports $2y$ bcrypt)."""
    import ctypes
    import ctypes.util
    lib = ctypes.CDLL(ctypes.util.find_library("crypt") or "libcrypt.so")
    lib.crypt.restype = ctypes.c_char_p
    lib.crypt.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
    result = lib.crypt(password.encode(), stored_hash.encode())
    return result.decode() == stored_hash if result else False


def validate_system_user(username: str, password: str) -> bool:
    """Check if credentials match an OPNsense system user."""
    try:
        tree = ET.parse('/conf/config.xml')
        root = tree.getroot()
        for user in root.findall('.//system/user'):
            if user.findtext('name', '') != username:
                continue
            stored = user.findtext('password', '')
            if not stored:
                continue
            if _crypt_verify(password, stored):
                return True
        return False
    except Exception:
        return False


def validate(username: str, password: str) -> bool:
    """Validate against OTP first, then system users."""
    # First try OTP (for mobile app setup)
    if validate_otp(username, password):
        return True
    # Fall back to system user auth
    return validate_system_user(username, password)


def check_rate_limit(username: str) -> bool:
    """Check if username has exceeded failed attempt limit (5 attempts per 5 min)."""
    try:
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        cutoff = int(time.time()) - 300  # 5 minutes
        cur.execute("""
            SELECT COUNT(*) FROM auth_attempts
            WHERE username = ? AND timestamp > ? AND success = 0
        """, (username, cutoff))
        count = cur.fetchone()[0]
        conn.close()
        return count < 5
    except Exception:
        return True  # Allow on error


def record_attempt(username: str, success: bool) -> None:
    """Record authentication attempt for rate limiting."""
    try:
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS auth_attempts (
                id INTEGER PRIMARY KEY,
                username TEXT,
                timestamp INTEGER,
                success INTEGER
            )
        """)
        cur.execute(
            "INSERT INTO auth_attempts (username, timestamp, success) VALUES (?, ?, ?)",
            (username, int(time.time()), 1 if success else 0)
        )
        # Clean old entries
        cutoff = int(time.time()) - 3600
        cur.execute("DELETE FROM auth_attempts WHERE timestamp < ?", (cutoff,))
        conn.commit()
        conn.close()
    except Exception:
        pass


if __name__ == '__main__':
    # configd passes parameters as single comma-delimited token (%s)
    if len(sys.argv) == 2:
        parts = sys.argv[1].split(',')
        args = [unquote(p.strip("'\"")) for p in parts]
    else:
        args = sys.argv[1:]

    username = args[0] if len(args) > 0 else ''
    password = args[1] if len(args) > 1 else ''

    if not username or not password:
        print(json.dumps({'status': 'error', 'message': 'username and password required'}))
        sys.exit(0)

    # Rate limit check
    if not check_rate_limit(username):
        print(json.dumps({'status': 'error', 'message': 'too many attempts, try again later'}))
        sys.exit(0)

    if validate(username, password):
        record_attempt(username, True)
        print(json.dumps({'status': 'ok', 'username': username}))
    else:
        record_attempt(username, False)
        print(json.dumps({'status': 'error', 'message': 'invalid credentials'}))
        sys.exit(0)
