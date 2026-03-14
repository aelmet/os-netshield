#!/usr/local/bin/python3
# Copyright (c) 2025, NetShield Project
# All rights reserved.
#
# Send mobile app setup info (OTP credentials) to Telegram.

import json
import os
import sys
from urllib.error import URLError
from urllib.parse import urlencode
from urllib.request import urlopen, Request

_SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))
if _SCRIPT_DIR not in sys.path:
    sys.path.insert(0, _SCRIPT_DIR)

from lib.config import load_config

TELEGRAM_API = "https://api.telegram.org/bot{token}/sendMessage"


def send_telegram(token: str, chat_id: str, text: str) -> bool:
    """Send a message to Telegram. Returns True on success."""
    url = TELEGRAM_API.format(token=token)
    payload = urlencode({
        "chat_id": chat_id,
        "text": text,
        "parse_mode": "Markdown",
        "disable_web_page_preview": "true",
    }).encode()

    try:
        req = Request(url, data=payload, method="POST")
        req.add_header("Content-Type", "application/x-www-form-urlencoded")
        with urlopen(req, timeout=15) as resp:
            return resp.status == 200
    except URLError as exc:
        return False
    except Exception:
        return False


def main():
    cfg = load_config()

    # Check if Telegram is configured (keys are in [general] section)
    tg_token = cfg.get("general", "telegram_bot_token", fallback="")
    tg_chat_id = cfg.get("general", "telegram_chat_id", fallback="")

    if not tg_token or not tg_chat_id:
        print(json.dumps({
            "status": "error",
            "message": "Telegram not configured. Set bot_token and chat_id in settings."
        }))
        return

    # Generate temporary credentials
    import hashlib
    import secrets
    import sqlite3
    import time

    username = "netshield-mobile"
    password = secrets.token_urlsafe(12)  # random password
    password_hash = hashlib.sha256(password.encode()).hexdigest()
    expires_in = 3600  # 1 hour
    expires_at = int(time.time()) + expires_in

    # Store in mobile_otp table (schema: username, password_hash, expires_at, used)
    try:
        conn = sqlite3.connect("/var/db/netshield/netshield.db")
        conn.execute("""
            CREATE TABLE IF NOT EXISTS mobile_otp (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                expires_at INTEGER NOT NULL,
                used INTEGER DEFAULT 0
            )
        """)
        # Invalidate previous OTPs for this username
        conn.execute("UPDATE mobile_otp SET used = 1 WHERE username = ? AND used = 0", (username,))
        conn.execute(
            "INSERT INTO mobile_otp (username, password_hash, expires_at) VALUES (?, ?, ?)",
            (username, password_hash, expires_at)
        )
        conn.commit()
        conn.close()
    except Exception as exc:
        print(json.dumps({"status": "error", "message": f"DB error: {exc}"}))
        return

    # Get server address from config or hostname
    server = cfg.get("general", "public_hostname", fallback="")
    if not server:
        import socket
        server = socket.getfqdn()

    # Build message
    message = f"""📱 *NetShield Mobile App Setup*

*Server:* `https://{server}`
*Username:* `{username}`
*Password:* `{password}`

⏱ This password expires in {expires_in // 60} minutes.

1. Open the NetShield app
2. Enter the server URL above
3. Login with the username and password above
4. Grant permissions when prompted"""

    # Send to Telegram
    sent = send_telegram(tg_token, tg_chat_id, message)

    if sent:
        print(json.dumps({
            "status": "ok",
            "message": "Setup info sent to Telegram",
            "server": server,
            "expires_in": expires_in
        }))
    else:
        print(json.dumps({
            "status": "error",
            "message": "Failed to send Telegram message. Check bot token and chat ID."
        }))


if __name__ == "__main__":
    main()
