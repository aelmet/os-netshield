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

"""NetShield alert delivery — database persistence and Telegram notifications."""

import configparser
import logging
import time
from typing import Any, Dict, List, Optional
from urllib.error import URLError
from urllib.parse import urlencode
from urllib.request import urlopen, Request

try:
    from . import db as _db
except ImportError:
    import db as _db

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Map alert_type -> emoji prefix for Telegram messages
_EMOJI_MAP: Dict[str, str] = {
    "New Device":         "📡",
    "Device Quarantined": "🔒",
    "Port Scan":          "🔍",
    "Threat Detected":    "⚠️",
    "VPN Detected":       "🔐",
    "Adult Content":      "🔞",
    "DNS Bypass":         "🕵️",
    "Data Exfiltration":  "📤",
    "Beaconing":          "📶",
}

_SEVERITY_PREFIX: Dict[str, str] = {
    "critical": "🚨 CRITICAL",
    "high":     "🔴 HIGH",
    "medium":   "🟡 MEDIUM",
    "low":      "🟢 LOW",
    "info":     "ℹ️  INFO",
}

_TELEGRAM_API = "https://api.telegram.org/bot{token}/sendMessage"

# Minimum severity levels (ordered low → critical)
_SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _severity_passes(severity: str, min_severity: str) -> bool:
    """Return True if *severity* is >= *min_severity*."""
    try:
        return _SEVERITY_ORDER.index(severity) >= _SEVERITY_ORDER.index(min_severity)
    except ValueError:
        return True


def _format_message(alert: Dict[str, Any]) -> str:
    """Build a human-readable Telegram message for a single alert."""
    alert_type = alert.get("alert_type", "Unknown")
    severity = alert.get("severity", "medium").lower()
    device_name = alert.get("device_name") or alert.get("device_mac", "Unknown")
    device_ip = alert.get("device_ip", "")
    detail = alert.get("detail", "")
    timestamp = alert.get("timestamp", "")

    emoji = _EMOJI_MAP.get(alert_type, "🔔")
    sev_label = _SEVERITY_PREFIX.get(severity, severity.upper())

    lines = [
        f"{emoji} *NetShield Alert*",
        f"*Type:* {alert_type}",
        f"*Severity:* {sev_label}",
        f"*Device:* {device_name}",
    ]
    if device_ip:
        lines.append(f"*IP:* {device_ip}")
    if detail:
        lines.append(f"*Detail:* {detail}")
    if timestamp:
        lines.append(f"*Time:* {timestamp}")

    return "\n".join(lines)


def _send_telegram(
    token: str,
    chat_id: str,
    text: str,
    max_retries: int = 3,
    retry_delay: float = 2.0,
) -> bool:
    """POST a message to the Telegram Bot API.  Returns True on success."""
    url = _TELEGRAM_API.format(token=token)
    payload = urlencode({
        "chat_id": chat_id,
        "text": text,
        "parse_mode": "Markdown",
        "disable_web_page_preview": "true",
    }).encode()

    for attempt in range(1, max_retries + 1):
        try:
            req = Request(url, data=payload, method="POST")
            req.add_header("Content-Type", "application/x-www-form-urlencoded")
            with urlopen(req, timeout=15) as resp:
                if resp.status == 200:
                    return True
                log.warning("Telegram HTTP %s (attempt %d/%d)", resp.status, attempt, max_retries)
        except URLError as exc:
            log.warning("Telegram request failed (attempt %d/%d): %s", attempt, max_retries, exc)
        except Exception as exc:
            log.error("Unexpected Telegram error: %s", exc)
            return False

        if attempt < max_retries:
            time.sleep(retry_delay)

    return False


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def send_alerts(
    alerts: List[Dict[str, Any]],
    config: configparser.ConfigParser,
    db_path: str = _db.DB_PATH,
) -> None:
    """Persist *alerts* to the database and optionally forward to Telegram.

    Each item in *alerts* should be a dict with keys matching the ``alerts``
    table columns: device_mac, device_ip, device_name, alert_type, severity,
    detail.  Missing keys fall back to empty strings / 'medium'.

    The function:
    1. Filters alerts below the configured severity threshold.
    2. Checks whether the specific alert type is enabled in config.
    3. Inserts each alert into the database.
    4. Batches Telegram notifications (respects batch_delay between messages).
    """
    if not alerts:
        return

    # Read config (keys are in [general] section)
    tg_token = config.get("general", "telegram_bot_token", fallback="")
    tg_chat_id = config.get("general", "telegram_chat_id", fallback="")
    # Telegram is enabled if both token and chat_id are set
    tg_enabled = bool(tg_token and tg_chat_id)
    batch_delay = config.getfloat("general", "batch_delay", fallback=2.0)
    max_retries = config.getint("general", "max_retries", fallback=3)
    min_severity = config.get("general", "severity_filter", fallback="low").lower()

    # Map of alert_type config keys
    _type_cfg_key: Dict[str, str] = {
        "New Device":         "new_device_alert",
        "Device Quarantined": "quarantine_alert",
        "Port Scan":          "port_scan_alert",
        "Threat Detected":    "threat_alert",
        "VPN Detected":       "vpn_alert",
        "Adult Content":      "adult_content_alert",
        "DNS Bypass":         "dns_bypass_alert",
        "Data Exfiltration":  "data_exfil_alert",
        "Beaconing":          "beaconing_alert",
    }

    for alert in alerts:
        alert_type = alert.get("alert_type", "")
        severity = alert.get("severity", "medium").lower()

        # Check severity threshold
        if not _severity_passes(severity, min_severity):
            log.debug("Skipping alert type=%s severity=%s (below threshold %s)",
                      alert_type, severity, min_severity)
            continue

        # Check if this alert type is enabled (keys are in [general] section)
        cfg_key = _type_cfg_key.get(alert_type)
        if cfg_key and not config.getboolean("general", cfg_key, fallback=True):
            log.debug("Alert type '%s' is disabled in config", alert_type)
            continue

        # Persist to DB
        try:
            alert_id = _db.add_alert(
                device_mac=alert.get("device_mac", ""),
                device_ip=alert.get("device_ip", ""),
                device_name=alert.get("device_name", ""),
                alert_type=alert_type,
                severity=severity,
                detail=alert.get("detail", ""),
                db_path=db_path,
            )
            log.debug("Alert id=%d persisted (type=%s)", alert_id, alert_type)
        except Exception as exc:
            log.error("Failed to persist alert: %s", exc)
            alert_id = None

        # Send to Telegram
        if tg_enabled and tg_token and tg_chat_id:
            message = _format_message(alert)
            sent = _send_telegram(
                token=tg_token,
                chat_id=tg_chat_id,
                text=message,
                max_retries=max_retries,
                retry_delay=batch_delay,
            )
            if sent and alert_id is not None:
                try:
                    with _db.get_db(db_path) as conn:
                        conn.execute(
                            "UPDATE alerts SET sent_telegram = 1 WHERE id = ?",
                            (alert_id,),
                        )
                except Exception as exc:
                    log.warning("Could not mark alert %d as sent_telegram: %s", alert_id, exc)

            # Respect batch delay between messages to avoid Telegram rate limits
            time.sleep(batch_delay)
