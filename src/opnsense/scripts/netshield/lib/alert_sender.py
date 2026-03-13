"""
SPDX-License-Identifier: BSD-2-Clause

Copyright (c) 2024 NetShield Contributors
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice,
   this list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
POSSIBILITY OF SUCH DAMAGE.

NetShield alert_sender.py — Alert persistence, syslog, and webhook delivery.
"""

import json
import logging
import socket
import ssl
import urllib.error
import urllib.request
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from . import db
from .config import get_config

log = logging.getLogger(__name__)

# Valid alert type identifiers
ALERT_TYPES = frozenset({
    "vpn_detected",
    "proxy_detected",
    "adult_content",
    "dns_bypass",
    "doh_bypass",
    "new_device",
    "policy_violation",
    "threat_detected",
    "quarantine_added",
    "quarantine_released",
})

# Syslog severity codes (RFC 5424)
_SYSLOG_FACILITY_LOCAL0 = 16
_SYSLOG_SEVERITY_WARNING = 4
_SYSLOG_SEVERITY_INFO = 6
_SYSLOG_SEVERITY_NOTICE = 5

# Syslog protocols
SYSLOG_UDP = "udp"
SYSLOG_TCP = "tcp"

# Maximum syslog message length (RFC 5424 recommends at least 480 bytes)
_SYSLOG_MAX_LEN = 2048

HOSTNAME = socket.gethostname()
APP_NAME = "netshield"


# ---------------------------------------------------------------------------
# DB operations
# ---------------------------------------------------------------------------

def save_alert(
    device: str,
    device_name: str,
    alert_type: str,
    detail: str,
) -> Optional[int]:
    """
    Persist an alert to the SQLite alerts table.
    Returns the new row ID, or None on failure.
    """
    if alert_type not in ALERT_TYPES:
        log.warning("save_alert: unknown alert_type '%s'", alert_type)

    db.init_db()
    cur = db.execute(
        """
        INSERT INTO alerts (device, device_name, alert_type, detail, timestamp, acknowledged)
        VALUES (?, ?, ?, ?, datetime('now','utc'), 0)
        """,
        (
            device or "",
            device_name or device or "",
            alert_type or "",
            detail or "",
        ),
    )
    if cur is not None:
        log.debug(
            "save_alert: id=%s type=%s device=%s",
            cur.lastrowid, alert_type, device,
        )
        return cur.lastrowid
    return None


def get_recent_alerts(
    limit: int = 100,
    alert_type: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """
    Return recent alerts from the DB, newest first.
    Optionally filter by alert_type.
    """
    db.init_db()
    if alert_type:
        return db.fetchall(
            """
            SELECT id, device, device_name, alert_type, detail, timestamp, acknowledged
              FROM alerts
             WHERE alert_type = ?
             ORDER BY id DESC
             LIMIT ?
            """,
            (alert_type, max(1, int(limit))),
        )
    return db.fetchall(
        """
        SELECT id, device, device_name, alert_type, detail, timestamp, acknowledged
          FROM alerts
         ORDER BY id DESC
         LIMIT ?
        """,
        (max(1, int(limit)),),
    )


def acknowledge_alert(alert_id: int) -> bool:
    """Mark an alert as acknowledged. Returns True on success."""
    db.init_db()
    cur = db.execute(
        "UPDATE alerts SET acknowledged = 1 WHERE id = ?",
        (int(alert_id),),
    )
    return cur is not None


def flush_old_alerts(days: int = 30) -> int:
    """
    Delete alerts older than `days` days.
    Returns the number of rows deleted.
    """
    db.init_db()
    cur = db.execute(
        "DELETE FROM alerts WHERE timestamp < datetime('now', ?, 'utc')",
        (f"-{max(1, int(days))} days",),
    )
    count = cur.rowcount if cur is not None else 0
    if count:
        log.info("flush_old_alerts: deleted %d alerts older than %d days", count, days)
    return count


# ---------------------------------------------------------------------------
# Syslog delivery
# ---------------------------------------------------------------------------

def send_syslog(
    message: str,
    host: str,
    port: int = 514,
    protocol: str = SYSLOG_UDP,
    facility: int = _SYSLOG_FACILITY_LOCAL0,
    severity: int = _SYSLOG_SEVERITY_WARNING,
) -> bool:
    """
    Send a syslog message via UDP or TCP (RFC 5424 format).

    message  — plain text message body
    host     — syslog server hostname or IP
    port     — syslog server port (default 514)
    protocol — "udp" or "tcp"
    Returns True on success.
    """
    if not host or not message:
        return False

    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    pri = (facility * 8) + severity
    # RFC 5424: <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID MSG
    formatted = (
        f"<{pri}>1 {ts} {HOSTNAME} {APP_NAME} - - - {message}"
    )
    # Truncate if too long
    formatted = formatted[:_SYSLOG_MAX_LEN]
    encoded = formatted.encode("utf-8", errors="replace")

    try:
        if protocol == SYSLOG_UDP:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(5)
                sock.sendto(encoded, (host, int(port)))
        elif protocol == SYSLOG_TCP:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(10)
                sock.connect((host, int(port)))
                # RFC 6587 octet-framing
                sock.sendall(f"{len(encoded)} ".encode() + encoded)
        else:
            log.error("send_syslog: unknown protocol '%s'", protocol)
            return False
        log.debug("Syslog sent to %s:%d [%s]", host, port, protocol)
        return True
    except (socket.timeout, socket.error, OSError) as exc:
        log.warning("send_syslog to %s:%d failed: %s", host, port, exc)
        return False


# ---------------------------------------------------------------------------
# Webhook delivery
# ---------------------------------------------------------------------------

def send_webhook(
    url: str,
    payload: Dict[str, Any],
    timeout: int = 10,
) -> bool:
    """
    POST a JSON payload to a webhook URL.

    url     — must be http:// or https://
    payload — dict to serialize as JSON
    timeout — seconds before giving up
    Returns True on success (2xx response).
    """
    if not url or not url.startswith(("http://", "https://")):
        log.error("send_webhook: invalid or missing URL")
        return False

    try:
        body = json.dumps(payload, default=str).encode("utf-8")
    except (TypeError, ValueError) as exc:
        log.error("send_webhook: failed to serialize payload: %s", exc)
        return False

    try:
        req = urllib.request.Request(
            url,
            data=body,
            method="POST",
            headers={
                "Content-Type": "application/json",
                "User-Agent": "NetShield-OPNsense/1.0",
                "Content-Length": str(len(body)),
            },
        )
        # Note: we do NOT disable SSL verification. Misconfigured webhooks
        # should fix their certificates, not bypass security.
        ctx = ssl.create_default_context()
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            status = resp.status
        if 200 <= status < 300:
            log.debug("Webhook delivered to %s (HTTP %d)", url, status)
            return True
        log.warning("Webhook to %s returned HTTP %d", url, status)
        return False
    except urllib.error.HTTPError as exc:
        log.warning("Webhook HTTP error %s to %s: %s", exc.code, url, exc.reason)
        return False
    except urllib.error.URLError as exc:
        log.warning("Webhook URL error to %s: %s", url, exc.reason)
        return False
    except (ssl.SSLError, OSError) as exc:
        log.warning("Webhook connection error to %s: %s", url, exc)
        return False


# ---------------------------------------------------------------------------
# Unified delivery
# ---------------------------------------------------------------------------

def _build_payload(alert: Dict[str, Any]) -> Dict[str, Any]:
    """Build a standardized webhook payload from an alert dict."""
    return {
        "source": "netshield",
        "alert_type": alert.get("alert_type", ""),
        "device": alert.get("device", ""),
        "device_name": alert.get("device_name", alert.get("device", "")),
        "detail": alert.get("detail", ""),
        "timestamp": alert.get("timestamp", datetime.now(timezone.utc).isoformat()),
        "hostname": HOSTNAME,
    }


def deliver_alert(alert: Dict[str, Any]) -> None:
    """
    Route an alert to all configured destinations (syslog, webhook).
    Config is read from [alerts] section of netshield.conf:
      syslog_enabled  = 1
      syslog_host     = 192.0.2.1
      syslog_port     = 514
      syslog_protocol = udp
      webhook_enabled = 1
      webhook_url     = https://hooks.example.com/netshield
    """
    cfg = get_config()
    alert_type = alert.get("alert_type", "unknown")
    device = alert.get("device", "")
    detail = alert.get("detail", "")

    # Persist to DB
    row_id = save_alert(
        device,
        alert.get("device_name", device),
        alert_type,
        detail,
    )

    # Syslog
    if cfg.getboolean("alerts", "syslog_enabled", default=False):
        host = cfg.get("alerts", "syslog_host", default="")
        if host:
            port = cfg.getint("alerts", "syslog_port", default=514)
            proto = cfg.get("alerts", "syslog_protocol", default=SYSLOG_UDP)
            msg = f"[{alert_type}] device={device} detail={detail}"
            send_syslog(msg, host, port, proto)

    # Webhook
    if cfg.getboolean("alerts", "webhook_enabled", default=False):
        webhook_url = cfg.get("alerts", "webhook_url", default="")
        if webhook_url:
            payload = _build_payload(alert)
            if row_id:
                payload["id"] = row_id
            send_webhook(webhook_url, payload)
