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

"""NetShield SQLite database manager."""

import os
import sqlite3
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

try:
    from .config import DB_DIR, DB_PATH
except ImportError:
    from config import DB_DIR, DB_PATH

# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------

_DDL = """
CREATE TABLE IF NOT EXISTS devices (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    mac TEXT UNIQUE NOT NULL,
    ip TEXT NOT NULL,
    hostname TEXT NOT NULL DEFAULT '',
    vendor TEXT NOT NULL DEFAULT '',
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    is_approved INTEGER NOT NULL DEFAULT 0,
    is_quarantined INTEGER NOT NULL DEFAULT 0,
    device_group TEXT NOT NULL DEFAULT '',
    notes TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_mac TEXT NOT NULL DEFAULT '',
    device_ip TEXT NOT NULL DEFAULT '',
    device_name TEXT NOT NULL DEFAULT '',
    alert_type TEXT NOT NULL,
    severity TEXT NOT NULL DEFAULT 'medium',
    detail TEXT NOT NULL DEFAULT '',
    timestamp TEXT NOT NULL,
    acknowledged INTEGER NOT NULL DEFAULT 0,
    sent_telegram INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    actor TEXT NOT NULL DEFAULT 'system',
    action TEXT NOT NULL,
    target TEXT NOT NULL DEFAULT '',
    detail TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS device_groups (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    created TEXT NOT NULL
);
"""

_INDEXES = """
CREATE INDEX IF NOT EXISTS idx_devices_mac ON devices(mac);
CREATE INDEX IF NOT EXISTS idx_devices_ip ON devices(ip);
CREATE INDEX IF NOT EXISTS idx_devices_quarantined ON devices(is_quarantined);
CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp);
CREATE INDEX IF NOT EXISTS idx_alerts_type ON alerts(alert_type);
CREATE INDEX IF NOT EXISTS idx_alerts_ack ON alerts(acknowledged);
CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_log(action);
"""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _now() -> str:
    """Return the current UTC timestamp as an ISO-8601 string."""
    return datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")


def _row_to_dict(row: sqlite3.Row) -> Dict[str, Any]:
    """Convert a sqlite3.Row to a plain dict."""
    return dict(row)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def init_db(db_path: str = DB_PATH) -> None:
    """Create tables and indexes.  Safe to call multiple times (IF NOT EXISTS)."""
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    with get_db(db_path) as conn:
        conn.executescript(_DDL)
        conn.executescript(_INDEXES)


def get_db(db_path: str = DB_PATH) -> sqlite3.Connection:
    """Open and return a SQLite connection with row_factory set.

    The caller is responsible for closing/using as a context manager.
    """
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    conn = sqlite3.connect(db_path, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


# ---------------------------------------------------------------------------
# Devices
# ---------------------------------------------------------------------------

def add_device(
    mac: str,
    ip: str,
    hostname: str = "",
    vendor: str = "",
    db_path: str = DB_PATH,
) -> bool:
    """Insert a new device or update ip/hostname/vendor and last_seen on conflict.

    Returns True if a brand-new row was inserted, False if an existing row was
    updated (so callers can detect new devices).
    """
    now = _now()
    with get_db(db_path) as conn:
        cur = conn.execute("SELECT id FROM devices WHERE mac = ?", (mac,))
        existing = cur.fetchone()

        if existing is None:
            conn.execute(
                """
                INSERT INTO devices (mac, ip, hostname, vendor, first_seen, last_seen)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (mac, ip, hostname, vendor, now, now),
            )
            return True
        else:
            conn.execute(
                """
                UPDATE devices
                SET ip = ?, hostname = CASE WHEN ? != '' THEN ? ELSE hostname END,
                    vendor = CASE WHEN ? != '' THEN ? ELSE vendor END,
                    last_seen = ?
                WHERE mac = ?
                """,
                (ip, hostname, hostname, vendor, vendor, now, mac),
            )
            return False


def get_devices(
    search: Optional[str] = None,
    quarantined: Optional[bool] = None,
    db_path: str = DB_PATH,
) -> List[Dict[str, Any]]:
    """Return a list of device dicts, optionally filtered.

    Args:
        search: Free-text filter applied to mac, ip, hostname, and vendor.
        quarantined: If True, return only quarantined devices; if False, only
                     non-quarantined; if None, return all.
    """
    query = "SELECT * FROM devices WHERE 1=1"
    params: List[Any] = []

    if quarantined is not None:
        query += " AND is_quarantined = ?"
        params.append(1 if quarantined else 0)

    if search:
        like = f"%{search}%"
        query += " AND (mac LIKE ? OR ip LIKE ? OR hostname LIKE ? OR vendor LIKE ?)"
        params.extend([like, like, like, like])

    query += " ORDER BY last_seen DESC"

    with get_db(db_path) as conn:
        cur = conn.execute(query, params)
        return [_row_to_dict(r) for r in cur.fetchall()]



def get_device_by_mac(mac: str, db_path: str = DB_PATH) -> "Optional[dict]":
    """Return a single device record by MAC address, or None."""
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    row = conn.execute("SELECT * FROM devices WHERE mac = ?", (mac,)).fetchone()
    conn.close()
    return dict(row) if row else None


def quarantine_device(mac: str, db_path: str = DB_PATH) -> bool:
    """Set is_quarantined=1 and write an audit entry.  Returns True on success."""
    with get_db(db_path) as conn:
        cur = conn.execute(
            "UPDATE devices SET is_quarantined = 1 WHERE mac = ?", (mac,)
        )
        if cur.rowcount == 0:
            return False
        conn.execute(
            "INSERT INTO audit_log (timestamp, action, target, detail) VALUES (?, ?, ?, ?)",
            (_now(), "quarantine", mac, "Device quarantined"),
        )
    return True


def unquarantine_device(mac: str, db_path: str = DB_PATH) -> bool:
    """Clear is_quarantined flag and write an audit entry.  Returns True on success."""
    with get_db(db_path) as conn:
        cur = conn.execute(
            "UPDATE devices SET is_quarantined = 0 WHERE mac = ?", (mac,)
        )
        if cur.rowcount == 0:
            return False
        conn.execute(
            "INSERT INTO audit_log (timestamp, action, target, detail) VALUES (?, ?, ?, ?)",
            (_now(), "unquarantine", mac, "Device released from quarantine"),
        )
    return True


def approve_device(mac: str, db_path: str = DB_PATH) -> bool:
    """Set is_approved=1 and write an audit entry.  Returns True on success."""
    with get_db(db_path) as conn:
        cur = conn.execute(
            "UPDATE devices SET is_approved = 1 WHERE mac = ?", (mac,)
        )
        if cur.rowcount == 0:
            return False
        conn.execute(
            "INSERT INTO audit_log (timestamp, action, target, detail) VALUES (?, ?, ?, ?)",
            (_now(), "approve", mac, "Device approved"),
        )
    return True


# ---------------------------------------------------------------------------
# Alerts
# ---------------------------------------------------------------------------

def add_alert(
    device_mac: str = "",
    device_ip: str = "",
    device_name: str = "",
    alert_type: str = "",
    severity: str = "medium",
    detail: str = "",
    db_path: str = DB_PATH,
) -> int:
    """Insert a new alert row and return its row id."""
    now = _now()
    with get_db(db_path) as conn:
        cur = conn.execute(
            """
            INSERT INTO alerts
                (device_mac, device_ip, device_name, alert_type, severity, detail, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (device_mac, device_ip, device_name, alert_type, severity, detail, now),
        )
        return cur.lastrowid


def get_alerts(
    limit: int = 100,
    alert_type: Optional[str] = None,
    db_path: str = DB_PATH,
) -> List[Dict[str, Any]]:
    """Return a list of alert dicts, most-recent first."""
    query = "SELECT * FROM alerts WHERE 1=1"
    params: List[Any] = []

    if alert_type:
        query += " AND alert_type = ?"
        params.append(alert_type)

    query += " ORDER BY timestamp DESC LIMIT ?"
    params.append(limit)

    with get_db(db_path) as conn:
        cur = conn.execute(query, params)
        return [_row_to_dict(r) for r in cur.fetchall()]


def get_alert_by_id(alert_id: int, db_path: str = DB_PATH) -> Optional[Dict[str, Any]]:
    """Return a single alert by ID, or None if not found."""
    with get_db(db_path) as conn:
        cur = conn.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,))
        row = cur.fetchone()
        return _row_to_dict(row) if row else None


def ack_alert(alert_id: int, db_path: str = DB_PATH) -> bool:
    """Set acknowledged=1 for *alert_id*.  Returns True on success."""
    with get_db(db_path) as conn:
        cur = conn.execute(
            "UPDATE alerts SET acknowledged = 1 WHERE id = ?", (alert_id,)
        )
        return cur.rowcount > 0


# Alias for backwards compatibility
def acknowledge_alert(alert_id: int, db_path: str = DB_PATH) -> bool:
    """Alias for ack_alert.  Set acknowledged=1 for *alert_id*."""
    return ack_alert(alert_id, db_path)


def flush_old_alerts(days: int = 30, db_path: str = DB_PATH) -> Dict[str, int]:
    """Delete alerts older than *days* days.  Returns dict with 'deleted' count."""
    cutoff = (datetime.utcnow() - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")
    with get_db(db_path) as conn:
        cur = conn.execute("DELETE FROM alerts WHERE timestamp < ?", (cutoff,))
        deleted = cur.rowcount
    return {"deleted": deleted}


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------

def get_stats(db_path: str = DB_PATH) -> Dict[str, Any]:
    """Return an aggregated statistics dict suitable for JSON output."""
    today = datetime.utcnow().strftime("%Y-%m-%d")
    with get_db(db_path) as conn:
        # Device totals
        total_devices = conn.execute("SELECT COUNT(*) FROM devices").fetchone()[0]
        approved_devices = conn.execute(
            "SELECT COUNT(*) FROM devices WHERE is_approved = 1"
        ).fetchone()[0]
        quarantined_devices = conn.execute(
            "SELECT COUNT(*) FROM devices WHERE is_quarantined = 1"
        ).fetchone()[0]
        new_today = conn.execute(
            "SELECT COUNT(*) FROM devices WHERE first_seen LIKE ?", (f"{today}%",)
        ).fetchone()[0]

        # Alert totals
        total_alerts = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
        unacked_alerts = conn.execute(
            "SELECT COUNT(*) FROM alerts WHERE acknowledged = 0"
        ).fetchone()[0]
        alerts_today = conn.execute(
            "SELECT COUNT(*) FROM alerts WHERE timestamp LIKE ?", (f"{today}%",)
        ).fetchone()[0]

        # Top devices by alert count
        top_rows = conn.execute(
            """
            SELECT device_mac, device_name, COUNT(*) AS cnt
            FROM alerts
            WHERE device_mac != ''
            GROUP BY device_mac
            ORDER BY cnt DESC
            LIMIT 5
            """
        ).fetchall()
        top_devices = [_row_to_dict(r) for r in top_rows]

        # Recent unacknowledged alerts
        recent_rows = conn.execute(
            """
            SELECT id, device_mac, device_name, alert_type, severity, timestamp
            FROM alerts
            WHERE acknowledged = 0
            ORDER BY timestamp DESC
            LIMIT 10
            """
        ).fetchall()
        recent_alerts = [_row_to_dict(r) for r in recent_rows]

        # Alert breakdown by type (today)
        type_rows = conn.execute(
            """
            SELECT alert_type, COUNT(*) AS cnt
            FROM alerts
            WHERE timestamp LIKE ?
            GROUP BY alert_type
            ORDER BY cnt DESC
            """,
            (f"{today}%",),
        ).fetchall()
        alerts_by_type = {r["alert_type"]: r["cnt"] for r in type_rows}

        # Severity breakdown (all time)
        sev_rows = conn.execute(
            """
            SELECT severity, COUNT(*) AS cnt
            FROM alerts
            GROUP BY severity
            ORDER BY cnt DESC
            """
        ).fetchall()
        alerts_by_severity = {r["severity"]: r["cnt"] for r in sev_rows}

    return {
        "devices": {
            "total": total_devices,
            "approved": approved_devices,
            "quarantined": quarantined_devices,
            "new_today": new_today,
        },
        "alerts": {
            "total": total_alerts,
            "unacknowledged": unacked_alerts,
            "today": alerts_today,
            "by_type": alerts_by_type,
            "by_severity": alerts_by_severity,
        },
        "top_devices": top_devices,
        "recent_alerts": recent_alerts,
    }


# ---------------------------------------------------------------------------
# Audit log
# ---------------------------------------------------------------------------

class Database:
    """Wrapper around SQLite providing query/execute/commit for scripts."""

    def __init__(self, db_path: str = DB_PATH):
        init_db(db_path)
        self._conn = get_db(db_path)

    def query(self, sql: str, params: tuple = ()) -> List[Dict[str, Any]]:
        cur = self._conn.execute(sql, params)
        return [_row_to_dict(r) for r in cur.fetchall()]

    def execute(self, sql: str, params: tuple = ()) -> None:
        self._conn.execute(sql, params)

    def executemany(self, sql: str, params_list) -> None:
        self._conn.executemany(sql, params_list)

    def commit(self) -> None:
        self._conn.commit()

    def close(self) -> None:
        self._conn.close()


def audit(
    action: str,
    target: str = "",
    detail: str = "",
    actor: str = "system",
    db_path: str = DB_PATH,
) -> None:
    """Append an entry to the audit_log table."""
    with get_db(db_path) as conn:
        conn.execute(
            "INSERT INTO audit_log (timestamp, actor, action, target, detail) VALUES (?, ?, ?, ?, ?)",
            (_now(), actor, action, target, detail),
        )
