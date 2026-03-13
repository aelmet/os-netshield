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

NetShield db.py — SQLite abstraction layer with WAL mode and thread safety.
"""

import logging
import os
import sqlite3
import threading
from typing import Any, Dict, List, Optional, Tuple

log = logging.getLogger(__name__)

DB_PATH = "/var/db/netshield/netshield.db"

# Thread-local storage for per-thread connections
_local = threading.local()
_init_lock = threading.Lock()
_initialized = False


# ------------------------------------------------------------------
# Schema DDL
# ------------------------------------------------------------------

_CREATE_ALERTS = """
CREATE TABLE IF NOT EXISTS alerts (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    device           TEXT NOT NULL DEFAULT '',
    device_name      TEXT NOT NULL DEFAULT '',
    alert_type       TEXT NOT NULL DEFAULT '',
    detail           TEXT NOT NULL DEFAULT '',
    timestamp        TEXT NOT NULL DEFAULT (datetime('now','utc')),
    acknowledged     INTEGER NOT NULL DEFAULT 0
);
"""

_CREATE_DEVICES = """
CREATE TABLE IF NOT EXISTS devices (
    mac          TEXT PRIMARY KEY,
    ip           TEXT NOT NULL DEFAULT '',
    hostname     TEXT NOT NULL DEFAULT '',
    vendor       TEXT NOT NULL DEFAULT '',
    category     TEXT NOT NULL DEFAULT '',
    first_seen   TEXT NOT NULL DEFAULT (datetime('now','utc')),
    last_seen    TEXT NOT NULL DEFAULT (datetime('now','utc')),
    approved     INTEGER NOT NULL DEFAULT 0
);
"""

_CREATE_ENFORCEMENT_LOG = """
CREATE TABLE IF NOT EXISTS enforcement_log (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp   TEXT NOT NULL DEFAULT (datetime('now','utc')),
    rule_type   TEXT NOT NULL DEFAULT '',
    target      TEXT NOT NULL DEFAULT '',
    action      TEXT NOT NULL DEFAULT '',
    detail      TEXT NOT NULL DEFAULT ''
);
"""

_CREATE_QUARANTINE = """
CREATE TABLE IF NOT EXISTS quarantine (
    mac        TEXT PRIMARY KEY,
    reason     TEXT NOT NULL DEFAULT '',
    timestamp  TEXT NOT NULL DEFAULT (datetime('now','utc'))
);
"""

_INDICES = [
    "CREATE INDEX IF NOT EXISTS idx_alerts_type      ON alerts(alert_type);",
    "CREATE INDEX IF NOT EXISTS idx_alerts_ts        ON alerts(timestamp);",
    "CREATE INDEX IF NOT EXISTS idx_alerts_ack       ON alerts(acknowledged);",
    "CREATE INDEX IF NOT EXISTS idx_devices_ip       ON devices(ip);",
    "CREATE INDEX IF NOT EXISTS idx_devices_hostname ON devices(hostname);",
    "CREATE INDEX IF NOT EXISTS idx_enf_ts           ON enforcement_log(timestamp);",
    "CREATE INDEX IF NOT EXISTS idx_enf_target       ON enforcement_log(target);",
]


# ------------------------------------------------------------------
# Connection management
# ------------------------------------------------------------------

def _get_connection() -> sqlite3.Connection:
    """
    Return a thread-local SQLite connection, creating it if necessary.
    WAL mode is enabled once per connection for concurrent read access.
    """
    conn = getattr(_local, "conn", None)
    if conn is None:
        conn = sqlite3.connect(DB_PATH, timeout=30, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA busy_timeout=10000")
        _local.conn = conn
        log.debug("Opened SQLite connection on thread %s", threading.current_thread().name)
    return conn


def _ensure_dir() -> None:
    """Create the DB directory if it does not exist."""
    db_dir = os.path.dirname(DB_PATH)
    if db_dir and not os.path.isdir(db_dir):
        os.makedirs(db_dir, mode=0o750, exist_ok=True)
        log.info("Created DB directory: %s", db_dir)


# ------------------------------------------------------------------
# Public API
# ------------------------------------------------------------------

def init_db(path: str = DB_PATH) -> None:
    """
    Create all tables and indices if they do not exist.
    Safe to call multiple times; subsequent calls are no-ops if already done.
    """
    global _initialized, DB_PATH
    with _init_lock:
        if _initialized and path == DB_PATH:
            return
        DB_PATH = path
        _ensure_dir()
        conn = _get_connection()
        try:
            with conn:
                conn.execute(_CREATE_ALERTS)
                conn.execute(_CREATE_DEVICES)
                conn.execute(_CREATE_ENFORCEMENT_LOG)
                conn.execute(_CREATE_QUARANTINE)
                for idx_sql in _INDICES:
                    conn.execute(idx_sql)
            _initialized = True
            log.info("NetShield DB initialised at %s", DB_PATH)
        except sqlite3.Error as exc:
            log.error("init_db failed: %s", exc)
            raise


def execute(sql: str, params: Tuple = ()) -> Optional[sqlite3.Cursor]:
    """
    Execute a write statement (INSERT/UPDATE/DELETE/CREATE) thread-safely.
    Returns the cursor, or None on error.
    """
    conn = _get_connection()
    try:
        with conn:
            cur = conn.execute(sql, params)
            return cur
    except sqlite3.Error as exc:
        log.error("DB execute error: %s | SQL: %.200s | params: %s", exc, sql, params)
        return None


def fetchall(sql: str, params: Tuple = ()) -> List[Dict[str, Any]]:
    """
    Execute a SELECT and return all rows as a list of dicts.
    Returns an empty list on error.
    """
    conn = _get_connection()
    try:
        cur = conn.execute(sql, params)
        rows = cur.fetchall()
        return [dict(row) for row in rows]
    except sqlite3.Error as exc:
        log.error("DB fetchall error: %s | SQL: %.200s", exc, sql)
        return []


def fetchone(sql: str, params: Tuple = ()) -> Optional[Dict[str, Any]]:
    """
    Execute a SELECT and return the first row as a dict, or None.
    """
    conn = _get_connection()
    try:
        cur = conn.execute(sql, params)
        row = cur.fetchone()
        return dict(row) if row is not None else None
    except sqlite3.Error as exc:
        log.error("DB fetchone error: %s | SQL: %.200s", exc, sql)
        return None


def close() -> None:
    """Close the thread-local connection if open."""
    conn = getattr(_local, "conn", None)
    if conn is not None:
        try:
            conn.close()
        except sqlite3.Error as exc:
            log.debug("Error closing DB connection: %s", exc)
        _local.conn = None


def vacuum() -> None:
    """Run VACUUM to reclaim unused space. Should be called infrequently."""
    conn = _get_connection()
    try:
        conn.execute("VACUUM")
        log.info("DB VACUUM completed")
    except sqlite3.Error as exc:
        log.warning("DB VACUUM failed: %s", exc)
