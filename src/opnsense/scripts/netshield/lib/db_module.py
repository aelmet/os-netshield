#!/usr/local/bin/python3
"""Compatibility wrapper for threat_intel database access."""
import sqlite3
import os

class DBWrapper:
    """Wrapper to provide fetchone/fetchall/execute/commit interface."""
    def __init__(self, conn):
        self._conn = conn
        self._conn.row_factory = sqlite3.Row

    def execute(self, sql, params=()):
        return self._conn.execute(sql, params)

    def fetchone(self, sql, params=()):
        return self._conn.execute(sql, params).fetchone()

    def fetchall(self, sql, params=()):
        return list(self._conn.execute(sql, params).fetchall())

    def commit(self):
        self._conn.commit()

_db_instance = None

def get_db():
    """Return singleton DBWrapper instance for threat_intel.db."""
    global _db_instance
    if _db_instance is None:
        os.makedirs("/var/netshield", exist_ok=True)
        conn = sqlite3.connect("/var/netshield/threat_intel.db")
        _db_instance = DBWrapper(conn)
    return _db_instance
