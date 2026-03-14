#!/usr/local/bin/python3
"""Sync blocked DNS queries from Unbound duckdb into NetShield connections.db."""
import os, sqlite3, time, json, fcntl
from datetime import datetime

CONN_DB = "/var/db/netshield/connections.db"
UNBOUND_DB = "/var/unbound/data/unbound.duckdb"
STATE_FILE = "/var/db/netshield/.blocked_sync_state"
LOCK_FILE = "/tmp/sync_blocked.lock"

def sync_blocked():
    # Single-instance lock
    lock_fd = open(LOCK_FILE, 'w')
    try:
        fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except (IOError, OSError):
        return {"status": "skipped", "message": "another instance running"}

    try:
        import duckdb
    except ImportError:
        lock_fd.close()
        return {"status": "error", "message": "duckdb not available"}

    last_ts = 0
    if os.path.exists(STATE_FILE):
        try:
            with open(STATE_FILE) as f:
                last_ts = int(f.read().strip())
        except (ValueError, OSError):
            pass

    now_ts = int(time.time())

    try:
        duck = duckdb.connect(UNBOUND_DB, read_only=True)
        rows = duck.execute(
            "SELECT time, client, domain FROM query WHERE action = 1 AND time > ? ORDER BY time",
            [last_ts]
        ).fetchall()
        duck.close()
    except Exception as e:
        lock_fd.close()
        return {"status": "error", "message": str(e)}

    # Save state FIRST so we never reprocess on crash
    with open(STATE_FILE, "w") as f:
        f.write(str(now_ts))

    if not rows:
        lock_fd.close()
        return {"status": "ok", "new_blocked": 0}

    # Prep data in memory
    entries = []
    for ts, client_ip, domain in rows:
        domain = domain.rstrip('.')
        ts_str = datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")
        entries.append((ts_str, client_ip, domain))

    # Simple bulk INSERT OR IGNORE — no UPDATE scan needed
    conn = sqlite3.connect(CONN_DB)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")

    cur = conn.executemany(
        "INSERT OR IGNORE INTO connections (timestamp, device_ip, dst_hostname, blocked, app_category) "
        "VALUES (?, ?, ?, 1, 'Blocked')",
        entries
    )
    inserted = cur.rowcount
    conn.commit()
    conn.close()

    lock_fd.close()
    return {"status": "ok", "inserted": inserted, "total_blocked": len(rows)}


if __name__ == "__main__":
    result = sync_blocked()
    print(json.dumps(result))
