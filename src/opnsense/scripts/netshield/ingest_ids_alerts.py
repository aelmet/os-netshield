#!/usr/local/bin/python3
"""Ingest Suricata eve.json alerts into NetShield ids_alerts table."""
import json
import os
import sqlite3
import sys

EVE_LOG = "/var/log/suricata/eve.json"
DB_PATH = "/var/db/netshield/netshield.db"
STATE_FILE = "/var/db/netshield/ids_ingest_state.json"

_SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))
if _SCRIPT_DIR not in sys.path:
    sys.path.insert(0, _SCRIPT_DIR)


def ensure_ids_table(conn):
    conn.execute("""
        CREATE TABLE IF NOT EXISTS ids_alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            src_ip TEXT,
            src_port INTEGER,
            dest_ip TEXT,
            dest_port INTEGER,
            protocol TEXT,
            signature TEXT,
            signature_id INTEGER,
            severity INTEGER DEFAULT 3,
            category TEXT,
            action TEXT DEFAULT 'allowed',
            acknowledged INTEGER DEFAULT 0,
            raw_event TEXT
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_ids_ts ON ids_alerts(timestamp)")
    conn.commit()


def load_state():
    if os.path.exists(STATE_FILE):
        try:
            with open(STATE_FILE) as f:
                return json.load(f)
        except Exception:
            pass
    return {"offset": 0, "inode": 0}


def save_state(state):
    os.makedirs(os.path.dirname(STATE_FILE), exist_ok=True)
    with open(STATE_FILE, "w") as f:
        json.dump(state, f)


def main():
    if not os.path.exists(EVE_LOG):
        print(json.dumps({"status": "ok", "ingested": 0, "message": "eve.json not found"}))
        return

    state = load_state()
    stat = os.stat(EVE_LOG)

    # File rotated or truncated
    if stat.st_ino != state.get("inode", 0) or stat.st_size < state.get("offset", 0):
        state = {"offset": 0, "inode": stat.st_ino}

    conn = sqlite3.connect(DB_PATH)
    ensure_ids_table(conn)

    ingested = 0

    try:
        with open(EVE_LOG, "rb") as f:
            f.seek(state["offset"])
            data = f.read()
            new_offset = f.tell()

        for line in data.decode("utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue

            if event.get("event_type") != "alert":
                continue

            alert = event.get("alert", {})
            ts = event.get("timestamp", "")
            src_ip = event.get("src_ip", "")
            src_port = event.get("src_port", 0)
            dest_ip = event.get("dest_ip", "")
            dest_port = event.get("dest_port", 0)
            proto = event.get("proto", "")
            sig = alert.get("signature", "")
            sig_id = alert.get("signature_id", 0)
            sev = alert.get("severity", 3)
            cat = alert.get("category", "")
            action = alert.get("action", "allowed")

            conn.execute(
                "INSERT INTO ids_alerts (timestamp, src_ip, src_port, dest_ip, dest_port, "
                "protocol, signature, signature_id, severity, category, action, raw_event) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (ts, src_ip, src_port, dest_ip, dest_port, proto,
                 sig, sig_id, sev, cat, action, line)
            )

            # Also add to main alerts table
            from lib import db as _db
            sev_name = "high" if sev == 1 else ("medium" if sev == 2 else "low")
            _db.add_alert(
                device_ip=src_ip,
                alert_type="IDS Alert",
                severity=sev_name,
                detail="{} (SID:{}) - {} -> {}:{}".format(sig, sig_id, src_ip, dest_ip, dest_port),
            )
            ingested += 1

        conn.commit()
    except Exception as e:
        print(json.dumps({"status": "error", "message": str(e), "ingested": ingested}))
        conn.close()
        return

    conn.close()

    state["offset"] = new_offset
    state["inode"] = stat.st_ino
    save_state(state)

    print(json.dumps({"status": "ok", "ingested": ingested}))


if __name__ == "__main__":
    main()
