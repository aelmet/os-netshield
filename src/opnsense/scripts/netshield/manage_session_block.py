#!/usr/local/bin/python3
"""NetShield - Session Block/Unblock Manager

Manages per-domain blocking from the sessions page.
Stores blocks in the policy_exclusions table of netshield.db.

Commands:
  block <domain>   - Add domain to blocklist
  unblock <domain> - Remove from blocklist, add to whitelist
"""

import json
import os
import sqlite3
import sys
from urllib.parse import unquote

NETSHIELD_DB = "/var/db/netshield/netshield.db"


def ensure_table(conn):
    """Ensure the policy_exclusions table exists for session-level blocks."""
    conn.execute("""
        CREATE TABLE IF NOT EXISTS policy_exclusions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT NOT NULL,
            list_type TEXT NOT NULL DEFAULT 'blacklist',
            source TEXT DEFAULT 'session',
            created_at TEXT DEFAULT (datetime('now')),
            UNIQUE(domain, list_type)
        )
    """)
    conn.commit()


def cmd_block(domain):
    """Add a domain to the blocklist."""
    domain = domain.lower().strip()
    if not domain:
        return {"status": "error", "message": "empty domain"}

    conn = sqlite3.connect(NETSHIELD_DB)
    ensure_table(conn)

    # Remove any whitelist entry for this domain
    conn.execute("DELETE FROM policy_exclusions WHERE domain = ? AND list_type = 'whitelist'", (domain,))

    # Add to blacklist (ignore if already exists)
    conn.execute(
        "INSERT OR IGNORE INTO policy_exclusions (domain, list_type, source) VALUES (?, 'blacklist', 'session')",
        (domain,)
    )
    conn.commit()
    conn.close()

    return {"status": "ok", "action": "blocked", "domain": domain}


def cmd_unblock(domain):
    """Remove domain from blocklist and add to whitelist."""
    domain = domain.lower().strip()
    if not domain:
        return {"status": "error", "message": "empty domain"}

    conn = sqlite3.connect(NETSHIELD_DB)
    ensure_table(conn)

    # Remove from blacklist
    conn.execute("DELETE FROM policy_exclusions WHERE domain = ? AND list_type = 'blacklist'", (domain,))

    # Add to whitelist (ignore if already exists)
    conn.execute(
        "INSERT OR IGNORE INTO policy_exclusions (domain, list_type, source) VALUES (?, 'whitelist', 'session')",
        (domain,)
    )
    conn.commit()
    conn.close()

    return {"status": "ok", "action": "unblocked", "domain": domain}


def main():
    try:
        if len(sys.argv) < 2:
            print(json.dumps({"status": "error", "message": "usage: manage_session_block.py <block|unblock>,<domain>"}))
            sys.exit(0)

        raw = sys.argv[1]
        parts = raw.split(',')
        parts = [unquote(p.strip("'\"")) for p in parts]

        command = parts[0] if parts else ''
        domain = parts[1] if len(parts) > 1 else ''

        if command == 'block':
            result = cmd_block(domain)
        elif command == 'unblock':
            result = cmd_unblock(domain)
        else:
            result = {"status": "error", "message": f"unknown command: {command}"}

        print(json.dumps(result))
    except Exception as e:
        print(json.dumps({"status": "error", "message": str(e)}))
        sys.exit(0)


if __name__ == "__main__":
    main()
