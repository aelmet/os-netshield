#!/usr/local/bin/python3
"""Output IP addresses of quarantined devices, one per line.
Used by netshield.inc firewall plugin to generate pf block rules.
"""
import sqlite3
import subprocess
import os

DB_PATH = "/var/db/netshield/netshield.db"

def get_quarantined_ips():
    if not os.path.exists(DB_PATH):
        return []

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        "SELECT mac, ip FROM devices WHERE is_quarantined = 1"
    ).fetchall()
    conn.close()

    if not rows:
        return []

    # Build MAC -> IP mapping from ARP table for fresh IPs
    arp_map = {}
    try:
        r = subprocess.run(["arp", "-an"], capture_output=True, text=True, timeout=5)
        for line in r.stdout.splitlines():
            if " at " in line and "(" in line:
                parts = line.split()
                ip = parts[1].strip("()")
                mac = parts[3].lower()
                if mac != "(incomplete)":
                    arp_map[mac] = ip
    except Exception:
        pass

    ips = set()
    for row in rows:
        mac = (row["mac"] or "").lower()
        db_ip = row["ip"] or ""
        ip = arp_map.get(mac, db_ip)
        if ip:
            ips.add(ip)

    return sorted(ips)

if __name__ == "__main__":
    for ip in get_quarantined_ips():
        print(ip)
