#!/usr/local/bin/python3
"""
OPNsense configd filter script for NetShield.
This is called by configd to generate filter rules.
"""
import os
import sys
import json
import subprocess
import sqlite3

PF_TABLES_DIR = "/var/db/netshield/pf_tables"
DB_PATH = "/var/db/netshield/netshield.db"
TOR_BLOCKLIST_PATH = os.path.join(PF_TABLES_DIR, "block_tor.txt")
TOR_PORTS = [9001, 9030, 9040, 9050, 9051, 9150, 9151]

# Service IP mappings
SERVICE_IPS = {
    "facebook": [
        "157.240.0.0/16", "31.13.0.0/16", "66.220.0.0/16", "69.63.0.0/16",
        "69.171.0.0/16", "74.119.76.0/22", "102.132.96.0/20", "103.4.96.0/22",
        "129.134.0.0/16", "173.252.64.0/18", "179.60.192.0/22", "185.60.216.0/22"
    ],
    "instagram": ["157.240.0.0/16", "31.13.0.0/16", "185.60.216.0/22"],
    "tiktok": ["142.250.0.0/16", "152.199.0.0/16", "161.117.0.0/16", "170.114.0.0/16"],
    "youtube": [
        "142.250.0.0/16", "172.217.0.0/16", "173.194.0.0/16", "208.65.152.0/22",
        "209.85.128.0/17", "216.58.192.0/19", "216.239.32.0/19"
    ],
    "twitter": ["104.244.40.0/21", "192.133.76.0/22", "199.16.156.0/22", "199.59.148.0/22"],
    "discord": ["162.159.128.0/17", "104.16.0.0/12"],
    "snapchat": ["34.96.0.0/12", "35.186.0.0/16"],
    "netflix": [
        "23.246.0.0/16", "37.77.184.0/21", "45.57.0.0/16", "64.120.128.0/17",
        "66.197.128.0/17", "108.175.32.0/20", "185.2.220.0/22", "185.9.188.0/22"
    ],
    "steam": [
        "103.10.124.0/23", "146.66.152.0/21", "155.133.224.0/19",
        "162.254.192.0/21", "185.25.180.0/22"
    ],
    "twitch": ["52.223.192.0/18", "99.181.64.0/18", "151.101.0.0/16", "185.42.204.0/22"]
}

PROFILE_BLOCKS = {
    "parental": ["instagram", "tiktok", "twitter", "snapchat", "discord"],
    "high": ["tiktok", "discord"],
    "moderate": ["tiktok"],
    "permissive": []
}

def ensure_tables():
    """Create pf tables for each service."""
    os.makedirs(PF_TABLES_DIR, exist_ok=True)
    for service, ips in SERVICE_IPS.items():
        table_file = os.path.join(PF_TABLES_DIR, f"block_{service}.txt")
        with open(table_file, "w") as f:
            for ip in ips:
                f.write(f"{ip}\n")
    return True

def get_device_profiles():
    """Get device to profile mappings from database."""
    profiles = {"parental": [], "high": [], "moderate": [], "permissive": []}
    
    if not os.path.exists(DB_PATH):
        return profiles
    
    try:
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        cur.execute("SELECT ip, profile_id FROM devices WHERE profile_id IS NOT NULL AND profile_id != ''")
        for row in cur.fetchall():
            ip, profile = row
            if profile in profiles and ip:
                profiles[profile].append(ip)
        conn.close()
    except Exception as e:
        print(f"# Error reading profiles: {e}", file=sys.stderr)
    
    return profiles

def load_pf_tables():
    """Load IP tables into pf."""
    results = []
    for service in SERVICE_IPS.keys():
        table_name = f"ns_block_{service}"
        table_file = os.path.join(PF_TABLES_DIR, f"block_{service}.txt")
        if os.path.exists(table_file):
            try:
                subprocess.run(
                    ["pfctl", "-t", table_name, "-T", "replace", "-f", table_file],
                    capture_output=True, timeout=10
                )
                results.append(table_name)
            except Exception:
                pass
    return results

def generate_anchor_rules():
    """Generate pf anchor rules."""
    lines = []
    lines.append("# NetShield IP Blocking Rules")
    lines.append("# Auto-generated - do not edit manually")
    lines.append("")
    
    profiles = get_device_profiles()
    
    # Create device tables
    for profile_name, device_ips in profiles.items():
        if device_ips:
            lines.append(f"table <ns_devices_{profile_name}> {{ {', '.join(device_ips)} }}")
    
    lines.append("")
    
    # Create service block tables
    for service in SERVICE_IPS.keys():
        table_file = os.path.join(PF_TABLES_DIR, f"block_{service}.txt")
        lines.append(f"table <ns_block_{service}> persist file \"{table_file}\"")
    
    lines.append("")
    lines.append("# Blocking rules by profile")
    
    # Generate block rules
    for profile_name, blocked_services in PROFILE_BLOCKS.items():
        if not blocked_services or not profiles.get(profile_name):
            continue
        
        lines.append(f"# {profile_name.upper()} profile blocks")
        for service in blocked_services:
            lines.append(f"block drop quick from <ns_devices_{profile_name}> to <ns_block_{service}>")
            lines.append(f"block drop quick from <ns_block_{service}> to <ns_devices_{profile_name}>")
        lines.append("")
    
    return "\n".join(lines)


def is_tor_blocking_enabled():
    """Check if Tor blocking is enabled in the database."""
    if not os.path.exists(DB_PATH):
        return False
    try:
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        cur.execute("SELECT value FROM tor_config WHERE key = 'enabled'")
        row = cur.fetchone()
        conn.close()
        return row and row[0] == "1"
    except Exception:
        return False


def generate_tor_rules():
    """Generate pf rules for Tor IP and port blocking."""
    lines = []

    if not is_tor_blocking_enabled():
        return ""

    lines.append("# ========================================")
    lines.append("# NetShield Tor/Anonymizer Blocking Rules")
    lines.append("# ========================================")
    lines.append("")

    # Tor IP table (loaded from file by TorBlocker)
    if os.path.exists(TOR_BLOCKLIST_PATH):
        lines.append(f'table <ns_block_tor> persist file "{TOR_BLOCKLIST_PATH}"')
        lines.append("block drop quick from any to <ns_block_tor>")
        lines.append("block drop quick from <ns_block_tor> to any")
        lines.append("")

    # Tor port blocking
    try:
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        cur.execute("SELECT value FROM tor_config WHERE key = 'block_ports'")
        row = cur.fetchone()
        conn.close()
        block_ports = row and row[0] == "1"
    except Exception:
        block_ports = True  # Default to blocking

    if block_ports:
        ports = ", ".join(str(p) for p in TOR_PORTS)
        lines.append("# Block common Tor ports")
        lines.append(f"block drop quick proto tcp from any to any port {{ {ports} }}")
        lines.append(f"block drop quick proto tcp from any port {{ {ports} }} to any")
        lines.append("")

    return "\n".join(lines)


def main():
    ensure_tables()
    load_pf_tables()
    rules = generate_anchor_rules()

    # Append Tor blocking rules
    tor_rules = generate_tor_rules()
    if tor_rules:
        rules += "\n\n" + tor_rules

    print(rules)
    return 0

if __name__ == "__main__":
    sys.exit(main())
