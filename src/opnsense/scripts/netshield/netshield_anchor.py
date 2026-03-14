#!/usr/local/bin/python3
"""
OPNsense filter plugin for NetShield.
Creates an anchor with blocking rules based on device profiles.
"""
import os
import sys
import json
sys.path.insert(0, "/usr/local/opnsense/scripts/netshield/lib")

ANCHOR_FILE = "/tmp/netshield_anchor.conf"
PF_TABLES_DIR = "/var/db/netshield/pf_tables"

def get_device_profiles():
    """Get device to profile mappings."""
    db_file = "/var/db/netshield/netshield.db"
    profiles = {"parental": [], "high": [], "moderate": [], "permissive": []}
    
    if os.path.exists(db_file):
        try:
            import sqlite3
            conn = sqlite3.connect(db_file)
            cur = conn.cursor()
            cur.execute("SELECT ip, device_group FROM devices WHERE device_group IS NOT NULL AND device_group != ''")
            for row in cur.fetchall():
                ip, group = row
                if group in profiles:
                    profiles[group].append(ip)
            conn.close()
        except Exception as e:
            print(f"# DB error: {e}", file=sys.stderr)
    
    return profiles

def get_blocked_services():
    """Get services that should be blocked per profile."""
    return {
        "parental": ["instagram", "tiktok", "twitter", "snapchat", "discord"],
        "high": ["tiktok", "discord"],
        "moderate": ["tiktok"],
        "permissive": []
    }

def generate_anchor_rules():
    """Generate pf anchor rules."""
    rules = []
    rules.append("# NetShield Anchor Rules")
    rules.append("# Generated automatically - do not edit")
    rules.append("")
    
    profiles = get_device_profiles()
    blocked_services = get_blocked_services()
    
    # For each profile with devices, create block rules
    for profile, devices in profiles.items():
        if not devices:
            continue
        
        services = blocked_services.get(profile, [])
        if not services:
            continue
        
        rules.append(f"# Profile: {profile}")
        for device_ip in devices:
            for service in services:
                table_name = f"ns_block_{service}"
                # Block outgoing to blocked service IPs
                rules.append(f"block drop quick from {device_ip} to <{table_name}>")
                rules.append(f"block drop quick from <{table_name}> to {device_ip}")
        rules.append("")
    
    return "\n".join(rules)

def main():
    # Ensure tables directory exists
    os.makedirs(PF_TABLES_DIR, exist_ok=True)
    
    # Generate rules
    anchor_rules = generate_anchor_rules()
    
    # Write to anchor file
    with open(ANCHOR_FILE, "w") as f:
        f.write(anchor_rules)
    
    # Output the rules (OPNsense filter plugins output to stdout)
    print(anchor_rules)
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
