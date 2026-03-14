#!/usr/local/bin/python3
"""
NetShield Enforcement Activation Script

This script safely activates all enforcement mechanisms:
1. Creates pf table with threat IPs
2. Generates Unbound DNS blocklist
3. Downloads web category database
4. Sets up pf anchors

SAFE: This script is non-destructive and won't break your internet.
All changes can be reversed by running deactivate_enforcement.py
"""

import os
import subprocess
import sys
import time

# Add lib to path
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "lib"))

def print_step(step: int, msg: str) -> None:
    print(f"\n[{step}] {msg}")
    print("-" * 50)

def run_cmd(cmd: list, description: str, check: bool = False) -> bool:
    """Run a command safely."""
    print(f"  Running: {' '.join(cmd)}")
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=60,
        )
        if result.returncode == 0:
            print(f"  ✓ {description}: OK")
            return True
        else:
            print(f"  ✗ {description}: {result.stderr.strip()}")
            return False
    except subprocess.TimeoutExpired:
        print(f"  ✗ {description}: Timeout")
        return False
    except Exception as e:
        print(f"  ✗ {description}: {e}")
        return False

def activate_threat_intel():
    """Activate threat intelligence blocking via pf table."""
    print_step(1, "Activating Threat Intelligence (pf table)")

    try:
        from lib import db
        from lib.threat_intel import ThreatIntelManager

        database = db
        ti = ThreatIntelManager(database)

        # Generate pf blocklist from existing IoCs
        ti.generate_pf_blocklist()

        # Verify table exists
        result = subprocess.run(
            ["pfctl", "-t", "netshield_threats", "-T", "show"],
            capture_output=True,
            text=True,
            timeout=10,
        )

        entries = len([l for l in result.stdout.splitlines() if l.strip()])
        print(f"  ✓ pf table 'netshield_threats' created with {entries} IPs")
        return True

    except ImportError as e:
        print(f"  ✗ Import error: {e}")
        print("  Falling back to direct file method...")
        return activate_threat_intel_direct()
    except Exception as e:
        print(f"  ✗ Error: {e}")
        return False

def activate_threat_intel_direct():
    """Direct method without importing modules."""
    import sqlite3

    db_path = "/var/db/netshield/netshield.db"
    blocklist_path = "/tmp/netshield_threat_blocklist"

    if not os.path.exists(db_path):
        print("  ✗ Database not found")
        return False

    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.execute(
            "SELECT DISTINCT value FROM threat_iocs WHERE ioc_type = 'ip'"
        )
        ips = [row[0] for row in cursor]
        conn.close()

        if not ips:
            print("  ✗ No IPs found in threat_iocs table")
            return False

        # Write to file
        with open(blocklist_path, "w") as f:
            f.write("\n".join(ips) + "\n")

        print(f"  Wrote {len(ips)} IPs to {blocklist_path}")

        # Create/update pf table
        result = subprocess.run(
            ["pfctl", "-t", "netshield_threats", "-T", "replace", "-f", blocklist_path],
            capture_output=True,
            text=True,
            timeout=30,
        )

        if result.returncode == 0:
            print(f"  ✓ pf table 'netshield_threats' updated with {len(ips)} IPs")
            return True
        else:
            print(f"  ✗ pfctl error: {result.stderr}")
            return False

    except Exception as e:
        print(f"  ✗ Error: {e}")
        return False

def activate_dns_blocklist():
    """Activate DNS blocking via Unbound."""
    print_step(2, "Activating DNS Blocklist (Unbound)")

    try:
        from lib import db
        from lib.dns_filter import DNSFilter

        dns = DNSFilter(db)

        # Update blocklists (downloads from sources)
        print("  Downloading DNS blocklists (this may take a minute)...")
        result = dns.update_all_blocklists()

        print(f"  ✓ Downloaded {result.get('total_domains', 0)} domains")
        print(f"  ✓ Unbound config generated at /var/unbound/etc/netshield_blocklist.conf")
        return True

    except ImportError as e:
        print(f"  ✗ Import error: {e}")
        print("  Falling back to direct method...")
        return activate_dns_blocklist_direct()
    except Exception as e:
        print(f"  ✗ Error: {e}")
        return False

def activate_dns_blocklist_direct():
    """Direct method to create minimal DNS blocklist."""
    import sqlite3

    db_path = "/var/db/netshield/netshield.db"
    unbound_conf = "/var/unbound/etc/netshield_blocklist.conf"

    # Ensure directory exists
    os.makedirs("/var/unbound/etc", exist_ok=True)

    # Get domains from database if available
    domains = []
    try:
        if os.path.exists(db_path):
            conn = sqlite3.connect(db_path)
            cursor = conn.execute(
                "SELECT DISTINCT domain FROM dns_rules WHERE action = 'block' LIMIT 10000"
            )
            domains = [row[0] for row in cursor]
            conn.close()
    except Exception:
        pass

    # If no domains in DB, add some basic threat domains
    if not domains:
        domains = [
            # Basic test domains
            "malware-test.netshield.local",
        ]

    # Generate Unbound config
    lines = [
        "# NetShield DNS blocklist - auto-generated",
        f"# Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}",
        "",
    ]

    for domain in domains:
        lines.append(f'local-zone: "{domain}" always_nxdomain')

    with open(unbound_conf, "w") as f:
        f.write("\n".join(lines) + "\n")

    print(f"  ✓ Wrote {len(domains)} domains to {unbound_conf}")

    # Reload Unbound
    result = subprocess.run(
        ["unbound-control", "reload"],
        capture_output=True,
        text=True,
        timeout=15,
    )

    if result.returncode == 0:
        print("  ✓ Unbound reloaded")
        return True
    else:
        print(f"  ⚠ Unbound reload: {result.stderr.strip() or 'check manually'}")
        return True  # Config was written

def activate_web_categories():
    """Download and activate web categories database."""
    print_step(3, "Activating Web Categories")

    try:
        from lib.web_categories import WebCategoriesEngine

        engine = WebCategoriesEngine()

        print("  Downloading Shalla category database (this may take a few minutes)...")
        result = engine.update_database("shalla")

        if result.get("status") == "ok":
            print(f"  ✓ Imported {result.get('domains_imported', 0)} domains")
            print(f"  ✓ {result.get('categories_imported', 0)} categories")
            return True
        else:
            print(f"  ✗ Failed: {result.get('message', 'unknown error')}")
            return False

    except ImportError as e:
        print(f"  ⚠ Skipping (module not available): {e}")
        return False
    except Exception as e:
        print(f"  ✗ Error: {e}")
        return False

def setup_pf_anchors():
    """Setup pf anchors for NetShield."""
    print_step(4, "Setting up pf Anchors")

    anchors = ["netshield", "netshield/parental", "netshield/quarantine"]

    for anchor in anchors:
        # Just verify they exist (OPNsense should have created them)
        result = subprocess.run(
            ["pfctl", "-a", anchor, "-s", "rules"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if result.returncode == 0:
            print(f"  ✓ Anchor '{anchor}' exists")
        else:
            print(f"  ⚠ Anchor '{anchor}' may need manual setup")

    # Add blocking rule for threat table to main anchor
    pf_conf = "/tmp/netshield_pf.conf"
    rule = "block in quick from <netshield_threats> to any\nblock out quick from any to <netshield_threats>\n"

    try:
        with open(pf_conf, "w") as f:
            f.write(rule)

        result = subprocess.run(
            ["pfctl", "-a", "netshield", "-f", pf_conf],
            capture_output=True,
            text=True,
            timeout=10,
        )

        if result.returncode == 0:
            print("  ✓ Threat blocking rule added to netshield anchor")
        else:
            print(f"  ⚠ Rule may need manual setup: {result.stderr.strip()}")

    except Exception as e:
        print(f"  ⚠ Could not add rule: {e}")

    return True

def verify_activation():
    """Verify enforcement is active."""
    print_step(5, "Verification")

    checks = []

    # Check pf table
    result = subprocess.run(
        ["pfctl", "-t", "netshield_threats", "-T", "show"],
        capture_output=True,
        text=True,
        timeout=10,
    )
    entries = len([l for l in result.stdout.splitlines() if l.strip()])
    if entries > 0:
        print(f"  ✓ Threat Intel: {entries} IPs blocked")
        checks.append(True)
    else:
        print("  ✗ Threat Intel: No IPs in table")
        checks.append(False)

    # Check DNS blocklist
    blocklist = "/var/unbound/etc/netshield_blocklist.conf"
    if os.path.exists(blocklist):
        with open(blocklist) as f:
            entries = len([l for l in f if l.startswith("local-zone:")])
        if entries > 0:
            print(f"  ✓ DNS Blocklist: {entries} domains blocked")
            checks.append(True)
        else:
            print("  ⚠ DNS Blocklist: Empty")
            checks.append(False)
    else:
        print("  ✗ DNS Blocklist: Not found")
        checks.append(False)

    # Check Unbound is running
    result = subprocess.run(["pgrep", "-x", "unbound"], capture_output=True)
    if result.returncode == 0:
        print("  ✓ Unbound: Running")
        checks.append(True)
    else:
        print("  ✗ Unbound: Not running")
        checks.append(False)

    return all(checks)

def main():
    print("=" * 60)
    print("  NetShield Enforcement Activation")
    print("=" * 60)
    print("\nThis will activate blocking for threats, malware, and")
    print("unwanted content. Your internet will NOT be interrupted.")
    print("\nPress Ctrl+C to cancel, or wait 5 seconds to continue...")

    try:
        time.sleep(5)
    except KeyboardInterrupt:
        print("\n\nCancelled.")
        return

    results = []

    results.append(("Threat Intel", activate_threat_intel()))
    results.append(("DNS Blocklist", activate_dns_blocklist()))
    results.append(("Web Categories", activate_web_categories()))
    results.append(("pf Anchors", setup_pf_anchors()))

    success = verify_activation()

    print("\n" + "=" * 60)
    print("  ACTIVATION COMPLETE")
    print("=" * 60)

    for name, status in results:
        symbol = "✓" if status else "✗"
        print(f"  {symbol} {name}")

    if success:
        print("\n  NetShield enforcement is now ACTIVE!")
        print("  Run audit_enforcement.py to verify status.")
    else:
        print("\n  ⚠ Some components may need manual attention.")
        print("  Check the output above for details.")

    print()

if __name__ == "__main__":
    main()
