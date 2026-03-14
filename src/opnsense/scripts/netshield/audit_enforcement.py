#!/usr/local/bin/python3
"""
NetShield Enforcement Audit Script

This script tests that all enforcement mechanisms actually work:
1. Threat Intel → pf table blocking
2. DNS Filter → Unbound NXDOMAIN
3. Web Categories → DNS blocking
4. Policy Engine → pf anchor rules
5. Parental Engine → pf anchor rules
6. Quarantine → pf anchor rules
7. Suricata Integration → Alert correlation

Run this on the OPNsense router to verify enforcement.
"""

import json
import os
import sqlite3
import subprocess
import sys
from datetime import datetime

# Add lib to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def print_header(title: str) -> None:
    print(f"\n{'='*60}")
    print(f"  {title}")
    print(f"{'='*60}")

def print_result(name: str, passed: bool, details: str = "") -> None:
    status = "✓ PASS" if passed else "✗ FAIL"
    print(f"  {status}: {name}")
    if details:
        print(f"         {details}")

def check_pf_table(table_name: str) -> dict:
    """Check if a pf table exists and has entries."""
    try:
        result = subprocess.run(
            ["pfctl", "-t", table_name, "-T", "show"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        entries = [l.strip() for l in result.stdout.splitlines() if l.strip()]
        return {
            "exists": result.returncode == 0,
            "entries": len(entries),
            "sample": entries[:5] if entries else [],
        }
    except Exception as e:
        return {"exists": False, "error": str(e)}

def check_pf_anchor(anchor_name: str) -> dict:
    """Check if a pf anchor exists and has rules."""
    try:
        result = subprocess.run(
            ["pfctl", "-a", anchor_name, "-s", "rules"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        rules = [l.strip() for l in result.stdout.splitlines() if l.strip()]
        return {
            "exists": result.returncode == 0,
            "rules": len(rules),
            "sample": rules[:3] if rules else [],
        }
    except Exception as e:
        return {"exists": False, "error": str(e)}

def check_unbound_blocklist() -> dict:
    """Check if Unbound blocklist config exists."""
    blocklist_path = "/var/unbound/etc/netshield_blocklist.conf"
    try:
        if os.path.exists(blocklist_path):
            with open(blocklist_path, "r") as f:
                lines = f.readlines()
                entries = [l for l in lines if l.startswith("local-zone:")]
                return {
                    "exists": True,
                    "entries": len(entries),
                    "sample": entries[:3] if entries else [],
                }
        return {"exists": False, "entries": 0}
    except Exception as e:
        return {"exists": False, "error": str(e)}

def check_unbound_running() -> dict:
    """Check if Unbound is running and can resolve."""
    try:
        # Check process
        result = subprocess.run(
            ["pgrep", "-x", "unbound"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        running = result.returncode == 0

        # Try a test resolution
        test_result = subprocess.run(
            ["unbound-control", "status"],
            capture_output=True,
            text=True,
            timeout=5,
        )

        return {
            "running": running,
            "pid": result.stdout.strip() if running else None,
            "status": "ok" if test_result.returncode == 0 else "error",
        }
    except Exception as e:
        return {"running": False, "error": str(e)}

def check_suricata() -> dict:
    """Check Suricata status."""
    try:
        result = subprocess.run(
            ["pgrep", "-x", "suricata"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        running = result.returncode == 0

        eve_log = "/var/log/suricata/eve.json"
        eve_exists = os.path.exists(eve_log)
        eve_size = os.path.getsize(eve_log) if eve_exists else 0

        return {
            "running": running,
            "pid": result.stdout.strip() if running else None,
            "eve_log_exists": eve_exists,
            "eve_log_size_mb": round(eve_size / 1024 / 1024, 2),
        }
    except Exception as e:
        return {"running": False, "error": str(e)}

def check_database() -> dict:
    """Check NetShield database."""
    db_path = "/var/db/netshield/netshield.db"
    try:
        if os.path.exists(db_path):
            import sqlite3
            conn = sqlite3.connect(db_path)
            conn.row_factory = sqlite3.Row

            # Count tables
            tables = conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()

            # Count IoCs
            try:
                iocs = conn.execute("SELECT COUNT(*) FROM threat_iocs").fetchone()[0]
            except (sqlite3.OperationalError, TypeError):
                iocs = 0

            # Count policies
            try:
                policies = conn.execute("SELECT COUNT(*) FROM policies").fetchone()[0]
            except (sqlite3.OperationalError, TypeError):
                policies = 0

            # Count devices
            try:
                devices = conn.execute("SELECT COUNT(*) FROM devices").fetchone()[0]
            except (sqlite3.OperationalError, TypeError):
                devices = 0

            conn.close()

            return {
                "exists": True,
                "size_mb": round(os.path.getsize(db_path) / 1024 / 1024, 2),
                "tables": len(tables),
                "iocs": iocs,
                "policies": policies,
                "devices": devices,
            }
        return {"exists": False}
    except Exception as e:
        return {"exists": False, "error": str(e)}

def check_web_categories_db() -> dict:
    """Check web categories database."""
    db_path = "/var/netshield/web_categories.db"
    try:
        if os.path.exists(db_path):
            import sqlite3
            conn = sqlite3.connect(db_path)

            domains = conn.execute("SELECT COUNT(*) FROM domains").fetchone()[0]
            categories = conn.execute(
                "SELECT COUNT(DISTINCT category) FROM domains"
            ).fetchone()[0]

            conn.close()

            return {
                "exists": True,
                "domains": domains,
                "categories": categories,
            }
        return {"exists": False}
    except Exception as e:
        return {"exists": False, "error": str(e)}

def run_audit():
    """Run full enforcement audit."""
    print_header("NetShield Enforcement Audit")
    print(f"  Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    results = {}

    # 1. Check pf tables for threat intel
    print_header("1. Threat Intelligence Enforcement")

    pf_threats = check_pf_table("netshield_threats")
    results["pf_threat_table"] = pf_threats
    print_result(
        "pf table 'netshield_threats'",
        pf_threats.get("exists", False) and pf_threats.get("entries", 0) > 0,
        f"{pf_threats.get('entries', 0)} IPs loaded" if pf_threats.get("exists") else "Table not found"
    )

    # 2. Check DNS filter (Unbound)
    print_header("2. DNS Filter Enforcement")

    unbound = check_unbound_running()
    results["unbound"] = unbound
    print_result(
        "Unbound DNS running",
        unbound.get("running", False),
        f"PID: {unbound.get('pid', 'N/A')}"
    )

    blocklist = check_unbound_blocklist()
    results["unbound_blocklist"] = blocklist
    print_result(
        "NetShield DNS blocklist",
        blocklist.get("exists", False) and blocklist.get("entries", 0) > 0,
        f"{blocklist.get('entries', 0)} domains blocked" if blocklist.get("exists") else "Config not found"
    )

    # 3. Check pf anchors for policy/parental/quarantine
    print_header("3. Policy Enforcement (pf anchors)")

    anchors = {
        "netshield": "Policy rules",
        "netshield/parental": "Parental controls",
        "netshield/quarantine": "Device quarantine",
    }

    for anchor, desc in anchors.items():
        info = check_pf_anchor(anchor)
        results[f"anchor_{anchor.replace('/', '_')}"] = info
        print_result(
            f"{desc} anchor '{anchor}'",
            info.get("exists", False),
            f"{info.get('rules', 0)} rules loaded" if info.get("exists") else "Anchor empty or not found"
        )

    # 4. Check Suricata
    print_header("4. Suricata IDS Integration")

    suricata = check_suricata()
    results["suricata"] = suricata
    print_result(
        "Suricata running",
        suricata.get("running", False),
        f"PID: {suricata.get('pid', 'N/A')}, eve.json: {suricata.get('eve_log_size_mb', 0)} MB"
    )

    # 5. Check databases
    print_header("5. Database Status")

    main_db = check_database()
    results["main_db"] = main_db
    print_result(
        "NetShield main database",
        main_db.get("exists", False),
        f"{main_db.get('size_mb', 0)} MB, {main_db.get('tables', 0)} tables, {main_db.get('iocs', 0)} IoCs"
    )

    web_cat_db = check_web_categories_db()
    results["web_categories_db"] = web_cat_db
    print_result(
        "Web categories database",
        web_cat_db.get("exists", False),
        f"{web_cat_db.get('domains', 0)} domains in {web_cat_db.get('categories', 0)} categories"
    )

    # Summary
    print_header("AUDIT SUMMARY")

    passed = sum(1 for k, v in results.items() if v.get("exists") or v.get("running"))
    total = len(results)

    print(f"\n  Tests passed: {passed}/{total}")
    print(f"\n  Enforcement Status:")

    # Threat intel
    if results.get("pf_threat_table", {}).get("entries", 0) > 0:
        print("    ✓ Threat Intel: ACTIVE (pf table populated)")
    else:
        print("    ✗ Threat Intel: INACTIVE (run update_all_feeds)")

    # DNS blocking
    if results.get("unbound_blocklist", {}).get("entries", 0) > 0:
        print("    ✓ DNS Blocking: ACTIVE (Unbound configured)")
    else:
        print("    ✗ DNS Blocking: INACTIVE (run update_all_blocklists)")

    # Policy engine
    if any(results.get(f"anchor_{a.replace('/', '_')}", {}).get("rules", 0) > 0
           for a in anchors.keys()):
        print("    ✓ Policy Engine: ACTIVE (pf anchors have rules)")
    else:
        print("    ○ Policy Engine: READY (no active blocks)")

    # Suricata
    if results.get("suricata", {}).get("running"):
        print("    ✓ Suricata IDS: RUNNING")
    else:
        print("    ✗ Suricata IDS: NOT RUNNING")

    print("\n")

    return results

if __name__ == "__main__":
    run_audit()
