#!/usr/local/bin/python3
# Copyright (c) 2025-2026, NetShield Project
# Unbound Enforcer - Comprehensive DNS blocking via DNSBL JSON
# Phase 1: Schedule-aware enforcement, No Internet kill switch, exclusions

"""
Unbound Enforcer for NetShield.

Reads ALL blocking sources and writes a unified DNSBL JSON file:
  1. Policies (netshield.db) - with scope: network/devices/vlan
  2. Web Categories (web_categories.db) - global + per-device
  3. Target Lists (target_lists.db) - lists with block policies

Supports:
  - Device-specific and VLAN-specific blocking via source_nets
  - Named schedules with day-of-week checking
  - No Internet kill switch (wildcard block all)
  - Per-policy exclusions (whitelist bypass, blacklist inject)
  - Tor/VPN/DoH/ECH prevention toggles
"""

import json
import logging
import os
import sqlite3
import subprocess
import sys
from datetime import datetime
from typing import Dict, List, Set

log = logging.getLogger(__name__)

DNSBL_JSON = "/var/unbound/data/dnsbl.json"
DNSBL_SIZE = "/var/unbound/data/dnsbl.size"
NETSHIELD_DB = "/var/db/netshield/netshield.db"
WEB_CATEGORIES_DB = "/var/netshield/web_categories.db"
TARGETLISTS_DB = "/var/netshield/target_lists.db"

DOH_BYPASS_DOMAINS = [
    "cloudflare-dns.com", "dns.google", "dns.google.com", "dns.quad9.net",
    "doh.opendns.com", "dns.nextdns.io", "doh.cleanbrowsing.org",
    "dns.adguard.com", "doh.dns.sb", "mozilla.cloudflare-dns.com",
    "use-application-dns.net", "1dot1dot1dot1.cloudflare-dns.com",
    "one.one.one.one", "dns64.dns.google", "family.cloudflare-dns.com",
    "doh.xfinity.com", "doh.cox.net", "ordns.he.net"
]

# Extended DoH list for block_doh toggle
EXTENDED_DOH_DOMAINS = DOH_BYPASS_DOMAINS + [
    "dns.adguard-dns.com", "dns-unfiltered.adguard.com",
    "doh.applied-privacy.net", "doh.li", "doh.dns.apple.com",
    "dns.alidns.com", "doh.360.cn", "dns.twnic.tw",
    "doh.centraleu.pi-dns.com", "doh.eastus.pi-dns.com",
    "jp.tiar.app", "doh.tiar.app", "doh.tiarap.org",
    "dns.rubyfish.cn", "dns.containerpi.com",
    "dns.digitale-gesellschaft.ch", "dns.flatuslifir.is",
    "doh.ffmuc.net", "dns.hostux.net", "dns.oszx.co",
    "doh.powerdns.org", "doh.seby.io", "resolver-eu.lelux.fi",
    "doh.libredns.gr", "dns.switch.ch"
]

# Tor infrastructure domains
TOR_DOMAINS = [
    "torproject.org", "www.torproject.org", "bridges.torproject.org",
    "snowflake.torproject.org", "tb-manual.torproject.org",
    "check.torproject.org", "dist.torproject.org",
    "tor.eff.org", "tor.blingblongbling.de",
    "onion.cab", "onion.link", "onion.ly",
    "onion.pet", "onion.ws", "onion.to",
    "tor2web.org", "tor2web.io",
    "torbrowser.cc", "torservers.net"
]

# VPN provider domains
VPN_DOMAINS = [
    "nordvpn.com", "expressvpn.com", "surfshark.com",
    "protonvpn.com", "mullvad.net", "windscribe.com",
    "privateinternetaccess.com", "cyberghostvpn.com",
    "ipvanish.com", "purevpn.com", "tunnelbear.com",
    "hide.me", "hotspotshield.com", "vyprvpn.com",
    "strongvpn.com", "zenmate.com", "torguard.net",
    "privatevpn.com", "astrill.com", "atlasvpn.com",
    "mozillavpn.com", "warp.cloudflare.com",
    "1.1.1.1"  # Cloudflare WARP VPN
]

# VLAN interface -> subnet mapping (populated at runtime)
VLAN_SUBNETS: Dict[str, str] = {}


def get_app_domains(app_id: str) -> List[str]:
    """Get domains for an app from app_signatures and convert wildcards to bare domains."""
    try:
        sys.path.insert(0, "/usr/local/opnsense/scripts/netshield/lib")
        from app_signatures import get_all_signatures
        all_sigs = get_all_signatures()
        sig = all_sigs.get(app_id, {})
        raw_domains = sig.get("domains", [])
        # Convert wildcard patterns to bare domains for Unbound blocking
        # *.facebook.com -> facebook.com (Unbound local-zone blocks all subdomains)
        clean = set()
        for d in raw_domains:
            d = d.strip().lower().rstrip(".")
            if d.startswith("*."):
                d = d[2:]
            if d and not d.startswith("*"):
                clean.add(d)
        return list(clean)
    except Exception as exc:
        log.warning("get_app_domains(%s) failed: %s", app_id, exc)
        return []


def get_category_domains(category: str) -> List[str]:
    """Get domains for a web category from web_categories.db."""
    if not os.path.exists(WEB_CATEGORIES_DB):
        return []
    try:
        conn = sqlite3.connect(WEB_CATEGORIES_DB)
        cursor = conn.execute(
            "SELECT domain FROM domains WHERE category = ? LIMIT 50000",
            (category,)
        )
        domains = [row[0] for row in cursor]
        conn.close()
        return domains
    except Exception:
        return []


def get_target_list_domains(list_id: int) -> List[str]:
    """Get domains from a target list by ID."""
    if not os.path.exists(TARGETLISTS_DB):
        return []
    try:
        conn = sqlite3.connect(TARGETLISTS_DB)
        cursor = conn.execute(
            "SELECT value FROM target_entries WHERE list_id = ? AND entry_type = 'domain'",
            (list_id,)
        )
        domains = [row[0] for row in cursor]
        conn.close()
        return domains
    except Exception:
        return []


def mac_to_ip(mac: str) -> str:
    """Look up IP for a MAC address from devices table."""
    if not os.path.exists(NETSHIELD_DB):
        return ""
    try:
        conn = sqlite3.connect(NETSHIELD_DB)
        cursor = conn.execute("SELECT ip FROM devices WHERE mac = ?", (mac,))
        row = cursor.fetchone()
        conn.close()
        return row[0] if row else ""
    except Exception:
        return ""


def get_vlan_subnets() -> Dict[str, str]:
    """Get VLAN interface -> subnet CIDR mapping from system."""
    subnets = {}
    try:
        result = subprocess.run(
            ["ifconfig"],
            capture_output=True, text=True, timeout=10
        )
        current_iface = ""
        for line in result.stdout.splitlines():
            if not line.startswith('\t') and ':' in line:
                current_iface = line.split(':')[0]
            if 'vlan' in current_iface and 'inet ' in line:
                parts = line.strip().split()
                ip_idx = parts.index('inet') + 1
                mask_idx = parts.index('netmask') + 1
                ip = parts[ip_idx]
                mask = parts[mask_idx]
                mask_int = int(mask, 16)
                cidr = bin(mask_int).count('1')
                import ipaddress
                net = ipaddress.ip_network(f"{ip}/{cidr}", strict=False)
                subnets[current_iface] = str(net)
    except Exception:
        pass
    return subnets


def resolve_source_nets(policy: dict) -> List[str]:
    """Resolve policy scope to a list of CIDR source_nets for DNSBL."""
    scope = policy.get('scope', 'network') or 'network'

    if scope == 'network':
        return []

    if scope == 'devices':
        devices_str = policy.get('devices', '') or ''
        nets = []
        for dev in devices_str.split(','):
            dev = dev.strip()
            if not dev:
                continue
            if ':' in dev:
                ip = mac_to_ip(dev)
                if ip:
                    nets.append(f"{ip}/32")
            elif '/' in dev:
                nets.append(dev)
            else:
                nets.append(f"{dev}/32")
        return nets

    if scope == 'vlan':
        vlans_str = policy.get('vlans', '') or ''
        nets = []
        vlan_subnets = get_vlan_subnets()
        for vlan in vlans_str.split(','):
            vlan = vlan.strip()
            if vlan and vlan in vlan_subnets:
                nets.append(vlan_subnets[vlan])
        return nets

    return []


def is_schedule_active(policy: dict) -> bool:
    """Check if any of the policy's schedules are currently active.

    If the policy has no schedules, it's always active.
    If it has schedules, at least one must match current time + day.
    """
    schedules_json = policy.get('schedules_json', '[]') or '[]'
    try:
        schedules = json.loads(schedules_json)
    except (json.JSONDecodeError, TypeError):
        return True

    if not schedules:
        return True  # No schedules = always active

    now = datetime.now()
    current_time = now.strftime('%H:%M')
    day_map = {0: 'mon', 1: 'tue', 2: 'wed', 3: 'thu', 4: 'fri', 5: 'sat', 6: 'sun'}
    current_day = day_map[now.weekday()]

    for sched in schedules:
        start = sched.get('start_time', '00:00')
        end = sched.get('end_time', '23:59')
        days_str = sched.get('days', 'mon,tue,wed,thu,fri,sat,sun')
        days = [d.strip() for d in days_str.split(',')]

        if current_day not in days:
            continue

        # Handle overnight schedules (e.g., 22:00-06:00)
        if start <= end:
            if start <= current_time <= end:
                return True
        else:
            # Overnight: active if current >= start OR current <= end
            if current_time >= start or current_time <= end:
                return True

    return False


def get_policy_exclusions(policy: dict) -> tuple:
    """Get whitelist and blacklist entries for a policy.

    Returns (whitelist_set, blacklist_set) of domain strings.
    """
    whitelist = set()
    blacklist = set()

    exclusions_json = policy.get('exclusions_json', '[]') or '[]'
    try:
        exclusions = json.loads(exclusions_json)
    except (json.JSONDecodeError, TypeError):
        return whitelist, blacklist

    for exc in exclusions:
        entry = exc.get('entry', '').strip().lower()
        if not entry:
            continue
        list_type = exc.get('list_type', 'blacklist')
        if list_type == 'whitelist':
            whitelist.add(entry)
        else:
            blacklist.add(entry)

    # Also check the DB table for persisted exclusions
    if os.path.exists(NETSHIELD_DB):
        try:
            policy_id = policy.get('id')
            if policy_id:
                conn = sqlite3.connect(NETSHIELD_DB)
                cursor = conn.execute(
                    "SELECT entry, list_type FROM policy_exclusions WHERE policy_id = ?",
                    (policy_id,)
                )
                for row in cursor:
                    entry = row[0].strip().lower()
                    if row[1] == 'whitelist':
                        whitelist.add(entry)
                    else:
                        blacklist.add(entry)
                conn.close()
        except Exception:
            pass

    return whitelist, blacklist


def enforce_policies() -> dict:
    """Read ALL blocking sources and write unified DNSBL JSON."""

    policy_configs = {}
    dnsbl_data: Dict[str, list] = {}
    policy_idx = 1
    details = []

    # Collect all whitelist entries across all policies for domain exclusion
    global_whitelist: Set[str] = set()

    # === 1) DoH bypass (always, network-wide) ===
    doh_config_idx = str(policy_idx)
    policy_configs[doh_config_idx] = {
        "address": "0.0.0.0",
        "rcode": "NXDOMAIN",
        "source_nets": []
    }
    for domain in DOH_BYPASS_DOMAINS:
        d = domain.lower().strip()
        if d:
            dnsbl_data[d] = [{"bl": "netshield-doh", "idx": doh_config_idx, "wildcard": True}]
    policy_idx += 1

    # === 2) NetShield Policies (netshield.db -> policies table) ===
    if os.path.exists(NETSHIELD_DB):
        conn = sqlite3.connect(NETSHIELD_DB)
        conn.row_factory = sqlite3.Row
        cursor = conn.execute(
            "SELECT * FROM policies WHERE enabled = 1"
        )
        policies = [dict(row) for row in cursor]

        # Load schedules from schedules table for each policy
        for p in policies:
            pid = p['id']
            try:
                cur = conn.execute(
                    "SELECT name, start_time, end_time, days FROM schedules WHERE policy_id = ? ORDER BY id",
                    (pid,)
                )
                scheds = [dict(r) for r in cur.fetchall()]
                if scheds:
                    p['schedules_json'] = json.dumps(scheds)
            except sqlite3.OperationalError:
                pass
        conn.close()

        for policy in policies:
            name = policy.get('name', 'unnamed')
            action = policy.get('action', 'block')

            # Skip non-blocking policies for DNSBL (allow/log/throttle don't need DNS blocking)
            if action not in ('block',):
                # But no_internet overrides this
                if not (policy.get('no_internet') in (1, '1')):
                    continue

            # Check schedule
            if not is_schedule_active(policy):
                details.append({"name": name, "domains": 0, "scope": policy.get('scope', 'network'),
                                "status": "inactive (schedule)"})
                continue

            source_nets = resolve_source_nets(policy)
            whitelist, blacklist = get_policy_exclusions(policy)
            global_whitelist.update(whitelist)

            # === No Internet Kill Switch ===
            if policy.get('no_internet') in (1, '1'):
                cfg_idx = str(policy_idx)
                policy_configs[cfg_idx] = {
                    "address": "0.0.0.0",
                    "rcode": "NXDOMAIN",
                    "source_nets": source_nets
                }
                policy_idx += 1
                # Block a wildcard catch-all domain
                wildcard_domain = "."
                if wildcard_domain not in dnsbl_data:
                    dnsbl_data[wildcard_domain] = []
                dnsbl_data[wildcard_domain].append(
                    {"bl": "netshield-nointernet", "idx": cfg_idx, "wildcard": True}
                )
                details.append({
                    "name": name,
                    "domains": "ALL (no internet)",
                    "scope": policy.get('scope', 'network'),
                    "source_nets": source_nets
                })
                continue  # No need to process apps/categories for no-internet

            domains: Set[str] = set()

            # Tor prevention
            if policy.get('block_tor') in (1, '1'):
                domains.update(TOR_DOMAINS)

            # VPN prevention
            if policy.get('block_vpn') in (1, '1'):
                domains.update(VPN_DOMAINS)

            # DoH prevention (extended list)
            if policy.get('block_doh') in (1, '1'):
                domains.update(EXTENDED_DOH_DOMAINS)

            # Apps
            apps_str = policy.get('apps', '') or ''
            if apps_str:
                for app_id in apps_str.split(','):
                    app_id = app_id.strip()
                    if app_id:
                        domains.update(get_app_domains(app_id))

            # Web categories
            cats_str = policy.get('web_categories', '') or ''
            if cats_str:
                for cat in cats_str.split(','):
                    cat = cat.strip()
                    if cat:
                        domains.update(get_category_domains(cat))

            # Security categories
            sec_cats_str = policy.get('security_categories', '{}') or '{}'
            try:
                sec_cats = json.loads(sec_cats_str)
                for cat_id, blocked in sec_cats.items():
                    if blocked:
                        domains.update(get_category_domains(cat_id))
            except (json.JSONDecodeError, TypeError):
                pass

            # Targets JSON (backwards compat)
            targets_str = policy.get('targets', '{}') or '{}'
            try:
                targets = json.loads(targets_str)
                for app_id in targets.get('apps', []):
                    if app_id:
                        domains.update(get_app_domains(app_id))
                for cat in targets.get('categories', []):
                    if cat:
                        domains.update(get_category_domains(cat))
            except (json.JSONDecodeError, TypeError):
                pass

            # Add blacklist entries
            domains.update(blacklist)

            # Remove whitelist entries
            domains -= whitelist

            if not domains:
                details.append({"name": name, "domains": 0, "scope": policy.get('scope', 'network')})
                continue

            cfg_idx = str(policy_idx)
            policy_configs[cfg_idx] = {
                "address": "0.0.0.0",
                "rcode": "NXDOMAIN",
                "source_nets": source_nets
            }
            policy_idx += 1

            for d in domains:
                d = d.lower().strip()
                if d:
                    if d not in dnsbl_data:
                        dnsbl_data[d] = []
                    dnsbl_data[d].append({"bl": "netshield-policy", "idx": cfg_idx, "wildcard": True})

            details.append({
                "name": name,
                "domains": len(domains),
                "scope": policy.get('scope', 'network'),
                "source_nets": source_nets
            })

    # === 3) Web Categories (web_categories.db -> category_config where enabled=0) ===
    global_cat_domains: Set[str] = set()
    if os.path.exists(WEB_CATEGORIES_DB):
        try:
            conn = sqlite3.connect(WEB_CATEGORIES_DB)

            cursor = conn.execute(
                "SELECT category FROM category_config WHERE enabled = 0"
            )
            blocked_cats = [row[0] for row in cursor]

            for cat in blocked_cats:
                cat_domains = get_category_domains(cat)
                global_cat_domains.update(cat_domains)

            # Per-device category blocks
            device_cat_domains: Dict[str, Set[str]] = {}
            try:
                cursor = conn.execute(
                    "SELECT mac, category FROM device_policies WHERE action = 'block'"
                )
                for row in cursor:
                    mac = row[0]
                    cat = row[1]
                    if mac not in device_cat_domains:
                        device_cat_domains[mac] = set()
                    device_cat_domains[mac].update(get_category_domains(cat))
            except sqlite3.OperationalError:
                pass

            conn.close()

            if global_cat_domains:
                # Remove whitelisted domains
                global_cat_domains -= global_whitelist

                cfg_idx = str(policy_idx)
                policy_configs[cfg_idx] = {
                    "address": "0.0.0.0",
                    "rcode": "NXDOMAIN",
                    "source_nets": []
                }
                policy_idx += 1

                for d in global_cat_domains:
                    d = d.lower().strip()
                    if d:
                        if d not in dnsbl_data:
                            dnsbl_data[d] = []
                        dnsbl_data[d].append({"bl": "netshield-category", "idx": cfg_idx, "wildcard": True})

                details.append({
                    "name": f"Global categories ({len(blocked_cats)})",
                    "domains": len(global_cat_domains),
                    "scope": "network",
                    "categories": blocked_cats
                })

            for mac, dev_domains in device_cat_domains.items():
                if not dev_domains:
                    continue
                dev_domains -= global_whitelist
                ip = mac_to_ip(mac)
                if not ip:
                    continue

                cfg_idx = str(policy_idx)
                policy_configs[cfg_idx] = {
                    "address": "0.0.0.0",
                    "rcode": "NXDOMAIN",
                    "source_nets": [f"{ip}/32"]
                }
                policy_idx += 1

                for d in dev_domains:
                    d = d.lower().strip()
                    if d:
                        if d not in dnsbl_data:
                            dnsbl_data[d] = []
                        dnsbl_data[d].append({"bl": "netshield-device", "idx": cfg_idx, "wildcard": True})

                details.append({
                    "name": f"Device {mac} ({ip})",
                    "domains": len(dev_domains),
                    "scope": "device"
                })

        except Exception as e:
            details.append({"name": "web_categories", "error": str(e)})

    # === 4) Target Lists ===
    tl_domains: Set[str] = set()
    if os.path.exists(TARGETLISTS_DB):
        try:
            conn = sqlite3.connect(TARGETLISTS_DB)
            conn.row_factory = sqlite3.Row
            cursor = conn.execute("""
                SELECT DISTINCT tl.id, tl.name FROM target_lists tl
                JOIN list_policies lp ON tl.id = lp.list_id
                WHERE lp.action = 'block' AND lp.enabled = 1
            """)
            blocked_lists = list(cursor)
            conn.close()

            for lst in blocked_lists:
                list_domains = get_target_list_domains(lst['id'])
                tl_domains.update(list_domains)
                details.append({
                    "name": f"Target list: {lst['name']}",
                    "domains": len(list_domains),
                    "scope": "network"
                })
        except Exception as e:
            details.append({"name": "target_lists", "error": str(e)})

    if tl_domains:
        tl_domains -= global_whitelist
        cfg_idx = str(policy_idx)
        policy_configs[cfg_idx] = {
            "address": "0.0.0.0",
            "rcode": "NXDOMAIN",
            "source_nets": []
        }
        policy_idx += 1

        for d in tl_domains:
            d = d.lower().strip()
            if d:
                if d not in dnsbl_data:
                    dnsbl_data[d] = []
                dnsbl_data[d].append({"bl": "netshield-targetlist", "idx": cfg_idx, "wildcard": True})

    # === Remove globally whitelisted domains from dnsbl_data ===
    for wl_domain in global_whitelist:
        dnsbl_data.pop(wl_domain.lower(), None)

    # === Merge NetShield entries into existing DNSBL JSON ===
    os.makedirs(os.path.dirname(DNSBL_JSON), exist_ok=True)

    existing = {"config": {"general": {"has_wildcards": False}}, "data": {}}
    if os.path.exists(DNSBL_JSON) and os.path.getsize(DNSBL_JSON) > 0:
        try:
            with open(DNSBL_JSON, "r") as f:
                existing = json.load(f)
        except (json.JSONDecodeError, IOError):
            log.warning("Could not read existing dnsbl.json, starting fresh")

    merged_config = {}
    uuid_to_short = {}
    opn_idx = 9000
    for idx, cfg in existing.get("config", {}).items():
        if idx == "general":
            merged_config[idx] = cfg
        elif not idx.isdigit():
            short_key = str(opn_idx)
            uuid_to_short[idx] = short_key
            merged_config[short_key] = cfg
            opn_idx += 1

    merged_config.update(policy_configs)
    if "general" in merged_config:
        merged_config["general"]["has_wildcards"] = existing.get("config", {}).get("general", {}).get("has_wildcards", False)
    else:
        merged_config["general"] = {"has_wildcards": False}

    merged_data = {}
    netshield_bls = {"netshield-policy", "netshield-category", "netshield-webcategory",
                     "netshield-targetlist", "netshield-doh", "netshield-device", "netshield-nointernet"}
    for domain, entries in existing.get("data", {}).items():
        if isinstance(entries, list):
            kept = []
            for e in entries:
                if e.get("bl") not in netshield_bls:
                    old_idx = str(e.get("idx", ""))
                    if old_idx in uuid_to_short:
                        e["idx"] = uuid_to_short[old_idx]
                    kept.append(e)
            if kept:
                merged_data[domain] = kept

    for domain, entries in dnsbl_data.items():
        if domain not in merged_data:
            merged_data[domain] = []
        merged_data[domain].extend(entries)

    dnsbl_json = {"config": merged_config, "data": merged_data}

    with open(DNSBL_JSON, "w") as f:
        json.dump(dnsbl_json, f, separators=(',', ':'))

    with open(DNSBL_SIZE, "w") as f:
        f.write(str(len(merged_data)))

    return {
        "status": "ok",
        "total_domains": len(dnsbl_data),
        "doh_blocked": len(DOH_BYPASS_DOMAINS),
        "global_categories_blocked": len(global_cat_domains),
        "target_lists_blocked": len(tl_domains),
        "policy_configs": policy_idx - 1,
        "details": details
    }


def get_status() -> dict:
    """Get current enforcement status."""
    status = {
        "dnsbl_exists": os.path.exists(DNSBL_JSON),
        "domains_blocked": 0,
        "unbound_running": False
    }

    if os.path.exists(DNSBL_SIZE):
        try:
            with open(DNSBL_SIZE) as f:
                status["domains_blocked"] = int(f.read().strip())
        except (ValueError, IOError):
            pass

    result = subprocess.run(["pgrep", "-x", "unbound"], capture_output=True)
    status["unbound_running"] = result.returncode == 0

    return status


# Backward-compatible wrappers
def enforce_category_blocking() -> dict:
    return enforce_policies()

def enforce_app_blocking() -> dict:
    return enforce_policies()

def enforce_target_list_blocking() -> dict:
    return enforce_policies()

def enforce_all() -> dict:
    return enforce_policies()

def reload_unbound() -> bool:
    return True


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    cmd = sys.argv[1] if len(sys.argv) > 1 else "all"

    if cmd == "all":
        print(json.dumps(enforce_policies()))
    elif cmd == "status":
        print(json.dumps(get_status()))
    else:
        print(json.dumps(enforce_policies()))
