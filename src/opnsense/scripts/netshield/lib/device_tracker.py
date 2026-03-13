"""
SPDX-License-Identifier: BSD-2-Clause

Copyright (c) 2024 NetShield Contributors
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice,
   this list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
POSSIBILITY OF SUCH DAMAGE.

NetShield device_tracker.py — Device discovery via ARP, DHCP leases, and config.xml.
"""

import logging
import os
import re
import subprocess
from datetime import datetime, timezone
from typing import Dict, List, Optional

from . import db
from .config import get_dhcp_staticmaps, load_config_xml

log = logging.getLogger(__name__)

# Possible locations for MAC vendor databases on FreeBSD
_OUI_PATHS = [
    "/usr/local/share/nmap/nmap-mac-prefixes",
    "/usr/share/misc/oui.txt",
    "/usr/local/share/oui.txt",
]

DHCP_LEASES_PATH = "/var/dhcpd/var/db/dhcpd.leases"

# ARP output: ? (192.168.1.1) at 00:11:22:33:44:55 on em0 [ether] ...
_ARP_RE = re.compile(
    r"\((?P<ip>[\d.]+)\)\s+at\s+(?P<mac>[0-9a-fA-F:]{17})",
)

# DHCP lease fields we care about
_LEASE_IP_RE = re.compile(r"^lease\s+([\d.]+)\s*\{")
_LEASE_ENDS_RE = re.compile(r"^\s*ends\s+\d+\s+([^;]+);")
_LEASE_HARDWARE_RE = re.compile(r"^\s*hardware\s+ethernet\s+([0-9a-fA-F:]{17})\s*;")
_LEASE_HOSTNAME_RE = re.compile(r'^\s*client-hostname\s+"([^"]+)"\s*;')

# OUI file: first 6 hex chars (no colons) -> vendor
_OUI_NMAP_RE = re.compile(r"^([0-9A-Fa-f]{6})\s+(.+)$")
_OUI_IEEE_RE = re.compile(r"^([0-9A-Fa-f]{2}-[0-9A-Fa-f]{2}-[0-9A-Fa-f]{2})\s+\(hex\)\s+(.+)$")

# Cached OUI table (loaded once)
_oui_cache: Optional[Dict[str, str]] = None


# ---------------------------------------------------------------------------
# OUI / Vendor lookup
# ---------------------------------------------------------------------------

def _load_oui_db() -> Dict[str, str]:
    """Load OUI prefix -> vendor name mapping from disk."""
    global _oui_cache
    if _oui_cache is not None:
        return _oui_cache

    table: Dict[str, str] = {}
    for path in _OUI_PATHS:
        if not os.path.isfile(path):
            continue
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    # nmap-mac-prefixes format: AABBCC VendorName
                    m = _OUI_NMAP_RE.match(line)
                    if m:
                        table[m.group(1).upper()] = m.group(2).strip()
                        continue
                    # IEEE oui.txt format: AA-BB-CC   (hex)  VendorName
                    m = _OUI_IEEE_RE.match(line)
                    if m:
                        prefix = m.group(1).replace("-", "").upper()
                        table[prefix] = m.group(2).strip()
            log.debug("Loaded %d OUI entries from %s", len(table), path)
            break
        except OSError as exc:
            log.warning("Failed to read OUI file %s: %s", path, exc)

    _oui_cache = table
    return table


def get_vendor(mac: str) -> str:
    """
    Look up the vendor/manufacturer name for a MAC address.
    Returns empty string if not found.
    """
    if not mac:
        return ""
    prefix = mac.replace(":", "").replace("-", "").upper()[:6]
    if len(prefix) < 6:
        return ""
    table = _load_oui_db()
    return table.get(prefix, "")


# ---------------------------------------------------------------------------
# ARP cache parsing
# ---------------------------------------------------------------------------

def _parse_arp_cache() -> List[Dict[str, str]]:
    """
    Run `arp -an` and return list of {ip, mac} dicts.
    """
    devices = []
    try:
        result = subprocess.run(
            ["/usr/sbin/arp", "-an"],
            capture_output=True,
            text=True,
            timeout=15,
        )
        for line in result.stdout.splitlines():
            m = _ARP_RE.search(line)
            if m:
                devices.append(
                    {
                        "ip": m.group("ip"),
                        "mac": m.group("mac").lower(),
                    }
                )
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError) as exc:
        log.warning("ARP cache read failed: %s", exc)
    return devices


# ---------------------------------------------------------------------------
# DHCP leases parsing
# ---------------------------------------------------------------------------

def _parse_dhcp_leases(path: str = DHCP_LEASES_PATH) -> Dict[str, Dict[str, str]]:
    """
    Parse ISC dhcpd leases file.
    Returns dict keyed by MAC address with {ip, hostname, ends} values.
    Only the most-recent active lease per MAC is kept.
    """
    leases: Dict[str, Dict] = {}
    if not os.path.isfile(path):
        log.debug("DHCP leases file not found: %s", path)
        return leases

    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            content = fh.read()
    except OSError as exc:
        log.warning("Cannot read DHCP leases: %s", exc)
        return leases

    current_ip: Optional[str] = None
    current: Dict[str, str] = {}

    for line in content.splitlines():
        m = _LEASE_IP_RE.match(line)
        if m:
            current_ip = m.group(1)
            current = {"ip": current_ip, "mac": "", "hostname": "", "ends": ""}
            continue

        if current_ip is None:
            continue

        m = _LEASE_HARDWARE_RE.match(line)
        if m:
            current["mac"] = m.group(1).lower()
            continue

        m = _LEASE_HOSTNAME_RE.match(line)
        if m:
            current["hostname"] = m.group(1)
            continue

        m = _LEASE_ENDS_RE.match(line)
        if m:
            current["ends"] = m.group(1).strip()
            continue

        if line.strip() == "}":
            mac = current.get("mac", "")
            if mac and current_ip:
                # Keep lease if it's newer than what we have
                existing = leases.get(mac)
                if existing is None or current.get("ends", "") >= existing.get("ends", ""):
                    leases[mac] = dict(current)
            current_ip = None
            current = {}

    return leases


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def discover_devices() -> List[Dict[str, str]]:
    """
    Discover all reachable devices by merging ARP cache + DHCP leases.
    Returns list of dicts with keys: mac, ip, hostname, vendor.
    """
    arp_devices = _parse_arp_cache()
    dhcp_leases = _parse_dhcp_leases()
    static_maps = get_dhcp_staticmaps()  # from config.xml

    # Build MAC -> static hostname map from config.xml
    static_hostnames: Dict[str, str] = {}
    for sm in static_maps:
        mac = sm.get("mac", "").lower()
        if mac:
            hostname = sm.get("hostname") or sm.get("descr") or ""
            if hostname:
                static_hostnames[mac] = hostname

    seen_macs: Dict[str, Dict] = {}

    # Seed from ARP
    for entry in arp_devices:
        mac = entry["mac"]
        seen_macs[mac] = {
            "mac": mac,
            "ip": entry["ip"],
            "hostname": "",
            "vendor": get_vendor(mac),
        }

    # Augment / add from DHCP leases
    for mac, lease in dhcp_leases.items():
        if mac in seen_macs:
            seen_macs[mac]["hostname"] = lease.get("hostname", "") or seen_macs[mac]["hostname"]
            if lease.get("ip"):
                seen_macs[mac]["ip"] = lease["ip"]
        else:
            seen_macs[mac] = {
                "mac": mac,
                "ip": lease.get("ip", ""),
                "hostname": lease.get("hostname", ""),
                "vendor": get_vendor(mac),
            }

    # Apply static hostnames (highest priority)
    for mac, hostname in static_hostnames.items():
        if mac in seen_macs:
            seen_macs[mac]["hostname"] = hostname
        else:
            seen_macs[mac] = {
                "mac": mac,
                "ip": "",
                "hostname": hostname,
                "vendor": get_vendor(mac),
            }

    return list(seen_macs.values())


def update_device_db(devices: List[Dict[str, str]]) -> int:
    """
    Upsert a list of device dicts into the SQLite devices table.
    Returns the number of rows upserted.
    """
    db.init_db()
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    count = 0
    for dev in devices:
        mac = dev.get("mac", "").strip().lower()
        if not mac:
            continue
        existing = db.fetchone(
            "SELECT mac, first_seen FROM devices WHERE mac = ?", (mac,)
        )
        if existing:
            db.execute(
                """
                UPDATE devices
                   SET ip        = ?,
                       hostname  = CASE WHEN ? != '' THEN ? ELSE hostname END,
                       vendor    = CASE WHEN ? != '' THEN ? ELSE vendor END,
                       last_seen = ?
                 WHERE mac = ?
                """,
                (
                    dev.get("ip", ""),
                    dev.get("hostname", ""), dev.get("hostname", ""),
                    dev.get("vendor", ""), dev.get("vendor", ""),
                    now,
                    mac,
                ),
            )
        else:
            db.execute(
                """
                INSERT INTO devices (mac, ip, hostname, vendor, category, first_seen, last_seen, approved)
                VALUES (?, ?, ?, ?, '', ?, ?, 0)
                """,
                (
                    mac,
                    dev.get("ip", ""),
                    dev.get("hostname", ""),
                    dev.get("vendor", ""),
                    now,
                    now,
                ),
            )
        count += 1
    log.debug("update_device_db: upserted %d devices", count)
    return count


def get_known_devices() -> List[Dict]:
    """Return all devices stored in the DB."""
    db.init_db()
    return db.fetchall("SELECT * FROM devices ORDER BY last_seen DESC")


def get_device_name(mac_or_ip: str) -> str:
    """
    Resolve a friendly display name for a device given its MAC or IP.
    Resolution order: DB hostname → DB vendor → MAC/IP fallback.
    """
    if not mac_or_ip:
        return ""
    db.init_db()

    # Try MAC lookup first
    row = db.fetchone(
        "SELECT hostname, vendor FROM devices WHERE mac = ?",
        (mac_or_ip.lower(),),
    )
    if row is None:
        # Try IP
        row = db.fetchone(
            "SELECT hostname, vendor FROM devices WHERE ip = ?",
            (mac_or_ip,),
        )

    if row:
        hostname = (row.get("hostname") or "").strip()
        if hostname:
            return hostname
        vendor = (row.get("vendor") or "").strip()
        if vendor:
            return vendor

    return mac_or_ip
