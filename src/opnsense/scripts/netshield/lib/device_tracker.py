#!/usr/local/bin/python3
# Copyright (c) 2025-2026, NetShield Contributors
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice,
#    this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright notice,
#    this list of conditions and the following disclaimer in the documentation
#    and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
# SPDX-License-Identifier: BSD-2-Clause

"""NetShield device discovery and tracking."""

import logging
import re
import subprocess
from typing import Any, Dict, List, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    import types

log = logging.getLogger(__name__)

# Paths
_DHCP_LEASES = "/var/dhcpd/var/db/dhcpd.leases"
_NMAP_OUI = "/usr/local/share/nmap/nmap-mac-prefixes"

# Regex patterns
_ARP_LINE_RE = re.compile(
    r"\((?P<ip>\d+\.\d+\.\d+\.\d+)\)\s+at\s+(?P<mac>[0-9a-f:]{17})",
    re.IGNORECASE,
)
_DHCP_IP_RE = re.compile(r"lease\s+(\d+\.\d+\.\d+\.\d+)\s*\{")
_DHCP_MAC_RE = re.compile(r"hardware\s+ethernet\s+([0-9a-f:]{17})\s*;", re.IGNORECASE)
_DHCP_HOSTNAME_RE = re.compile(r'client-hostname\s+"([^"]+)"\s*;')


# ---------------------------------------------------------------------------
# ARP parsing
# ---------------------------------------------------------------------------

def _parse_arp() -> Dict[str, Dict[str, str]]:
    """Run ``arp -an`` and return a dict keyed by MAC with ip values."""
    devices: Dict[str, Dict[str, str]] = {}
    try:
        output = subprocess.check_output(
            ["arp", "-an"], stderr=subprocess.DEVNULL, timeout=10
        ).decode("utf-8", errors="replace")
    except (subprocess.SubprocessError, FileNotFoundError, OSError) as exc:
        log.warning("arp -an failed: %s", exc)
        return devices

    for line in output.splitlines():
        m = _ARP_LINE_RE.search(line)
        if m:
            mac = m.group("mac").lower()
            ip = m.group("ip")
            # Skip incomplete / broadcast / multicast entries
            if mac in ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"):
                continue
            devices[mac] = {"mac": mac, "ip": ip, "hostname": ""}

    return devices


# ---------------------------------------------------------------------------
# DHCP lease parsing
# ---------------------------------------------------------------------------

def _parse_dhcp_leases(lease_file: str = _DHCP_LEASES) -> Dict[str, Dict[str, str]]:
    """Parse ISC dhcpd lease file.  Returns dict keyed by MAC."""
    leases: Dict[str, Dict[str, str]] = {}
    try:
        with open(lease_file, "r", encoding="utf-8", errors="replace") as fh:
            content = fh.read()
    except OSError as exc:
        log.debug("Cannot read DHCP leases (%s): %s", lease_file, exc)
        return leases

    # Split into individual lease blocks
    blocks = re.split(r"\}", content)
    current_ip: Optional[str] = None

    for block in blocks:
        ip_m = _DHCP_IP_RE.search(block)
        if not ip_m:
            continue
        current_ip = ip_m.group(1)

        mac_m = _DHCP_MAC_RE.search(block)
        host_m = _DHCP_HOSTNAME_RE.search(block)

        if mac_m:
            mac = mac_m.group(1).lower()
            hostname = host_m.group(1) if host_m else ""
            # Latest lease for a MAC wins (file is chronological)
            leases[mac] = {"mac": mac, "ip": current_ip, "hostname": hostname}

    return leases


# ---------------------------------------------------------------------------
# OUI / vendor lookup
# ---------------------------------------------------------------------------

def get_mac_vendor(mac: str, oui_file: str = _NMAP_OUI) -> str:
    """Return the vendor string for *mac* using the nmap OUI prefix file.

    Returns an empty string if the file is unavailable or the OUI is unknown.
    """
    # Normalise to uppercase hex without separators, take first 6 chars (OUI)
    oui = mac.upper().replace(":", "").replace("-", "")[:6]
    try:
        with open(oui_file, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if line.startswith(oui):
                    # Format: "AABBCC VendorName"
                    parts = line.split(None, 1)
                    if len(parts) == 2:
                        return parts[1]
    except OSError:
        pass
    return ""


# ---------------------------------------------------------------------------
# Device discovery
# ---------------------------------------------------------------------------

def discover_devices() -> List[Dict[str, str]]:
    """Return a merged list of dicts with keys: mac, ip, hostname.

    ARP provides the authoritative mac-to-ip mapping; DHCP leases enrich
    the result with hostnames.
    """
    arp_devices = _parse_arp()
    dhcp_devices = _parse_dhcp_leases()

    # Merge: start from ARP, overlay hostname from DHCP when available
    merged: Dict[str, Dict[str, str]] = {}
    for mac, info in arp_devices.items():
        merged[mac] = dict(info)
        if mac in dhcp_devices and dhcp_devices[mac].get("hostname"):
            merged[mac]["hostname"] = dhcp_devices[mac]["hostname"]

    # Also include DHCP-only entries (device may have left the ARP cache)
    for mac, info in dhcp_devices.items():
        if mac not in merged:
            merged[mac] = dict(info)

    return list(merged.values())


# ---------------------------------------------------------------------------
# Periodic tracker
# ---------------------------------------------------------------------------

def track_devices(db_module: Any) -> List[Dict[str, Any]]:
    """Discover devices, upsert them in the database, and return new-device alerts.

    Args:
        db_module: The ``lib.db`` module (or any object with ``add_device``,
                   ``get_devices``, and ``add_alert`` callables).  Using the
                   module as a parameter avoids circular imports and makes
                   testing easier.

    Returns:
        A list of alert dicts for each newly-seen device.
    """
    new_alerts: List[Dict[str, Any]] = []

    try:
        devices = discover_devices()
    except Exception as exc:
        log.error("discover_devices failed: %s", exc)
        return new_alerts

    for dev in devices:
        mac = dev.get("mac", "")
        ip = dev.get("ip", "")
        hostname = dev.get("hostname", "")

        if not mac or not ip:
            continue

        vendor = get_mac_vendor(mac)

        try:
            is_new = db_module.add_device(mac=mac, ip=ip, hostname=hostname, vendor=vendor)
        except Exception as exc:
            log.error("add_device(%s) failed: %s", mac, exc)
            continue

        if is_new:
            log.info("New device discovered: %s (%s) %s", mac, ip, hostname)
            alert = {
                "device_mac": mac,
                "device_ip": ip,
                "device_name": hostname or mac,
                "alert_type": "New Device",
                "severity": "low",
                "detail": (
                    f"New device detected — MAC: {mac}, IP: {ip}"
                    + (f", Hostname: {hostname}" if hostname else "")
                    + (f", Vendor: {vendor}" if vendor else "")
                ),
            }
            new_alerts.append(alert)

            # Persist alert to database
            try:
                db_module.add_alert(**alert)
            except Exception as exc:
                log.error("add_alert(%s) failed: %s", mac, exc)

    return new_alerts
