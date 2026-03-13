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

NetShield vpn_detector.py — VPN, proxy, and DoH/DoT detection engine.
"""

import json
import logging
import os
import re
import subprocess
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Signature databases
# ---------------------------------------------------------------------------

# VPN provider domain patterns (substring match against DNS queries / TLS SNI)
VPN_DOMAINS: List[str] = [
    # NordVPN
    "nordvpn.com", "nordlynx.net",
    # ExpressVPN
    "expressvpn.com", "expressrelay.com", "xvpn.io",
    # Surfshark
    "surfshark.com", "surfshark.net",
    # ProtonVPN / ProtonMail
    "protonvpn.com", "proton.me", "protonmail.com",
    # Mullvad
    "mullvad.net",
    # Private Internet Access
    "privateinternetaccess.com", "piaproxy.com",
    # CyberGhost
    "cyberghostvpn.com",
    # IPVanish
    "ipvanish.com",
    # AirVPN
    "airvpn.org",
    # IVPN
    "ivpn.net",
    # Windscribe
    "windscribe.com", "windscribevpn.net",
    # Hide.me
    "hide.me",
    # TunnelBear
    "tunnelbear.com",
    # VyprVPN
    "vyprvpn.com", "giganews.com",
    # HotspotShield
    "hotspotshield.com", "aura.com",
    # Zenmate
    "zenmate.com",
    # StrongVPN
    "strongvpn.com",
    # Trust.Zone
    "trust.zone",
    # Perfect Privacy
    "perfect-privacy.com",
    # Astrill
    "astrill.com",
    # Torguard
    "torguard.net",
    # VPN Unlimited
    "vpnunlimitedapp.com", "keepsolid.com",
    # Atlas VPN
    "atlasvpn.com",
    # Hotspot Shield (additional)
    "anchorfree.net",
    # PrivadoVPN
    "privadovpn.com",
    # PureVPN
    "purevpn.com",
    # Cloudflare WARP
    "cloudflareclient.com", "cloudflaregateway.com",
    # Lantern
    "getlantern.org",
    # Psiphon
    "psiphon.ca", "psiphon3.com",
    # Ultrasurf
    "ultrasurf.us",
    # Hola VPN
    "hola.org",
    # Opera VPN
    "opera-vpn.com",
    # F-Secure Freedome
    "freedome-vpn.net",
    # Avast SecureLine
    "secureline.avast.com",
    # Bitdefender VPN / Aura
    "vpn.bitdefender.com",
    # Private Tunnel
    "privatetunnel.com",
    # OpenVPN Access Server
    "openvpn.net",
    # WireGuard project (detection only)
    "wireguard.com",
    # Tailscale
    "tailscale.com",
    # ZeroTier
    "zerotier.com",
    # Warp+ / 1.1.1.1 WARP
    "1dot1dot1dot1.cloudflare-dns.com",
]

# Port -> protocol name mapping for VPN protocols
VPN_PORTS: Dict[int, str] = {
    51820: "WireGuard",
    51821: "WireGuard",
    1194:  "OpenVPN/UDP",
    1195:  "OpenVPN/UDP-alt",
    1196:  "OpenVPN/UDP-alt",
    443:   "OpenVPN/TCP-443",   # only flagged when dst is known VPN IP
    500:   "IPSec-IKE",
    4500:  "IPSec-NAT",
    1701:  "L2TP",
    1723:  "PPTP",
    1194:  "OpenVPN",
    8080:  "OpenVPN/TCP-8080",
}

# Port -> protocol name for proxy protocols
PROXY_PORTS: Dict[int, str] = {
    1080:  "SOCKS5",
    1081:  "SOCKS5-alt",
    3128:  "HTTP-Proxy",
    8080:  "HTTP-Proxy-alt",
    8118:  "Privoxy",
    8388:  "Shadowsocks",
    8389:  "Shadowsocks-alt",
    9050:  "Tor-SOCKS",
    9150:  "Tor-Browser",
    9001:  "Tor-OR",
    9030:  "Tor-Dir",
    9040:  "Tor-Trans",
    2080:  "V2Ray",
    10808: "V2Ray-alt",
    7890:  "Clash",
    8081:  "HTTP-alt",
}

# Known DoH / DoT provider IPs
DOH_PROVIDER_IPS: List[str] = [
    # Cloudflare
    "1.1.1.1", "1.0.0.1",
    "2606:4700:4700::1111", "2606:4700:4700::1001",
    # Google
    "8.8.8.8", "8.8.4.4",
    "2001:4860:4860::8888", "2001:4860:4860::8844",
    # Quad9
    "9.9.9.9", "149.112.112.112",
    "2620:fe::fe", "2620:fe::9",
    # AdGuard
    "94.140.14.14", "94.140.15.15",
    "2a10:50c0::ad1:ff", "2a10:50c0::ad2:ff",
    # NextDNS
    "45.90.28.0", "45.90.30.0",
    # OpenDNS (Cisco) DoH
    "208.67.222.222", "208.67.220.220",
    # Comodo
    "8.26.56.26", "8.20.247.20",
    # Alternate DNS
    "198.101.242.72", "23.253.163.53",
]

# DoH / DoT provider domain names
DOH_DOMAINS: List[str] = [
    "dns.google",
    "dns64.dns.google",
    "one.one.one.one",
    "dns.cloudflare.com",
    "cloudflare-dns.com",
    "dns.quad9.net",
    "dns9.quad9.net",
    "dns.adguard-dns.com",
    "dns-unfiltered.adguard.com",
    "nextdns.io",
    "dns.nextdns.io",
    "doh.opendns.com",
    "doh.familyshield.opendns.com",
    "dns.comodo.com",
    "doh.cleanbrowsing.org",
    "doh.dns.sb",
    "mozilla.cloudflare-dns.com",
    "freedns.controld.com",
    "dns.controld.com",
]

# DoH standard port
DOH_PORT = 443
DOT_PORT = 853  # DNS-over-TLS

# ---------------------------------------------------------------------------
# Detection helpers
# ---------------------------------------------------------------------------

_PF_STATE_RE = re.compile(
    r"(?P<proto>tcp|udp)\s+.*?(?P<src>[\d.]+):(?P<sport>\d+)\s*->\s*(?P<dst>[\d.]+):(?P<dport>\d+)",
    re.IGNORECASE,
)


def _read_pf_states() -> List[str]:
    """Run pfctl -s state and return output lines."""
    try:
        result = subprocess.run(
            ["/sbin/pfctl", "-s", "state"],
            capture_output=True,
            text=True,
            timeout=20,
        )
        return result.stdout.splitlines()
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError) as exc:
        log.warning("pfctl -s state failed: %s", exc)
        return []


def _build_alert(
    alert_type: str,
    device_ip: str,
    detail: str,
    source: str,
) -> Dict[str, Any]:
    return {
        "alert_type": alert_type,
        "device": device_ip,
        "device_name": device_ip,
        "detail": detail,
        "source": source,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def check_pf_states() -> List[Dict[str, Any]]:
    """
    Scan the pf state table for connections to known VPN or proxy ports.
    Returns a list of alert dicts.
    """
    alerts: List[Dict[str, Any]] = []
    lines = _read_pf_states()

    for line in lines:
        m = _PF_STATE_RE.search(line)
        if not m:
            continue
        src_ip = m.group("src")
        dst_ip = m.group("dst")
        dport = int(m.group("dport"))
        sport = int(m.group("sport"))

        # Check for VPN ports (check destination port)
        vpn_proto = VPN_PORTS.get(dport)
        if vpn_proto:
            # Skip common false positives: 443 is also HTTPS
            if dport == 443:
                pass  # Will catch via SNI checks instead
            else:
                alerts.append(
                    _build_alert(
                        "vpn_detected",
                        src_ip,
                        f"{vpn_proto} connection to {dst_ip}:{dport}",
                        "pf_states",
                    )
                )
            continue

        # Check for proxy ports
        proxy_proto = PROXY_PORTS.get(dport)
        if proxy_proto:
            # Skip 8080/8081 as they are common HTTP ports
            if dport in (8080, 8081):
                continue
            alerts.append(
                _build_alert(
                    "proxy_detected",
                    src_ip,
                    f"{proxy_proto} connection to {dst_ip}:{dport}",
                    "pf_states",
                )
            )

        # Check for DoT (port 853)
        if dport == DOT_PORT:
            alerts.append(
                _build_alert(
                    "doh_bypass",
                    src_ip,
                    f"DNS-over-TLS connection to {dst_ip}:853",
                    "pf_states",
                )
            )

    return alerts


def check_dns_queries(duckdb_path: str) -> List[Dict[str, Any]]:
    """
    Query Unbound's DuckDB log for VPN-related domain resolutions.
    Gracefully returns [] if duckdb module is not available or DB doesn't exist.

    duckdb_path — path to Unbound DuckDB file (e.g. /var/db/unbound/dns_log.db)
    """
    alerts: List[Dict[str, Any]] = []

    if not os.path.isfile(duckdb_path):
        log.debug("DuckDB path not found: %s", duckdb_path)
        return alerts

    try:
        import duckdb  # type: ignore
    except ImportError:
        log.debug("duckdb module not available — skipping DNS query check")
        return alerts

    try:
        conn = duckdb.connect(duckdb_path, read_only=True)
        # Query recent DNS resolutions; table name may vary by Unbound version
        # Try common schema: columns (timestamp, client, qname, qtype, rcode)
        query = """
            SELECT client, qname
            FROM dns_log
            WHERE timestamp > now() - INTERVAL 5 MINUTE
              AND rcode = 'NOERROR'
            LIMIT 10000
        """
        try:
            rows = conn.execute(query).fetchall()
        except Exception as exc:
            log.debug("DNS log query failed (schema may differ): %s", exc)
            conn.close()
            return alerts

        conn.close()

        for client_ip, qname in rows:
            qname_lower = (qname or "").lower().rstrip(".")
            for vpn_domain in VPN_DOMAINS:
                if vpn_domain in qname_lower:
                    alerts.append(
                        _build_alert(
                            "vpn_detected",
                            client_ip or "",
                            f"DNS query for VPN domain: {qname}",
                            "dns_log",
                        )
                    )
                    break
            for doh_domain in DOH_DOMAINS:
                if doh_domain in qname_lower:
                    alerts.append(
                        _build_alert(
                            "doh_bypass",
                            client_ip or "",
                            f"DNS query for DoH provider: {qname}",
                            "dns_log",
                        )
                    )
                    break

    except Exception as exc:
        log.warning("check_dns_queries failed: %s", exc)

    return alerts


def check_tls_sni(eve_path: str) -> List[Dict[str, Any]]:
    """
    Parse Suricata eve.json for TLS events with SNI matching VPN/DoH domains.
    Reads only the tail of the file (last 50k bytes) to avoid processing the
    entire log on each call.

    eve_path — path to Suricata eve.json log file
    """
    alerts: List[Dict[str, Any]] = []

    if not os.path.isfile(eve_path):
        log.debug("Suricata eve.json not found: %s", eve_path)
        return alerts

    # Build combined lookup set for fast substring matching
    all_vpn = set(VPN_DOMAINS)
    all_doh = set(DOH_DOMAINS)

    try:
        # Read up to last 50 KB to avoid large file reads
        tail_bytes = 50 * 1024
        with open(eve_path, "rb") as fh:
            fh.seek(0, 2)
            size = fh.tell()
            fh.seek(max(0, size - tail_bytes))
            raw = fh.read()
    except OSError as exc:
        log.warning("Cannot read eve.json %s: %s", eve_path, exc)
        return alerts

    for line in raw.decode("utf-8", errors="replace").splitlines():
        if '"event_type":"tls"' not in line and '"event_type": "tls"' not in line:
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue

        if event.get("event_type") != "tls":
            continue

        tls = event.get("tls", {})
        sni = tls.get("sni", "").lower()
        if not sni:
            continue

        src_ip = event.get("src_ip", "")

        for vpn_dom in all_vpn:
            if vpn_dom in sni:
                alerts.append(
                    _build_alert(
                        "vpn_detected",
                        src_ip,
                        f"TLS SNI matched VPN domain: {sni}",
                        "suricata_eve",
                    )
                )
                break

        for doh_dom in all_doh:
            if doh_dom in sni:
                alerts.append(
                    _build_alert(
                        "doh_bypass",
                        src_ip,
                        f"TLS SNI matched DoH provider: {sni}",
                        "suricata_eve",
                    )
                )
                break

    return alerts


def check_doh_bypass() -> List[Dict[str, Any]]:
    """
    Detect DNS-over-HTTPS and DNS-over-TLS bypass attempts by checking
    pf states for connections to known DoH provider IPs on ports 443/853.
    """
    alerts: List[Dict[str, Any]] = []
    lines = _read_pf_states()
    doh_ip_set = set(DOH_PROVIDER_IPS)

    for line in lines:
        m = _PF_STATE_RE.search(line)
        if not m:
            continue
        src_ip = m.group("src")
        dst_ip = m.group("dst")
        dport = int(m.group("dport"))

        if dst_ip in doh_ip_set and dport in (DOH_PORT, DOT_PORT):
            proto_name = "DoH" if dport == 443 else "DoT"
            alerts.append(
                _build_alert(
                    "doh_bypass",
                    src_ip,
                    f"{proto_name} connection to known resolver {dst_ip}:{dport}",
                    "pf_states_doh",
                )
            )

    return alerts


def run_all_checks(
    duckdb_path: str = "/var/db/unbound/dns_log.db",
    eve_path: str = "/var/log/suricata/eve.json",
) -> List[Dict[str, Any]]:
    """
    Run all detection methods and return deduplicated list of alert dicts.
    Each alert has keys: alert_type, device, device_name, detail, source, timestamp.
    """
    all_alerts: List[Dict[str, Any]] = []

    try:
        all_alerts.extend(check_pf_states())
    except Exception as exc:
        log.warning("check_pf_states error: %s", exc)

    try:
        all_alerts.extend(check_dns_queries(duckdb_path))
    except Exception as exc:
        log.warning("check_dns_queries error: %s", exc)

    try:
        all_alerts.extend(check_tls_sni(eve_path))
    except Exception as exc:
        log.warning("check_tls_sni error: %s", exc)

    try:
        all_alerts.extend(check_doh_bypass())
    except Exception as exc:
        log.warning("check_doh_bypass error: %s", exc)

    # Deduplicate: same device + alert_type + detail within this run
    seen = set()
    unique: List[Dict[str, Any]] = []
    for alert in all_alerts:
        key = (alert.get("device"), alert.get("alert_type"), alert.get("detail"))
        if key not in seen:
            seen.add(key)
            unique.append(alert)

    log.debug("run_all_checks: %d unique alerts from %d total", len(unique), len(all_alerts))
    return unique
