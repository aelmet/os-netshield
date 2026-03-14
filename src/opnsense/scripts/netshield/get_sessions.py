#!/usr/local/bin/python3
"""
get_sessions.py — configd script for live session/connection monitoring.
Queries pf state table via pfctl and dpi_flows for app classification.
All output is JSON on stdout.
"""

import argparse
import json
import logging
import os
import re
import subprocess
import sys
from datetime import datetime
from urllib.parse import unquote

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, SCRIPT_DIR)

_log_dir = "/var/log/netshield"
if not os.path.isdir(_log_dir):
    os.makedirs(_log_dir, exist_ok=True)
logging.basicConfig(
    filename=os.path.join(_log_dir, "get_sessions.log"),
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
log = logging.getLogger("get_sessions")


def _parse_pf_states():
    """Parse pfctl -ss output into a list of connection dicts."""
    sessions = []
    try:
        result = subprocess.run(
            ["pfctl", "-ss"],
            capture_output=True, text=True, timeout=10
        )
        for line in result.stdout.splitlines():
            s = _parse_state_line(line)
            if s:
                sessions.append(s)
    except Exception as exc:
        log.warning("pfctl -ss failed: %s", exc)
    return sessions


def _parse_state_line(line):
    """Parse a single pfctl state line into a dict.

    Formats seen on OPNsense/FreeBSD:
      all tcp 192.168.1.100:54321 -> 93.184.216.34:443       ESTABLISHED:ESTABLISHED
      all tcp 192.168.1.100:54321 -> 93.184.216.34:443 (86.159.138.101:25622) ESTABLISHED:ESTABLISHED
      all udp 192.168.1.100:12345 -> 8.8.8.8:53              SINGLE:NO_TRAFFIC
    """
    parts = line.strip().split()
    if len(parts) < 6:
        return None

    try:
        interface = parts[0]
        proto = parts[1].upper()
        if proto not in ("TCP", "UDP", "ICMP"):
            return None

        # Find the arrow (-> or <-) to locate src/dst
        try:
            arrow_idx = next(i for i, p in enumerate(parts) if p in ("->", "<-"))
        except StopIteration:
            return None

        if arrow_idx < 2 or arrow_idx + 1 >= len(parts):
            return None

        src_full = parts[arrow_idx - 1]
        direction = parts[arrow_idx]
        dst_full = parts[arrow_idx + 1]

        # Skip NAT translation entries — parenthesized IPs
        if src_full.startswith("(") or dst_full.startswith("(") or dst_full == "->":
            return None

        src_ip, src_port = _split_addr(src_full)
        dst_ip, dst_port = _split_addr(dst_full)

        if not src_ip or not dst_ip:
            return None

        # Find state string - skip any (NAT) parenthesized tokens
        state_str = ""
        for p in parts[arrow_idx + 2:]:
            if p.startswith("(") or p.endswith(")"):
                continue
            if ":" in p and any(s in p.upper() for s in ("ESTABLISHED", "SINGLE", "MULTIPLE",
                    "SYN_SENT", "SYN_RCVD", "TIME_WAIT", "FIN_WAIT", "CLOSED", "NO_TRAFFIC")):
                state_str = p
                break
            if p[0].isalpha():
                state_str = p
                break

        pf_state = state_str.split(":")[0] if ":" in state_str else state_str
        is_active = pf_state in ("ESTABLISHED", "SINGLE", "MULTIPLE", "SYN_SENT", "SYN_RCVD")

        # Parse bytes if present [bytes_in:bytes_out]
        bytes_in = 0
        bytes_out = 0
        for p in parts[arrow_idx + 2:]:
            m = re.match(r'\[(\d+):', p)
            if m:
                bytes_in = int(m.group(1))
            m2 = re.match(r'(\d+)\]', p)
            if m2:
                bytes_out = int(m2.group(1))

        return {
            "src_ip": src_ip,
            "src_port": int(src_port) if src_port else 0,
            "dst_ip": dst_ip,
            "dst_port": int(dst_port) if dst_port else 0,
            "protocol": proto,
            "state": pf_state,
            "is_active": is_active,
            "bytes_in": bytes_in,
            "bytes_out": bytes_out,
            "interface": interface,
            "direction": direction,
            "blocked": False,
            "app_name": "",
            "category": "",
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        }
    except Exception:
        return None


def _split_addr(addr):
    """Split '192.168.1.1:443' or '192.168.1.1' into (ip, port)."""
    if not addr:
        return None, None
    # IPv4 with port
    m = re.match(r'^(\d+\.\d+\.\d+\.\d+):(\d+)$', addr)
    if m:
        return m.group(1), m.group(2)
    # IPv4 without port
    m = re.match(r'^(\d+\.\d+\.\d+\.\d+)$', addr)
    if m:
        return m.group(1), None
    return addr, None


def _enrich_with_dpi(sessions):
    """Enrich sessions with DPI app/category data from database."""
    try:
        from lib.db import get_db, DB_PATH
        with get_db(DB_PATH) as conn:
            # Build lookup from recent DPI flows
            rows = conn.execute(
                "SELECT src_ip, dst_ip, dst_port, protocol, app_name, category "
                "FROM dpi_flows ORDER BY last_seen DESC LIMIT 5000"
            ).fetchall()
            lookup = {}
            for r in rows:
                key = (r["dst_ip"], r["dst_port"], r["protocol"])
                if key not in lookup:
                    lookup[key] = (r["app_name"], r["category"])

            # Also get device names
            devices = {}
            try:
                dev_rows = conn.execute("SELECT mac, ip, hostname FROM devices").fetchall()
                for d in dev_rows:
                    if d["ip"]:
                        devices[d["ip"]] = d["hostname"] or d["mac"] or d["ip"]
            except Exception:
                pass

        for s in sessions:
            key = (s["dst_ip"], s["dst_port"], s["protocol"])
            if key in lookup:
                s["app_name"] = lookup[key][0]
                s["category"] = lookup[key][1]
            # Add device name
            s["device_name"] = devices.get(s["src_ip"], s["src_ip"])
    except Exception as exc:
        log.warning("DPI enrichment failed: %s", exc)


def _enrich_with_dns(sessions):
    """Resolve destination IPs to hostnames via Unbound DuckDB + reverse DNS."""
    # Collect unique external destination IPs
    ext_ips = set()
    for s in sessions:
        if not _is_local_ip(s["dst_ip"]) and not s.get("dst_hostname"):
            ext_ips.add(s["dst_ip"])

    if not ext_ips:
        return

    # Use the same IP→domain map builder as stats
    ip_domain_map = _build_ip_domain_map(list(ext_ips))

    for s in sessions:
        if not s.get("dst_hostname"):
            s["dst_hostname"] = ip_domain_map.get(s["dst_ip"], "")


def _check_blocked(sessions):
    """Check which sessions match blocking rules."""
    try:
        from lib.db import get_db, DB_PATH
        with get_db(DB_PATH) as conn:
            # Check dns_rules for blocked domains
            blocked_domains = set()
            try:
                rows = conn.execute(
                    "SELECT domain FROM dns_rules WHERE action = 'block'"
                ).fetchall()
                blocked_domains = {r["domain"] for r in rows}
            except Exception:
                pass

        for s in sessions:
            hostname = s.get("dst_hostname", "")
            if hostname and hostname in blocked_domains:
                s["blocked"] = True
    except Exception as exc:
        log.warning("Blocked check failed: %s", exc)


def cmd_list(args):
    """List live sessions from pf state table."""
    sessions = _parse_pf_states()

    # Normalize direction: ensure LAN device is always src (the "device")
    for s in sessions:
        if not _is_local_ip(s["src_ip"]) and _is_local_ip(s["dst_ip"]):
            # Swap src/dst so LAN device is the source
            s["src_ip"], s["dst_ip"] = s["dst_ip"], s["src_ip"]
            s["src_port"], s["dst_port"] = s["dst_port"], s["src_port"]
            s["bytes_in"], s["bytes_out"] = s["bytes_out"], s["bytes_in"]

    # Deduplicate: merge sessions with same src_ip+dst_ip+dst_port+protocol
    seen = {}
    deduped = []
    for s in sessions:
        key = (s["src_ip"], s["dst_ip"], s["dst_port"], s["protocol"])
        if key in seen:
            existing = seen[key]
            existing["bytes_in"] += s.get("bytes_in", 0)
            existing["bytes_out"] += s.get("bytes_out", 0)
        else:
            seen[key] = s
            deduped.append(s)
    sessions = deduped

    _enrich_with_dpi(sessions)
    _enrich_with_dns(sessions)
    _check_blocked(sessions)

    # Enrich with app identification from hostname patterns
    for s in sessions:
        if not s.get("app_name") and s.get("dst_hostname"):
            s["app_name"] = _identify_app(s["dst_hostname"])
        # Port-based category fallback
        if not s.get("category") or s["category"] == "Unknown":
            if s.get("app_name"):
                s["category"] = s["app_name"]
            else:
                s["category"] = _categorize_port(s.get("dst_port", 0)) or ""

    # Apply filters
    if args.device:
        device = unquote(args.device)
        sessions = [s for s in sessions if device in (s["src_ip"], s.get("device_name", ""))]
    if args.blocked is not None:
        want_blocked = args.blocked == "1"
        sessions = [s for s in sessions if s["blocked"] == want_blocked]
    if args.app_category:
        cat = unquote(args.app_category).lower()
        sessions = [s for s in sessions if s.get("category", "").lower() == cat]
    if args.search:
        q = unquote(args.search).lower()
        sessions = [s for s in sessions if (
            q in s["src_ip"].lower() or
            q in s["dst_ip"].lower() or
            q in s.get("dst_hostname", "").lower() or
            q in s.get("app_name", "").lower() or
            q in s.get("device_name", "").lower()
        )]

    total = len(sessions)

    # Sort by bytes descending
    sessions.sort(key=lambda x: x.get("bytes_in", 0) + x.get("bytes_out", 0), reverse=True)

    # Pagination
    offset = int(args.offset) if args.offset else 0
    limit = int(args.limit) if args.limit else 100
    page = sessions[offset:offset + limit]

    # Map fields to what the frontend expects
    for s in page:
        s["device_ip"] = s.get("src_ip", "")
        s["application"] = s.get("app_name", "")
        s["app_category"] = s.get("category", "")

    return {
        "status": "ok",
        "data": {
            "sessions": page,
            "total": total,
        }
    }


# Known service hostname patterns → app name
HOSTNAME_APPS = [
    # Streaming
    (r"youtube|googlevideo|ytimg", "YouTube"),
    (r"netflix|nflx", "Netflix"),
    (r"spotify|scdn", "Spotify"),
    (r"twitch\.tv|ttvnw", "Twitch"),
    (r"disneyplus|disney\+|bamgrid", "Disney+"),
    (r"primevideo|amazonvideo|atv-ps", "Prime Video"),
    # Social
    (r"facebook|fbcdn|fb\.com", "Facebook"),
    (r"instagram|cdninstagram", "Instagram"),
    (r"twitter|twimg|x\.com", "X/Twitter"),
    (r"tiktok|tiktokcdn|musical\.ly", "TikTok"),
    (r"snapchat|snap-storage|sc-cdn", "Snapchat"),
    (r"reddit|redd\.it|redditstatic", "Reddit"),
    (r"whatsapp|wa\.me", "WhatsApp"),
    (r"telegram|t\.me|tdesktop", "Telegram"),
    (r"discord|discordapp", "Discord"),
    # Productivity
    (r"microsoft|office|outlook|live\.com|msedge|bing|windowsupdate|msn\.com|skype", "Microsoft"),
    (r"google|googleapis|gstatic|goog|gmail|firebase|crashlytics|android\.clients|gvt[0-9]|ggpht|chromium|doubleclick|googlesyndication|googleadservices|googleusercontent", "Google"),
    (r"apple|icloud|mzstatic|apple-dns|itunes|push-apple|apple\.com|swcdn\.apple", "Apple"),
    (r"amazon(?!video)|aws|cloudfront|amazonaws|alexa\.", "Amazon/AWS"),
    (r"zoom\.us|zoom\.com", "Zoom"),
    (r"slack\.com|slack-edge", "Slack"),
    # Gaming
    (r"steam|steampowered|valve", "Steam"),
    (r"playstation|orbis|sie\.com", "PlayStation"),
    (r"xbox|xboxlive", "Xbox"),
    (r"epicgames|fortnite", "Epic Games"),
    # Infrastructure
    (r"cloudflare|cf-|1\.1\.1\.1", "Cloudflare"),
    (r"akamai|akam|edgekey", "Akamai CDN"),
    (r"fastly|fastlylb", "Fastly CDN"),
    # VPN/Security
    (r"surfshark", "Surfshark VPN"),
    (r"nordvpn|nord-", "NordVPN"),
    (r"openvpn", "OpenVPN"),
]

PORT_CATEGORIES = {
    443: "Web (HTTPS)", 80: "Web (HTTP)", 8080: "Web (Proxy)", 8443: "Web (HTTPS Alt)",
    53: "DNS", 853: "DNS over TLS",
    22: "SSH", 23: "Telnet", 3389: "Remote Desktop",
    25: "Email (SMTP)", 465: "Email (SMTPS)", 587: "Email (Submission)",
    110: "Email (POP3)", 143: "Email (IMAP)", 993: "Email (IMAPS)", 995: "Email (POP3S)",
    21: "FTP", 990: "FTPS",
    1194: "OpenVPN", 51820: "WireGuard", 500: "IPSec", 4500: "IPSec NAT-T",
    5060: "VoIP (SIP)", 5061: "VoIP (SIPS)",
    123: "NTP", 161: "SNMP", 162: "SNMP Trap",
    3306: "Database (MySQL)", 5432: "Database (PostgreSQL)", 6379: "Database (Redis)",
    1883: "IoT (MQTT)", 8883: "IoT (MQTT TLS)",
    5353: "mDNS", 1900: "UPnP/SSDP",
    9100: "Printing",
}


def _get_device_names():
    """Load device hostname/MAC from database."""
    devices = {}
    try:
        from lib.db import get_db, DB_PATH
        with get_db(DB_PATH) as conn:
            rows = conn.execute("SELECT mac, ip, hostname FROM devices").fetchall()
            for d in rows:
                if d["ip"]:
                    devices[d["ip"]] = d["hostname"] or d["mac"] or d["ip"]
    except Exception:
        pass
    return devices


DUCKDB_PATH = "/var/unbound/data/unbound.duckdb"


def _build_ip_domain_map(ips=None):
    """Build IP→domain map from Unbound DuckDB query log.
    Resolves recent queried domains to IPs via local DNS cache.
    Falls back to reverse DNS if DuckDB unavailable.
    """
    import socket
    ip_to_domain = {}

    # Strategy 1: Unbound DuckDB (has 500k+ DNS queries)
    domains = set()
    try:
        import duckdb
        conn = duckdb.connect(DUCKDB_PATH, read_only=True)
        # Get recent unique domains (last ~1 hour)
        cutoff = int(datetime.now().timestamp()) - 3600
        rows = conn.execute(
            "SELECT DISTINCT domain FROM query "
            "WHERE time > ? AND action = 0 AND rcode = 0 "
            "ORDER BY time DESC LIMIT 500",
            [cutoff]
        ).fetchall()
        for r in rows:
            d = r[0].rstrip(".")  # Remove trailing dot
            if d:
                domains.add(d)
        conn.close()
    except Exception as exc:
        log.warning("DuckDB read failed: %s", exc)

    # Resolve domains to IPs via local DNS (fast, cached by Unbound)
    if domains:
        socket.setdefaulttimeout(0.3)
        for domain in domains:
            try:
                results = socket.getaddrinfo(domain, None, socket.AF_INET)
                for res in results:
                    ip = res[4][0]
                    if ip and ip not in ip_to_domain:
                        ip_to_domain[ip] = domain
            except (socket.gaierror, OSError, TimeoutError):
                pass

    if ip_to_domain:
        return ip_to_domain

    # Strategy 2: Batch reverse DNS fallback
    if not ips:
        return ip_to_domain

    from concurrent.futures import ThreadPoolExecutor, as_completed

    def _reverse_one(ip):
        try:
            socket.setdefaulttimeout(0.5)
            hostname = socket.gethostbyaddr(ip)[0]
            if hostname and hostname != ip:
                return ip, hostname
        except (socket.herror, socket.gaierror, OSError):
            pass
        return ip, None

    with ThreadPoolExecutor(max_workers=20) as executor:
        futures = {executor.submit(_reverse_one, ip): ip for ip in ips}
        for future in as_completed(futures, timeout=5):
            try:
                ip, hostname = future.result()
                if hostname:
                    ip_to_domain[ip] = hostname
            except Exception:
                pass

    return ip_to_domain


def _is_local_ip(ip):
    """Check if IP is a private/LAN address."""
    if not ip:
        return False
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    try:
        a, b = int(parts[0]), int(parts[1])
    except ValueError:
        return False
    return (a == 10 or (a == 172 and 16 <= b <= 31) or (a == 192 and b == 168))


def _identify_app(hostname):
    """Identify app/service from hostname using pattern matching."""
    if not hostname:
        return ""
    hostname_lower = hostname.lower()
    for pattern, app_name in HOSTNAME_APPS:
        if re.search(pattern, hostname_lower):
            return app_name
    return ""


def _categorize_port(port):
    """Fallback port-based category when DPI is unavailable."""
    return PORT_CATEGORIES.get(port, "")


def _get_blocked_count():
    """Count blocked connections from DNS rules."""
    try:
        from lib.db import get_db, DB_PATH
        with get_db(DB_PATH) as conn:
            row = conn.execute(
                "SELECT COUNT(*) as cnt FROM dns_rules WHERE action = 'block'"
            ).fetchone()
            return row["cnt"] if row else 0
    except Exception:
        return 0


def cmd_stats(args):
    """Return session statistics with device names, DNS hostnames, and categories."""
    sessions = _parse_pf_states()
    _enrich_with_dpi(sessions)

    # Load device names for enrichment
    device_names = _get_device_names()

    # Collect unique external IPs for DNS resolution
    ext_ips = set()
    for s in sessions:
        if not _is_local_ip(s["dst_ip"]):
            ext_ips.add(s["dst_ip"])

    # Build IP→domain map (DNS query log or reverse DNS fallback)
    ip_domain_map = _build_ip_domain_map(list(ext_ips))

    total = len(sessions)
    tcp_count = sum(1 for s in sessions if s["protocol"] == "TCP")
    udp_count = sum(1 for s in sessions if s["protocol"] == "UDP")
    blocked_count = _get_blocked_count()

    # Top devices by connection count (LAN devices only, with names)
    device_counts = {}
    device_bytes = {}
    for s in sessions:
        ip = s["src_ip"]
        if not _is_local_ip(ip):
            # For inbound connections, count the dst if it's local
            ip = s["dst_ip"]
            if not _is_local_ip(ip):
                continue
        device_counts[ip] = device_counts.get(ip, 0) + 1
        device_bytes[ip] = device_bytes.get(ip, 0) + s.get("bytes_in", 0) + s.get("bytes_out", 0)
    top_devices_raw = sorted(device_counts.items(), key=lambda x: x[1], reverse=True)[:10]

    # Collect unique external destination IPs
    dst_ip_counts = {}
    for s in sessions:
        dst_ip = s["dst_ip"]
        if _is_local_ip(dst_ip):
            continue
        dst_ip_counts[dst_ip] = dst_ip_counts.get(dst_ip, 0) + 1

    top_dst_raw = sorted(dst_ip_counts.items(), key=lambda x: x[1], reverse=True)

    # Top domains (resolved from DNS query log)
    top_domains = [
        (ip_domain_map.get(ip, ip), count) for ip, count in top_dst_raw[:10]
    ]

    # --- DNS-based app/domain stats (works even behind VPN) ---
    # Query DuckDB directly for accurate domain/app stats from DNS queries
    dns_domain_counts = {}
    dns_app_counts = {}
    try:
        import duckdb
        conn = duckdb.connect(DUCKDB_PATH, read_only=True)
        cutoff = int(datetime.now().timestamp()) - 3600
        rows = conn.execute(
            "SELECT domain, COUNT(*) as cnt FROM query "
            "WHERE time > ? AND action = 0 AND rcode = 0 "
            "GROUP BY domain ORDER BY cnt DESC LIMIT 50",
            [cutoff]
        ).fetchall()
        conn.close()

        for r in rows:
            domain = r[0].rstrip(".")
            count = r[1]
            # Skip reverse DNS lookups and internal domains
            if not domain or domain.endswith(".arpa") or domain.endswith(".local"):
                continue
            dns_domain_counts[domain] = count
            app = _identify_app(domain)
            if app:
                dns_app_counts[app] = dns_app_counts.get(app, 0) + count
    except Exception as exc:
        log.warning("DuckDB stats query failed: %s", exc)

    # Use DNS-based domains if pf-based domains are mostly raw IPs
    resolved_count = sum(1 for d in top_domains if not re.match(r'^\d+\.\d+\.\d+\.\d+$', d[0]))
    if resolved_count < 3 and dns_domain_counts:
        # Replace with DNS query-based top domains
        top_domains = [
            (domain, count) for domain, count in
            sorted(dns_domain_counts.items(), key=lambda x: x[1], reverse=True)[:10]
        ]

    # Top apps — prefer DNS-based (works behind VPN)
    app_counts = dict(dns_app_counts)
    # Also add pf-state based app matches
    for ip, count in dst_ip_counts.items():
        domain = ip_domain_map.get(ip, "")
        app = _identify_app(domain)
        if app and app not in app_counts:
            app_counts[app] = app_counts.get(app, 0) + count
    top_apps = sorted(app_counts.items(), key=lambda x: x[1], reverse=True)[:10]

    # Top categories — use DNS-based app counts (works behind VPN)
    # Group by broader categories derived from app names
    APP_TO_CATEGORY = {
        "YouTube": "Streaming", "Netflix": "Streaming", "Spotify": "Streaming",
        "Twitch": "Streaming", "Disney+": "Streaming", "Prime Video": "Streaming",
        "Facebook": "Social", "Instagram": "Social", "X/Twitter": "Social",
        "TikTok": "Social", "Snapchat": "Social", "Reddit": "Social",
        "WhatsApp": "Messaging", "Telegram": "Messaging", "Discord": "Messaging",
        "Microsoft": "Productivity", "Google": "Productivity", "Zoom": "Productivity",
        "Slack": "Productivity", "Apple": "Productivity",
        "Steam": "Gaming", "PlayStation": "Gaming", "Xbox": "Gaming", "Epic Games": "Gaming",
        "Amazon/AWS": "Cloud/CDN", "Cloudflare": "Cloud/CDN", "Akamai CDN": "Cloud/CDN",
        "Fastly CDN": "Cloud/CDN",
        "Surfshark VPN": "VPN", "NordVPN": "VPN", "OpenVPN": "VPN",
    }
    cat_counts = {}
    if app_counts:
        for app, count in app_counts.items():
            cat = APP_TO_CATEGORY.get(app, app)
            cat_counts[cat] = cat_counts.get(cat, 0) + count
    else:
        # Fallback to port-based if no app data
        for s in sessions:
            cat = s.get("category") or _categorize_port(s.get("dst_port", 0)) or "Other"
            cat_counts[cat] = cat_counts.get(cat, 0) + 1
    top_categories = sorted(cat_counts.items(), key=lambda x: x[1], reverse=True)[:10]

    return {
        "status": "ok",
        "data": {
            "total_connections": total,
            "tcp_connections": tcp_count,
            "udp_connections": udp_count,
            "blocked_count": blocked_count,
            "today": {
                "total": total,
                "blocked": blocked_count,
                "top_devices": [
                    {
                        "ip": d[0],
                        "name": device_names.get(d[0], d[0]),
                        "count": d[1],
                        "bytes": device_bytes.get(d[0], 0),
                    }
                    for d in top_devices_raw
                ],
                "top_domains": [{"domain": d[0], "count": d[1]} for d in top_domains],
                "top_apps": [{"app": a[0], "count": a[1]} for a in top_apps],
                "top_categories": [{"category": c[0], "count": c[1]} for c in top_categories],
            }
        }
    }


def cmd_purge(args):
    """Purge old data (placeholder)."""
    return {"status": "ok", "message": "purge not needed for live state table"}


def main():
    if len(sys.argv) == 2:
        arg = sys.argv[1]
        parts = arg.replace(',', ' ').split()
        sys.argv = [sys.argv[0]] + [unquote(p.strip("'\"")) for p in parts]

    parser = argparse.ArgumentParser(description="NetShield session monitor")
    sub = parser.add_subparsers(dest="action")

    p_list = sub.add_parser("list", help="List live sessions")
    p_list.add_argument("--device", default=None)
    p_list.add_argument("--blocked", default=None)
    p_list.add_argument("--app_category", default=None)
    p_list.add_argument("--search", default=None)
    p_list.add_argument("--start_date", default=None)
    p_list.add_argument("--end_date", default=None)
    p_list.add_argument("--limit", default="100")
    p_list.add_argument("--offset", default="0")

    sub.add_parser("stats", help="Session statistics")

    p_purge = sub.add_parser("purge", help="Purge old data")
    p_purge.add_argument("--days", default="7")

    args = parser.parse_args()

    if not args.action:
        print(json.dumps({"status": "error", "message": "no action specified"}))
        return

    try:
        if args.action == "list":
            result = cmd_list(args)
        elif args.action == "stats":
            result = cmd_stats(args)
        elif args.action == "purge":
            result = cmd_purge(args)
        else:
            result = {"status": "error", "message": f"unknown action: {args.action}"}

        print(json.dumps(result, default=str))
    except Exception as exc:
        log.exception("Unhandled error")
        print(json.dumps({"status": "error", "message": str(exc)}))


if __name__ == "__main__":
    main()
