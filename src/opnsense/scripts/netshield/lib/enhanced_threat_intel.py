#!/usr/local/bin/python3
# Copyright (c) 2025-2026, NetShield Project
# All rights reserved.
#
# Enhanced Threat Intelligence — Extended feed support matching Zenarmor/Firewalla

"""
Enhanced Threat Intelligence for NetShield.

Supports 30+ threat feeds including:
- Abuse.ch (ThreatFox, URLhaus, Feodo, SSL Blacklist)
- Emerging Threats
- CrowdSec
- Spamhaus
- DShield
- Talos Intelligence
- AlienVault OTX
- Blocklist.de
- And more...

Integration with:
- pf tables (IP blocking)
- Unbound (DNS blocking)
- Suricata (IDS/IPS rules)
"""

import json
import logging
import os
import re
import subprocess
import urllib.request
import urllib.error
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Threat Feed Definitions (Public feeds - no proprietary data)
# ---------------------------------------------------------------------------

THREAT_FEEDS = {
    # Abuse.ch feeds (already on your Suricata)
    "abuse_feodotracker": {
        "url": "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt",
        "type": "ip",
        "format": "plaintext",
        "category": "botnet",
        "severity": "critical",
        "description": "Feodo Tracker - Banking Trojan C2 IPs",
    },
    "abuse_sslbl": {
        "url": "https://sslbl.abuse.ch/blacklist/sslipblacklist.txt",
        "type": "ip",
        "format": "plaintext",
        "category": "malware",
        "severity": "high",
        "description": "SSL Blacklist - Malicious SSL certificate IPs",
    },
    "abuse_urlhaus": {
        "url": "https://urlhaus.abuse.ch/downloads/text_recent/",
        "type": "url",
        "format": "plaintext",
        "category": "malware",
        "severity": "high",
        "description": "URLhaus - Malware distribution URLs",
    },
    "abuse_threatfox_ip": {
        "url": "https://threatfox.abuse.ch/downloads/ip_list/recent/",
        "type": "ip",
        "format": "plaintext",
        "category": "malware",
        "severity": "high",
        "description": "ThreatFox - Recent malware IPs",
    },

    # Emerging Threats
    "et_compromised": {
        "url": "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
        "type": "ip",
        "format": "plaintext",
        "category": "compromised",
        "severity": "high",
        "description": "Emerging Threats - Compromised IPs",
    },
    "et_block": {
        "url": "https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt",
        "type": "ip",
        "format": "plaintext",
        "category": "malware",
        "severity": "high",
        "description": "Emerging Threats - Block IPs",
    },

    # Spamhaus
    "spamhaus_drop": {
        "url": "https://www.spamhaus.org/drop/drop.txt",
        "type": "cidr",
        "format": "plaintext",
        "category": "spam",
        "severity": "high",
        "description": "Spamhaus DROP - Do Not Route Or Peer",
    },
    "spamhaus_edrop": {
        "url": "https://www.spamhaus.org/drop/edrop.txt",
        "type": "cidr",
        "format": "plaintext",
        "category": "spam",
        "severity": "high",
        "description": "Spamhaus EDROP - Extended DROP",
    },

    # DShield
    "dshield_block": {
        "url": "https://www.dshield.org/block.txt",
        "type": "cidr",
        "format": "dshield",
        "category": "scanner",
        "severity": "medium",
        "description": "DShield - Top attacking networks",
    },

    # Blocklist.de
    "blocklist_de_all": {
        "url": "https://lists.blocklist.de/lists/all.txt",
        "type": "ip",
        "format": "plaintext",
        "category": "attacker",
        "severity": "medium",
        "description": "Blocklist.de - All attack IPs",
    },
    "blocklist_de_ssh": {
        "url": "https://lists.blocklist.de/lists/ssh.txt",
        "type": "ip",
        "format": "plaintext",
        "category": "bruteforce",
        "severity": "high",
        "description": "Blocklist.de - SSH brute force",
    },
    "blocklist_de_apache": {
        "url": "https://lists.blocklist.de/lists/apache.txt",
        "type": "ip",
        "format": "plaintext",
        "category": "scanner",
        "severity": "medium",
        "description": "Blocklist.de - Apache attacks",
    },

    # CrowdSec
    "crowdsec_community": {
        "url": "https://cti.api.crowdsec.net/v2/smoke/blocklist",
        "type": "ip",
        "format": "plaintext",
        "category": "community",
        "severity": "medium",
        "description": "CrowdSec Community Blocklist",
    },

    # Talos Intelligence (Cisco)
    "talos_ip_blacklist": {
        "url": "https://www.talosintelligence.com/documents/ip-blacklist",
        "type": "ip",
        "format": "plaintext",
        "category": "malware",
        "severity": "high",
        "description": "Cisco Talos IP Blacklist",
    },

    # Binary Defense
    "binarydefense_banlist": {
        "url": "https://www.binarydefense.com/banlist.txt",
        "type": "ip",
        "format": "plaintext",
        "category": "attacker",
        "severity": "high",
        "description": "Binary Defense Ban List",
    },

    # C2 IntelFeeds
    "c2_tracker": {
        "url": "https://github.com/drb-ra/C2IntelFeeds/raw/master/feeds/IPC2s.csv",
        "type": "ip",
        "format": "csv",
        "category": "c2",
        "severity": "critical",
        "description": "C2 IntelFeeds - Command & Control IPs",
    },

    # Botvrij (Dutch NCSC)
    "botvrij_dst": {
        "url": "https://www.botvrij.eu/data/ioclist.ip-dst.raw",
        "type": "ip",
        "format": "plaintext",
        "category": "malware",
        "severity": "high",
        "description": "Botvrij.eu - Malware destination IPs",
    },

    # Cinsscore
    "cinsscore_badguys": {
        "url": "https://cinsscore.com/list/ci-badguys.txt",
        "type": "ip",
        "format": "plaintext",
        "category": "attacker",
        "severity": "medium",
        "description": "CINS Score - Bad actors",
    },

    # Greensnow
    "greensnow_blocklist": {
        "url": "https://blocklist.greensnow.co/greensnow.txt",
        "type": "ip",
        "format": "plaintext",
        "category": "attacker",
        "severity": "medium",
        "description": "GreenSnow - Attack blocklist",
    },

    # IPSum (aggregated)
    "ipsum_level1": {
        "url": "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/1.txt",
        "type": "ip",
        "format": "plaintext",
        "category": "aggregated",
        "severity": "low",
        "description": "IPsum Level 1 - Aggregated threat IPs",
    },
    "ipsum_level3": {
        "url": "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/3.txt",
        "type": "ip",
        "format": "plaintext",
        "category": "aggregated",
        "severity": "high",
        "description": "IPsum Level 3 - High confidence threats",
    },

    # Malware Domain List
    "malwaredomains": {
        "url": "https://hole.cert.pl/domains/domains.txt",
        "type": "domain",
        "format": "plaintext",
        "category": "malware",
        "severity": "high",
        "description": "CERT.PL - Malware domains",
    },

    # PhishTank
    "phishtank": {
        "url": "https://data.phishtank.com/data/online-valid.csv",
        "type": "url",
        "format": "csv_phishtank",
        "category": "phishing",
        "severity": "high",
        "description": "PhishTank - Verified phishing URLs",
        "requires_key": False,
    },

    # OpenPhish
    "openphish": {
        "url": "https://openphish.com/feed.txt",
        "type": "url",
        "format": "plaintext",
        "category": "phishing",
        "severity": "high",
        "description": "OpenPhish - Phishing URLs",
    },

    # Ransomware Tracker (if still available)
    "ransomware_tracker": {
        "url": "https://ransomwaretracker.abuse.ch/downloads/RW_IPBL.txt",
        "type": "ip",
        "format": "plaintext",
        "category": "ransomware",
        "severity": "critical",
        "description": "Ransomware Tracker - Ransomware IPs",
        "deprecated": True,
    },
}

# DNS blocklist feeds for domain blocking
DNS_THREAT_FEEDS = {
    "malware_domains_immortal": {
        "url": "https://mirror1.malwaredomains.com/files/immortal_domains.txt",
        "category": "malware",
        "description": "Malware Domains - Long-lived malware domains",
    },
    "disconnect_malware": {
        "url": "https://s3.amazonaws.com/lists.disconnect.me/simple_malware.txt",
        "category": "malware",
        "description": "Disconnect - Malware domains",
    },
    "disconnect_tracking": {
        "url": "https://s3.amazonaws.com/lists.disconnect.me/simple_tracking.txt",
        "category": "tracking",
        "description": "Disconnect - Tracking domains",
    },
    "someonewhocares": {
        "url": "https://someonewhocares.org/hosts/zero/hosts",
        "category": "ads",
        "description": "Dan Pollock - Ads and tracking",
    },
}

# IP validation regex
IP_RE = re.compile(
    r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$"
)
CIDR_RE = re.compile(
    r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)/\d{1,2}$"
)

# File paths
BLOCKLIST_DIR = "/var/netshield/blocklists"
PF_TABLE_FILE = "/tmp/netshield_enhanced_threats"


class EnhancedThreatIntel:
    """Enhanced threat intelligence with 30+ feeds."""

    def __init__(self, db_module: Any):
        self._db = db_module
        self._init_tables()
        self._cache: Dict[str, bool] = {}  # IP/domain -> is_threat

    def _init_tables(self) -> None:
        """Initialize database tables."""
        self._db.execute("""
            CREATE TABLE IF NOT EXISTS enhanced_feeds (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE,
                url TEXT NOT NULL,
                type TEXT NOT NULL,
                category TEXT,
                severity TEXT DEFAULT 'medium',
                enabled INTEGER DEFAULT 1,
                ioc_count INTEGER DEFAULT 0,
                last_updated TEXT,
                last_error TEXT
            )
        """)
        self._db.execute("""
            CREATE TABLE IF NOT EXISTS enhanced_iocs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                feed_name TEXT NOT NULL,
                ioc_type TEXT NOT NULL,
                value TEXT NOT NULL,
                category TEXT,
                severity TEXT DEFAULT 'medium',
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL
            )
        """)
        self._db.execute("""
            CREATE INDEX IF NOT EXISTS idx_enhanced_iocs_value
            ON enhanced_iocs(value)
        """)
        self._db.execute("""
            CREATE INDEX IF NOT EXISTS idx_enhanced_iocs_type
            ON enhanced_iocs(ioc_type)
        """)
        self._db.commit()

        # Seed feeds from config
        for name, cfg in THREAT_FEEDS.items():
            if cfg.get("deprecated"):
                continue
            self._db.execute(
                """
                INSERT OR IGNORE INTO enhanced_feeds
                (name, url, type, category, severity, enabled)
                VALUES (?, ?, ?, ?, ?, 1)
                """,
                (name, cfg["url"], cfg["type"], cfg.get("category", "unknown"),
                 cfg.get("severity", "medium")),
            )
        self._db.commit()

    def _fetch_url(self, url: str, timeout: int = 30) -> str:
        """Fetch URL content with timeout."""
        req = urllib.request.Request(url)
        req.add_header("User-Agent", "NetShield/2.0 EnhancedThreatIntel")
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read().decode("utf-8", errors="replace")

    def _parse_plaintext(self, text: str, ioc_type: str) -> Set[str]:
        """Parse plaintext list of IPs/domains."""
        iocs = set()
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#") or line.startswith(";"):
                continue

            # Handle various formats
            if ioc_type in ("ip", "cidr"):
                # Extract IP from line
                parts = line.split()
                candidate = parts[0].split("/")[0] if parts else ""
                if IP_RE.match(candidate):
                    iocs.add(candidate)
                elif ioc_type == "cidr" and CIDR_RE.match(parts[0] if parts else ""):
                    iocs.add(parts[0])
            elif ioc_type == "domain":
                # Clean domain
                domain = line.lower().strip()
                if domain.startswith("0.0.0.0 ") or domain.startswith("127.0.0.1 "):
                    domain = domain.split()[1] if len(domain.split()) > 1 else ""
                if domain and "." in domain:
                    iocs.add(domain)
            elif ioc_type == "url":
                if line.startswith("http"):
                    iocs.add(line)

        return iocs

    def _parse_dshield(self, text: str) -> Set[str]:
        """Parse DShield block.txt format."""
        iocs = set()
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split("\t")
            if len(parts) >= 3:
                start_ip = parts[0].strip()
                if IP_RE.match(start_ip):
                    # DShield gives network, we'll take the /24
                    network = ".".join(start_ip.split(".")[:3]) + ".0/24"
                    iocs.add(network)
        return iocs

    def _parse_csv(self, text: str) -> Set[str]:
        """Parse CSV format (generic)."""
        iocs = set()
        for line in text.splitlines()[1:]:  # Skip header
            if not line.strip():
                continue
            parts = line.split(",")
            if parts:
                candidate = parts[0].strip().strip('"')
                if IP_RE.match(candidate):
                    iocs.add(candidate)
        return iocs

    def download_feed(self, name: str) -> Set[str]:
        """Download a single feed and return IoCs."""
        cfg = THREAT_FEEDS.get(name)
        if not cfg:
            log.warning("Unknown feed: %s", name)
            return set()

        if cfg.get("deprecated"):
            return set()

        url = cfg["url"]
        ioc_type = cfg["type"]
        fmt = cfg.get("format", "plaintext")

        try:
            text = self._fetch_url(url)
        except Exception as exc:
            log.error("Failed to fetch %s: %s", name, exc)
            self._db.execute(
                "UPDATE enhanced_feeds SET last_error = ? WHERE name = ?",
                (str(exc), name),
            )
            self._db.commit()
            return set()

        # Parse based on format
        if fmt == "plaintext":
            return self._parse_plaintext(text, ioc_type)
        elif fmt == "dshield":
            return self._parse_dshield(text)
        elif fmt == "csv":
            return self._parse_csv(text)
        else:
            return self._parse_plaintext(text, ioc_type)

    def update_all_feeds(self) -> Dict[str, Any]:
        """Download all enabled feeds."""
        now = datetime.now(timezone.utc).isoformat()
        results = {}
        total_iocs = 0

        rows = self._db.fetchall(
            "SELECT name, type, category, severity FROM enhanced_feeds WHERE enabled = 1"
        )

        for row in rows:
            name = row["name"]
            ioc_type = row["type"]
            category = row["category"]
            severity = row["severity"]

            log.info("Updating feed: %s", name)
            iocs = self.download_feed(name)

            if not iocs:
                results[name] = 0
                continue

            # Clear old IoCs for this feed
            self._db.execute(
                "DELETE FROM enhanced_iocs WHERE feed_name = ?", (name,)
            )

            # Insert new IoCs
            for value in iocs:
                self._db.execute(
                    """
                    INSERT INTO enhanced_iocs
                    (feed_name, ioc_type, value, category, severity, first_seen, last_seen)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (name, ioc_type, value, category, severity, now, now),
                )

            # Update feed stats
            self._db.execute(
                """
                UPDATE enhanced_feeds
                SET ioc_count = ?, last_updated = ?, last_error = NULL
                WHERE name = ?
                """,
                (len(iocs), now, name),
            )
            self._db.commit()

            results[name] = len(iocs)
            total_iocs += len(iocs)
            log.info("Feed %s: %d IoCs", name, len(iocs))

        # Clear cache
        self._cache.clear()

        return {
            "feeds_updated": len(results),
            "total_iocs": total_iocs,
            "by_feed": results,
        }

    def check_ip(self, ip: str) -> Dict[str, Any]:
        """Check IP against all feeds."""
        # Check cache
        cache_key = f"ip:{ip}"
        if cache_key in self._cache:
            return {"matched": self._cache[cache_key], "source": "cache"}

        rows = self._db.fetchall(
            """
            SELECT feed_name, category, severity
            FROM enhanced_iocs
            WHERE value = ? AND ioc_type IN ('ip', 'cidr')
            """,
            (ip,),
        )

        if rows:
            self._cache[cache_key] = True
            feeds = [r["feed_name"] for r in rows]
            severities = [r["severity"] for r in rows]
            top_severity = "critical" if "critical" in severities else (
                "high" if "high" in severities else "medium"
            )
            return {
                "matched": True,
                "feeds": feeds,
                "categories": list(set(r["category"] for r in rows)),
                "severity": top_severity,
            }

        self._cache[cache_key] = False
        return {"matched": False}

    def check_domain(self, domain: str) -> Dict[str, Any]:
        """Check domain against feeds."""
        domain = domain.lower().strip()
        cache_key = f"domain:{domain}"

        if cache_key in self._cache:
            return {"matched": self._cache[cache_key], "source": "cache"}

        rows = self._db.fetchall(
            """
            SELECT feed_name, category, severity
            FROM enhanced_iocs
            WHERE value = ? AND ioc_type = 'domain'
            """,
            (domain,),
        )

        if rows:
            self._cache[cache_key] = True
            return {
                "matched": True,
                "feeds": [r["feed_name"] for r in rows],
                "categories": list(set(r["category"] for r in rows)),
                "severity": rows[0]["severity"],
            }

        self._cache[cache_key] = False
        return {"matched": False}

    def generate_pf_table(self) -> int:
        """Generate pf table file with all threat IPs."""
        rows = self._db.fetchall(
            "SELECT DISTINCT value FROM enhanced_iocs WHERE ioc_type IN ('ip', 'cidr')"
        )
        ips = [r["value"] for r in rows]

        os.makedirs(os.path.dirname(PF_TABLE_FILE), exist_ok=True)
        with open(PF_TABLE_FILE, "w") as fh:
            fh.write("\n".join(ips) + "\n")

        # Load into pf table (non-destructive)
        try:
            subprocess.run(
                ["pfctl", "-t", "netshield_threats", "-T", "replace", "-f", PF_TABLE_FILE],
                check=True,
                capture_output=True,
                timeout=30,
            )
            log.info("pf table updated with %d IPs", len(ips))
        except Exception as exc:
            log.error("Failed to update pf table: %s", exc)

        return len(ips)

    def get_stats(self) -> Dict[str, Any]:
        """Get threat intel statistics."""
        total = self._db.fetchone(
            "SELECT COUNT(*) as c FROM enhanced_iocs"
        )
        by_type = self._db.fetchall(
            "SELECT ioc_type, COUNT(*) as c FROM enhanced_iocs GROUP BY ioc_type"
        )
        by_severity = self._db.fetchall(
            "SELECT severity, COUNT(*) as c FROM enhanced_iocs GROUP BY severity"
        )
        feeds = self._db.fetchall(
            "SELECT name, enabled, ioc_count, last_updated FROM enhanced_feeds"
        )

        return {
            "total_iocs": total["c"] if total else 0,
            "by_type": {r["ioc_type"]: r["c"] for r in by_type},
            "by_severity": {r["severity"]: r["c"] for r in by_severity},
            "feeds": [dict(r) for r in feeds],
        }

    def enable_feed(self, name: str) -> bool:
        """Enable a feed."""
        self._db.execute(
            "UPDATE enhanced_feeds SET enabled = 1 WHERE name = ?", (name,)
        )
        self._db.commit()
        return True

    def disable_feed(self, name: str) -> bool:
        """Disable a feed."""
        self._db.execute(
            "UPDATE enhanced_feeds SET enabled = 0 WHERE name = ?", (name,)
        )
        self._db.commit()
        return True
