#!/usr/local/bin/python3

# Copyright (c) 2025-2026, NetShield Contributors
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice,
#    this list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
# SPDX-License-Identifier: BSD-2-Clause

"""
Threat Intelligence Feed Manager — Downloads and manages IoC feeds for NetShield.
Supports IP blocklists and URL threat feeds from multiple threat intel sources.
"""

import json
import logging
import os
import re
import subprocess
import urllib.request
import urllib.error
from datetime import datetime, timezone

log = logging.getLogger(__name__)

THREAT_FEEDS = {
    # === Existing Feeds ===
    "crowdsec": {
        "url": "https://cti.api.crowdsec.net/v2/smoke/blocklist",
        "type": "ip",
        "format": "plaintext",
    },
    "abuseipdb": {
        "url": "https://api.abuseipdb.com/api/v2/blacklist",
        "type": "ip",
        "format": "json",
        "api_key_required": True,
    },
    "urlhaus": {
        "url": "https://urlhaus.abuse.ch/downloads/text_recent/",
        "type": "url",
        "format": "plaintext",
    },
    "feodo_tracker": {
        "url": "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt",
        "type": "ip",
        "format": "plaintext",
    },
    "emerging_threats": {
        "url": "https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt",
        "type": "ip",
        "format": "plaintext",
    },
    # === NEW FREE FEEDS ===
    "spamhaus_drop": {
        "url": "https://www.spamhaus.org/drop/drop.txt",
        "type": "cidr",
        "format": "plaintext",
        "description": "Spamhaus Don't Route Or Peer - worst offenders",
    },
    "spamhaus_edrop": {
        "url": "https://www.spamhaus.org/drop/edrop.txt",
        "type": "cidr",
        "format": "plaintext",
        "description": "Spamhaus Extended DROP - hijacked netblocks",
    },
    "blocklist_de": {
        "url": "https://lists.blocklist.de/lists/all.txt",
        "type": "ip",
        "format": "plaintext",
        "description": "Blocklist.de - reported attack IPs",
    },
    "cins_army": {
        "url": "https://cinsscore.com/list/ci-badguys.txt",
        "type": "ip",
        "format": "plaintext",
        "description": "CINS Army - collective intelligence threat IPs",
    },
    "ssl_blacklist": {
        "url": "https://sslbl.abuse.ch/blacklist/sslipblacklist.txt",
        "type": "ip",
        "format": "plaintext",
        "description": "SSL Blacklist - botnet C2 servers using SSL",
    },
    "openphish": {
        "url": "https://openphish.com/feed.txt",
        "type": "url",
        "format": "plaintext",
        "description": "OpenPhish - phishing URLs",
    },
    "malware_domains": {
        "url": "https://mirror1.malwaredomains.com/files/justdomains",
        "type": "domain",
        "format": "plaintext",
        "description": "Malware Domain List - known malware domains",
    },
    "ransomware_tracker": {
        "url": "https://ransomwaretracker.abuse.ch/downloads/RW_DOMBL.txt",
        "type": "domain",
        "format": "plaintext",
        "description": "Ransomware Tracker domains (historical)",
    },
    # === ADDITIONAL ZENARMOR-STYLE FEEDS ===
    "threatfox_iocs": {
        "url": "https://threatfox.abuse.ch/downloads/hostfile/",
        "type": "domain",
        "format": "hostfile",
        "description": "ThreatFox - malware IOCs from abuse.ch",
    },
    "alienvault_reputation": {
        "url": "https://reputation.alienvault.com/reputation.generic",
        "type": "ip",
        "format": "plaintext",
        "description": "AlienVault OTX IP reputation",
    },
    "dshield_block": {
        "url": "https://www.dshield.org/block.txt",
        "type": "cidr",
        "format": "dshield",
        "description": "DShield recommended block list",
    },
    "firehol_level1": {
        "url": "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset",
        "type": "cidr",
        "format": "plaintext",
        "description": "FireHOL Level 1 - high confidence malicious IPs",
    },
    "firehol_level2": {
        "url": "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level2.netset",
        "type": "cidr",
        "format": "plaintext",
        "description": "FireHOL Level 2 - attacks and spyware",
    },
    "stamparm_ipsum": {
        "url": "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/1.txt",
        "type": "ip",
        "format": "plaintext",
        "description": "IPsum Level 1 - high confidence threat IPs",
    },
    "binarydefense": {
        "url": "https://www.binarydefense.com/banlist.txt",
        "type": "ip",
        "format": "plaintext",
        "description": "Binary Defense IP ban list",
    },
    "greensnow": {
        "url": "https://blocklist.greensnow.co/greensnow.txt",
        "type": "ip",
        "format": "plaintext",
        "description": "GreenSnow attackers blocklist",
    },
    "bruteforceblocker": {
        "url": "https://danger.rulez.sk/projects/bruteforceblocker/blist.php",
        "type": "ip",
        "format": "plaintext",
        "description": "Brute Force Blocker - SSH attackers",
    },
    "myip_full": {
        "url": "https://myip.ms/files/blacklist/general/full_blacklist_database.zip",
        "type": "ip",
        "format": "zip_txt",
        "description": "MyIP.ms full blacklist database",
    },
    "talos_ip": {
        "url": "https://snort.org/downloads/ip-block-list",
        "type": "ip",
        "format": "plaintext",
        "description": "Cisco Talos IP blocklist",
    },
    "tor_exit_nodes": {
        "url": "https://check.torproject.org/torbulkexitlist",
        "type": "ip",
        "format": "plaintext",
        "description": "Tor exit node IPs",
    },
    "phishtank": {
        "url": "http://data.phishtank.com/data/online-valid.csv",
        "type": "url",
        "format": "csv",
        "description": "PhishTank verified phishing URLs",
    },
    "botvrij_dst": {
        "url": "https://www.botvrij.eu/data/ioclist.domain.raw",
        "type": "domain",
        "format": "plaintext",
        "description": "Botvrij.eu malicious domains",
    },
    "cybercrime_tracker": {
        "url": "https://cybercrime-tracker.net/all.php",
        "type": "url",
        "format": "plaintext",
        "description": "Cybercrime Tracker C2 panels",
    },
    "vxvault": {
        "url": "http://vxvault.net/URL_List.php",
        "type": "url",
        "format": "plaintext",
        "description": "VXVault malware URLs",
    },
    "malc0de": {
        "url": "https://malc0de.com/bl/BOOT",
        "type": "domain",
        "format": "plaintext",
        "description": "Malc0de malicious domains",
    },
    "disposable_email": {
        "url": "https://raw.githubusercontent.com/disposable-email-domains/disposable-email-domains/master/disposable_email_blocklist.conf",
        "type": "domain",
        "format": "plaintext",
        "description": "Disposable email domains",
    },
}

BLOCKLIST_PATH = "/tmp/netshield_threat_blocklist"
IP_RE = re.compile(
    r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$"
)


class ThreatIntelManager:
    """Manages threat intelligence feeds and IoC lookups."""

    def __init__(self, db_module):
        self._db = db_module
        self._init_tables()

    # ------------------------------------------------------------------
    # Schema
    # ------------------------------------------------------------------

    def _init_tables(self):
        self._db.execute(
            """
            CREATE TABLE IF NOT EXISTS threat_feeds (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                name        TEXT    NOT NULL UNIQUE,
                url         TEXT    NOT NULL,
                type        TEXT    NOT NULL DEFAULT 'ip',
                enabled     INTEGER NOT NULL DEFAULT 1,
                ioc_count   INTEGER NOT NULL DEFAULT 0,
                last_updated TEXT,
                last_error  TEXT
            )
            """
        )
        self._db.execute(
            """
            CREATE TABLE IF NOT EXISTS threat_iocs (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                feed_name  TEXT NOT NULL,
                ioc_type   TEXT NOT NULL,
                value      TEXT NOT NULL,
                severity   TEXT NOT NULL DEFAULT 'medium',
                first_seen TEXT NOT NULL,
                last_seen  TEXT NOT NULL
            )
            """
        )
        self._db.execute(
            "CREATE INDEX IF NOT EXISTS idx_threat_iocs_value ON threat_iocs (value)"
        )
        self._db.commit()

        # Seed feed registry from static config
        for name, cfg in THREAT_FEEDS.items():
            self._db.execute(
                """
                INSERT OR IGNORE INTO threat_feeds (name, url, type)
                VALUES (?, ?, ?)
                """,
                (name, cfg["url"], cfg["type"]),
            )
        self._db.commit()

    # ------------------------------------------------------------------
    # Feed downloading
    # ------------------------------------------------------------------

    def _fetch_url(self, url, headers=None, timeout=30):
        req = urllib.request.Request(url, headers=headers or {})
        req.add_header("User-Agent", "NetShield/1.0 ThreatIntel")
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read().decode("utf-8", errors="replace")

    def _parse_plaintext(self, text, ioc_type="ip"):
        iocs = set()
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("//"):
                continue
            if ioc_type in ("ip", "cidr"):
                candidate = line.split("/")[0].strip()
                if IP_RE.match(candidate):
                    iocs.add(line.strip() if ioc_type == "cidr" and "/" in line else candidate)
            elif ioc_type == "domain":
                domain = line.lower().strip()
                # Handle hostfile format: 0.0.0.0 domain or 127.0.0.1 domain
                if domain.startswith("0.0.0.0 ") or domain.startswith("127.0.0.1 "):
                    parts = domain.split()
                    if len(parts) >= 2:
                        domain = parts[1]
                # Strip any trailing comments
                domain = domain.split("#")[0].strip()
                if domain and "." in domain and not domain.startswith("."):
                    iocs.add(domain)
            elif ioc_type == "url":
                if line.startswith("http"):
                    iocs.add(line)
            else:
                # Fallback: try IP, then URL
                candidate = line.split("/")[0].strip()
                if IP_RE.match(candidate):
                    iocs.add(candidate)
                elif line.startswith("http"):
                    iocs.add(line)
        return iocs

    def _parse_json_abuseipdb(self, text):
        iocs = set()
        try:
            data = json.loads(text)
            for entry in data.get("data", []):
                ip = entry.get("ipAddress", "").strip()
                if IP_RE.match(ip):
                    iocs.add(ip)
        except (json.JSONDecodeError, KeyError) as exc:
            log.warning("AbuseIPDB JSON parse error: %s", exc)
        return iocs

    def download_feed(self, name):
        """Download a single feed by name. Returns set of IoC strings."""
        cfg = THREAT_FEEDS.get(name)
        row = self._db.fetchone(
            "SELECT url, type, enabled FROM threat_feeds WHERE name = ?", (name,)
        )
        if not cfg and not row:
            raise ValueError(f"Unknown feed: {name}")

        url = (row["url"] if row else cfg["url"])
        fmt = cfg.get("format", "plaintext") if cfg else "plaintext"

        if cfg and cfg.get("api_key_required"):
            api_key = os.environ.get("ABUSEIPDB_API_KEY", "")
            if not api_key:
                log.warning("Feed %s requires API key; skipping", name)
                return set()
            headers = {"Key": api_key, "Accept": "application/json"}
            url = url + "?confidenceMinimum=90&limit=10000"
        else:
            headers = {}

        try:
            text = self._fetch_url(url, headers=headers)
        except urllib.error.URLError as exc:
            log.error("Failed to fetch feed %s: %s", name, exc)
            self._db.execute(
                "UPDATE threat_feeds SET last_error = ? WHERE name = ?",
                (str(exc), name),
            )
            self._db.commit()
            return set()

        ioc_type = cfg.get("type", "ip") if cfg else "ip"

        if fmt == "json":
            return self._parse_json_abuseipdb(text)
        if fmt == "hostfile":
            return self._parse_plaintext(text, "domain")
        if fmt == "dshield":
            return self._parse_dshield(text)
        if fmt == "csv":
            return self._parse_csv(text, ioc_type)
        return self._parse_plaintext(text, ioc_type)

    def _parse_dshield(self, text):
        iocs = set()
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split("\t")
            if parts and IP_RE.match(parts[0].strip()):
                # DShield format: start_ip\tend_ip\tcount
                start = parts[0].strip()
                iocs.add(start)
        return iocs

    def _parse_csv(self, text, ioc_type="url"):
        iocs = set()
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(",")
            if ioc_type == "url":
                for part in parts:
                    part = part.strip().strip('"')
                    if part.startswith("http"):
                        iocs.add(part)
                        break
            elif ioc_type == "ip":
                for part in parts:
                    part = part.strip().strip('"')
                    if IP_RE.match(part):
                        iocs.add(part)
                        break
        return iocs

    # ------------------------------------------------------------------
    # Feed management
    # ------------------------------------------------------------------

    def update_all_feeds(self):
        """Download all enabled feeds and persist IoCs to the database."""
        now = datetime.now(timezone.utc).isoformat()
        rows = self._db.fetchall(
            "SELECT name, type FROM threat_feeds WHERE enabled = 1"
        )
        for row in rows:
            name = row["name"]
            ioc_type = row["type"]
            log.info("Updating feed: %s", name)
            iocs = self.download_feed(name)
            if not iocs:
                continue

            # Remove old IoCs for this feed then re-insert
            self._db.execute(
                "DELETE FROM threat_iocs WHERE feed_name = ?", (name,)
            )
            severity = "high" if name in ("feodo_tracker", "emerging_threats") else "medium"
            for value in iocs:
                self._db.execute(
                    """
                    INSERT INTO threat_iocs
                        (feed_name, ioc_type, value, severity, first_seen, last_seen)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (name, ioc_type, value, severity, now, now),
                )
            self._db.execute(
                """
                UPDATE threat_feeds
                SET ioc_count = ?, last_updated = ?, last_error = NULL
                WHERE name = ?
                """,
                (len(iocs), now, name),
            )
            self._db.commit()
            log.info("Feed %s: %d IoCs loaded", name, len(iocs))

    def enable_feed(self, name):
        self._db.execute(
            "UPDATE threat_feeds SET enabled = 1 WHERE name = ?", (name,)
        )
        self._db.commit()

    def disable_feed(self, name):
        self._db.execute(
            "UPDATE threat_feeds SET enabled = 0 WHERE name = ?", (name,)
        )
        self._db.commit()

    # ------------------------------------------------------------------
    # Lookups
    # ------------------------------------------------------------------

    def check_ip(self, ip):
        """Check an IP against all loaded IoCs. Returns match info dict."""
        rows = self._db.fetchall(
            "SELECT feed_name, severity FROM threat_iocs WHERE value = ? AND ioc_type = 'ip'",
            (ip,),
        )
        if not rows:
            return {"matched": False, "feeds": [], "severity": None}
        feeds = [r["feed_name"] for r in rows]
        severities = [r["severity"] for r in rows]
        top = "critical" if "critical" in severities else ("high" if "high" in severities else "medium")
        return {"matched": True, "feeds": feeds, "severity": top}

    def check_domain(self, domain):
        """Check a domain or URL value against IoCs."""
        rows = self._db.fetchall(
            "SELECT feed_name, severity FROM threat_iocs WHERE value LIKE ? AND ioc_type IN ('domain', 'url')",
            (f"%{domain}%",),
        )
        if not rows:
            return {"matched": False, "feeds": [], "severity": None}
        feeds = [r["feed_name"] for r in rows]
        severities = [r["severity"] for r in rows]
        top = "critical" if "critical" in severities else ("high" if "high" in severities else "medium")
        return {"matched": True, "feeds": feeds, "severity": top}

    # ------------------------------------------------------------------
    # PF blocklist
    # ------------------------------------------------------------------

    def generate_pf_blocklist(self):
        """Write IP IoCs to BLOCKLIST_PATH and load into pf table."""
        rows = self._db.fetchall(
            "SELECT DISTINCT value FROM threat_iocs WHERE ioc_type = 'ip'"
        )
        ips = [r["value"] for r in rows]
        try:
            with open(BLOCKLIST_PATH, "w") as fh:
                fh.write("\n".join(ips) + "\n")
            subprocess.run(
                ["pfctl", "-t", "netshield_threats", "-T", "replace", "-f", BLOCKLIST_PATH],
                check=True,
                capture_output=True,
            )
            log.info("PF threat blocklist updated with %d IPs", len(ips))
        except (OSError, subprocess.CalledProcessError) as exc:
            log.error("Failed to update pf blocklist: %s", exc)

    # ------------------------------------------------------------------
    # Stats / status
    # ------------------------------------------------------------------

    def get_stats(self):
        total = self._db.fetchone("SELECT COUNT(*) AS c FROM threat_iocs")
        active = self._db.fetchone(
            "SELECT COUNT(*) AS c FROM threat_feeds WHERE enabled = 1"
        )
        last_row = self._db.fetchone(
            "SELECT last_updated FROM threat_feeds WHERE last_updated IS NOT NULL ORDER BY last_updated DESC LIMIT 1"
        )
        top = self._db.fetchall(
            "SELECT feed_name, COUNT(*) AS cnt FROM threat_iocs GROUP BY feed_name ORDER BY cnt DESC LIMIT 5"
        )
        return {
            "total_iocs": total["c"] if total else 0,
            "feeds_active": active["c"] if active else 0,
            "last_updated": last_row["last_updated"] if last_row else None,
            "top_feeds": [{"feed": r["feed_name"], "count": r["cnt"]} for r in top],
        }

    def get_feed_status(self):
        rows = self._db.fetchall(
            "SELECT name, enabled, ioc_count, last_updated, last_error FROM threat_feeds ORDER BY name"
        )
        return [
            {
                "name": r["name"],
                "enabled": bool(r["enabled"]),
                "ioc_count": r["ioc_count"],
                "last_updated": r["last_updated"],
                "last_error": r["last_error"],
            }
            for r in rows
        ]
