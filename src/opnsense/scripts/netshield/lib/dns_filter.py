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

"""
DNS Filter — DNS-based filtering engine.
Integrates with Unbound via override files at /var/unbound/etc/.
Downloads and merges blocklists, writes local-zone NXDOMAIN overrides,
manages custom allow/block/redirect rules, and exposes safe-search overrides.
"""

import logging
import os
import subprocess
import time
import urllib.request
from datetime import datetime
from typing import Any, Dict, List, Optional, Set

log = logging.getLogger(__name__)

UNBOUND_OVERRIDE_DIR = "/var/unbound/etc"
UNBOUND_BLOCKLIST_CONF = os.path.join(UNBOUND_OVERRIDE_DIR, "netshield_blocklist.conf")
UNBOUND_SAFESEARCH_CONF = os.path.join(UNBOUND_OVERRIDE_DIR, "netshield_safesearch.conf")

BLOCKLIST_SOURCES: Dict[str, Dict[str, str]] = {
    # --- Ads & Tracking ---
    "adguard_dns": {
        "url": "https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt",
        "category": "ads",
    },
    "oisd": {
        "url": "https://big.oisd.nl/domainswild",
        "category": "ads",
    },
    "stevenblack_unified": {
        "url": "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
        "category": "ads",
    },
    "hagezi_pro": {
        "url": "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/pro.txt",
        "category": "ads",
    },
    "easylist_adservers": {
        "url": "https://raw.githubusercontent.com/nickspaargaren/no-google/master/pihole-google.txt",
        "category": "tracking",
    },
    "hagezi_tif": {
        "url": "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/tif.txt",
        "category": "tracking",
    },
    # --- Malware ---
    "urlhaus_malware": {
        "url": "https://urlhaus.abuse.ch/downloads/hostfile/",
        "category": "malware",
    },
    "abuse_ch_threatfox": {
        "url": "https://threatfox.abuse.ch/downloads/hostfile/",
        "category": "malware",
    },
    "malwaredomainlist": {
        "url": "https://raw.githubusercontent.com/RPiList/specials/master/Blocklisten/malware",
        "category": "malware",
    },
    # --- Phishing ---
    "phishing_army": {
        "url": "https://phishing.army/download/phishing_army_blocklist.txt",
        "category": "phishing",
    },
    "openphish": {
        "url": "https://raw.githubusercontent.com/openphish/public_feed/main/url_list.txt",
        "category": "phishing",
    },
    # --- Adult Content ---
    "stevenblack_porn": {
        "url": "https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/porn/hosts",
        "category": "adult",
    },
    "oisd_nsfw": {
        "url": "https://nsfw.oisd.nl/domainswild",
        "category": "adult",
    },
    # --- Gambling ---
    "stevenblack_gambling": {
        "url": "https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/gambling/hosts",
        "category": "gambling",
    },
    # --- Social Media ---
    "stevenblack_social": {
        "url": "https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/social/hosts",
        "category": "social",
    },
    # --- Crypto Mining ---
    "nocoin": {
        "url": "https://raw.githubusercontent.com/nickspaargaren/pihole-google/master/nickspaargaren_nocoin.txt",
        "category": "cryptomining",
    },
    "coin_blocker": {
        "url": "https://zerodot1.gitlab.io/CoinBlockerLists/hosts_browser",
        "category": "cryptomining",
    },
}

# Safe-search CNAME overrides: domain_suffix -> cname_target
SAFE_SEARCH_OVERRIDES: Dict[str, List[str]] = {
    "forcesafesearch.google.com": [
        "www.google.com",
        "google.com",
        "www.google.co.uk",
        "google.co.uk",
    ],
    "restrict.youtube.com": [
        "www.youtube.com",
        "youtube.com",
        "m.youtube.com",
    ],
    "safe.duckduckgo.com": [
        "duckduckgo.com",
        "www.duckduckgo.com",
    ],
    "strict.bing.com": [
        "www.bing.com",
        "bing.com",
    ],
}

# Download timeout in seconds
DOWNLOAD_TIMEOUT = 30


class DNSFilter:
    """DNS-based filtering engine backed by an SQLite database."""

    def __init__(self, db_module: Any) -> None:
        self._db = db_module
        self._init_tables()
        self._init_default_blocklists()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _init_tables(self) -> None:
        self._db.execute("""
            CREATE TABLE IF NOT EXISTS dns_rules (
                id      INTEGER PRIMARY KEY AUTOINCREMENT,
                domain  TEXT    NOT NULL UNIQUE,
                action  TEXT    NOT NULL DEFAULT 'block',
                source  TEXT    NOT NULL DEFAULT 'custom',
                created TEXT    NOT NULL,
                updated TEXT    NOT NULL
            )
        """)
        self._db.execute("""
            CREATE TABLE IF NOT EXISTS dns_blocklists (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                name         TEXT    NOT NULL UNIQUE,
                url          TEXT    NOT NULL,
                enabled      INTEGER NOT NULL DEFAULT 1,
                domain_count INTEGER NOT NULL DEFAULT 0,
                last_updated TEXT,
                category     TEXT    NOT NULL DEFAULT ''
            )
        """)
        # Migration: add category column if missing (existing DBs)
        try:
            self._db.execute("SELECT category FROM dns_blocklists LIMIT 1")
        except Exception:
            try:
                self._db.execute("ALTER TABLE dns_blocklists ADD COLUMN category TEXT NOT NULL DEFAULT ''")
                self._db.commit()
            except Exception:
                pass
        self._db.execute("""
            CREATE TABLE IF NOT EXISTS dns_query_log (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp     TEXT    NOT NULL,
                client_ip     TEXT,
                domain        TEXT,
                action        TEXT,
                blocklist_name TEXT
            )
        """)
        self._db.commit()

    def _init_default_blocklists(self) -> None:
        for name, info in BLOCKLIST_SOURCES.items():
            url = info["url"]
            category = info.get("category", "")
            existing = self._db.query(
                "SELECT id FROM dns_blocklists WHERE name = ?", (name,)
            )
            if not existing:
                # New lists default to disabled except the original 4
                enabled = 1 if name in ("adguard_dns", "oisd", "stevenblack_unified", "hagezi_pro") else 0
                self._db.execute(
                    "INSERT INTO dns_blocklists (name, url, enabled, category) VALUES (?, ?, ?, ?)",
                    (name, url, enabled, category),
                )
            else:
                # Update URL and category for existing entries
                self._db.execute(
                    "UPDATE dns_blocklists SET url = ?, category = ? WHERE name = ?",
                    (url, category, name),
                )
        self._db.commit()

    @staticmethod
    def _now() -> str:
        return datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")

    @staticmethod
    def _clean_domain(domain: str) -> Optional[str]:
        """Strip leading wildcards and whitespace; return None if invalid."""
        domain = domain.strip().lower()
        if domain.startswith("*."):
            domain = domain[2:]
        # Remove trailing dot
        domain = domain.rstrip(".")
        if not domain or " " in domain or "\t" in domain:
            return None
        return domain

    # ------------------------------------------------------------------
    # Blocklist management
    # ------------------------------------------------------------------

    def download_blocklist(self, name: str, url: str) -> Set[str]:
        """Download a blocklist from *url* and return a set of domains."""
        domains: Set[str] = set()
        try:
            req = urllib.request.Request(
                url,
                headers={"User-Agent": "NetShield/1.0 (OPNsense DNS filter)"},
            )
            with urllib.request.urlopen(req, timeout=DOWNLOAD_TIMEOUT) as resp:
                for raw_line in resp:
                    line = raw_line.decode("utf-8", errors="replace").strip()
                    if not line or line.startswith("#") or line.startswith("!"):
                        continue
                    # Handle hosts-file format: "0.0.0.0 domain" or "127.0.0.1 domain"
                    parts = line.split()
                    if len(parts) == 2 and parts[0] in ("0.0.0.0", "127.0.0.1", "::"):
                        candidate = parts[1]
                    elif len(parts) == 1:
                        candidate = parts[0]
                    else:
                        continue
                    cleaned = self._clean_domain(candidate)
                    if cleaned and "." in cleaned:
                        domains.add(cleaned)
        except Exception as exc:
            log.warning("Failed to download blocklist '%s' from %s: %s", name, url, exc)
        return domains

    def update_all_blocklists(self) -> Dict[str, Any]:
        """Download all enabled blocklists, merge into dns_rules, write Unbound config."""
        blocklists = self._db.query(
            "SELECT id, name, url FROM dns_blocklists WHERE enabled = 1"
        )
        results: Dict[str, int] = {}
        all_domains: Set[str] = set()

        for row in blocklists:
            bl_id, name, url = row["id"], row["name"], row["url"]
            log.info("Downloading blocklist: %s", name)
            domains = self.download_blocklist(name, url)
            results[name] = len(domains)
            all_domains.update(domains)

            self._db.execute(
                "UPDATE dns_blocklists SET domain_count = ?, last_updated = ? WHERE id = ?",
                (len(domains), self._now(), bl_id),
            )

        # Merge into dns_rules (only auto-sourced entries)
        self._db.execute(
            "DELETE FROM dns_rules WHERE source != 'custom'"
        )
        now = self._now()
        batch = [
            (domain, "block", "blocklist", now, now)
            for domain in all_domains
        ]
        self._db.executemany(
            "INSERT OR IGNORE INTO dns_rules (domain, action, source, created, updated) "
            "VALUES (?, ?, ?, ?, ?)",
            batch,
        )
        self._db.commit()

        self.generate_unbound_overrides()
        self.reload_unbound()

        return {"updated": results, "total_domains": len(all_domains)}

    def generate_unbound_overrides(self) -> None:
        """Write /var/unbound/etc/netshield_blocklist.conf with NXDOMAIN entries."""
        os.makedirs(UNBOUND_OVERRIDE_DIR, exist_ok=True)

        block_domains = self._db.query(
            "SELECT domain FROM dns_rules WHERE action = 'block'"
        )

        lines = [
            "# NetShield DNS blocklist — auto-generated, do not edit manually",
            "# Generated: {}".format(self._now()),
            "",
        ]
        for row in block_domains:
            domain = row["domain"]
            lines.append('local-zone: "{}" always_nxdomain'.format(domain))

        content = "\n".join(lines) + "\n"
        with open(UNBOUND_BLOCKLIST_CONF, "w", encoding="utf-8") as fh:
            fh.write(content)

        log.info(
            "Wrote %d NXDOMAIN entries to %s", len(block_domains), UNBOUND_BLOCKLIST_CONF
        )

    def reload_unbound(self) -> bool:
        """Reload Unbound via unbound-control."""
        try:
            result = subprocess.run(
                ["unbound-control", "reload"],
                capture_output=True,
                text=True,
                timeout=15,
            )
            if result.returncode == 0:
                log.info("Unbound reloaded successfully")
                return True
            log.warning("unbound-control reload failed: %s", result.stderr.strip())
            return False
        except Exception as exc:
            log.warning("Failed to reload Unbound: %s", exc)
            return False

    # ------------------------------------------------------------------
    # Custom rules
    # ------------------------------------------------------------------

    def add_custom_rule(self, domain: str, action: str = "block") -> Dict[str, Any]:
        """Add or update a custom DNS rule. action: block | allow | redirect."""
        domain = self._clean_domain(domain) or domain.strip()
        if action not in ("block", "allow", "redirect"):
            return {"result": "failed", "message": "action must be block, allow, or redirect"}
        now = self._now()
        self._db.execute(
            "INSERT INTO dns_rules (domain, action, source, created, updated) "
            "VALUES (?, ?, 'custom', ?, ?) "
            "ON CONFLICT(domain) DO UPDATE SET action = excluded.action, updated = excluded.updated",
            (domain, action, now, now),
        )
        self._db.commit()
        self.generate_unbound_overrides()
        self.reload_unbound()
        return {"result": "ok", "domain": domain, "action": action}

    def remove_custom_rule(self, domain: str) -> Dict[str, Any]:
        domain = self._clean_domain(domain) or domain.strip()
        self._db.execute(
            "DELETE FROM dns_rules WHERE domain = ? AND source = 'custom'",
            (domain,),
        )
        self._db.commit()
        self.generate_unbound_overrides()
        self.reload_unbound()
        return {"result": "ok", "domain": domain}

    def get_rules(self, search: Optional[str] = None) -> List[Dict[str, Any]]:
        if search:
            rows = self._db.query(
                "SELECT * FROM dns_rules WHERE domain LIKE ? ORDER BY created DESC",
                ("%{}%".format(search),),
            )
        else:
            rows = self._db.query(
                "SELECT * FROM dns_rules ORDER BY created DESC"
            )
        return [dict(r) for r in rows]

    def is_blocked(self, domain: str) -> bool:
        domain = self._clean_domain(domain) or domain.strip()
        row = self._db.query(
            "SELECT action FROM dns_rules WHERE domain = ?", (domain,)
        )
        if row:
            return row[0]["action"] == "block"
        return False

    # ------------------------------------------------------------------
    # Query log
    # ------------------------------------------------------------------

    def get_query_log(self, limit: int = 100) -> List[Dict[str, Any]]:
        rows = self._db.query(
            "SELECT * FROM dns_query_log ORDER BY timestamp DESC LIMIT ?", (limit,)
        )
        return [dict(r) for r in rows]

    def log_query(
        self,
        client_ip: str,
        domain: str,
        action: str,
        blocklist_name: Optional[str] = None,
    ) -> None:
        self._db.execute(
            "INSERT INTO dns_query_log (timestamp, client_ip, domain, action, blocklist_name) "
            "VALUES (?, ?, ?, ?, ?)",
            (self._now(), client_ip, domain, action, blocklist_name),
        )
        self._db.commit()

    # ------------------------------------------------------------------
    # Statistics
    # ------------------------------------------------------------------

    def get_stats(self) -> Dict[str, Any]:
        today = datetime.utcnow().strftime("%Y-%m-%d")

        blocked_today = self._db.query(
            "SELECT COUNT(*) AS cnt FROM dns_query_log "
            "WHERE action = 'block' AND timestamp LIKE ?",
            ("{}%".format(today),),
        )
        allowed_today = self._db.query(
            "SELECT COUNT(*) AS cnt FROM dns_query_log "
            "WHERE action = 'allow' AND timestamp LIKE ?",
            ("{}%".format(today),),
        )
        top_blocked = self._db.query(
            "SELECT domain, COUNT(*) AS hits FROM dns_query_log "
            "WHERE action = 'block' GROUP BY domain ORDER BY hits DESC LIMIT 10"
        )
        bl_counts = self._db.query(
            "SELECT name, domain_count, enabled, last_updated FROM dns_blocklists"
        )

        return {
            "total_blocked": (blocked_today[0]["cnt"] if blocked_today else 0),
            "total_allowed": (allowed_today[0]["cnt"] if allowed_today else 0),
            "top_blocked_domains": [dict(r) for r in top_blocked],
            "blocklist_counts": [dict(r) for r in bl_counts],
        }

    # ------------------------------------------------------------------
    # Safe search
    # ------------------------------------------------------------------

    def enable_safe_search(self) -> Dict[str, Any]:
        """Write CNAME overrides for safe-search enforcement."""
        os.makedirs(UNBOUND_OVERRIDE_DIR, exist_ok=True)
        lines = [
            "# NetShield safe-search overrides — auto-generated",
            "# Generated: {}".format(self._now()),
            "",
        ]
        for cname_target, source_domains in SAFE_SEARCH_OVERRIDES.items():
            for domain in source_domains:
                lines.append('local-data: "{} CNAME {}"'.format(domain, cname_target))

        content = "\n".join(lines) + "\n"
        with open(UNBOUND_SAFESEARCH_CONF, "w", encoding="utf-8") as fh:
            fh.write(content)

        self.reload_unbound()
        return {"result": "ok", "safe_search": "enabled"}

    def disable_safe_search(self) -> Dict[str, Any]:
        """Remove safe-search CNAME override file."""
        try:
            if os.path.exists(UNBOUND_SAFESEARCH_CONF):
                os.remove(UNBOUND_SAFESEARCH_CONF)
                self.reload_unbound()
        except Exception as exc:
            log.warning("Failed to remove safe-search config: %s", exc)
            return {"result": "failed", "message": str(exc)}
        return {"result": "ok", "safe_search": "disabled"}

    def get_safe_search_status(self) -> bool:
        return os.path.exists(UNBOUND_SAFESEARCH_CONF)
