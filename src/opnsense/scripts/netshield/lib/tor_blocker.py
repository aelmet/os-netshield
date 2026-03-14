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
Tor Blocker — Multi-layer Tor/anonymizer blocking engine for NetShield.

Layers:
  1. IP blocklist  — Tor exit nodes, relays, bridges (auto-updating from multiple sources)
  2. Port blocking — Common Tor ports blocked via pf rules
  3. DNS blocking  — Tor-related domains blocked via Unbound NXDOMAIN
  4. Alerts        — Log and alert on any Tor connection attempt
"""

import logging
import os
import re
import subprocess
import urllib.request
import urllib.error
from datetime import datetime, timezone
from typing import Any, Dict, List, Set

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Multiple Tor node list sources for redundancy
TOR_IP_SOURCES = {
    "tor_exit_nodes": {
        "url": "https://check.torproject.org/torbulkexitlist",
        "description": "Official Tor Project exit node list",
    },
    "tor_exit_dan": {
        "url": "https://www.dan.me.uk/torlist/?exit",
        "description": "dan.me.uk Tor exit node list",
    },
    "tor_all_dan": {
        "url": "https://www.dan.me.uk/torlist/",
        "description": "dan.me.uk all Tor node list (exits + relays + guards)",
    },
    "tor_onionoo_relays": {
        "url": "https://onionoo.torproject.org/summary?type=relay&running=true&fields=or_addresses",
        "description": "Tor Onionoo relay IP addresses (JSON)",
        "format": "onionoo_json",
    },
}

# Tor-related domains to block at DNS level
TOR_BLOCKED_DOMAINS = [
    # Tor Project
    "torproject.org",
    "www.torproject.org",
    "dist.torproject.org",
    "bridges.torproject.org",
    "check.torproject.org",
    "blog.torproject.org",
    "metrics.torproject.org",
    "collector.torproject.org",
    "onionoo.torproject.org",
    "stem.torproject.org",
    "gitweb.torproject.org",
    "trac.torproject.org",
    "ooni.torproject.org",
    "tb-manual.torproject.org",
    # Tor Browser download mirrors
    "tor.eff.org",
    "tor.calyxinstitute.org",
    "tor.ccc.de",
    # Tor bridges and pluggable transports
    "snowflake.torproject.org",
    "snowflake-broker.torproject.org",
    "meek.azureedge.net",
    # Onion routing services / directories
    "onion.link",
    "onion.ly",
    "onion.pet",
    "onion.ws",
    "onion.cab",
    "onion.direct",
    "onion.top",
    "onion.sh",
    "tor2web.org",
    "tor2web.io",
    "tor2web.fi",
    "darknet.to",
    # Tor-related tools
    "tails.boum.org",
    "tails.net",
    "whonix.org",
    "i2p.net",
    "geti2p.net",
    # Common Tor bridge distribution
    "bridges.torproject.org",
    "moat.torproject.org",
]

# Tor default ports
TOR_PORTS = [
    9001,   # OR (Onion Router) port — relay traffic
    9030,   # Directory server port
    9040,   # Transparent proxy port
    9050,   # SOCKS proxy (default)
    9051,   # Control port
    9150,   # Tor Browser SOCKS port
    9151,   # Tor Browser control port
]

# Extended ports used by Tor bridges and pluggable transports
TOR_BRIDGE_PORTS = [
    443,    # obfs4 often runs on 443 (can't block without breaking HTTPS)
    80,     # meek transport
    # These are less common but used by some bridges:
    4443,
    8443,
    9443,
]

# File paths
TOR_BLOCKLIST_PATH = "/var/db/netshield/pf_tables/block_tor.txt"
TOR_PORTS_CONF = "/var/db/netshield/pf_tables/tor_ports.txt"
TOR_DNS_CONF = "/var/unbound/etc/netshield_tor_block.conf"
TOR_STATUS_FILE = "/var/db/netshield/tor_blocker_status.json"

IP_RE = re.compile(
    r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$"
)


class TorBlocker:
    """Multi-layer Tor blocking engine."""

    def __init__(self, db_module):
        self._db = db_module
        self._init_tables()

    # ------------------------------------------------------------------
    # Schema
    # ------------------------------------------------------------------

    def _init_tables(self):
        self._db.execute("""
            CREATE TABLE IF NOT EXISTS tor_blocked_ips (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                ip         TEXT    NOT NULL UNIQUE,
                source     TEXT    NOT NULL,
                node_type  TEXT    NOT NULL DEFAULT 'exit',
                first_seen TEXT    NOT NULL,
                last_seen  TEXT    NOT NULL
            )
        """)
        self._db.execute("""
            CREATE TABLE IF NOT EXISTS tor_config (
                key   TEXT PRIMARY KEY,
                value TEXT NOT NULL
            )
        """)
        self._db.execute("""
            CREATE TABLE IF NOT EXISTS tor_blocked_log (
                id        INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT    NOT NULL,
                src_ip    TEXT,
                dst_ip    TEXT,
                dst_port  INTEGER,
                action    TEXT    NOT NULL DEFAULT 'blocked',
                detail    TEXT
            )
        """)
        self._db.execute(
            "CREATE INDEX IF NOT EXISTS idx_tor_ips ON tor_blocked_ips (ip)"
        )
        self._db.execute(
            "CREATE INDEX IF NOT EXISTS idx_tor_log_ts ON tor_blocked_log (timestamp)"
        )
        self._db.commit()

        # Set defaults if not configured
        self._set_default("enabled", "1")
        self._set_default("block_ports", "1")
        self._set_default("block_dns", "1")
        self._set_default("block_ips", "1")
        self._set_default("alert_on_attempt", "1")
        self._set_default("last_updated", "")

    def _set_default(self, key, value):
        self._db.execute(
            "INSERT OR IGNORE INTO tor_config (key, value) VALUES (?, ?)",
            (key, value),
        )
        self._db.commit()

    def _get_config(self, key):
        rows = self._db.query(
            "SELECT value FROM tor_config WHERE key = ?", (key,)
        )
        return rows[0]["value"] if rows else None

    def _set_config(self, key, value):
        self._db.execute(
            "INSERT INTO tor_config (key, value) VALUES (?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (key, str(value)),
        )
        self._db.commit()

    # ------------------------------------------------------------------
    # IP Download
    # ------------------------------------------------------------------

    @staticmethod
    def _fetch_url(url, timeout=30):
        req = urllib.request.Request(url)
        req.add_header("User-Agent", "NetShield/1.0 TorBlocker")
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read().decode("utf-8", errors="replace")

    def _parse_plaintext_ips(self, text):
        ips = set()
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("!"):
                continue
            candidate = line.split("/")[0].strip()
            if IP_RE.match(candidate):
                ips.add(candidate)
        return ips

    def _parse_onionoo_json(self, text):
        """Parse Onionoo summary JSON for relay IP addresses."""
        import json
        ips = set()
        try:
            data = json.loads(text)
            for relay in data.get("relays", []):
                for addr in relay.get("a", []):
                    # Format: "ip:port" or just "ip"
                    ip = addr.split(":")[0].strip("[]")
                    if IP_RE.match(ip):
                        ips.add(ip)
        except (ValueError, KeyError) as exc:
            log.warning("Onionoo JSON parse error: %s", exc)
        return ips

    def download_tor_ips(self):
        """Download Tor node IPs from all sources. Returns total set of IPs."""
        all_ips = set()
        source_counts = {}
        now = datetime.now(timezone.utc).isoformat()

        for name, cfg in TOR_IP_SOURCES.items():
            try:
                text = self._fetch_url(cfg["url"])
                fmt = cfg.get("format", "plaintext")

                if fmt == "onionoo_json":
                    ips = self._parse_onionoo_json(text)
                else:
                    ips = self._parse_plaintext_ips(text)

                source_counts[name] = len(ips)
                log.info("Tor source %s: %d IPs", name, len(ips))

                # Store in database
                node_type = "exit" if "exit" in name else "relay"
                for ip in ips:
                    self._db.execute(
                        """
                        INSERT INTO tor_blocked_ips (ip, source, node_type, first_seen, last_seen)
                        VALUES (?, ?, ?, ?, ?)
                        ON CONFLICT(ip) DO UPDATE SET
                            last_seen = excluded.last_seen,
                            source = excluded.source
                        """,
                        (ip, name, node_type, now, now),
                    )

                all_ips.update(ips)

            except urllib.error.URLError as exc:
                log.warning("Failed to fetch Tor source %s: %s", name, exc)
                source_counts[name] = -1

        self._db.commit()
        self._set_config("last_updated", now)

        return {
            "total_ips": len(all_ips),
            "sources": source_counts,
        }

    # ------------------------------------------------------------------
    # PF IP Blocking
    # ------------------------------------------------------------------

    def generate_pf_blocklist(self):
        """Write all Tor IPs to a pf table file and load it."""
        rows = self._db.query("SELECT DISTINCT ip FROM tor_blocked_ips")
        ips = [r["ip"] for r in rows]

        os.makedirs(os.path.dirname(TOR_BLOCKLIST_PATH), exist_ok=True)
        with open(TOR_BLOCKLIST_PATH, "w") as fh:
            fh.write("\n".join(ips) + "\n")

        try:
            subprocess.run(
                ["pfctl", "-t", "ns_block_tor", "-T", "replace", "-f", TOR_BLOCKLIST_PATH],
                check=True,
                capture_output=True,
            )
            log.info("PF Tor blocklist loaded: %d IPs", len(ips))
            return {"result": "ok", "ips_loaded": len(ips)}
        except subprocess.CalledProcessError as exc:
            log.error("Failed to load Tor pf table: %s", exc.stderr.decode())
            return {"result": "failed", "message": exc.stderr.decode()}

    # ------------------------------------------------------------------
    # PF Port Blocking
    # ------------------------------------------------------------------

    def generate_port_rules(self):
        """Generate pf rules to block common Tor ports for all LAN clients."""
        rules = [
            "# NetShield Tor Port Blocking — auto-generated",
            "# Blocks common Tor ports for all LAN traffic",
            "",
        ]

        ports = ",".join(str(p) for p in TOR_PORTS)
        rules.append(
            f"block drop quick proto tcp from any to any port {{ {ports} }}"
        )
        rules.append(
            f"block drop quick proto tcp from any port {{ {ports} }} to any"
        )
        rules.append("")

        return "\n".join(rules)

    # ------------------------------------------------------------------
    # DNS Blocking (via OPNsense DNSBL JSON — the correct integration)
    # ------------------------------------------------------------------

    DNSBL_FILE = "/var/unbound/data/dnsbl.json"
    DNSBL_SIZE_FILE = "/var/unbound/data/dnsbl.size"

    def generate_dns_overrides(self):
        """Inject Tor domains into OPNsense's DNSBL system."""
        import json as _json

        if not os.path.isfile(self.DNSBL_FILE):
            log.warning("DNSBL file not found: %s", self.DNSBL_FILE)
            return {"result": "warning", "message": "DNSBL file not found",
                    "domains_blocked": 0}

        with open(self.DNSBL_FILE) as fh:
            dnsbl = _json.load(fh)

        data = dnsbl.get("data", {})

        # Get idx from existing entry
        idx = "netshield-tor-blocker"
        for v in data.values():
            if isinstance(v, list) and len(v) > 0:
                idx = v[0].get("idx", idx)
                break

        added = 0
        for domain in TOR_BLOCKED_DOMAINS:
            domain = domain.lower().strip()
            if domain in data:
                existing_bls = [e.get("bl") for e in data[domain]]
                if "tor_block" not in existing_bls:
                    data[domain].append({"bl": "tor_block", "wildcard": True, "idx": idx})
                    added += 1
            else:
                data[domain] = [{"bl": "tor_block", "wildcard": True, "idx": idx}]
                added += 1

        dnsbl["data"] = data
        with open(self.DNSBL_FILE, "w") as fh:
            _json.dump(dnsbl, fh)

        size = os.path.getsize(self.DNSBL_FILE)
        with open(self.DNSBL_SIZE_FILE, "w") as fh:
            fh.write(str(size))

        # Restart Unbound to pick up changes
        subprocess.run(["configctl", "unbound", "cache", "flush"],
                        capture_output=True, timeout=15)
        subprocess.run(["service", "unbound", "restart"],
                        capture_output=True, timeout=30)

        log.info("Injected %d Tor domains into DNSBL", added)
        return {"result": "ok", "domains_blocked": len(TOR_BLOCKED_DOMAINS),
                "domains_added": added}

    def remove_dns_overrides(self):
        """Remove Tor domains from OPNsense's DNSBL system."""
        import json as _json

        if not os.path.isfile(self.DNSBL_FILE):
            return {"result": "ok"}

        with open(self.DNSBL_FILE) as fh:
            dnsbl = _json.load(fh)

        data = dnsbl.get("data", {})
        removed = 0
        for domain in list(data.keys()):
            entries = data[domain]
            new_entries = [e for e in entries if e.get("bl") != "tor_block"]
            if len(new_entries) < len(entries):
                removed += 1
                if new_entries:
                    data[domain] = new_entries
                else:
                    del data[domain]

        dnsbl["data"] = data
        with open(self.DNSBL_FILE, "w") as fh:
            _json.dump(dnsbl, fh)

        size = os.path.getsize(self.DNSBL_FILE)
        with open(self.DNSBL_SIZE_FILE, "w") as fh:
            fh.write(str(size))

        subprocess.run(["configctl", "unbound", "cache", "flush"],
                        capture_output=True, timeout=15)
        subprocess.run(["service", "unbound", "restart"],
                        capture_output=True, timeout=30)

        return {"result": "ok", "domains_removed": removed}

    # ------------------------------------------------------------------
    # Full Enable/Disable
    # ------------------------------------------------------------------

    def enable(self):
        """Enable all Tor blocking layers."""
        self._set_config("enabled", "1")
        results = {}

        # Layer 1: Download and block IPs
        if self._get_config("block_ips") == "1":
            dl = self.download_tor_ips()
            pf = self.generate_pf_blocklist()
            results["ip_blocking"] = {**dl, **pf}

        # Layer 2: Port blocking (generated as anchor rules)
        if self._get_config("block_ports") == "1":
            results["port_blocking"] = {"result": "ok", "ports": TOR_PORTS}

        # Layer 3: DNS blocking
        if self._get_config("block_dns") == "1":
            dns = self.generate_dns_overrides()
            results["dns_blocking"] = dns

        # Load pf anchor rules directly
        try:
            self._load_pf_anchor()
            results["pf_anchor"] = "ok"
        except Exception as exc:
            results["pf_anchor"] = str(exc)

        return {"result": "ok", "layers": results}

    def _load_pf_anchor(self):
        """Load Tor blocking rules into the netshield_tor pf anchor."""
        TOR_PORTS_STR = ", ".join(str(p) for p in TOR_PORTS)
        MERGE_RULES = "/tmp/netshield_tor_merge.conf"

        with open(MERGE_RULES, "w") as fh:
            fh.write('table <ns_block_tor> persist file "{}"\n'.format(TOR_BLOCKLIST_PATH))
            fh.write("block drop quick from any to <ns_block_tor>\n")
            fh.write("block drop quick from <ns_block_tor> to any\n")
            fh.write("block drop quick proto tcp from any to any port {{ {} }}\n".format(TOR_PORTS_STR))
            fh.write("block drop quick proto tcp from any port {{ {} }} to any\n".format(TOR_PORTS_STR))

        subprocess.run(
            ["pfctl", "-t", "ns_block_tor", "-T", "replace", "-f", TOR_BLOCKLIST_PATH],
            capture_output=True, timeout=10,
        )
        subprocess.run(
            ["pfctl", "-a", "netshield_tor", "-f", MERGE_RULES],
            capture_output=True, timeout=10,
        )

    def disable(self):
        """Disable all Tor blocking layers."""
        self._set_config("enabled", "0")
        results = {}

        # Remove pf table
        try:
            subprocess.run(
                ["pfctl", "-t", "ns_block_tor", "-T", "flush"],
                capture_output=True, timeout=10,
            )
            results["ip_blocking"] = "disabled"
        except Exception:
            results["ip_blocking"] = "table not found (ok)"

        # Remove DNS overrides
        dns = self.remove_dns_overrides()
        results["dns_blocking"] = dns

        # Reload pf
        try:
            subprocess.run(
                ["configctl", "filter", "reload"],
                capture_output=True, timeout=30,
            )
            results["filter_reload"] = "ok"
        except Exception as exc:
            results["filter_reload"] = str(exc)

        return {"result": "ok", "layers": results}

    def update(self):
        """Update Tor IP lists and regenerate all blocking rules."""
        if self._get_config("enabled") != "1":
            return {"result": "skipped", "message": "Tor blocking is disabled"}

        results = {}
        dl = self.download_tor_ips()
        results["download"] = dl

        pf = self.generate_pf_blocklist()
        results["pf_update"] = pf

        dns = self.generate_dns_overrides()
        results["dns_update"] = dns

        try:
            self._load_pf_anchor()
            results["pf_anchor"] = "ok"
        except Exception as exc:
            results["pf_anchor"] = str(exc)

        return {"result": "ok", **results}

    # ------------------------------------------------------------------
    # Layer Toggles
    # ------------------------------------------------------------------

    def toggle_layer(self, layer, enabled):
        """Toggle a specific blocking layer. layer: block_ips|block_ports|block_dns"""
        if layer not in ("block_ips", "block_ports", "block_dns", "alert_on_attempt"):
            return {"result": "failed", "message": "Unknown layer: {}".format(layer)}

        self._set_config(layer, "1" if enabled else "0")
        return {"result": "ok", "layer": layer, "enabled": enabled}

    # ------------------------------------------------------------------
    # Status / Stats
    # ------------------------------------------------------------------

    def get_status(self):
        """Return current Tor blocker status and statistics."""
        total_ips = self._db.query("SELECT COUNT(*) AS c FROM tor_blocked_ips")
        exit_ips = self._db.query(
            "SELECT COUNT(*) AS c FROM tor_blocked_ips WHERE node_type = 'exit'"
        )
        relay_ips = self._db.query(
            "SELECT COUNT(*) AS c FROM tor_blocked_ips WHERE node_type = 'relay'"
        )
        sources = self._db.query(
            "SELECT source, COUNT(*) AS cnt FROM tor_blocked_ips GROUP BY source ORDER BY cnt DESC"
        )
        recent_blocks = self._db.query(
            "SELECT * FROM tor_blocked_log ORDER BY timestamp DESC LIMIT 20"
        )
        block_count = self._db.query("SELECT COUNT(*) AS c FROM tor_blocked_log")

        return {
            "enabled": self._get_config("enabled") == "1",
            "layers": {
                "block_ips": self._get_config("block_ips") == "1",
                "block_ports": self._get_config("block_ports") == "1",
                "block_dns": self._get_config("block_dns") == "1",
                "alert_on_attempt": self._get_config("alert_on_attempt") == "1",
            },
            "last_updated": self._get_config("last_updated"),
            "ip_stats": {
                "total": total_ips[0]["c"] if total_ips else 0,
                "exit_nodes": exit_ips[0]["c"] if exit_ips else 0,
                "relay_nodes": relay_ips[0]["c"] if relay_ips else 0,
            },
            "sources": [{"source": r["source"], "count": r["cnt"]} for r in sources],
            "blocked_ports": TOR_PORTS,
            "blocked_domains": len(TOR_BLOCKED_DOMAINS),
            "total_blocks_logged": block_count[0]["c"] if block_count else 0,
            "recent_blocks": [dict(r) for r in recent_blocks],
        }

    def check_ip(self, ip):
        """Check if an IP is a known Tor node."""
        rows = self._db.query(
            "SELECT ip, source, node_type, first_seen, last_seen "
            "FROM tor_blocked_ips WHERE ip = ?",
            (ip,),
        )
        if rows:
            return {"is_tor": True, **dict(rows[0])}
        return {"is_tor": False, "ip": ip}

    def log_block(self, src_ip=None, dst_ip=None, dst_port=None, detail=None):
        """Log a Tor connection block attempt."""
        now = datetime.now(timezone.utc).isoformat()
        self._db.execute(
            "INSERT INTO tor_blocked_log (timestamp, src_ip, dst_ip, dst_port, detail) "
            "VALUES (?, ?, ?, ?, ?)",
            (now, src_ip, dst_ip, dst_port, detail),
        )
        self._db.commit()

    def get_blocked_ips_list(self, limit=100, offset=0):
        """Return paginated list of blocked Tor IPs."""
        rows = self._db.query(
            "SELECT * FROM tor_blocked_ips ORDER BY last_seen DESC LIMIT ? OFFSET ?",
            (limit, offset),
        )
        total = self._db.query("SELECT COUNT(*) AS c FROM tor_blocked_ips")
        return {
            "ips": [dict(r) for r in rows],
            "total": total[0]["c"] if total else 0,
        }

    def purge_stale_ips(self, days=7):
        """Remove Tor IPs not seen in the last N days."""
        from datetime import timedelta
        cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
        self._db.execute(
            "DELETE FROM tor_blocked_ips WHERE last_seen < ?", (cutoff,)
        )
        self._db.commit()
        return {"result": "ok", "cutoff": cutoff}
