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
GeoIP Lookup and Blocking — Country-based traffic control using MaxMind GeoLite2.
"""

import logging
import subprocess
from datetime import datetime, timezone

log = logging.getLogger(__name__)

MAXMIND_DB_PATH = "/usr/local/share/GeoIP/GeoLite2-Country.mmdb"
VALID_ACTIONS = ("allow", "block", "log")

# Common ISO 3166-1 alpha-2 country names
COUNTRY_NAMES = {
    "AF": "Afghanistan", "AL": "Albania", "DZ": "Algeria", "AR": "Argentina",
    "AU": "Australia", "AT": "Austria", "BD": "Bangladesh", "BY": "Belarus",
    "BE": "Belgium", "BR": "Brazil", "BG": "Bulgaria", "CA": "Canada",
    "CL": "Chile", "CN": "China", "CO": "Colombia", "HR": "Croatia",
    "CU": "Cuba", "CZ": "Czech Republic", "DK": "Denmark", "EG": "Egypt",
    "FI": "Finland", "FR": "France", "DE": "Germany", "GR": "Greece",
    "HK": "Hong Kong", "HU": "Hungary", "IN": "India", "ID": "Indonesia",
    "IR": "Iran", "IQ": "Iraq", "IE": "Ireland", "IL": "Israel",
    "IT": "Italy", "JP": "Japan", "KZ": "Kazakhstan", "KE": "Kenya",
    "KP": "North Korea", "KR": "South Korea", "KW": "Kuwait", "MY": "Malaysia",
    "MX": "Mexico", "MA": "Morocco", "NL": "Netherlands", "NZ": "New Zealand",
    "NG": "Nigeria", "NO": "Norway", "PK": "Pakistan", "PE": "Peru",
    "PH": "Philippines", "PL": "Poland", "PT": "Portugal", "QA": "Qatar",
    "RO": "Romania", "RU": "Russia", "SA": "Saudi Arabia", "SG": "Singapore",
    "ZA": "South Africa", "ES": "Spain", "SE": "Sweden", "CH": "Switzerland",
    "TW": "Taiwan", "TH": "Thailand", "TR": "Turkey", "UA": "Ukraine",
    "AE": "United Arab Emirates", "GB": "United Kingdom", "US": "United States",
    "VN": "Vietnam", "YE": "Yemen",
}


class GeoIPManager:
    """Manages GeoIP country rules and pf integration."""

    def __init__(self, db_module):
        self._db = db_module
        self._reader = None
        self._init_tables()
        self._load_maxmind()

    # ------------------------------------------------------------------
    # Schema
    # ------------------------------------------------------------------

    def _init_tables(self):
        self._db.execute(
            """
            CREATE TABLE IF NOT EXISTS geoip_rules (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                country_code TEXT    NOT NULL UNIQUE,
                country_name TEXT    NOT NULL DEFAULT '',
                action       TEXT    NOT NULL DEFAULT 'block',
                created      TEXT    NOT NULL
            )
            """
        )
        self._db.execute(
            """
            CREATE TABLE IF NOT EXISTS geoip_connections (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                country_code TEXT    NOT NULL,
                country_name TEXT    NOT NULL DEFAULT '',
                action_taken TEXT    NOT NULL DEFAULT 'allow',
                timestamp    TEXT    NOT NULL
            )
            """
        )
        self._db.commit()

    # ------------------------------------------------------------------
    # MaxMind
    # ------------------------------------------------------------------

    def _load_maxmind(self):
        try:
            import maxminddb  # type: ignore
            self._reader = maxminddb.open_database(MAXMIND_DB_PATH)
            log.info("MaxMind GeoLite2 database loaded from %s", MAXMIND_DB_PATH)
            return
        except ImportError:
            log.info("maxminddb module not installed; trying pure-Python reader")
        except FileNotFoundError:
            log.warning("MaxMind DB not found at %s; GeoIP lookups disabled", MAXMIND_DB_PATH)
            self._reader = None
            return
        except Exception as exc:
            log.error("Failed to load MaxMind DB: %s", exc)

        # Fallback: pure-Python MMDB reader (no dependencies)
        try:
            from lib.mmdb_reader import MMDBReader
            self._reader = MMDBReader(MAXMIND_DB_PATH)
            log.info("Pure-Python MMDB reader loaded from %s", MAXMIND_DB_PATH)
        except FileNotFoundError:
            log.warning("MaxMind DB not found at %s; GeoIP lookups disabled", MAXMIND_DB_PATH)
            self._reader = None
        except Exception as exc:
            log.error("Failed to load pure-Python MMDB reader: %s", exc)
            self._reader = None

    # ------------------------------------------------------------------
    # Lookup
    # ------------------------------------------------------------------

    def lookup(self, ip):
        """Look up an IP and return country info dict."""
        if self._reader is None:
            return {"country_code": "XX", "country_name": "Unknown", "continent": "Unknown"}
        try:
            record = self._reader.get(ip)
            if record is None:
                return {"country_code": "XX", "country_name": "Unknown", "continent": "Unknown"}
            country = record.get("country", {})
            continent = record.get("continent", {})
            return {
                "country_code": country.get("iso_code", "XX"),
                "country_name": country.get("names", {}).get("en", "Unknown"),
                "continent": continent.get("names", {}).get("en", "Unknown"),
            }
        except Exception as exc:
            log.error("GeoIP lookup failed for %s: %s", ip, exc)
            return {"country_code": "XX", "country_name": "Unknown", "continent": "Unknown"}

    # ------------------------------------------------------------------
    # Rule matching
    # ------------------------------------------------------------------

    def check_rules(self, ip):
        """Return action dict for an IP based on country rules."""
        geo = self.lookup(ip)
        cc = geo["country_code"]

        row = self._db.fetchone(
            "SELECT action, country_name FROM geoip_rules WHERE country_code = ?", (cc,)
        )
        if row:
            action = row["action"]
        else:
            action = "allow"

        # Record this connection
        now = datetime.now(timezone.utc).isoformat()
        self._db.execute(
            """
            INSERT INTO geoip_connections (country_code, country_name, action_taken, timestamp)
            VALUES (?, ?, ?, ?)
            """,
            (cc, geo["country_name"], action, now),
        )
        self._db.commit()

        return {
            "action": action,
            "rule_matched": row is not None,
            "country_code": cc,
            "country_name": geo["country_name"],
        }

    # ------------------------------------------------------------------
    # Rule CRUD
    # ------------------------------------------------------------------

    def add_rule(self, country_code, action, country_name=""):
        if action not in VALID_ACTIONS:
            raise ValueError(f"Invalid action '{action}'. Must be one of: {VALID_ACTIONS}")
        country_code = country_code.upper()

        # Auto-resolve country name from lookup table if not provided
        if not country_name:
            country_name = COUNTRY_NAMES.get(country_code, country_code)

        now = datetime.now(timezone.utc).isoformat()
        self._db.execute(
            """
            INSERT INTO geoip_rules (country_code, country_name, action, created)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(country_code) DO UPDATE SET action = excluded.action,
                country_name = CASE WHEN excluded.country_name != '' THEN excluded.country_name
                               ELSE country_name END
            """,
            (country_code, country_name, action, now),
        )
        self._db.commit()
        log.info("GeoIP rule added: %s -> %s", country_code, action)

    def remove_rule(self, country_code):
        country_code = country_code.upper()
        self._db.execute(
            "DELETE FROM geoip_rules WHERE country_code = ?", (country_code,)
        )
        self._db.commit()
        log.info("GeoIP rule removed: %s", country_code)

    def get_rules(self):
        rows = self._db.fetchall(
            "SELECT country_code, country_name, action, created FROM geoip_rules ORDER BY country_code"
        )
        return [
            {
                "country_code": r["country_code"],
                "country_name": r["country_name"],
                "action": r["action"],
                "created": r["created"],
            }
            for r in rows
        ]

    # ------------------------------------------------------------------
    # PF integration
    # ------------------------------------------------------------------

    def generate_pf_rules(self):
        """Generate and apply country-based pf block rules."""
        block_rows = self._db.fetchall(
            "SELECT country_code FROM geoip_rules WHERE action = 'block'"
        )
        if not block_rows:
            log.info("No GeoIP block rules to apply")
            return

        for row in block_rows:
            cc = row["country_code"]
            table_name = f"netshield_geo_{cc.lower()}"
            try:
                # Flush and recreate per-country table
                subprocess.run(
                    ["pfctl", "-t", table_name, "-T", "flush"],
                    capture_output=True,
                )
                # If geoip2-tools or similar generates per-country files:
                cc_file = f"/usr/local/share/GeoIP/country/{cc}.txt"
                subprocess.run(
                    ["pfctl", "-t", table_name, "-T", "add", "-f", cc_file],
                    capture_output=True,
                )
                log.info("Applied GeoIP block for country: %s", cc)
            except (FileNotFoundError, subprocess.CalledProcessError) as exc:
                log.warning("pf GeoIP rule failed for %s: %s", cc, exc)

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_stats(self):
        """Build GeoIP stats from live pf state table."""
        import subprocess as _sp
        from collections import Counter as _Counter

        dst_ips = _Counter()
        try:
            result = _sp.run(["pfctl", "-s", "state"], capture_output=True, text=True, timeout=5)
            for line in result.stdout.strip().split("\n"):
                parts = line.split()
                for i, p in enumerate(parts):
                    if p == "->":
                        if i + 1 < len(parts):
                            ip_port = parts[i + 1]
                            ip = ip_port.rsplit(":", 1)[0] if ":" in ip_port else ip_port
                            # Skip private/local IPs
                            if not ip.startswith(("192.168.", "10.", "127.", "172.1", "172.2", "172.3", "fe80", "::1")):
                                dst_ips[ip] += 1
                        break
        except Exception as exc:
            log.warning("Failed to read pf state: %s", exc)

        # GeoIP enrich top IPs
        country_counts = _Counter()
        for ip, count in dst_ips.most_common(500):
            geo = self.lookup(ip)
            cc = geo.get("country_code", "XX")
            cn = geo.get("country_name", "Unknown")
            if cc != "XX":
                country_counts[(cc, cn)] += count

        connections_by_country = [
            {"country_code": cc, "country_name": cn, "count": cnt}
            for (cc, cn), cnt in country_counts.most_common(20)
        ]

        # Count blocked from rules
        block_rules = self._db.fetchall(
            "SELECT country_code FROM geoip_rules WHERE action = 'block'"
        )
        blocked_codes = {r["country_code"] for r in block_rules}
        blocked_count = sum(
            c["count"] for c in connections_by_country if c["country_code"] in blocked_codes
        )

        total_connections = sum(dst_ips.values())

        return {
            "connections_by_country": connections_by_country,
            "blocked_count": blocked_count,
            "total_connections": total_connections,
            "rules_count": len(block_rules),
        }

