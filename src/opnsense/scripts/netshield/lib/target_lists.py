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

NetShield target_lists.py — Custom blocklist management and Unbound config generation.

Supported list formats:
  - plain_domain  : one domain per line (with optional comments)
  - plain_ip      : one IP/CIDR per line
  - hosts         : hosts-file format (IP <whitespace> domain)
  - mixed         : auto-detect per line (domain or IP)
"""

import ipaddress
import logging
import os
import re
import sqlite3
import urllib.error
import urllib.request
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

log = logging.getLogger(__name__)

TARGET_LISTS_DB_PATH = "/var/db/netshield/target_lists.db"

_LIST_TYPES = ("plain_domain", "plain_ip", "hosts", "mixed")

# Max download size: 100 MB
_MAX_DOWNLOAD_BYTES = 100 * 1024 * 1024

# ---------------------------------------------------------------------------
# DB setup
# ---------------------------------------------------------------------------

_DB_SCHEMA = """
CREATE TABLE IF NOT EXISTS lists (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    name         TEXT NOT NULL,
    domain       TEXT NOT NULL,
    list_type    TEXT NOT NULL DEFAULT 'plain_domain',
    last_updated TEXT NOT NULL DEFAULT (datetime('now','utc')),
    UNIQUE(name, domain)
);
CREATE INDEX IF NOT EXISTS idx_lists_name   ON lists(name);
CREATE INDEX IF NOT EXISTS idx_lists_domain ON lists(domain);
"""


def _get_conn(path: str = TARGET_LISTS_DB_PATH) -> sqlite3.Connection:
    db_dir = os.path.dirname(path)
    if db_dir and not os.path.isdir(db_dir):
        os.makedirs(db_dir, mode=0o750, exist_ok=True)
    conn = sqlite3.connect(path, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    for stmt in _DB_SCHEMA.strip().split(";"):
        stmt = stmt.strip()
        if stmt:
            conn.execute(stmt)
    conn.commit()
    return conn


# ---------------------------------------------------------------------------
# Parsing helpers
# ---------------------------------------------------------------------------

_COMMENT_RE = re.compile(r"[#;].*$")
_DOMAIN_RE = re.compile(
    r"^(?:[a-z0-9*](?:[a-z0-9\-]*[a-z0-9])?\.)+[a-z]{2,}$",
    re.IGNORECASE,
)


def _is_ip_or_cidr(value: str) -> bool:
    try:
        ipaddress.ip_network(value, strict=False)
        return True
    except ValueError:
        return False


def _is_domain(value: str) -> bool:
    return bool(_DOMAIN_RE.match(value))


def _clean_line(line: str) -> str:
    """Strip comments, whitespace, and trailing dots from a line."""
    line = _COMMENT_RE.sub("", line)
    return line.strip().rstrip(".").lower()


def parse_list(content: str, list_type: str) -> Tuple[List[str], List[str]]:
    """
    Parse a blocklist from raw string content.

    Returns a tuple of (domains, ips) where:
      domains — list of cleaned domain strings
      ips     — list of IP/CIDR strings

    list_type must be one of: plain_domain, plain_ip, hosts, mixed
    """
    if list_type not in _LIST_TYPES:
        log.warning("Unknown list_type '%s', defaulting to 'mixed'", list_type)
        list_type = "mixed"

    domains: List[str] = []
    ips: List[str] = []

    for raw_line in content.splitlines():
        line = _clean_line(raw_line)
        if not line:
            continue

        if list_type == "plain_domain":
            if _is_domain(line):
                domains.append(line)
            # Skip IPs and invalid entries

        elif list_type == "plain_ip":
            if _is_ip_or_cidr(line):
                ips.append(line)

        elif list_type == "hosts":
            # hosts format: "127.0.0.1 example.com" or "0.0.0.0 example.com"
            parts = line.split()
            if len(parts) >= 2:
                # First token is IP, rest are domains
                for domain_part in parts[1:]:
                    domain_part = domain_part.strip().rstrip(".").lower()
                    # Skip localhost and invalid
                    if domain_part in ("localhost", "local", "broadcasthost"):
                        continue
                    if _is_domain(domain_part):
                        domains.append(domain_part)
            elif len(parts) == 1:
                # Plain domain with no IP prefix
                if _is_domain(parts[0]):
                    domains.append(parts[0])

        elif list_type == "mixed":
            # Auto-detect
            if _is_ip_or_cidr(line):
                ips.append(line)
            elif _is_domain(line):
                domains.append(line)
            else:
                # Try hosts format
                parts = line.split()
                if len(parts) >= 2 and _is_ip_or_cidr(parts[0]):
                    for dp in parts[1:]:
                        dp = dp.strip().rstrip(".").lower()
                        if dp not in ("localhost", "local", "broadcasthost") and _is_domain(dp):
                            domains.append(dp)

    # Deduplicate while preserving order
    seen_d: set = set()
    seen_i: set = set()
    unique_domains = [d for d in domains if not (d in seen_d or seen_d.add(d))]
    unique_ips = [ip for ip in ips if not (ip in seen_i or seen_i.add(ip))]

    return unique_domains, unique_ips


# ---------------------------------------------------------------------------
# Download
# ---------------------------------------------------------------------------

def download_list(url: str, timeout: int = 60) -> Optional[str]:
    """
    Download a domain/IP list from a URL.
    Only http:// and https:// are accepted.
    Returns raw content as a string, or None on failure.
    """
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        log.error("download_list: only http/https URLs accepted")
        return None
    try:
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "NetShield-OPNsense/1.0"},
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read(_MAX_DOWNLOAD_BYTES)
        content = raw.decode("utf-8", errors="replace")
        log.info("Downloaded list from %s (%d bytes)", url, len(raw))
        return content
    except urllib.error.URLError as exc:
        log.warning("Failed to download list from %s: %s", url, exc)
        return None
    except Exception as exc:
        log.error("Unexpected error downloading %s: %s", url, exc)
        return None


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def sync_list(
    name: str,
    url: str,
    list_type: str = "mixed",
    path: str = TARGET_LISTS_DB_PATH,
) -> int:
    """
    Download a list from url and update the named list in the DB.
    Returns the number of domains/IPs stored, or -1 on failure.
    """
    content = download_list(url)
    if content is None:
        return -1

    domains, ips = parse_list(content, list_type)
    all_entries = [(d, "domain") for d in domains] + [(ip, "ip") for ip in ips]

    if not all_entries:
        log.warning("sync_list '%s': no valid entries parsed from %s", name, url)
        return 0

    try:
        conn = _get_conn(path)
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        # Delete stale entries for this list
        with conn:
            conn.execute("DELETE FROM lists WHERE name = ?", (name,))
            conn.executemany(
                """
                INSERT OR REPLACE INTO lists (name, domain, list_type, last_updated)
                VALUES (?, ?, ?, ?)
                """,
                [(name, entry, list_type, ts) for entry, _ in all_entries],
            )
        conn.close()
        log.info("sync_list '%s': stored %d entries", name, len(all_entries))
        return len(all_entries)
    except sqlite3.Error as exc:
        log.error("sync_list '%s' DB error: %s", name, exc)
        return -1


def get_list_domains(name: str, path: str = TARGET_LISTS_DB_PATH) -> List[str]:
    """
    Return all domain/IP entries for a named list.
    """
    try:
        conn = _get_conn(path)
        cur = conn.execute(
            "SELECT domain FROM lists WHERE name = ? ORDER BY domain",
            (name,),
        )
        rows = cur.fetchall()
        conn.close()
        return [row[0] for row in rows]
    except sqlite3.Error as exc:
        log.error("get_list_domains '%s' failed: %s", name, exc)
        return []


def export_unbound_config(
    active_lists: List[str],
    path: str = TARGET_LISTS_DB_PATH,
) -> str:
    """
    Generate Unbound local-zone NXDOMAIN config for all domain entries
    in the specified active list names.
    IP entries are excluded (pf handles those separately).
    Returns config content as a string.
    """
    if not active_lists:
        return "# NetShield target_lists — no active lists\n"

    lines = [
        "# NetShield target_lists — generated Unbound block config",
        "# Do not edit manually.",
        "",
    ]

    seen: set = set()
    try:
        conn = _get_conn(path)
        placeholders = ",".join("?" for _ in active_lists)
        cur = conn.execute(
            f"""
            SELECT DISTINCT domain FROM lists
            WHERE name IN ({placeholders})
              AND list_type != 'plain_ip'
            """,
            active_lists,
        )
        for row in cur:
            domain = row[0].strip().lower().rstrip(".")
            if not domain or domain in seen:
                continue
            # Skip pure IP entries that snuck in
            if _is_ip_or_cidr(domain):
                continue
            if _is_domain(domain):
                seen.add(domain)
                lines.append(f'local-zone: "{domain}." always_nxdomain')
        conn.close()
    except sqlite3.Error as exc:
        log.error("export_unbound_config failed: %s", exc)

    lines.append("")
    log.debug(
        "export_unbound_config: %d domains from lists %s",
        len(seen), active_lists,
    )
    return "\n".join(lines)


def list_names(path: str = TARGET_LISTS_DB_PATH) -> List[Dict]:
    """
    Return summary info for all stored lists: name, count, last_updated.
    """
    try:
        conn = _get_conn(path)
        cur = conn.execute(
            """
            SELECT name, COUNT(*) as count, MAX(last_updated) as last_updated
            FROM lists GROUP BY name ORDER BY name
            """
        )
        rows = cur.fetchall()
        conn.close()
        return [dict(row) for row in rows]
    except sqlite3.Error as exc:
        log.error("list_names failed: %s", exc)
        return []


def delete_list(name: str, path: str = TARGET_LISTS_DB_PATH) -> bool:
    """Remove all entries for a named list from the DB."""
    try:
        conn = _get_conn(path)
        with conn:
            conn.execute("DELETE FROM lists WHERE name = ?", (name,))
        conn.close()
        log.info("Deleted list '%s'", name)
        return True
    except sqlite3.Error as exc:
        log.error("delete_list '%s' failed: %s", name, exc)
        return False
