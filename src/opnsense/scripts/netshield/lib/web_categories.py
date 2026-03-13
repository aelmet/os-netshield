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

NetShield web_categories.py — Web content categorization and Unbound config generation.
"""

import logging
import os
import sqlite3
import tempfile
import urllib.request
import urllib.error
from typing import Dict, List, Optional, Tuple

log = logging.getLogger(__name__)

CATEGORIES_DB_PATH = "/var/db/netshield/web_categories.db"

# ---------------------------------------------------------------------------
# Category definitions
# ---------------------------------------------------------------------------

DEFAULT_CATEGORIES: Dict[str, str] = {
    # --- Security / Threats ---
    "malware":              "Malware distribution and C2 communication",
    "phishing":             "Phishing and credential harvesting sites",
    "spyware":              "Spyware and stalkerware",
    "botnets":              "Known botnet command and control",
    "spam":                 "Spam-related domains",
    "ransomware":           "Ransomware delivery and infrastructure",
    "exploit_kits":         "Drive-by exploit delivery",
    "keyloggers":           "Keylogger distribution",
    "fraudulent":           "Online fraud and scam sites",
    "suspicious":           "Suspicious or potentially unsafe",
    # --- Adult / Sensitive ---
    "adult":                "Adult and sexually explicit content",
    "adult_chat":           "Adult chat and dating services",
    "nudity":               "Non-explicit nudity",
    "lingerie":             "Lingerie and swimwear",
    # --- Legal concerns ---
    "gambling":             "Online gambling and casinos",
    "weapons":              "Weapons sales and information",
    "drugs":                "Drug-related content and sales",
    "illegal_downloads":    "Piracy and illegal content distribution",
    "torrent":              "BitTorrent and peer-to-peer file sharing",
    "warez":                "Software cracks and warez",
    "hacking":              "Hacking tools and tutorials",
    "hate_speech":          "Hate speech and extremism",
    # --- Social ---
    "social_media":         "Social networking platforms",
    "dating":               "Online dating services",
    "forums":               "Discussion boards and forums",
    "blogs":                "Personal and public blogs",
    "chat":                 "Chat and instant messaging",
    "personals":            "Personal ads",
    # --- Entertainment ---
    "streaming":            "Video and audio streaming services",
    "gaming":               "Online games and gaming platforms",
    "gambling_games":       "Simulated gambling (free-to-play)",
    "entertainment":        "General entertainment sites",
    "humor":                "Humor and comedy",
    "sports":               "Sports news and scores",
    "music":                "Music and lyrics",
    "movies":               "Film and cinema",
    "anime":                "Anime and manga",
    "comics":               "Comics and graphic novels",
    # --- Communication ---
    "email":                "Webmail and email services",
    "voip":                 "VoIP and internet telephony",
    "messaging":            "Messaging applications",
    "conferencing":         "Video conferencing",
    # --- Business / Productivity ---
    "productivity":         "Productivity and office tools",
    "business":             "Business and enterprise software",
    "finance":              "Financial services and banking",
    "cryptocurrency":       "Cryptocurrency exchanges and wallets",
    "shopping":             "E-commerce and online shopping",
    "auctions":             "Auction sites",
    "real_estate":          "Real estate listings",
    "travel":               "Travel and booking",
    "job_search":           "Job boards and career sites",
    # --- Technology ---
    "technology":           "Technology news and resources",
    "software_downloads":   "Software and app downloads",
    "developer_tools":      "Developer tools and code hosting",
    "cloud_storage":        "Cloud storage and file sharing",
    "cdn":                  "Content delivery networks",
    # --- Information ---
    "news":                 "News and media",
    "education":            "Educational content",
    "reference":            "Reference and encyclopaedia",
    "government":           "Government websites",
    "health":               "Health and medical information",
    "religion":             "Religion and spirituality",
    "politics":             "Political content",
    "legal":                "Legal services and information",
    # --- Network / Evasion ---
    "vpn":                  "VPN and anonymizer services",
    "proxy":                "Web proxies and circumvention tools",
    "tor":                  "Tor network entry nodes and related",
    "anonymizers":          "General anonymization services",
    "doh":                  "DNS-over-HTTPS providers",
    # --- Advertising / Tracking ---
    "advertising":          "Online advertising networks",
    "analytics":            "Web analytics and tracking",
    # --- Parental control ---
    "child_abuse":          "Child sexual abuse material (CSAM) — always blocked",
    "violence":             "Graphic violence",
    "self_harm":            "Self-harm and suicide content",
}


# ---------------------------------------------------------------------------
# DB setup
# ---------------------------------------------------------------------------

_DB_SCHEMA = """
CREATE TABLE IF NOT EXISTS categories (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    category    TEXT NOT NULL,
    domain      TEXT NOT NULL,
    last_updated TEXT NOT NULL DEFAULT (datetime('now','utc')),
    UNIQUE(category, domain)
);
CREATE INDEX IF NOT EXISTS idx_cat_domain ON categories(domain);
CREATE INDEX IF NOT EXISTS idx_cat_name   ON categories(category);
"""


def _get_conn(path: str = CATEGORIES_DB_PATH) -> sqlite3.Connection:
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
# Download / fetch
# ---------------------------------------------------------------------------

def download_category_list(url: str, timeout: int = 30) -> Optional[str]:
    """
    Fetch a domain list from a URL.
    Only http:// and https:// schemes are accepted.
    Returns raw content as a string, or None on failure.

    Note: the URL must be configured by the administrator in the plugin settings.
    No outbound calls are made unless explicitly configured.
    """
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        log.error("download_category_list: only http/https URLs accepted, got: %.100s", url)
        return None
    try:
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "NetShield-OPNsense/1.0"},
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            # Limit download to 50 MB to avoid memory exhaustion
            raw = resp.read(50 * 1024 * 1024)
        content = raw.decode("utf-8", errors="replace")
        log.info("Downloaded category list from %s (%d bytes)", url, len(raw))
        return content
    except urllib.error.URLError as exc:
        log.warning("Failed to download category list from %s: %s", url, exc)
        return None
    except Exception as exc:
        log.error("Unexpected error downloading %s: %s", url, exc)
        return None


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def load_categories_db(path: str = CATEGORIES_DB_PATH) -> Dict[str, int]:
    """
    Return a dict of {category_name: domain_count} for all categories in the DB.
    """
    try:
        conn = _get_conn(path)
        cur = conn.execute(
            "SELECT category, COUNT(*) as cnt FROM categories GROUP BY category"
        )
        rows = cur.fetchall()
        conn.close()
        return {row["category"]: row["cnt"] for row in rows}
    except sqlite3.Error as exc:
        log.error("load_categories_db failed: %s", exc)
        return {}


def categorize_domain(domain: str, path: str = CATEGORIES_DB_PATH) -> Optional[str]:
    """
    Look up the category for a domain.
    Tries exact match, then strips subdomains one level at a time.
    Returns the first matching category name, or None.
    """
    if not domain:
        return None
    domain = domain.lower().rstrip(".")
    try:
        conn = _get_conn(path)
        # Try exact then parent domains
        parts = domain.split(".")
        for i in range(len(parts) - 1):
            candidate = ".".join(parts[i:])
            row = conn.execute(
                "SELECT category FROM categories WHERE domain = ? LIMIT 1",
                (candidate,),
            ).fetchone()
            if row:
                conn.close()
                return row["category"]
        conn.close()
    except sqlite3.Error as exc:
        log.error("categorize_domain failed for %s: %s", domain, exc)
    return None


def get_blocked_categories(path: str = CATEGORIES_DB_PATH) -> List[str]:
    """
    Return list of category names that have at least one domain in the DB.
    (Caller should check policy engine to determine which are actually blocked.)
    """
    counts = load_categories_db(path)
    return [cat for cat, cnt in counts.items() if cnt > 0]


def update_category_db(
    category_name: str,
    domains: List[str],
    path: str = CATEGORIES_DB_PATH,
) -> int:
    """
    Insert or update domains for a category.
    Returns the number of domains successfully inserted/updated.
    """
    if not category_name or not domains:
        return 0
    count = 0
    try:
        conn = _get_conn(path)
        with conn:
            for domain in domains:
                domain = domain.strip().lower().rstrip(".")
                if not domain:
                    continue
                conn.execute(
                    """
                    INSERT INTO categories (category, domain, last_updated)
                    VALUES (?, ?, datetime('now','utc'))
                    ON CONFLICT(category, domain) DO UPDATE
                      SET last_updated = excluded.last_updated
                    """,
                    (category_name, domain),
                )
                count += 1
        conn.close()
        log.debug("update_category_db: %s += %d domains", category_name, count)
    except sqlite3.Error as exc:
        log.error("update_category_db failed: %s", exc)
    return count


def export_unbound_config(
    blocked_categories: List[str],
    path: str = CATEGORIES_DB_PATH,
) -> str:
    """
    Generate Unbound local-zone NXDOMAIN config for all domains
    in the specified blocked categories.
    Returns config content as a string.
    """
    if not blocked_categories:
        return "# NetShield web_categories — no blocked categories\n"

    lines = [
        "# NetShield web_categories — generated Unbound block config",
        "# Do not edit manually.",
        "",
    ]

    seen: set = set()
    try:
        conn = _get_conn(path)
        placeholders = ",".join("?" for _ in blocked_categories)
        cur = conn.execute(
            f"SELECT DISTINCT domain FROM categories WHERE category IN ({placeholders})",
            blocked_categories,
        )
        for row in cur:
            domain = row[0].strip().lower().rstrip(".")
            if domain and domain not in seen:
                seen.add(domain)
                lines.append(f'local-zone: "{domain}." always_nxdomain')
        conn.close()
    except sqlite3.Error as exc:
        log.error("export_unbound_config failed: %s", exc)

    lines.append("")
    log.debug(
        "export_unbound_config: %d domains for %d categories",
        len(seen), len(blocked_categories),
    )
    return "\n".join(lines)
