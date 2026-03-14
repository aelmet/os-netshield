#!/usr/local/bin/python3
# Copyright (c) 2025-2026, NetShield Project
# All rights reserved.
#
# Web Categories Engine - Domain categorization and filtering
# Based on Zenarmor web filtering architecture.

"""
Web Categories Engine for NetShield.

Features:
- 60+ web content categories
- Shalla/UT1 blacklist database support
- Per-device/user category blocking
- Real-time URL classification
- Custom domain overrides
- Category usage statistics
"""

import hashlib
import logging
import os
import re
import sqlite3
import tarfile
import tempfile
import urllib.request
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

CATEGORIES_DB = "/var/netshield/web_categories.db"
CATEGORIES_DIR = "/var/netshield/categories"

# Category database sources
CATEGORY_SOURCES = {
    "shalla": {
        "url": "http://www.shallalist.de/Downloads/shallalist.tar.gz",
        "format": "shalla",
    },
    "ut1": {
        "url": "ftp://ftp.ut-capitole.fr/pub/reseau/cache/squidguard_contrib/blacklists.tar.gz",
        "format": "ut1",
    },
}

# Standard category definitions (Zenarmor/Firewalla compatible)
STANDARD_CATEGORIES = {
    # Adult & Mature
    "adult": {"name": "Adult Content", "group": "Adult", "severity": "high"},
    "pornography": {"name": "Pornography", "group": "Adult", "severity": "high"},
    "nudity": {"name": "Nudity", "group": "Adult", "severity": "high"},
    "sex_education": {"name": "Sex Education", "group": "Adult", "severity": "medium"},

    # Security Threats
    "malware": {"name": "Malware", "group": "Security", "severity": "critical"},
    "phishing": {"name": "Phishing", "group": "Security", "severity": "critical"},
    "spyware": {"name": "Spyware", "group": "Security", "severity": "critical"},
    "cryptomining": {"name": "Cryptomining", "group": "Security", "severity": "high"},
    "spam": {"name": "Spam Sources", "group": "Security", "severity": "medium"},

    # Social Media
    "social_networking": {"name": "Social Networking", "group": "Social", "severity": "low"},
    "social_media": {"name": "Social Media", "group": "Social", "severity": "low"},
    "dating": {"name": "Dating", "group": "Social", "severity": "medium"},
    "forums": {"name": "Forums", "group": "Social", "severity": "low"},

    # Entertainment
    "streaming": {"name": "Streaming Media", "group": "Entertainment", "severity": "low"},
    "video": {"name": "Video Sites", "group": "Entertainment", "severity": "low"},
    "music": {"name": "Music Sites", "group": "Entertainment", "severity": "low"},
    "gaming": {"name": "Gaming", "group": "Entertainment", "severity": "low"},
    "gambling": {"name": "Gambling", "group": "Entertainment", "severity": "high"},

    # Communication
    "chat": {"name": "Chat/IM", "group": "Communication", "severity": "low"},
    "webmail": {"name": "Webmail", "group": "Communication", "severity": "low"},
    "voip": {"name": "VoIP", "group": "Communication", "severity": "low"},

    # Shopping & Commerce
    "shopping": {"name": "Shopping", "group": "Commerce", "severity": "low"},
    "auctions": {"name": "Auctions", "group": "Commerce", "severity": "low"},
    "banking": {"name": "Banking", "group": "Commerce", "severity": "low"},
    "financial": {"name": "Financial Services", "group": "Commerce", "severity": "low"},
    "cryptocurrency": {"name": "Cryptocurrency", "group": "Commerce", "severity": "medium"},

    # News & Information
    "news": {"name": "News", "group": "Information", "severity": "low"},
    "reference": {"name": "Reference", "group": "Information", "severity": "low"},
    "education": {"name": "Education", "group": "Information", "severity": "low"},
    "government": {"name": "Government", "group": "Information", "severity": "low"},
    "legal": {"name": "Legal", "group": "Information", "severity": "low"},
    "health": {"name": "Health", "group": "Information", "severity": "low"},
    "religion": {"name": "Religion", "group": "Information", "severity": "low"},

    # Technology
    "tech": {"name": "Technology", "group": "Technology", "severity": "low"},
    "software": {"name": "Software Downloads", "group": "Technology", "severity": "medium"},
    "hacking": {"name": "Hacking", "group": "Technology", "severity": "high"},
    "proxies": {"name": "Proxy/Anonymizer", "group": "Technology", "severity": "high"},
    "vpn": {"name": "VPN Services", "group": "Technology", "severity": "medium"},
    "hosting": {"name": "Web Hosting", "group": "Technology", "severity": "low"},
    "search_engines": {"name": "Search Engines", "group": "Technology", "severity": "low"},

    # Business
    "business": {"name": "Business", "group": "Business", "severity": "low"},
    "job_search": {"name": "Job Search", "group": "Business", "severity": "low"},
    "real_estate": {"name": "Real Estate", "group": "Business", "severity": "low"},

    # Controversial
    "weapons": {"name": "Weapons", "group": "Controversial", "severity": "high"},
    "violence": {"name": "Violence", "group": "Controversial", "severity": "high"},
    "hate_speech": {"name": "Hate Speech", "group": "Controversial", "severity": "high"},
    "drugs": {"name": "Drugs", "group": "Controversial", "severity": "high"},
    "alcohol": {"name": "Alcohol", "group": "Controversial", "severity": "medium"},
    "tobacco": {"name": "Tobacco", "group": "Controversial", "severity": "medium"},

    # Ads & Tracking
    "ads": {"name": "Advertising", "group": "Ads", "severity": "low"},
    "trackers": {"name": "Trackers", "group": "Ads", "severity": "medium"},

    # File Sharing
    "file_sharing": {"name": "File Sharing", "group": "Downloads", "severity": "medium"},
    "torrents": {"name": "Torrents/P2P", "group": "Downloads", "severity": "medium"},
    "warez": {"name": "Warez/Piracy", "group": "Downloads", "severity": "high"},

    # Other
    "uncategorized": {"name": "Uncategorized", "group": "Other", "severity": "low"},
    "parked": {"name": "Parked Domains", "group": "Other", "severity": "low"},
    "dynamic_dns": {"name": "Dynamic DNS", "group": "Other", "severity": "medium"},
}

# Category group colors (for UI)
GROUP_COLORS = {
    "Adult": "#e74c3c",
    "Security": "#c0392b",
    "Social": "#3498db",
    "Entertainment": "#9b59b6",
    "Communication": "#1abc9c",
    "Commerce": "#f39c12",
    "Information": "#27ae60",
    "Technology": "#34495e",
    "Business": "#95a5a6",
    "Controversial": "#e67e22",
    "Ads": "#7f8c8d",
    "Downloads": "#d35400",
    "Other": "#bdc3c7",
}


# ---------------------------------------------------------------------------
# Data Classes
# ---------------------------------------------------------------------------


@dataclass
class WebCategory:
    """Represents a web category."""
    id: str
    name: str
    group: str
    severity: str
    domain_count: int = 0
    enabled: bool = True
    blocked_count: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "group": self.group,
            "severity": self.severity,
            "domain_count": self.domain_count,
            "enabled": self.enabled,
            "blocked_count": self.blocked_count,
            "color": GROUP_COLORS.get(self.group, "#bdc3c7"),
        }


@dataclass
class DomainClassification:
    """Result of domain classification."""
    domain: str
    category: str
    category_name: str
    group: str
    severity: str
    source: str  # "database", "custom", "cache"
    confidence: float = 1.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "domain": self.domain,
            "category": self.category,
            "category_name": self.category_name,
            "group": self.group,
            "severity": self.severity,
            "source": self.source,
            "confidence": self.confidence,
        }


# ---------------------------------------------------------------------------
# Category Database
# ---------------------------------------------------------------------------


class CategoryDatabase:
    """SQLite-based domain category database."""

    def __init__(self, db_path: str = CATEGORIES_DB):
        self.db_path = db_path
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        self._init_db()

    def _init_db(self) -> None:
        """Initialize database schema."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS domains (
                    domain TEXT PRIMARY KEY,
                    category TEXT NOT NULL,
                    source TEXT DEFAULT 'shalla',
                    added_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            """)

            conn.execute("""
                CREATE TABLE IF NOT EXISTS custom_overrides (
                    domain TEXT PRIMARY KEY,
                    category TEXT NOT NULL,
                    action TEXT DEFAULT 'categorize',
                    added_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            """)

            conn.execute("""
                CREATE TABLE IF NOT EXISTS category_config (
                    category TEXT PRIMARY KEY,
                    enabled INTEGER DEFAULT 1,
                    blocked_count INTEGER DEFAULT 0,
                    last_block TEXT
                )
            """)

            conn.execute("""
                CREATE TABLE IF NOT EXISTS device_policies (
                    mac TEXT NOT NULL,
                    category TEXT NOT NULL,
                    action TEXT DEFAULT 'block',
                    PRIMARY KEY (mac, category)
                )
            """)

            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_domains_category
                ON domains(category)
            """)

            conn.commit()

    def lookup_domain(self, domain: str) -> Optional[str]:
        """Look up category for a domain."""
        # Normalize domain
        domain = domain.lower().strip()
        if domain.startswith("www."):
            domain = domain[4:]

        with sqlite3.connect(self.db_path) as conn:
            # Check custom overrides first
            cursor = conn.execute(
                "SELECT category FROM custom_overrides WHERE domain = ?",
                (domain,)
            )
            row = cursor.fetchone()
            if row:
                return row[0]

            # Check main database
            cursor = conn.execute(
                "SELECT category FROM domains WHERE domain = ?",
                (domain,)
            )
            row = cursor.fetchone()
            if row:
                return row[0]

            # Try parent domains
            parts = domain.split(".")
            for i in range(1, len(parts) - 1):
                parent = ".".join(parts[i:])
                cursor = conn.execute(
                    "SELECT category FROM domains WHERE domain = ?",
                    (parent,)
                )
                row = cursor.fetchone()
                if row:
                    return row[0]

        return None

    def add_domains(self, domains: List[Tuple[str, str]], source: str = "import") -> int:
        """Bulk add domains with categories."""
        count = 0
        with sqlite3.connect(self.db_path) as conn:
            for domain, category in domains:
                try:
                    conn.execute(
                        "INSERT OR REPLACE INTO domains (domain, category, source) VALUES (?, ?, ?)",
                        (domain.lower(), category, source)
                    )
                    count += 1
                except Exception:
                    continue
            conn.commit()
        return count

    def add_custom_override(self, domain: str, category: str, action: str = "categorize") -> bool:
        """Add a custom domain override."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "INSERT OR REPLACE INTO custom_overrides (domain, category, action) VALUES (?, ?, ?)",
                (domain.lower(), category, action)
            )
            conn.commit()
        return True

    def remove_custom_override(self, domain: str) -> bool:
        """Remove a custom domain override."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("DELETE FROM custom_overrides WHERE domain = ?", (domain.lower(),))
            conn.commit()
        return True

    def get_custom_overrides(self) -> List[Dict[str, Any]]:
        """Get all custom overrides."""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute("SELECT * FROM custom_overrides ORDER BY added_at DESC")
            return [dict(row) for row in cursor.fetchall()]

    def get_category_counts(self) -> Dict[str, int]:
        """Get domain counts per category."""
        counts = {}
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute(
                "SELECT category, COUNT(*) as cnt FROM domains GROUP BY category"
            )
            for row in cursor:
                counts[row[0]] = row[1]
        return counts

    def set_category_enabled(self, category: str, enabled: bool) -> bool:
        """Enable or disable a category."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """
                INSERT INTO category_config (category, enabled)
                VALUES (?, ?)
                ON CONFLICT(category) DO UPDATE SET enabled = ?
                """,
                (category, int(enabled), int(enabled))
            )
            conn.commit()
        return True

    def get_enabled_categories(self) -> Set[str]:
        """Get set of enabled categories."""
        enabled = set(STANDARD_CATEGORIES.keys())
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute("SELECT category, enabled FROM category_config")
            for row in cursor:
                if row[1] == 0:
                    enabled.discard(row[0])
                else:
                    enabled.add(row[0])
        return enabled

    def increment_blocked(self, category: str) -> None:
        """Increment blocked count for a category."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """
                INSERT INTO category_config (category, blocked_count, last_block)
                VALUES (?, 1, datetime('now'))
                ON CONFLICT(category) DO UPDATE SET
                    blocked_count = blocked_count + 1,
                    last_block = datetime('now')
                """,
                (category,)
            )
            conn.commit()

    def get_blocked_counts(self) -> Dict[str, int]:
        """Get blocked counts per category."""
        counts = {}
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute("SELECT category, blocked_count FROM category_config")
            for row in cursor:
                counts[row[0]] = row[1]
        return counts

    def set_device_policy(self, mac: str, category: str, action: str = "block") -> bool:
        """Set category policy for a device."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO device_policies (mac, category, action)
                VALUES (?, ?, ?)
                """,
                (mac.upper(), category, action)
            )
            conn.commit()
        return True

    def remove_device_policy(self, mac: str, category: str) -> bool:
        """Remove category policy for a device."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "DELETE FROM device_policies WHERE mac = ? AND category = ?",
                (mac.upper(), category)
            )
            conn.commit()
        return True

    def get_device_policies(self, mac: str) -> Dict[str, str]:
        """Get category policies for a device."""
        policies = {}
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute(
                "SELECT category, action FROM device_policies WHERE mac = ?",
                (mac.upper(),)
            )
            for row in cursor:
                policies[row[0]] = row[1]
        return policies

    def get_stats(self) -> Dict[str, Any]:
        """Get database statistics."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute("SELECT COUNT(*) FROM domains")
            domain_count = cursor.fetchone()[0]

            cursor = conn.execute("SELECT COUNT(DISTINCT category) FROM domains")
            category_count = cursor.fetchone()[0]

            cursor = conn.execute("SELECT COUNT(*) FROM custom_overrides")
            override_count = cursor.fetchone()[0]

        return {
            "total_domains": domain_count,
            "categories_used": category_count,
            "custom_overrides": override_count,
        }


# ---------------------------------------------------------------------------
# Category Importer
# ---------------------------------------------------------------------------


class CategoryImporter:
    """Imports category databases from various sources."""

    def __init__(self, database: CategoryDatabase):
        self.database = database

    def import_shalla(self, archive_path: str) -> Dict[str, int]:
        """Import Shalla blacklist archive."""
        counts = {}

        try:
            with tarfile.open(archive_path, "r:gz") as tar:
                for member in tar.getmembers():
                    if member.name.endswith("/domains"):
                        # Extract category from path
                        parts = member.name.split("/")
                        if len(parts) >= 2:
                            category = self._normalize_category(parts[-2])

                            # Read domains
                            f = tar.extractfile(member)
                            if f:
                                domains = []
                                for line in f:
                                    domain = line.decode("utf-8", errors="ignore").strip()
                                    if domain and not domain.startswith("#"):
                                        domains.append((domain, category))

                                count = self.database.add_domains(domains, "shalla")
                                counts[category] = count
                                log.info("Imported %d domains for category: %s", count, category)
        except Exception as e:
            log.error("Error importing Shalla list: %s", e)

        return counts

    def import_ut1(self, archive_path: str) -> Dict[str, int]:
        """Import UT1 blacklist archive."""
        counts = {}

        try:
            with tarfile.open(archive_path, "r:gz") as tar:
                for member in tar.getmembers():
                    if member.name.endswith("/domains"):
                        parts = member.name.split("/")
                        if len(parts) >= 2:
                            category = self._normalize_category(parts[-2])

                            f = tar.extractfile(member)
                            if f:
                                domains = []
                                for line in f:
                                    domain = line.decode("utf-8", errors="ignore").strip()
                                    if domain and not domain.startswith("#"):
                                        domains.append((domain, category))

                                count = self.database.add_domains(domains, "ut1")
                                counts[category] = count
        except Exception as e:
            log.error("Error importing UT1 list: %s", e)

        return counts

    def download_and_import(self, source: str = "shalla") -> Dict[str, Any]:
        """Download and import a category source."""
        if source not in CATEGORY_SOURCES:
            return {"status": "error", "message": f"Unknown source: {source}"}

        config = CATEGORY_SOURCES[source]
        url = config["url"]

        try:
            # Download to temp file
            with tempfile.NamedTemporaryFile(suffix=".tar.gz", delete=False) as tmp:
                log.info("Downloading category database from %s", url)
                urllib.request.urlretrieve(url, tmp.name)

                if config["format"] == "shalla":
                    counts = self.import_shalla(tmp.name)
                elif config["format"] == "ut1":
                    counts = self.import_ut1(tmp.name)
                else:
                    return {"status": "error", "message": f"Unknown format: {config['format']}"}

                os.unlink(tmp.name)

            total = sum(counts.values())
            return {
                "status": "ok",
                "source": source,
                "categories_imported": len(counts),
                "domains_imported": total,
                "breakdown": counts,
            }
        except Exception as e:
            log.error("Error downloading/importing %s: %s", source, e)
            return {"status": "error", "message": str(e)}

    def _normalize_category(self, raw_category: str) -> str:
        """Normalize category name to standard category."""
        raw = raw_category.lower().replace("-", "_").replace(" ", "_")

        # Mapping from source categories to standard categories
        mapping = {
            "porn": "pornography",
            "adult": "adult",
            "sex": "adult",
            "gambling": "gambling",
            "games": "gaming",
            "socialnet": "social_networking",
            "social": "social_networking",
            "chat": "chat",
            "dating": "dating",
            "shopping": "shopping",
            "finance": "financial",
            "banking": "banking",
            "news": "news",
            "education": "education",
            "government": "government",
            "religion": "religion",
            "drugs": "drugs",
            "alcohol": "alcohol",
            "weapons": "weapons",
            "violence": "violence",
            "hacking": "hacking",
            "proxy": "proxies",
            "anonymizer": "proxies",
            "vpn": "vpn",
            "malware": "malware",
            "phishing": "phishing",
            "spam": "spam",
            "tracker": "trackers",
            "adv": "ads",
            "ads": "ads",
            "advertising": "ads",
            "warez": "warez",
            "filehosting": "file_sharing",
            "p2p": "torrents",
            "torrent": "torrents",
            "streaming": "streaming",
            "video": "video",
            "music": "music",
            "webmail": "webmail",
            "search": "search_engines",
        }

        for key, value in mapping.items():
            if key in raw:
                return value

        # Return as-is if no mapping found
        if raw in STANDARD_CATEGORIES:
            return raw

        return "uncategorized"


# ---------------------------------------------------------------------------
# Web Categories Engine
# ---------------------------------------------------------------------------


class WebCategoriesEngine:
    """Main web categories engine with DNS enforcement integration."""

    def __init__(self, dns_filter: Any = None):
        self.database = CategoryDatabase()
        self.importer = CategoryImporter(self.database)
        self._cache: Dict[str, Tuple[str, float]] = {}  # domain -> (category, timestamp)
        self._cache_ttl = 3600  # 1 hour
        self._dns_filter = dns_filter  # DNS filter for enforcement
        self._blocked_categories: Set[str] = set()  # Categories to block globally

    def classify(self, domain: str) -> DomainClassification:
        """Classify a domain."""
        domain = domain.lower().strip()
        if domain.startswith("www."):
            domain = domain[4:]

        # Check cache
        now = datetime.now().timestamp()
        if domain in self._cache:
            category, cached_at = self._cache[domain]
            if now - cached_at < self._cache_ttl:
                cat_info = STANDARD_CATEGORIES.get(category, {})
                return DomainClassification(
                    domain=domain,
                    category=category,
                    category_name=cat_info.get("name", category),
                    group=cat_info.get("group", "Other"),
                    severity=cat_info.get("severity", "low"),
                    source="cache",
                )

        # Look up in database
        category = self.database.lookup_domain(domain)

        if category:
            self._cache[domain] = (category, now)
            cat_info = STANDARD_CATEGORIES.get(category, {})
            return DomainClassification(
                domain=domain,
                category=category,
                category_name=cat_info.get("name", category),
                group=cat_info.get("group", "Other"),
                severity=cat_info.get("severity", "low"),
                source="database",
            )

        # Uncategorized
        return DomainClassification(
            domain=domain,
            category="uncategorized",
            category_name="Uncategorized",
            group="Other",
            severity="low",
            source="default",
            confidence=0.0,
        )

    def should_block(self, domain: str, device_mac: Optional[str] = None) -> Tuple[bool, str]:
        """Check if a domain should be blocked."""
        classification = self.classify(domain)
        category = classification.category

        # Check if category is globally enabled for blocking
        enabled = self.database.get_enabled_categories()
        if category not in enabled:
            return False, ""

        # Check device-specific policy if MAC provided
        if device_mac:
            policies = self.database.get_device_policies(device_mac)
            if category in policies:
                action = policies[category]
                if action == "block":
                    self.database.increment_blocked(category)
                    return True, classification.category_name
                elif action == "allow":
                    return False, ""

        return False, ""

    def get_categories(self) -> List[WebCategory]:
        """Get all categories with stats."""
        domain_counts = self.database.get_category_counts()
        blocked_counts = self.database.get_blocked_counts()
        enabled = self.database.get_enabled_categories()

        categories = []
        for cat_id, cat_info in STANDARD_CATEGORIES.items():
            categories.append(WebCategory(
                id=cat_id,
                name=cat_info["name"],
                group=cat_info["group"],
                severity=cat_info["severity"],
                domain_count=domain_counts.get(cat_id, 0),
                enabled=cat_id in enabled,
                blocked_count=blocked_counts.get(cat_id, 0),
            ))

        return sorted(categories, key=lambda c: (c.group, c.name))

    def get_category_groups(self) -> List[Dict[str, Any]]:
        """Get categories grouped."""
        categories = self.get_categories()
        groups = defaultdict(list)

        for cat in categories:
            groups[cat.group].append(cat.to_dict())

        return [
            {
                "name": name,
                "color": GROUP_COLORS.get(name, "#bdc3c7"),
                "categories": cats,
            }
            for name, cats in sorted(groups.items())
        ]

    def enable_category(self, category: str) -> Dict[str, Any]:
        """Enable blocking for a category."""
        if category not in STANDARD_CATEGORIES:
            return {"status": "error", "message": f"Unknown category: {category}"}
        self.database.set_category_enabled(category, True)
        return {"status": "ok", "category": category, "enabled": True}

    def disable_category(self, category: str) -> Dict[str, Any]:
        """Disable blocking for a category."""
        if category not in STANDARD_CATEGORIES:
            return {"status": "error", "message": f"Unknown category: {category}"}
        self.database.set_category_enabled(category, False)
        return {"status": "ok", "category": category, "enabled": False}

    def add_override(self, domain: str, category: str) -> Dict[str, Any]:
        """Add a custom domain override."""
        if category not in STANDARD_CATEGORIES and category != "uncategorized":
            return {"status": "error", "message": f"Unknown category: {category}"}
        self.database.add_custom_override(domain, category)
        # Clear cache
        domain = domain.lower()
        if domain in self._cache:
            del self._cache[domain]
        return {"status": "ok", "domain": domain, "category": category}

    def remove_override(self, domain: str) -> Dict[str, Any]:
        """Remove a custom domain override."""
        self.database.remove_custom_override(domain)
        domain = domain.lower()
        if domain in self._cache:
            del self._cache[domain]
        return {"status": "ok", "domain": domain}

    def get_overrides(self) -> List[Dict[str, Any]]:
        """Get all custom overrides."""
        return self.database.get_custom_overrides()

    def set_device_policy(self, mac: str, category: str, action: str) -> Dict[str, Any]:
        """Set category policy for a device."""
        if category not in STANDARD_CATEGORIES:
            return {"status": "error", "message": f"Unknown category: {category}"}
        if action not in ("block", "allow"):
            return {"status": "error", "message": "Action must be 'block' or 'allow'"}
        self.database.set_device_policy(mac, category, action)
        return {"status": "ok", "mac": mac, "category": category, "action": action}

    def get_device_policies(self, mac: str) -> Dict[str, str]:
        """Get category policies for a device."""
        return self.database.get_device_policies(mac)

    def update_database(self, source: str = "shalla") -> Dict[str, Any]:
        """Update category database from source."""
        return self.importer.download_and_import(source)

    def get_stats(self) -> Dict[str, Any]:
        """Get engine statistics."""
        db_stats = self.database.get_stats()
        return {
            **db_stats,
            "categories_defined": len(STANDARD_CATEGORIES),
            "groups_defined": len(GROUP_COLORS),
            "cache_size": len(self._cache),
        }

    def search_domains(self, query: str, category: Optional[str] = None, limit: int = 100) -> List[Dict[str, Any]]:
        """Search for domains in database."""
        results = []
        query = query.lower()

        with sqlite3.connect(self.database.db_path) as conn:
            if category:
                cursor = conn.execute(
                    "SELECT domain, category FROM domains WHERE domain LIKE ? AND category = ? LIMIT ?",
                    (f"%{query}%", category, limit)
                )
            else:
                cursor = conn.execute(
                    "SELECT domain, category FROM domains WHERE domain LIKE ? LIMIT ?",
                    (f"%{query}%", limit)
                )

            for row in cursor:
                cat_info = STANDARD_CATEGORIES.get(row[1], {})
                results.append({
                    "domain": row[0],
                    "category": row[1],
                    "category_name": cat_info.get("name", row[1]),
                })

        return results

    # ------------------------------------------------------------------
    # DNS Enforcement Integration (NEW)
    # ------------------------------------------------------------------

    def set_dns_filter(self, dns_filter: Any) -> None:
        """Set DNS filter module for enforcement."""
        self._dns_filter = dns_filter

    def block_and_enforce(self, domain: str, device_mac: Optional[str] = None) -> Dict[str, Any]:
        """
        Check if domain should be blocked AND enforce via DNS filter.

        This is the main enforcement entry point that:
        1. Classifies the domain
        2. Checks if blocking is needed
        3. Actually blocks via Unbound DNS
        """
        should_block, category_name = self.should_block(domain, device_mac)

        if not should_block:
            return {
                "blocked": False,
                "domain": domain,
                "category": None,
            }

        # Get full classification
        classification = self.classify(domain)

        # Enforce via DNS filter
        if self._dns_filter:
            self._dns_filter.add_custom_rule(domain, "block")
            log.info(
                "WEB_CATEGORY BLOCK: domain=%s category=%s device=%s",
                domain, category_name, device_mac or "global"
            )

        return {
            "blocked": True,
            "domain": domain,
            "category": classification.category,
            "category_name": category_name,
            "group": classification.group,
            "severity": classification.severity,
            "enforced": self._dns_filter is not None,
        }

    def set_category_blocking(self, category: str, block: bool = True) -> Dict[str, Any]:
        """
        Enable/disable blocking for a category and sync to DNS.

        When enabled, all domains in this category will be blocked via Unbound.
        """
        if category not in STANDARD_CATEGORIES:
            return {"status": "error", "message": f"Unknown category: {category}"}

        if block:
            self._blocked_categories.add(category)
            self.database.set_category_enabled(category, True)
        else:
            self._blocked_categories.discard(category)
            self.database.set_category_enabled(category, False)

        return {
            "status": "ok",
            "category": category,
            "blocking": block,
        }

    def sync_blocked_categories_to_dns(self, batch_size: int = 1000) -> Dict[str, Any]:
        """
        Sync all domains from blocked categories to DNS filter.

        This creates NXDOMAIN entries in Unbound for all domains
        in categories that have blocking enabled.
        """
        if not self._dns_filter:
            return {"status": "error", "message": "DNS filter not configured"}

        blocked_count = 0
        enabled_categories = self.database.get_enabled_categories()

        # Get device policies that specify blocking
        # For global blocking, we sync all enabled categories

        with sqlite3.connect(self.database.db_path) as conn:
            for category in enabled_categories:
                cursor = conn.execute(
                    "SELECT domain FROM domains WHERE category = ? LIMIT ?",
                    (category, batch_size)
                )

                for row in cursor:
                    domain = row[0]
                    self._dns_filter.add_custom_rule(domain, "block")
                    blocked_count += 1

        # Regenerate Unbound config
        self._dns_filter.generate_unbound_overrides()
        self._dns_filter.reload_unbound()

        log.info("Synced %d domains from %d categories to DNS blocklist",
                 blocked_count, len(enabled_categories))

        return {
            "status": "ok",
            "domains_blocked": blocked_count,
            "categories_synced": len(enabled_categories),
        }

    def get_blocking_status(self) -> Dict[str, Any]:
        """Get current blocking status for all categories."""
        enabled = self.database.get_enabled_categories()
        blocked_counts = self.database.get_blocked_counts()

        status = []
        for cat_id, cat_info in STANDARD_CATEGORIES.items():
            status.append({
                "category": cat_id,
                "name": cat_info["name"],
                "group": cat_info["group"],
                "severity": cat_info["severity"],
                "blocking_enabled": cat_id in enabled,
                "blocked_count": blocked_counts.get(cat_id, 0),
            })

        return {
            "categories": sorted(status, key=lambda x: (x["group"], x["name"])),
            "dns_filter_configured": self._dns_filter is not None,
            "total_enabled": len(enabled),
        }
