#!/usr/local/bin/python3
# Copyright (c) 2025-2026, NetShield Project
# Application Control - nDPI/Suricata-based app detection and blocking

"""
Application Control for NetShield.

Features:
- Real-time application detection via Suricata/nDPI
- Application blocking via pf rules
- Per-device app policies
- Bandwidth limits per app
"""

import json
import logging
import os
import re
import sqlite3
import subprocess
from dataclasses import dataclass
from datetime import datetime
from typing import Dict, List, Optional, Set

log = logging.getLogger(__name__)

DB_PATH = "/var/db/netshield/netshield.db"
EVE_LOG = "/var/log/suricata/eve.json"

# Application signatures (SNI/domain patterns)
APP_SIGNATURES = {
    # Social Media
    "facebook": {
        "id": 1202,
        "name": "Facebook",
        "category": "Social Media",
        "patterns": [
            "facebook.com", "facebook.net", "fbcdn.net", "fb.com", "fbsbx.com",
            "messenger.com", "m.me", "accountkit.com", "facebookcorewwwi.onion",
            "workplace.com", "facebook-hardware.com", "freebasics.com",
        ],
    },
    "instagram": {
        "id": 1203,
        "name": "Instagram",
        "category": "Social Media",
        "patterns": [
            "instagram.com", "cdninstagram.com", "ig.me",
        ],
    },
    "twitter": {
        "id": 1204,
        "name": "Twitter/X",
        "category": "Social Media",
        "patterns": [
            "twitter.com", "twimg.com", "x.com", "t.co",
            "tweetdeck.com", "periscope.tv", "pscp.tv",
        ],
    },
    "tiktok": {
        "id": 1205,
        "name": "TikTok",
        "category": "Social Media",
        "patterns": [
            "tiktok.com", "tiktokcdn.com", "tiktokcdn-eu.com", "tiktokcdn-us.com",
            "tiktokv.com", "tiktokw.us", "tiktokpangle.us",
            "byteoversea.com", "ibytedtos.com", "ibyteimg.com",
            "musical.ly", "muscdn.com", "ttwstatic.com",
        ],
    },
    "snapchat": {
        "id": 1206,
        "name": "Snapchat",
        "category": "Social Media",
        "patterns": [
            "snapchat.com", "snap.com", "sc-cdn.net", "sc-static.net",
            "sc-jpl.com", "snapkit.co", "bitmoji.com",
        ],
    },
    "linkedin": {
        "id": 1207,
        "name": "LinkedIn",
        "category": "Social Media",
        "patterns": ["linkedin.com", "licdn.com", "linkedin.cn"],
    },
    "reddit": {
        "id": 1208,
        "name": "Reddit",
        "category": "Social Media",
        "patterns": ["reddit.com", "redd.it", "redditstatic.com", "redditmedia.com", "redditspace.com"],
    },

    # Streaming Video
    "youtube": {
        "id": 1302,
        "name": "YouTube",
        "category": "Streaming Video",
        "patterns": [
            "youtube.com", "youtu.be", "ytimg.com", "googlevideo.com",
            "yt3.ggpht.com", "youtube-nocookie.com", "youtube-ui.l.google.com",
            "youtubei.googleapis.com", "youtube.googleapis.com",
            "video-stats.l.google.com",
        ],
    },
    "netflix": {
        "id": 1303,
        "name": "Netflix",
        "category": "Streaming Video",
        "patterns": [
            "netflix.com", "nflxvideo.net", "nflximg.net", "nflxext.com",
            "nflxso.net", "netflix.net",
        ],
    },
    "twitch": {
        "id": 1304,
        "name": "Twitch",
        "category": "Streaming Video",
        "patterns": [
            "twitch.tv", "twitchcdn.net", "jtvnw.net", "twitchsvc.net",
            "ext-twitch.tv",
        ],
    },
    "disney": {
        "id": 1305,
        "name": "Disney+",
        "category": "Streaming Video",
        "patterns": [
            "disneyplus.com", "disney-plus.net", "dssott.com", "bamgrid.com",
            "disney-portal.my.onetrust.com", "disneystreaming.com",
        ],
    },
    "amazon_video": {
        "id": 1306,
        "name": "Amazon Prime Video",
        "category": "Streaming Video",
        "patterns": [
            "primevideo.com", "amazonvideo.com", "atv-ps.amazon.com",
            "aiv-cdn.net", "aiv-delivery.net",
        ],
    },
    "hulu": {
        "id": 1307,
        "name": "Hulu",
        "category": "Streaming Video",
        "patterns": ["hulu.com", "hulustream.com", "hulu.ad", "huluim.com"],
    },
    "spotify": {
        "id": 1308,
        "name": "Spotify",
        "category": "Streaming Audio",
        "patterns": [
            "spotify.com", "scdn.co", "spotifycdn.com",
            "spotify.design", "spotilocal.com", "audio-ak-spotify-com.akamaized.net",
        ],
    },

    # Gaming
    "steam": {
        "id": 1402,
        "name": "Steam",
        "category": "Gaming",
        "patterns": [
            "steampowered.com", "steamcommunity.com", "steamstatic.com",
            "steamcdn-a.akamaihd.net", "steamgames.com", "steamusercontent.com",
            "steamcontent.com",
        ],
    },
    "xbox_live": {
        "id": 1403,
        "name": "Xbox Live",
        "category": "Gaming",
        "patterns": ["xbox.com", "xboxlive.com", "xbox.net", "xboxservices.com"],
    },
    "playstation": {
        "id": 1404,
        "name": "PlayStation Network",
        "category": "Gaming",
        "patterns": [
            "playstation.com", "playstation.net", "sonyentertainmentnetwork.com",
            "sony.net", "sie.com",
        ],
    },
    "epic_games": {
        "id": 1405,
        "name": "Epic Games",
        "category": "Gaming",
        "patterns": [
            "epicgames.com", "unrealengine.com", "fortnite.com",
            "epicgames.dev", "ol.epicgames.com",
        ],
    },
    "roblox": {
        "id": 1406,
        "name": "Roblox",
        "category": "Gaming",
        "patterns": ["roblox.com", "rbxcdn.com", "roblox.cn", "rbx.com"],
    },

    # Messaging
    "whatsapp": {
        "id": 1502,
        "name": "WhatsApp",
        "category": "Messaging",
        "patterns": [
            "whatsapp.com", "whatsapp.net", "wa.me",
            "whatsapp-plus.info",
        ],
    },
    "telegram": {
        "id": 1503,
        "name": "Telegram",
        "category": "Messaging",
        "patterns": [
            "telegram.org", "t.me", "telegram.me",
            "telesco.pe", "tdesktop.com", "telegra.ph",
        ],
    },
    "signal": {
        "id": 1504,
        "name": "Signal",
        "category": "Messaging",
        "patterns": [
            "signal.org", "whispersystems.org",
            "signal.art", "signal.group",
        ],
    },
    "discord": {
        "id": 1505,
        "name": "Discord",
        "category": "Messaging",
        "patterns": [
            "discord.com", "discordapp.com", "discord.gg",
            "discordapp.net", "dis.gd", "discord.new",
        ],
    },
    "slack": {
        "id": 1506,
        "name": "Slack",
        "category": "Messaging",
        "patterns": ["slack.com", "slack-edge.com"],
    },
    "teams": {
        "id": 1507,
        "name": "Microsoft Teams",
        "category": "Messaging",
        "patterns": ["teams.microsoft.com", "teams.live.com"],
    },
    "zoom": {
        "id": 1508,
        "name": "Zoom",
        "category": "Messaging",
        "patterns": ["zoom.us", "zoomcdn.com", "zoomus.cn"],
    },

    # Cloud Storage
    "dropbox": {
        "id": 1602,
        "name": "Dropbox",
        "category": "Cloud Storage",
        "patterns": ["dropbox.com", "dropboxapi.com"],
    },
    "google_drive": {
        "id": 1603,
        "name": "Google Drive",
        "category": "Cloud Storage",
        "patterns": ["drive.google.com", "docs.google.com"],
    },
    "onedrive": {
        "id": 1604,
        "name": "OneDrive",
        "category": "Cloud Storage",
        "patterns": ["onedrive.live.com", "1drv.ms"],
    },
    "icloud": {
        "id": 1605,
        "name": "iCloud",
        "category": "Cloud Storage",
        "patterns": ["icloud.com", "apple.com"],
    },

    "pinterest": {
        "id": 1209,
        "name": "Pinterest",
        "category": "Social Media",
        "patterns": ["pinterest.com", "pinimg.com"],
    },

    # VPN/Proxy
    "tor": {
        "id": 1702,
        "name": "Tor",
        "category": "VPN/Proxy",
        "patterns": ["torproject.org"],
    },

    # P2P/Torrents
    "bittorrent": {
        "id": 1102,
        "name": "BitTorrent",
        "category": "P2P",
        "patterns": ["bittorrent.com", "utorrent.com"],
        "ports": [6881, 6882, 6883, 6884, 6885, 6886, 6887, 6888, 6889],
    },

    # Anime/Manga
    "crunchyroll": {
        "id": 1901,
        "name": "Crunchyroll",
        "category": "Anime/Manga",
        "patterns": ["crunchyroll.com", "vrv.co"],
    },
    "funimation": {
        "id": 1902,
        "name": "Funimation",
        "category": "Anime/Manga",
        "patterns": ["funimation.com"],
    },
    "myanimelist": {
        "id": 1903,
        "name": "MyAnimeList",
        "category": "Anime/Manga",
        "patterns": ["myanimelist.net"],
    },
    "anilist": {
        "id": 1904,
        "name": "AniList",
        "category": "Anime/Manga",
        "patterns": ["anilist.co"],
    },
    "9anime": {
        "id": 1905,
        "name": "9anime",
        "category": "Anime/Manga",
        "patterns": ["9anime.to", "9anime.me", "9anime.id", "9anime.gs", "9anime.se", "9anime.pl"],
    },
    "gogoanime": {
        "id": 1906,
        "name": "GoGoAnime",
        "category": "Anime/Manga",
        "patterns": ["gogoanime.gg", "gogoanime.pe", "gogoanime.fi", "gogoanimehd.io", "anitaku.to", "anitaku.pe"],
    },
    "animepahe": {
        "id": 1907,
        "name": "AnimePahe",
        "category": "Anime/Manga",
        "patterns": ["animepahe.com", "animepahe.ru", "animepahe.org"],
    },
    "zoro": {
        "id": 1908,
        "name": "Zoro/Aniwatch",
        "category": "Anime/Manga",
        "patterns": ["zoro.to", "aniwatch.to", "aniwatch.me", "hianime.to"],
    },
    "mangadex": {
        "id": 1909,
        "name": "MangaDex",
        "category": "Anime/Manga",
        "patterns": ["mangadex.org", "mangadex.tv"],
    },
    "mangakakalot": {
        "id": 1910,
        "name": "Mangakakalot",
        "category": "Anime/Manga",
        "patterns": ["mangakakalot.com", "manganato.com", "chapmanganato.to", "chapmanganelo.com"],
    },
    "mangahere": {
        "id": 1911,
        "name": "MangaHere",
        "category": "Anime/Manga",
        "patterns": ["mangahere.cc", "mangahere.us"],
    },
    "mangareader": {
        "id": 1912,
        "name": "MangaReader",
        "category": "Anime/Manga",
        "patterns": ["mangareader.to", "mangareader.cc"],
    },
    "kissmanga": {
        "id": 1913,
        "name": "KissManga",
        "category": "Anime/Manga",
        "patterns": ["kissmanga.org", "kissmanga.in"],
    },
    "kitsu": {
        "id": 1914,
        "name": "Kitsu",
        "category": "Anime/Manga",
        "patterns": ["kitsu.io", "kitsu.app"],
    },
    "anime_planet": {
        "id": 1915,
        "name": "Anime-Planet",
        "category": "Anime/Manga",
        "patterns": ["anime-planet.com"],
    },
    "animekisa": {
        "id": 1916,
        "name": "AnimeKisa",
        "category": "Anime/Manga",
        "patterns": ["animekisa.tv", "animekisa.in"],
    },
    "animesuge": {
        "id": 1917,
        "name": "AnimeSuge",
        "category": "Anime/Manga",
        "patterns": ["animesuge.to", "animesuge.io"],
    },
    "webtoon": {
        "id": 1918,
        "name": "Webtoon",
        "category": "Anime/Manga",
        "patterns": ["webtoons.com", "webtoon.xyz"],
    },
    "tapas": {
        "id": 1919,
        "name": "Tapas",
        "category": "Anime/Manga",
        "patterns": ["tapas.io"],
    },
}

# Category to apps mapping
APP_CATEGORIES = {
    "Social Media": ["facebook", "instagram", "twitter", "tiktok", "snapchat", "linkedin", "reddit", "pinterest"],
    "Streaming Video": ["youtube", "netflix", "twitch", "disney", "amazon_video", "hulu"],
    "Streaming Audio": ["spotify"],
    "Gaming": ["steam", "xbox_live", "playstation", "epic_games", "roblox"],
    "Messaging": ["whatsapp", "telegram", "signal", "discord", "slack", "teams", "zoom"],
    "Cloud Storage": ["dropbox", "google_drive", "onedrive", "icloud"],
    "VPN/Proxy": ["tor"],
    "P2P": ["bittorrent"],
    "Anime/Manga": [
        "crunchyroll", "funimation", "myanimelist", "anilist", "9anime", "gogoanime",
        "animepahe", "zoro", "mangadex", "mangakakalot", "mangahere", "mangareader",
        "kissmanga", "kitsu", "anime_planet", "animekisa", "animesuge", "webtoon", "tapas"
    ],
}


@dataclass
class AppMatch:
    """Application match result."""
    app_id: str
    app_name: str
    category: str
    confidence: float = 1.0
    matched_pattern: str = ""

    def to_dict(self) -> dict:
        return {
            "app_id": self.app_id,
            "app_name": self.app_name,
            "category": self.category,
            "confidence": self.confidence,
            "matched_pattern": self.matched_pattern,
        }


class AppController:
    """Application control engine."""

    def __init__(self, db_path: str = DB_PATH):
        self.db_path = db_path
        self._init_database()

    def _init_database(self):
        """Initialize app control tables."""
        conn = sqlite3.connect(self.db_path)

        # Blocked apps table
        conn.execute("""
            CREATE TABLE IF NOT EXISTS blocked_apps (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                app_id TEXT NOT NULL,
                app_name TEXT,
                blocked_by TEXT DEFAULT 'policy',
                device_mac TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(app_id, device_mac)
            )
        """)

        # App usage tracking
        conn.execute("""
            CREATE TABLE IF NOT EXISTS app_usage (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                device_mac TEXT,
                app_id TEXT NOT NULL,
                bytes_in INTEGER DEFAULT 0,
                bytes_out INTEGER DEFAULT 0,
                connections INTEGER DEFAULT 1
            )
        """)

        conn.execute("CREATE INDEX IF NOT EXISTS idx_blocked_apps ON blocked_apps(app_id)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_app_usage_time ON app_usage(timestamp)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_app_usage_app ON app_usage(app_id)")

        conn.commit()
        conn.close()

    def classify_sni(self, sni: str) -> Optional[AppMatch]:
        """Classify an application from SNI hostname."""
        if not sni:
            return None

        sni = sni.lower()

        for app_id, app_info in APP_SIGNATURES.items():
            for pattern in app_info["patterns"]:
                if pattern in sni or sni.endswith(pattern):
                    return AppMatch(
                        app_id=app_id,
                        app_name=app_info["name"],
                        category=app_info["category"],
                        matched_pattern=pattern,
                    )

        return None

    def classify_ip_port(self, dst_port: int, protocol: str = "tcp") -> Optional[AppMatch]:
        """Classify an application from destination port."""
        for app_id, app_info in APP_SIGNATURES.items():
            if "ports" in app_info and dst_port in app_info["ports"]:
                return AppMatch(
                    app_id=app_id,
                    app_name=app_info["name"],
                    category=app_info["category"],
                    confidence=0.7,  # Lower confidence for port-based
                    matched_pattern=f"port:{dst_port}",
                )

        return None

    def get_blocked_apps(self, device_mac: str = None) -> List[dict]:
        """Get list of blocked applications."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row

        if device_mac:
            cursor = conn.execute("""
                SELECT * FROM blocked_apps
                WHERE device_mac = ? OR device_mac IS NULL
                ORDER BY app_name
            """, (device_mac.upper(),))
        else:
            cursor = conn.execute("""
                SELECT * FROM blocked_apps
                WHERE device_mac IS NULL
                ORDER BY app_name
            """)

        apps = []
        for row in cursor:
            apps.append({
                "app_id": row["app_id"],
                "app_name": row["app_name"],
                "blocked_by": row["blocked_by"],
                "device_mac": row["device_mac"],
            })

        conn.close()
        return apps

    def block_app(self, app_id: str, device_mac: str = None, blocked_by: str = "user") -> dict:
        """Block an application."""
        if app_id not in APP_SIGNATURES:
            return {"status": "error", "message": f"Unknown app: {app_id}"}

        app_info = APP_SIGNATURES[app_id]
        conn = sqlite3.connect(self.db_path)

        try:
            conn.execute("""
                INSERT OR REPLACE INTO blocked_apps (app_id, app_name, blocked_by, device_mac)
                VALUES (?, ?, ?, ?)
            """, (app_id, app_info["name"], blocked_by, device_mac.upper() if device_mac else None))
            conn.commit()

            # Create DNS blocking rules for the app's domains
            self._enforce_app_block(app_id, app_info)

            return {
                "status": "ok",
                "app_id": app_id,
                "app_name": app_info["name"],
                "device_mac": device_mac,
            }
        except Exception as e:
            return {"status": "error", "message": str(e)}
        finally:
            conn.close()

    def unblock_app(self, app_id: str, device_mac: str = None) -> dict:
        """Unblock an application."""
        conn = sqlite3.connect(self.db_path)

        try:
            if device_mac:
                conn.execute("""
                    DELETE FROM blocked_apps WHERE app_id = ? AND device_mac = ?
                """, (app_id, device_mac.upper()))
            else:
                conn.execute("""
                    DELETE FROM blocked_apps WHERE app_id = ? AND device_mac IS NULL
                """, (app_id,))

            conn.commit()

            # Remove DNS blocking rules
            self._remove_app_block(app_id)

            return {"status": "ok", "app_id": app_id}
        except Exception as e:
            return {"status": "error", "message": str(e)}
        finally:
            conn.close()

    def block_category(self, category: str, device_mac: str = None) -> dict:
        """Block all apps in a category."""
        if category not in APP_CATEGORIES:
            return {"status": "error", "message": f"Unknown category: {category}"}

        results = []
        for app_id in APP_CATEGORIES[category]:
            result = self.block_app(app_id, device_mac, blocked_by="category")
            results.append(result)

        return {
            "status": "ok",
            "category": category,
            "blocked_apps": len(results),
        }

    def _enforce_app_block(self, app_id: str, app_info: dict):
        """Enforce app block via DNS."""
        patterns = app_info.get("patterns", [])
        if not patterns:
            return

        # Add to Unbound blocklist
        blocklist_path = "/var/unbound/etc/netshield_apps.conf"

        # Read existing rules
        existing = ""
        if os.path.exists(blocklist_path):
            with open(blocklist_path, "r") as f:
                existing = f.read()

        # Add new rules if not already present
        new_rules = []
        for pattern in patterns:
            rule = f'    local-zone: "{pattern}" always_nxdomain'
            if rule not in existing:
                new_rules.append(rule)

        if new_rules:
            with open(blocklist_path, "a") as f:
                if not existing.strip():
                    f.write("# NetShield App Blocking\nserver:\n")
                f.write(f"\n# {app_info['name']}\n")
                f.write("\n".join(new_rules) + "\n")

            # Reload Unbound
            subprocess.run(
                ["unbound-control", "-c", "/var/unbound/unbound.conf", "reload"],
                capture_output=True, timeout=15
            )

    def _remove_app_block(self, app_id: str):
        """Remove app block from DNS."""
        if app_id not in APP_SIGNATURES:
            return

        app_info = APP_SIGNATURES[app_id]
        patterns = app_info.get("patterns", [])

        blocklist_path = "/var/unbound/etc/netshield_apps.conf"
        if not os.path.exists(blocklist_path):
            return

        with open(blocklist_path, "r") as f:
            lines = f.readlines()

        new_lines = []
        skip_next = False
        for line in lines:
            if f"# {app_info['name']}" in line:
                skip_next = True
                continue
            if skip_next and any(p in line for p in patterns):
                continue
            skip_next = False
            new_lines.append(line)

        with open(blocklist_path, "w") as f:
            f.writelines(new_lines)

        subprocess.run(
            ["unbound-control", "-c", "/var/unbound/unbound.conf", "reload"],
            capture_output=True, timeout=15
        )

    def get_app_usage(self, hours: int = 24, device_mac: str = None) -> List[dict]:
        """Get application usage statistics."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row

        query = """
            SELECT app_id, SUM(bytes_in + bytes_out) as total_bytes,
                   SUM(connections) as total_connections
            FROM app_usage
            WHERE timestamp > datetime('now', ?)
        """
        params = [f"-{hours} hours"]

        if device_mac:
            query += " AND device_mac = ?"
            params.append(device_mac.upper())

        query += " GROUP BY app_id ORDER BY total_bytes DESC LIMIT 20"

        cursor = conn.execute(query, params)

        usage = []
        for row in cursor:
            app_info = APP_SIGNATURES.get(row["app_id"], {})
            usage.append({
                "app_id": row["app_id"],
                "app_name": app_info.get("name", row["app_id"]),
                "category": app_info.get("category", "Unknown"),
                "total_bytes": row["total_bytes"],
                "total_connections": row["total_connections"],
            })

        conn.close()
        return usage

    def get_available_apps(self) -> List[dict]:
        """Get list of all known applications."""
        apps = []
        for app_id, app_info in APP_SIGNATURES.items():
            apps.append({
                "id": app_id,
                "name": app_info["name"],
                "category": app_info["category"],
                "numeric_id": app_info["id"],
            })
        return sorted(apps, key=lambda x: x["name"])

    def get_categories(self) -> List[dict]:
        """Get application categories."""
        categories = []
        for cat_name, app_ids in APP_CATEGORIES.items():
            categories.append({
                "name": cat_name,
                "apps": app_ids,
                "count": len(app_ids),
            })
        return categories


# CLI interface
if __name__ == "__main__":
    import sys

    controller = AppController()

    if len(sys.argv) < 2:
        print(json.dumps({"error": "No command"}))
        sys.exit(1)

    cmd = sys.argv[1]

    if cmd == "list":
        print(json.dumps(controller.get_available_apps()))
    elif cmd == "categories":
        print(json.dumps(controller.get_categories()))
    elif cmd == "blocked":
        mac = sys.argv[2] if len(sys.argv) > 2 else None
        print(json.dumps(controller.get_blocked_apps(mac)))
    elif cmd == "block":
        if len(sys.argv) < 3:
            print(json.dumps({"error": "App ID required"}))
            sys.exit(1)
        app_id = sys.argv[2]
        mac = sys.argv[3] if len(sys.argv) > 3 else None
        print(json.dumps(controller.block_app(app_id, mac)))
    elif cmd == "unblock":
        if len(sys.argv) < 3:
            print(json.dumps({"error": "App ID required"}))
            sys.exit(1)
        app_id = sys.argv[2]
        mac = sys.argv[3] if len(sys.argv) > 3 else None
        print(json.dumps(controller.unblock_app(app_id, mac)))
    elif cmd == "block-category":
        if len(sys.argv) < 3:
            print(json.dumps({"error": "Category required"}))
            sys.exit(1)
        category = sys.argv[2]
        mac = sys.argv[3] if len(sys.argv) > 3 else None
        print(json.dumps(controller.block_category(category, mac)))
    elif cmd == "usage":
        hours = int(sys.argv[2]) if len(sys.argv) > 2 else 24
        mac = sys.argv[3] if len(sys.argv) > 3 else None
        print(json.dumps(controller.get_app_usage(hours, mac)))
    elif cmd == "classify":
        if len(sys.argv) < 3:
            print(json.dumps({"error": "SNI/hostname required"}))
            sys.exit(1)
        result = controller.classify_sni(sys.argv[2])
        print(json.dumps(result.to_dict() if result else {"app_id": None}))
    else:
        print(json.dumps({"error": f"Unknown command: {cmd}"}))
