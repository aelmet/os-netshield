#!/usr/local/bin/python3
# Copyright (c) 2025-2026, NetShield Project
# All rights reserved.
#
# Target Lists - Firewalla-style grouped domains/IPs for bulk rule management

"""
Target Lists for NetShield.

Features (matching Firewalla):
- Group domains and IPs into named lists
- Apply policies to entire lists
- Mute alarms by target list
- Import/export lists
- Built-in lists for common use cases
"""

import ipaddress
import json
import logging
import os
import re
import sqlite3
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Set, Tuple

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

TARGET_LISTS_DB = "/var/netshield/target_lists.db"

# Built-in lists (Zenarmor-style comprehensive)
BUILTIN_LISTS = {
    # === Social & Communication ===
    "social_media": {
        "name": "Social Media",
        "description": "Major social media platforms",
        "type": "domain",
        "entries": [
            "facebook.com", "fb.com", "fbcdn.net", "instagram.com", "twitter.com", "x.com",
            "tiktok.com", "tiktokcdn.com", "snapchat.com", "snap.com", "reddit.com",
            "linkedin.com", "pinterest.com", "tumblr.com", "threads.net", "mastodon.social",
            "discord.com", "discordapp.com", "telegram.org", "web.telegram.org",
            "whatsapp.com", "web.whatsapp.com", "signal.org", "viber.com",
            "wechat.com", "weixin.qq.com", "line.me", "kakaotalk.com",
            "vk.com", "ok.ru", "weibo.com", "qzone.qq.com", "renren.com",
            "clubhouse.com", "bereal.com", "locket.camera",
        ],
    },
    "messaging": {
        "name": "Messaging Apps",
        "description": "Instant messaging and chat apps",
        "type": "domain",
        "entries": [
            "discord.com", "discordapp.com", "discord.gg", "telegram.org", "t.me",
            "whatsapp.com", "whatsapp.net", "signal.org", "viber.com",
            "skype.com", "skype.net", "messenger.com", "slack.com",
            "teams.microsoft.com", "zoom.us", "webex.com", "gotomeeting.com",
            "hangouts.google.com", "meet.google.com", "duo.google.com",
            "imo.im", "kik.com", "groupme.com", "wire.com",
        ],
    },
    # === Entertainment ===
    "streaming": {
        "name": "Streaming Services",
        "description": "Video and music streaming platforms",
        "type": "domain",
        "entries": [
            "netflix.com", "nflxvideo.net", "nflximg.net", "nflxext.com",
            "youtube.com", "youtu.be", "googlevideo.com", "ytimg.com", "yt.be",
            "hulu.com", "hulustream.com", "disneyplus.com", "disney-plus.net",
            "hbomax.com", "max.com", "peacocktv.com", "paramount.com", "paramountplus.com",
            "primevideo.com", "amazon.com", "amazonvideo.com", "aiv-cdn.net",
            "spotify.com", "spotifycdn.com", "scdn.co", "apple.com", "tv.apple.com",
            "twitch.tv", "twitchcdn.net", "crunchyroll.com", "funimation.com",
            "hulu.com", "vudu.com", "tubi.tv", "peacocktv.com", "fubo.tv",
            "sling.com", "plex.tv", "plexapp.com", "emby.media",
            "deezer.com", "pandora.com", "soundcloud.com", "tidal.com",
            "vimeo.com", "dailymotion.com", "rumble.com", "bitchute.com",
            "odysee.com", "lbry.tv", "kick.com", "trovo.live",
        ],
    },
    "gaming": {
        "name": "Gaming Platforms",
        "description": "Gaming services and platforms",
        "type": "domain",
        "entries": [
            "steampowered.com", "steamcommunity.com", "steamstatic.com", "steamcdn-a.akamaihd.net",
            "epicgames.com", "unrealengine.com", "ea.com", "origin.com", "eaassets-a.akamaihd.net",
            "ubisoft.com", "ubi.com", "uplaypc.s3.amazonaws.com",
            "riotgames.com", "leagueoflegends.com", "valorant.com", "riotcdn.net",
            "blizzard.com", "battle.net", "blz-contentstack.com", "blizzard.cn",
            "playstation.com", "playstation.net", "sonyentertainmentnetwork.com",
            "xbox.com", "xboxlive.com", "microsoft.com", "live.com",
            "nintendo.com", "nintendo.net", "noa.nintendo.com",
            "roblox.com", "rbxcdn.com", "minecraft.net", "mojang.com",
            "gog.com", "gogcdn.net", "itch.io", "humblebundle.com",
            "garena.com", "mihoyo.com", "genshin.hoyoverse.com",
            "fortnite.com", "activision.com", "callofduty.com",
            "rockstargames.com", "socialclub.rockstargames.com",
            "nexusmods.com", "curseforge.com", "overwolf.com",
        ],
    },
    "gambling": {
        "name": "Gambling",
        "description": "Online gambling and betting sites",
        "type": "domain",
        "entries": [
            "bet365.com", "draftkings.com", "fanduel.com", "betmgm.com",
            "caesars.com", "williamhill.com", "pokerstars.com", "888poker.com",
            "bovada.lv", "betonline.ag", "mybookie.ag", "betway.com",
            "unibet.com", "bwin.com", "ladbrokes.com", "paddypower.com",
            "betfair.com", "pinnacle.com", "stake.com", "roobet.com",
            "polymarket.com", "predictit.org", "sportsbet.io",
            "partypoker.com", "ggpoker.com", "wsop.com", "globalpoker.com",
        ],
    },
    "dating": {
        "name": "Dating Sites",
        "description": "Online dating and matchmaking",
        "type": "domain",
        "entries": [
            "tinder.com", "bumble.com", "hinge.co", "match.com",
            "okcupid.com", "plentyoffish.com", "pof.com", "eharmony.com",
            "zoosk.com", "elitesingles.com", "silversingles.com", "ourtime.com",
            "christianmingle.com", "jdate.com", "grindr.com", "her.com",
            "coffee-meets-bagel.com", "theinner.circle", "feeld.co",
            "badoo.com", "happn.com", "tagged.com", "meetme.com",
            "seeking.com", "ashleymadison.com", "adultfriendfinder.com",
        ],
    },
    # === Productivity & Work ===
    "work_apps": {
        "name": "Work Applications",
        "description": "Business and productivity apps",
        "type": "domain",
        "entries": [
            "slack.com", "slack-edge.com", "slack-imgs.com",
            "zoom.us", "zoomgov.com", "cloudflare.zoom.us",
            "teams.microsoft.com", "teams.live.com", "teamwork.com",
            "webex.com", "webexconnect.com", "gotomeeting.com", "join.me",
            "asana.com", "monday.com", "clickup.com", "wrike.com",
            "trello.com", "trellocdn.com", "notion.so", "notion.site",
            "basecamp.com", "todoist.com", "ticktick.com", "any.do",
            "airtable.com", "coda.io", "smartsheet.com", "quip.com",
            "miro.com", "figma.com", "sketch.com", "canva.com",
            "lucidchart.com", "drawio.com", "whimsical.com",
            "atlassian.com", "jira.com", "confluence.com", "bitbucket.org",
            "github.com", "gitlab.com", "azure.com", "aws.amazon.com",
        ],
    },
    "cloud_storage": {
        "name": "Cloud Storage",
        "description": "Cloud storage and file sharing services",
        "type": "domain",
        "entries": [
            "dropbox.com", "dropboxstatic.com", "dropboxusercontent.com",
            "drive.google.com", "docs.google.com", "googleapis.com",
            "onedrive.live.com", "onedrive.com", "sharepoint.com",
            "box.com", "boxcdn.net", "icloud.com", "icloud-content.com",
            "mega.nz", "mega.io", "megaup.net",
            "mediafire.com", "sendspace.com", "zippyshare.com",
            "wetransfer.com", "transfernow.net", "filemail.com",
            "pcloud.com", "sync.com", "tresorit.com", "icedrive.net",
            "idrive.com", "backblaze.com", "carbonite.com", "crashplan.com",
        ],
    },
    # === Shopping & Finance ===
    "ecommerce": {
        "name": "E-Commerce",
        "description": "Online shopping platforms",
        "type": "domain",
        "entries": [
            "amazon.com", "amazon.co.uk", "amazon.de", "amazon.fr", "amazon.in",
            "ebay.com", "ebay.co.uk", "ebayimg.com", "ebaystatic.com",
            "walmart.com", "target.com", "bestbuy.com", "costco.com",
            "homedepot.com", "lowes.com", "wayfair.com", "overstock.com",
            "etsy.com", "etsystatic.com", "shopify.com", "myshopify.com",
            "aliexpress.com", "alibaba.com", "wish.com", "gearbest.com",
            "banggood.com", "dhgate.com", "temu.com", "shein.com",
            "newegg.com", "bhphotovideo.com", "adorama.com",
            "zappos.com", "nordstrom.com", "macys.com", "kohls.com",
            "asos.com", "zara.com", "hm.com", "uniqlo.com", "nike.com",
            "adidas.com", "reebok.com", "underarmour.com", "lululemon.com",
        ],
    },
    "banking": {
        "name": "Banking & Finance",
        "description": "Banks and financial services",
        "type": "domain",
        "entries": [
            "chase.com", "bankofamerica.com", "wellsfargo.com", "citi.com",
            "usbank.com", "capitalone.com", "pnc.com", "tdbank.com",
            "ally.com", "discover.com", "americanexpress.com", "amex.com",
            "fidelity.com", "vanguard.com", "schwab.com", "etrade.com",
            "robinhood.com", "webull.com", "sofi.com", "acorns.com",
            "paypal.com", "venmo.com", "zelle.com", "cashapp.com",
            "stripe.com", "square.com", "braintreepayments.com",
            "intuit.com", "quickbooks.com", "mint.com", "turbotax.com",
            "creditkarma.com", "nerdwallet.com", "bankrate.com",
            "wise.com", "revolut.com", "n26.com", "chime.com",
        ],
    },
    "cryptocurrency": {
        "name": "Cryptocurrency",
        "description": "Crypto exchanges and wallets",
        "type": "domain",
        "entries": [
            "coinbase.com", "binance.com", "binance.us", "kraken.com",
            "gemini.com", "ftx.com", "kucoin.com", "huobi.com",
            "crypto.com", "blockchain.com", "bitfinex.com", "bitstamp.net",
            "okx.com", "bybit.com", "gate.io", "bitget.com",
            "metamask.io", "phantom.app", "trustwallet.com", "exodus.com",
            "ledger.com", "trezor.io", "keepkey.com",
            "coingecko.com", "coinmarketcap.com", "tradingview.com",
            "uniswap.org", "opensea.io", "rarible.com", "foundation.app",
            "etherscan.io", "bscscan.com", "polygonscan.com",
        ],
    },
    # === Security & Privacy ===
    "ad_networks": {
        "name": "Advertising Networks",
        "description": "Ad networks and trackers",
        "type": "domain",
        "entries": [
            "doubleclick.net", "googlesyndication.com", "googleadservices.com",
            "googletagmanager.com", "googletagservices.com", "google-analytics.com",
            "facebook.net", "fbcdn.net", "facebook.com", "fb.com",
            "advertising.com", "adnxs.com", "adsrvr.org", "casalemedia.com",
            "criteo.com", "criteo.net", "taboola.com", "outbrain.com",
            "pubmatic.com", "rubiconproject.com", "openx.com", "indexww.com",
            "appnexus.com", "mediamath.com", "tradedesk.com", "liveramp.com",
            "quantcast.com", "scorecardresearch.com", "comscore.com",
            "hotjar.com", "fullstory.com", "mouseflow.com", "crazyegg.com",
            "mixpanel.com", "amplitude.com", "segment.com", "heap.io",
            "branch.io", "adjust.com", "appsflyer.com", "kochava.com",
            "moat.com", "doubleverify.com", "ias.com", "pixalate.com",
        ],
    },
    "trackers": {
        "name": "Trackers & Analytics",
        "description": "Web tracking and analytics services",
        "type": "domain",
        "entries": [
            "google-analytics.com", "analytics.google.com", "googletagmanager.com",
            "facebook.com", "pixel.facebook.com", "connect.facebook.net",
            "hotjar.com", "static.hotjar.com", "fullstory.com",
            "segment.com", "segment.io", "mixpanel.com", "api.mixpanel.com",
            "amplitude.com", "api.amplitude.com", "heap.io", "heapanalytics.com",
            "clarity.ms", "mouseflow.com", "crazyegg.com", "luckyorange.com",
            "inspectlet.com", "clicktale.com", "sessioncam.com",
            "quantcast.com", "scorecardresearch.com", "comscore.com",
            "newrelic.com", "nr-data.net", "datadoghq.com", "sentry.io",
            "bugsnag.com", "rollbar.com", "logrocket.com", "smartlook.com",
        ],
    },
    "malware": {
        "name": "Malware & Phishing",
        "description": "Known malicious domains",
        "type": "domain",
        "entries": [],  # Populated via threat feed updates
        "update_url": "https://urlhaus.abuse.ch/downloads/text_recent/",
    },
    "cryptomining": {
        "name": "Cryptomining",
        "description": "Browser-based cryptomining scripts",
        "type": "domain",
        "entries": [
            "coinhive.com", "coin-hive.com", "authedmine.com",
            "jsecoin.com", "crypto-loot.com", "cryptoloot.pro",
            "minero.cc", "miner.pr0gramm.com", "coin-have.com",
            "ppoi.org", "cnhv.co", "coinerra.com", "coinnebula.com",
            "minercry.pt", "reasedoper.pw", "mataharirama.xyz",
            "cryptonight.wasm", "webminepool.com", "webmine.cz",
            "papoto.com", "coinpirate.cf", "rocks.io", "cookiescript.info",
        ],
    },
    "vpn_providers": {
        "name": "VPN Providers",
        "description": "Commercial VPN services",
        "type": "domain",
        "entries": [
            "nordvpn.com", "nordvpn.net", "expressvpn.com", "expressvpngo.com",
            "surfshark.com", "privateinternetaccess.com", "cyberghostvpn.com",
            "protonvpn.com", "proton.me", "mullvad.net", "windscribe.com",
            "ipvanish.com", "vyprvpn.com", "tunnelbear.com", "hotspotshield.com",
            "hide.me", "purevpn.com", "privatevpn.com", "torguard.net",
            "airvpn.org", "perfectprivacy.com", "ivpn.net", "azirevpn.com",
            "mozillavpn.com", "warp.cloudflare.com", "1.1.1.1",
        ],
    },
    "tor_exits": {
        "name": "Tor Exit Nodes",
        "description": "Known Tor exit node IPs",
        "type": "ip",
        "entries": [],  # Populated via update
        "update_url": "https://check.torproject.org/torbulkexitlist",
    },
    "proxy_sites": {
        "name": "Proxy Sites",
        "description": "Web proxies and anonymizers",
        "type": "domain",
        "entries": [
            "hide.me", "hidemyass.com", "kproxy.com", "proxysite.com",
            "filterbypass.me", "unblocksites.co", "vpnbook.com",
            "croxyproxy.com", "blockaway.net", "hidester.com",
            "anonymouse.org", "whoer.net", "dontfilter.us",
            "4everproxy.com", "hidemy.name", "free-proxy.cz",
        ],
    },
    # === Smart Home & IoT ===
    "smart_home": {
        "name": "Smart Home Devices",
        "description": "IoT and smart home cloud services",
        "type": "domain",
        "entries": [
            "nest.com", "home.nest.com", "ring.com", "ring.amazonaws.com",
            "wyze.com", "wyzecam.com", "ecobee.com", "philips-hue.com",
            "meethue.com", "smartthings.com", "tuya.com", "tuyaus.com",
            "ifttt.com", "homeassistant.io", "hubitat.com",
            "amazon-adsystem.com", "alexa.amazon.com", "avs-alexa.amazon.com",
            "googlehome.googleapis.com", "chromecast.com",
            "wink.com", "insteon.com", "homeseer.com", "vera.control4.com",
            "yeelight.com", "lifx.co", "sengled.com", "cync.com",
            "arlo.com", "blink.com", "eufy.com", "anker-in.com",
            "august.com", "schlage.com", "yale.com", "kwikset.com",
            "rachio.com", "orbit.com", "roomba.com", "irobot.com",
        ],
    },
    "voice_assistants": {
        "name": "Voice Assistants",
        "description": "Voice assistant services",
        "type": "domain",
        "entries": [
            "alexa.amazon.com", "avs-alexa.amazon.com", "pitangui.amazon.com",
            "assistant.google.com", "googlehome.googleapis.com",
            "siri.apple.com", "guzzoni.apple.com", "smoot.apple.com",
            "cortana.microsoft.com", "bing.com", "bixby.samsung.com",
        ],
    },
    # === Education & Reference ===
    "education": {
        "name": "Education",
        "description": "Educational platforms and tools",
        "type": "domain",
        "entries": [
            "khanacademy.org", "coursera.org", "udemy.com", "edx.org",
            "skillshare.com", "masterclass.com", "linkedin.com", "lynda.com",
            "pluralsight.com", "codecademy.com", "freecodecamp.org",
            "udacity.com", "brilliant.org", "duolingo.com", "babbel.com",
            "chegg.com", "quizlet.com", "brainly.com", "studyblue.com",
            "academia.edu", "researchgate.net", "jstor.org", "scholar.google.com",
            "canvas.com", "blackboard.com", "schoology.com", "moodle.org",
            "google.com", "classroom.google.com", "edu.google.com",
            "kahoot.com", "quizizz.com", "nearpod.com", "pear.deck",
        ],
    },
    "news": {
        "name": "News Sites",
        "description": "News and media outlets",
        "type": "domain",
        "entries": [
            "cnn.com", "bbc.com", "bbc.co.uk", "nytimes.com", "washingtonpost.com",
            "wsj.com", "reuters.com", "apnews.com", "foxnews.com", "nbcnews.com",
            "cbsnews.com", "abcnews.go.com", "msnbc.com", "npr.org",
            "theguardian.com", "usatoday.com", "latimes.com", "chicagotribune.com",
            "huffpost.com", "buzzfeednews.com", "vice.com", "vox.com",
            "politico.com", "thehill.com", "axios.com", "bloomberg.com",
            "cnbc.com", "ft.com", "economist.com", "forbes.com",
            "time.com", "newsweek.com", "theatlantic.com", "newyorker.com",
            "aljazeera.com", "dw.com", "france24.com", "rt.com",
        ],
    },
    "search_engines": {
        "name": "Search Engines",
        "description": "Web search engines",
        "type": "domain",
        "entries": [
            "google.com", "google.co.uk", "google.de", "google.fr",
            "bing.com", "yahoo.com", "search.yahoo.com",
            "duckduckgo.com", "startpage.com", "qwant.com",
            "ecosia.org", "brave.com", "search.brave.com",
            "yandex.com", "baidu.com", "sogou.com", "so.com",
            "wolframalpha.com", "ask.com", "aol.com",
            "perplexity.ai", "you.com", "neeva.com", "kagi.com",
        ],
    },
    # === Developer Tools ===
    "developer_tools": {
        "name": "Developer Tools",
        "description": "Development platforms and tools",
        "type": "domain",
        "entries": [
            "github.com", "githubusercontent.com", "github.io", "githubassets.com",
            "gitlab.com", "gitlab.io", "bitbucket.org", "bitbucket.io",
            "stackoverflow.com", "stackexchange.com", "serverfault.com",
            "npmjs.com", "registry.npmjs.org", "unpkg.com", "jsdelivr.net",
            "pypi.org", "pypi.python.org", "files.pythonhosted.org",
            "rubygems.org", "bundler.io", "crates.io", "rust-lang.org",
            "packagist.org", "composer.json", "nuget.org",
            "docker.com", "docker.io", "hub.docker.com", "ghcr.io",
            "aws.amazon.com", "console.aws.amazon.com", "amazonaws.com",
            "azure.microsoft.com", "portal.azure.com", "azure.com",
            "cloud.google.com", "console.cloud.google.com", "gcp.com",
            "vercel.com", "vercel.app", "netlify.com", "netlify.app",
            "heroku.com", "digitalocean.com", "linode.com", "vultr.com",
            "cloudflare.com", "cloudflare.net", "cdnjs.cloudflare.com",
            "codepen.io", "jsfiddle.net", "codesandbox.io", "replit.com",
        ],
    },
    # === AI Services ===
    "ai_services": {
        "name": "AI Services",
        "description": "AI chatbots and services",
        "type": "domain",
        "entries": [
            "openai.com", "chat.openai.com", "api.openai.com",
            "anthropic.com", "claude.ai", "api.anthropic.com",
            "google.com", "bard.google.com", "gemini.google.com",
            "bing.com", "copilot.microsoft.com", "github.com",
            "perplexity.ai", "you.com", "character.ai", "replika.ai",
            "midjourney.com", "stability.ai", "stablediffusionweb.com",
            "huggingface.co", "kaggle.com", "colab.research.google.com",
            "runwayml.com", "jasper.ai", "copy.ai", "writesonic.com",
            "grammarly.com", "deepl.com", "translate.google.com",
        ],
    },
}


# ---------------------------------------------------------------------------
# Data Classes
# ---------------------------------------------------------------------------


@dataclass
class TargetList:
    """Represents a target list."""
    id: int
    name: str
    description: str
    list_type: str  # "domain", "ip", "mixed"
    builtin: bool = False
    entry_count: int = 0
    created_at: str = ""
    updated_at: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "type": self.list_type,
            "builtin": self.builtin,
            "entry_count": self.entry_count,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }


@dataclass
class TargetEntry:
    """Represents an entry in a target list."""
    id: int
    list_id: int
    value: str
    entry_type: str  # "domain", "ip", "cidr"
    comment: str = ""
    added_at: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "list_id": self.list_id,
            "value": self.value,
            "type": self.entry_type,
            "comment": self.comment,
            "added_at": self.added_at,
        }


# ---------------------------------------------------------------------------
# Target Lists Manager
# ---------------------------------------------------------------------------


class TargetListsManager:
    """Manages target lists for NetShield."""

    def __init__(self, db_path: str = TARGET_LISTS_DB):
        self.db_path = db_path
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        self._init_db()
        self._ensure_builtin_lists()

    def _init_db(self) -> None:
        """Initialize database schema."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS target_lists (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL UNIQUE,
                    description TEXT DEFAULT '',
                    list_type TEXT DEFAULT 'domain',
                    builtin INTEGER DEFAULT 0,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    updated_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            """)

            conn.execute("""
                CREATE TABLE IF NOT EXISTS target_entries (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    list_id INTEGER NOT NULL,
                    value TEXT NOT NULL,
                    entry_type TEXT DEFAULT 'domain',
                    comment TEXT DEFAULT '',
                    added_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (list_id) REFERENCES target_lists(id) ON DELETE CASCADE,
                    UNIQUE(list_id, value)
                )
            """)

            conn.execute("""
                CREATE TABLE IF NOT EXISTS list_policies (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    list_id INTEGER NOT NULL,
                    action TEXT NOT NULL,
                    direction TEXT DEFAULT 'both',
                    enabled INTEGER DEFAULT 1,
                    priority INTEGER DEFAULT 100,
                    schedule TEXT,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (list_id) REFERENCES target_lists(id) ON DELETE CASCADE
                )
            """)

            conn.execute("""
                CREATE TABLE IF NOT EXISTS list_alarm_mutes (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    list_id INTEGER NOT NULL,
                    alarm_type TEXT,
                    muted_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (list_id) REFERENCES target_lists(id) ON DELETE CASCADE
                )
            """)

            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_entries_list
                ON target_entries(list_id)
            """)

            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_entries_value
                ON target_entries(value)
            """)

            conn.commit()

    def _ensure_builtin_lists(self) -> None:
        """Ensure built-in lists exist."""
        for list_key, list_data in BUILTIN_LISTS.items():
            existing = self.get_list_by_name(list_data["name"])
            if not existing:
                list_id = self.create_list(
                    name=list_data["name"],
                    description=list_data["description"],
                    list_type=list_data["type"],
                    builtin=True,
                )
                if list_id and list_data.get("entries"):
                    for entry in list_data["entries"]:
                        self.add_entry(list_id, entry)

    # -----------------------------------------------------------------------
    # List Management
    # -----------------------------------------------------------------------

    def create_list(
        self,
        name: str,
        description: str = "",
        list_type: str = "domain",
        builtin: bool = False,
    ) -> Optional[int]:
        """Create a new target list."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute(
                    """
                    INSERT INTO target_lists (name, description, list_type, builtin)
                    VALUES (?, ?, ?, ?)
                    """,
                    (name, description, list_type, int(builtin))
                )
                conn.commit()
                return cursor.lastrowid
        except sqlite3.IntegrityError:
            log.error("List with name '%s' already exists", name)
            return None
        except Exception as e:
            log.error("Error creating list: %s", e)
            return None

    def delete_list(self, list_id: int) -> bool:
        """Delete a target list."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                # Check if builtin
                cursor = conn.execute(
                    "SELECT builtin FROM target_lists WHERE id = ?",
                    (list_id,)
                )
                row = cursor.fetchone()
                if row and row[0]:
                    log.warning("Cannot delete built-in list %d", list_id)
                    return False

                conn.execute("DELETE FROM target_lists WHERE id = ?", (list_id,))
                conn.commit()
                return True
        except Exception as e:
            log.error("Error deleting list: %s", e)
            return False

    def update_list(
        self,
        list_id: int,
        name: Optional[str] = None,
        description: Optional[str] = None,
    ) -> bool:
        """Update list metadata."""
        try:
            updates = []
            params = []

            if name is not None:
                updates.append("name = ?")
                params.append(name)
            if description is not None:
                updates.append("description = ?")
                params.append(description)

            if not updates:
                return True

            updates.append("updated_at = datetime('now')")
            params.append(list_id)

            with sqlite3.connect(self.db_path) as conn:
                conn.execute(
                    f"UPDATE target_lists SET {', '.join(updates)} WHERE id = ?",
                    tuple(params)
                )
                conn.commit()
            return True
        except Exception as e:
            log.error("Error updating list: %s", e)
            return False

    def get_list(self, list_id: int) -> Optional[TargetList]:
        """Get a target list by ID."""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute(
                """
                SELECT l.*, COUNT(e.id) as entry_count
                FROM target_lists l
                LEFT JOIN target_entries e ON l.id = e.list_id
                WHERE l.id = ?
                GROUP BY l.id
                """,
                (list_id,)
            )
            row = cursor.fetchone()
            if row:
                return TargetList(
                    id=row["id"],
                    name=row["name"],
                    description=row["description"],
                    list_type=row["list_type"],
                    builtin=bool(row["builtin"]),
                    entry_count=row["entry_count"],
                    created_at=row["created_at"],
                    updated_at=row["updated_at"],
                )
        return None

    def get_list_by_name(self, name: str) -> Optional[TargetList]:
        """Get a target list by name."""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute(
                """
                SELECT l.*, COUNT(e.id) as entry_count
                FROM target_lists l
                LEFT JOIN target_entries e ON l.id = e.list_id
                WHERE l.name = ?
                GROUP BY l.id
                """,
                (name,)
            )
            row = cursor.fetchone()
            if row:
                return TargetList(
                    id=row["id"],
                    name=row["name"],
                    description=row["description"],
                    list_type=row["list_type"],
                    builtin=bool(row["builtin"]),
                    entry_count=row["entry_count"],
                    created_at=row["created_at"],
                    updated_at=row["updated_at"],
                )
        return None

    def get_all_lists(self) -> List[TargetList]:
        """Get all target lists."""
        lists = []
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute("""
                SELECT l.*, COUNT(e.id) as entry_count
                FROM target_lists l
                LEFT JOIN target_entries e ON l.id = e.list_id
                GROUP BY l.id
                ORDER BY l.builtin DESC, l.name
            """)
            for row in cursor:
                lists.append(TargetList(
                    id=row["id"],
                    name=row["name"],
                    description=row["description"],
                    list_type=row["list_type"],
                    builtin=bool(row["builtin"]),
                    entry_count=row["entry_count"],
                    created_at=row["created_at"],
                    updated_at=row["updated_at"],
                ))
        return lists

    # -----------------------------------------------------------------------
    # Entry Management
    # -----------------------------------------------------------------------

    def add_entry(
        self,
        list_id: int,
        value: str,
        comment: str = "",
    ) -> Optional[int]:
        """Add an entry to a list."""
        # Determine entry type
        entry_type = self._detect_entry_type(value)
        value = self._normalize_entry(value, entry_type)

        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute(
                    """
                    INSERT INTO target_entries (list_id, value, entry_type, comment)
                    VALUES (?, ?, ?, ?)
                    """,
                    (list_id, value, entry_type, comment)
                )
                conn.execute(
                    "UPDATE target_lists SET updated_at = datetime('now') WHERE id = ?",
                    (list_id,)
                )
                conn.commit()
                return cursor.lastrowid
        except sqlite3.IntegrityError:
            log.debug("Entry '%s' already exists in list %d", value, list_id)
            return None
        except Exception as e:
            log.error("Error adding entry: %s", e)
            return None

    def remove_entry(self, entry_id: int) -> bool:
        """Remove an entry from a list."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute(
                    "SELECT list_id FROM target_entries WHERE id = ?",
                    (entry_id,)
                )
                row = cursor.fetchone()
                if row:
                    list_id = row[0]
                    conn.execute("DELETE FROM target_entries WHERE id = ?", (entry_id,))
                    conn.execute(
                        "UPDATE target_lists SET updated_at = datetime('now') WHERE id = ?",
                        (list_id,)
                    )
                    conn.commit()
                    return True
        except Exception as e:
            log.error("Error removing entry: %s", e)
        return False

    def remove_entry_by_value(self, list_id: int, value: str) -> bool:
        """Remove an entry by value."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute(
                    "DELETE FROM target_entries WHERE list_id = ? AND value = ?",
                    (list_id, value.lower())
                )
                conn.execute(
                    "UPDATE target_lists SET updated_at = datetime('now') WHERE id = ?",
                    (list_id,)
                )
                conn.commit()
                return True
        except Exception as e:
            log.error("Error removing entry: %s", e)
            return False

    def get_entries(
        self,
        list_id: int,
        limit: int = 1000,
        offset: int = 0,
        search: Optional[str] = None,
    ) -> Tuple[List[TargetEntry], int]:
        """Get entries for a list."""
        entries = []
        total = 0

        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row

            # Get total
            if search:
                cursor = conn.execute(
                    "SELECT COUNT(*) FROM target_entries WHERE list_id = ? AND value LIKE ?",
                    (list_id, f"%{search}%")
                )
            else:
                cursor = conn.execute(
                    "SELECT COUNT(*) FROM target_entries WHERE list_id = ?",
                    (list_id,)
                )
            total = cursor.fetchone()[0]

            # Get entries
            if search:
                cursor = conn.execute(
                    """
                    SELECT * FROM target_entries
                    WHERE list_id = ? AND value LIKE ?
                    ORDER BY added_at DESC
                    LIMIT ? OFFSET ?
                    """,
                    (list_id, f"%{search}%", limit, offset)
                )
            else:
                cursor = conn.execute(
                    """
                    SELECT * FROM target_entries
                    WHERE list_id = ?
                    ORDER BY added_at DESC
                    LIMIT ? OFFSET ?
                    """,
                    (list_id, limit, offset)
                )

            for row in cursor:
                entries.append(TargetEntry(
                    id=row["id"],
                    list_id=row["list_id"],
                    value=row["value"],
                    entry_type=row["entry_type"],
                    comment=row["comment"] or "",
                    added_at=row["added_at"],
                ))

        return entries, total

    def bulk_add_entries(self, list_id: int, entries: List[str]) -> int:
        """Bulk add entries to a list."""
        count = 0
        for entry in entries:
            entry = entry.strip()
            if entry and not entry.startswith("#"):
                if self.add_entry(list_id, entry):
                    count += 1
        return count

    # -----------------------------------------------------------------------
    # Lookup and Matching
    # -----------------------------------------------------------------------

    def check_domain(self, domain: str) -> List[TargetList]:
        """Check if a domain is in any list."""
        domain = domain.lower().strip()
        matches = []

        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row

            # Exact match
            cursor = conn.execute("""
                SELECT DISTINCT l.*
                FROM target_lists l
                JOIN target_entries e ON l.id = e.list_id
                WHERE e.entry_type = 'domain' AND e.value = ?
            """, (domain,))

            for row in cursor:
                matches.append(TargetList(
                    id=row["id"],
                    name=row["name"],
                    description=row["description"],
                    list_type=row["list_type"],
                    builtin=bool(row["builtin"]),
                    created_at=row["created_at"],
                    updated_at=row["updated_at"],
                ))

            # Parent domain match
            parts = domain.split(".")
            for i in range(1, len(parts) - 1):
                parent = ".".join(parts[i:])
                cursor = conn.execute("""
                    SELECT DISTINCT l.*
                    FROM target_lists l
                    JOIN target_entries e ON l.id = e.list_id
                    WHERE e.entry_type = 'domain' AND e.value = ?
                """, (parent,))

                for row in cursor:
                    target_list = TargetList(
                        id=row["id"],
                        name=row["name"],
                        description=row["description"],
                        list_type=row["list_type"],
                        builtin=bool(row["builtin"]),
                        created_at=row["created_at"],
                        updated_at=row["updated_at"],
                    )
                    if target_list not in matches:
                        matches.append(target_list)

        return matches

    def check_ip(self, ip: str) -> List[TargetList]:
        """Check if an IP is in any list."""
        matches = []

        try:
            ip_obj = ipaddress.ip_address(ip)
        except ValueError:
            return matches

        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row

            # Get all IP and CIDR entries
            cursor = conn.execute("""
                SELECT l.*, e.value, e.entry_type
                FROM target_lists l
                JOIN target_entries e ON l.id = e.list_id
                WHERE e.entry_type IN ('ip', 'cidr')
            """)

            for row in cursor:
                try:
                    if row["entry_type"] == "ip":
                        if str(ip_obj) == row["value"]:
                            matches.append(TargetList(
                                id=row["id"],
                                name=row["name"],
                                description=row["description"],
                                list_type=row["list_type"],
                                builtin=bool(row["builtin"]),
                                created_at=row["created_at"],
                                updated_at=row["updated_at"],
                            ))
                    elif row["entry_type"] == "cidr":
                        network = ipaddress.ip_network(row["value"], strict=False)
                        if ip_obj in network:
                            target_list = TargetList(
                                id=row["id"],
                                name=row["name"],
                                description=row["description"],
                                list_type=row["list_type"],
                                builtin=bool(row["builtin"]),
                                created_at=row["created_at"],
                                updated_at=row["updated_at"],
                            )
                            if target_list not in matches:
                                matches.append(target_list)
                except Exception:
                    continue

        return matches

    # -----------------------------------------------------------------------
    # Policies
    # -----------------------------------------------------------------------

    def add_policy(
        self,
        list_id: int,
        action: str,
        direction: str = "both",
        priority: int = 100,
        schedule: Optional[str] = None,
    ) -> Optional[int]:
        """Add a policy for a target list."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute(
                    """
                    INSERT INTO list_policies (list_id, action, direction, priority, schedule)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (list_id, action, direction, priority, schedule)
                )
                conn.commit()
                return cursor.lastrowid
        except Exception as e:
            log.error("Error adding policy: %s", e)
            return None

    def remove_policy(self, policy_id: int) -> bool:
        """Remove a policy."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("DELETE FROM list_policies WHERE id = ?", (policy_id,))
                conn.commit()
                return True
        except Exception as e:
            log.error("Error removing policy: %s", e)
            return False

    def get_policies(self, list_id: int) -> List[Dict[str, Any]]:
        """Get policies for a list."""
        policies = []
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute(
                "SELECT * FROM list_policies WHERE list_id = ? ORDER BY priority",
                (list_id,)
            )
            for row in cursor:
                policies.append(dict(row))
        return policies

    # -----------------------------------------------------------------------
    # Alarm Muting (Firewalla feature)
    # -----------------------------------------------------------------------

    def mute_alarms(self, list_id: int, alarm_type: Optional[str] = None) -> bool:
        """Mute alarms for targets in a list."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute(
                    """
                    INSERT INTO list_alarm_mutes (list_id, alarm_type)
                    VALUES (?, ?)
                    """,
                    (list_id, alarm_type)
                )
                conn.commit()
                return True
        except Exception as e:
            log.error("Error muting alarms: %s", e)
            return False

    def unmute_alarms(self, list_id: int, alarm_type: Optional[str] = None) -> bool:
        """Unmute alarms for targets in a list."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                if alarm_type:
                    conn.execute(
                        "DELETE FROM list_alarm_mutes WHERE list_id = ? AND alarm_type = ?",
                        (list_id, alarm_type)
                    )
                else:
                    conn.execute(
                        "DELETE FROM list_alarm_mutes WHERE list_id = ?",
                        (list_id,)
                    )
                conn.commit()
                return True
        except Exception as e:
            log.error("Error unmuting alarms: %s", e)
            return False

    def is_alarm_muted(self, target: str, alarm_type: str) -> bool:
        """Check if alarms are muted for a target."""
        # Check domain lists
        domain_matches = self.check_domain(target)
        ip_matches = self.check_ip(target)
        all_matches = domain_matches + ip_matches

        if not all_matches:
            return False

        list_ids = [m.id for m in all_matches]
        placeholders = ",".join("?" * len(list_ids))

        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute(
                f"""
                SELECT COUNT(*) FROM list_alarm_mutes
                WHERE list_id IN ({placeholders})
                AND (alarm_type IS NULL OR alarm_type = ?)
                """,
                tuple(list_ids) + (alarm_type,)
            )
            return cursor.fetchone()[0] > 0

    # -----------------------------------------------------------------------
    # Import/Export
    # -----------------------------------------------------------------------

    def export_list(self, list_id: int) -> Dict[str, Any]:
        """Export a list to JSON format."""
        target_list = self.get_list(list_id)
        if not target_list:
            return {}

        entries, _ = self.get_entries(list_id, limit=10000)
        policies = self.get_policies(list_id)

        return {
            "name": target_list.name,
            "description": target_list.description,
            "type": target_list.list_type,
            "entries": [e.value for e in entries],
            "policies": policies,
            "exported_at": datetime.now().isoformat(),
        }

    def import_list(self, data: Dict[str, Any]) -> Optional[int]:
        """Import a list from JSON format."""
        name = data.get("name")
        if not name:
            return None

        # Create list
        list_id = self.create_list(
            name=name,
            description=data.get("description", ""),
            list_type=data.get("type", "domain"),
        )

        if not list_id:
            return None

        # Add entries
        entries = data.get("entries", [])
        self.bulk_add_entries(list_id, entries)

        # Add policies
        for policy in data.get("policies", []):
            self.add_policy(
                list_id=list_id,
                action=policy.get("action", "block"),
                direction=policy.get("direction", "both"),
                priority=policy.get("priority", 100),
                schedule=policy.get("schedule"),
            )

        return list_id

    # -----------------------------------------------------------------------
    # Helpers
    # -----------------------------------------------------------------------

    def _detect_entry_type(self, value: str) -> str:
        """Detect entry type from value."""
        value = value.strip()

        # Check for CIDR
        if "/" in value:
            try:
                ipaddress.ip_network(value, strict=False)
                return "cidr"
            except ValueError:
                pass

        # Check for IP
        try:
            ipaddress.ip_address(value)
            return "ip"
        except ValueError:
            pass

        return "domain"

    def _normalize_entry(self, value: str, entry_type: str) -> str:
        """Normalize an entry value."""
        value = value.strip().lower()

        if entry_type == "domain":
            # Remove protocol and path
            value = re.sub(r"^https?://", "", value)
            value = value.split("/")[0]
            if value.startswith("www."):
                value = value[4:]

        return value

    def get_stats(self) -> Dict[str, Any]:
        """Get statistics."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute("SELECT COUNT(*) FROM target_lists")
            list_count = cursor.fetchone()[0]

            cursor = conn.execute("SELECT COUNT(*) FROM target_lists WHERE builtin = 1")
            builtin_count = cursor.fetchone()[0]

            cursor = conn.execute("SELECT COUNT(*) FROM target_entries")
            entry_count = cursor.fetchone()[0]

            cursor = conn.execute("SELECT COUNT(*) FROM list_policies")
            policy_count = cursor.fetchone()[0]

        return {
            "total_lists": list_count,
            "builtin_lists": builtin_count,
            "custom_lists": list_count - builtin_count,
            "total_entries": entry_count,
            "total_policies": policy_count,
        }
