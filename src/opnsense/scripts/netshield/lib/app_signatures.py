"""
SPDX-License-Identifier: BSD-2-Clause
Copyright (c) 2024-2026 NetShield Contributors
All rights reserved.

NetShield app_signatures.py - Comprehensive application signature database.

Each entry has:
  name         (str)   - display name
  category     (str)   - category key
  domains      (list)  - wildcard domain patterns (*.x.com matches sub.x.com AND x.com)
  sni_patterns (list)  - TLS SNI substring patterns for deep inspection

Domain lists include web, mobile app backends, CDNs, APIs, analytics, and push
notification domains so blocking actually works on phones/tablets too.
"""

import json
import logging
import os
from typing import Dict, List, Optional, Tuple

log = logging.getLogger(__name__)

CUSTOM_SIGNATURES_PATH = "/var/db/netshield/custom_signatures.json"

# ============================================================================
# Application Categories
# ============================================================================

APP_CATEGORIES = {
    "social_media": "Social Media",
    "streaming_video": "Video Streaming",
    "streaming_music": "Music Streaming",
    "gaming": "Gaming",
    "communication": "Communication & Messaging",
    "vpn_proxy": "VPN & Proxy Services",
    "cryptocurrency": "Cryptocurrency",
    "p2p": "P2P & Torrents",
    "shopping": "Shopping & E-Commerce",
    "productivity": "Productivity & Business",
    "news": "News & Media",
    "dating": "Dating",
    "education": "Education",
    "adult": "Adult Content",
    "gambling": "Gambling & Betting",
    "cloud_storage": "Cloud Storage",
    "ai_tools": "AI Tools",
    "other": "Other",
}

# ============================================================================
# Built-in Application Database (80+ apps with full mobile domain coverage)
# ============================================================================

DEFAULT_APPS: Dict[str, Dict] = {

    # ======================================================================
    # SOCIAL MEDIA
    # ======================================================================
    "facebook": {
        "name": "Facebook",
        "category": "social_media",
        "domains": [
            "*.facebook.com", "*.fbcdn.net", "*.fb.com", "*.fbsbx.com",
            "*.fbpigeon.com", "*.fb.gg", "*.facebook.net",
            "*.accountkit.com", "*.facebookcorephotos.com",
            "*.facebookcorewwwi.onion", "*.fbcdn.com",
            "facebook.com", "fb.com", "fb.gg",
            # Mobile app API/SDK
            "*.connect.facebook.net", "*.graph.facebook.com",
            "*.api.facebook.com", "*.b-api.facebook.com",
            "*.edge-chat.facebook.com", "*.upload.facebook.com",
            "*.star.facebook.com", "*.channel.facebook.com",
            "*.mqtt-mini.facebook.com", "*.edge-mqtt.facebook.com",
            # Analytics & ads (needed to fully block)
            "*.pixel.facebook.com", "*.an.facebook.com",
            "*.web.facebook.com",
        ],
        "sni_patterns": ["facebook.com", "fbcdn.net", "fb.com", "fbsbx.com"],
    },
    "instagram": {
        "name": "Instagram",
        "category": "social_media",
        "domains": [
            "*.instagram.com", "*.cdninstagram.com", "*.instagram.net",
            "instagram.com",
            # Mobile app specific
            "*.i.instagram.com", "*.graph.instagram.com",
            "*.edge-chat.instagram.com",
            "*.instagram.c10r.facebook.com",
            "*.scontent.cdninstagram.com",
            # Shared with FB infra
            "*.instagram.fmct1-2.fna.fbcdn.net",
        ],
        "sni_patterns": ["instagram.com", "cdninstagram.com"],
    },
    "twitter": {
        "name": "Twitter / X",
        "category": "social_media",
        "domains": [
            "*.twitter.com", "*.x.com", "*.twimg.com", "*.t.co",
            "*.tweetdeck.com", "*.periscope.tv", "*.vine.co",
            "twitter.com", "x.com", "t.co",
            # Mobile API & CDN
            "*.api.twitter.com", "*.mobile.twitter.com",
            "*.abs.twimg.com", "*.pbs.twimg.com", "*.video.twimg.com",
            "*.ton.twimg.com", "*.caps.twitter.com",
            "*.syndication.twitter.com",
            # X rebrand infrastructure
            "*.api.x.com",
        ],
        "sni_patterns": ["twitter.com", "x.com", "twimg.com", "t.co"],
    },
    "tiktok": {
        "name": "TikTok",
        "category": "social_media",
        "domains": [
            "*.tiktok.com", "*.tiktokcdn.com", "*.tiktokv.com",
            "*.tiktokcdn-us.com", "*.tiktok.org",
            "tiktok.com",
            # ByteDance infrastructure (mobile app backend)
            "*.musical.ly", "*.muscdn.com",
            "*.byteoversea.com", "*.byteimg.com", "*.bytegecko.com",
            "*.bytedance.com", "*.ibytedtos.com", "*.ibyteimg.com",
            "*.bytednsdispatch.com", "*.bytetcc.com",
            "*.tiktokd.org", "*.tiktokcdn-in.com",
            "*.sgsnssdk.com", "*.sgpstatp.com",
            # CapCut (TikTok video editor)
            "*.capcut.com",
            # Push notifications
            "*.lf1-ttcdn-tos.pstatp.com", "*.p16-tiktokcdn-com.akamaized.net",
        ],
        "sni_patterns": [
            "tiktok.com", "tiktokcdn.com", "byteoversea.com",
            "musical.ly", "bytedance.com", "byteimg.com",
        ],
    },
    "snapchat": {
        "name": "Snapchat",
        "category": "social_media",
        "domains": [
            "*.snapchat.com", "*.snap.com", "*.snapkit.co",
            "*.bitmoji.com", "*.snapads.com",
            "snapchat.com", "snap.com",
            # Mobile API & CDN
            "*.app.snapchat.com", "*.gcp.api.snapchat.com",
            "*.us-east4-gcp.api.snapchat.com",
            "*.bolt-gcdn.sc-cdn.net", "*.cf-st.sc-cdn.net",
            "*.sc-cdn.net", "*.sc-static.net", "*.sc-jpl.com",
            "*.sc-prod.net", "*.impala-media-production.s3.amazonaws.com",
        ],
        "sni_patterns": ["snapchat.com", "snap.com", "sc-cdn.net", "bitmoji.com"],
    },
    "linkedin": {
        "name": "LinkedIn",
        "category": "social_media",
        "domains": [
            "*.linkedin.com", "*.licdn.com", "*.linkedin.cn",
            "*.lnkd.in",
            "linkedin.com", "lnkd.in",
            # Mobile & API
            "*.api.linkedin.com", "*.mobile.linkedin.com",
            "*.media.licdn.com", "*.static.licdn.com",
            "*.platform.linkedin.com",
        ],
        "sni_patterns": ["linkedin.com", "licdn.com"],
    },
    "reddit": {
        "name": "Reddit",
        "category": "social_media",
        "domains": [
            "*.reddit.com", "*.redd.it", "*.redditmedia.com",
            "*.redditstatic.com", "*.reddit.map.fastly.net",
            "reddit.com", "redd.it",
            # Mobile API
            "*.oauth.reddit.com", "*.gateway.reddit.com",
            "*.gql.reddit.com", "*.i.redd.it", "*.v.redd.it",
            "*.preview.redd.it", "*.external-preview.redd.it",
            "*.styles.redditmedia.com",
        ],
        "sni_patterns": ["reddit.com", "redd.it", "redditmedia.com"],
    },
    "pinterest": {
        "name": "Pinterest",
        "category": "social_media",
        "domains": [
            "*.pinterest.com", "*.pinimg.com", "*.pinterest.co.uk",
            "*.pinterest.de", "*.pinterest.fr",
            "pinterest.com",
            "*.api.pinterest.com", "*.widgets.pinterest.com",
        ],
        "sni_patterns": ["pinterest.com", "pinimg.com"],
    },
    "threads": {
        "name": "Threads",
        "category": "social_media",
        "domains": [
            "*.threads.net", "*.threads.instagram.com",
            "threads.net",
        ],
        "sni_patterns": ["threads.net"],
    },
    "bereal": {
        "name": "BeReal",
        "category": "social_media",
        "domains": [
            "*.bereal.com", "*.bfrnd.co", "*.bereal.team",
            "bereal.com",
        ],
        "sni_patterns": ["bereal.com", "bfrnd.co"],
    },
    "tumblr": {
        "name": "Tumblr",
        "category": "social_media",
        "domains": [
            "*.tumblr.com", "*.txmblr.com",
            "tumblr.com",
            "*.api.tumblr.com", "*.assets.tumblr.com",
        ],
        "sni_patterns": ["tumblr.com"],
    },

    # ======================================================================
    # VIDEO STREAMING
    # ======================================================================
    "youtube": {
        "name": "YouTube",
        "category": "streaming_video",
        "domains": [
            "*.youtube.com", "*.googlevideo.com", "*.ytimg.com",
            "*.youtube-nocookie.com", "*.youtube-ui.l.google.com",
            "*.youtu.be", "*.yt.be",
            "youtube.com", "youtu.be",
            # Mobile app / API / player
            "*.youtubei.googleapis.com", "*.yt3.ggpht.com",
            "*.yt3.googleusercontent.com",
            "*.wide-youtube.l.google.com",
            "*.youtube.googleapis.com",
            # YouTube Music
            "*.music.youtube.com",
            # YouTube Kids
            "*.youtubekids.com",
            # Shorts, live, studio
            "*.studio.youtube.com",
        ],
        "sni_patterns": [
            "youtube.com", "googlevideo.com", "ytimg.com",
            "youtu.be", "youtubei.googleapis.com",
        ],
    },
    "netflix": {
        "name": "Netflix",
        "category": "streaming_video",
        "domains": [
            "*.netflix.com", "*.nflxvideo.net", "*.nflxso.net",
            "*.nflxext.com", "*.nflximg.net", "*.nflximg.com",
            "netflix.com",
            # Mobile / API / CDN
            "*.api-global.netflix.com", "*.appboot.netflix.com",
            "*.ichnaea.netflix.com", "*.customerevents.netflix.com",
            "*.codex.nflxext.com", "*.assets.nflxext.com",
            "*.presentationtracking.esn.netflix.com",
            "*.nmtracking.netflix.com",
            # Fast.com (Netflix speed test)
            "*.fast.com",
        ],
        "sni_patterns": [
            "netflix.com", "nflxvideo.net", "nflxso.net",
            "nflxext.com", "nflximg.net",
        ],
    },
    "twitch": {
        "name": "Twitch",
        "category": "streaming_video",
        "domains": [
            "*.twitch.tv", "*.twitchcdn.net", "*.twitchsvc.net",
            "*.jtvnw.net", "*.ttvnw.net",
            "twitch.tv",
            # Mobile & API
            "*.api.twitch.tv", "*.pubsub-edge.twitch.tv",
            "*.irc-ws.chat.twitch.tv", "*.gql.twitch.tv",
            "*.clips.twitch.tv", "*.vod-secure.twitch.tv",
            "*.static.twitchcdn.net", "*.usher.ttvnw.net",
        ],
        "sni_patterns": ["twitch.tv", "twitchcdn.net", "jtvnw.net", "ttvnw.net"],
    },
    "disneyplus": {
        "name": "Disney+",
        "category": "streaming_video",
        "domains": [
            "*.disneyplus.com", "*.disney-plus.net", "*.bamgrid.com",
            "*.dssott.com", "*.disney.io", "*.disneystreaming.com",
            "*.execute-api.us-east-1.amazonaws.com",
            "disneyplus.com",
            "*.disney.api.edge.bamgrid.com",
            "*.cdn.registerdisney.go.com",
            "*.global.edge.bamgrid.com",
            "*.starott.com", "*.star.api.edge.bamgrid.com",
        ],
        "sni_patterns": [
            "disneyplus.com", "bamgrid.com", "dssott.com",
            "disney-plus.net", "disneystreaming.com",
        ],
    },
    "hulu": {
        "name": "Hulu",
        "category": "streaming_video",
        "domains": [
            "*.hulu.com", "*.hulustream.com", "*.hulu.tv",
            "*.huluim.com", "*.huluqa.com",
            "hulu.com",
            "*.api.hulu.com", "*.assetshuluimcom-a.akamaihd.net",
        ],
        "sni_patterns": ["hulu.com", "hulustream.com", "huluim.com"],
    },
    "amazonprime": {
        "name": "Amazon Prime Video",
        "category": "streaming_video",
        "domains": [
            "*.primevideo.com", "*.aiv-cdn.net", "*.aiv-delivery.net",
            "*.amazonvideo.com", "*.atv-ps.amazon.com",
            "primevideo.com",
            "*.api.amazonvideo.com", "*.dmqdd6hw24ucf.cloudfront.net",
            "*.d25xi40x97liuc.cloudfront.net",
            "*.avodmp4s3ww-a.akamaihd.net",
            "*.fls-na.amazon.com",
        ],
        "sni_patterns": [
            "primevideo.com", "aiv-cdn.net", "amazonvideo.com",
        ],
    },
    "hbomax": {
        "name": "HBO Max / Max",
        "category": "streaming_video",
        "domains": [
            "*.max.com", "*.hbomax.com", "*.hbo.com",
            "*.wbd.com", "*.warnerbros.com",
            "max.com", "hbomax.com", "hbo.com",
            "*.api.hbo.com", "*.play.hbomax.com",
            "*.manifests.api.hbo.com",
            "*.comet.api.hbo.com",
        ],
        "sni_patterns": ["max.com", "hbomax.com", "hbo.com"],
    },
    "peacock": {
        "name": "Peacock TV",
        "category": "streaming_video",
        "domains": [
            "*.peacocktv.com", "*.nbcuni.com",
            "peacocktv.com",
        ],
        "sni_patterns": ["peacocktv.com"],
    },
    "crunchyroll": {
        "name": "Crunchyroll",
        "category": "streaming_video",
        "domains": [
            "*.crunchyroll.com", "*.vrv.co",
            "crunchyroll.com",
            "*.api.crunchyroll.com", "*.static.crunchyroll.com",
            "*.img1.ak.crunchyroll.com",
        ],
        "sni_patterns": ["crunchyroll.com", "vrv.co"],
    },
    "appletv": {
        "name": "Apple TV+",
        "category": "streaming_video",
        "domains": [
            "*.tv.apple.com", "*.trailers.apple.com",
            "*.play-edge.itunes.apple.com",
            "*.hls.itunes.apple.com",
            "*.apple.com",  # Note: broad - consider only blocking tv.apple.com subdomain
        ],
        "sni_patterns": ["tv.apple.com"],
    },
    "paramountplus": {
        "name": "Paramount+",
        "category": "streaming_video",
        "domains": [
            "*.paramountplus.com", "*.cbsi.com", "*.cbsaavideo.com",
            "*.cbsivideo.com",
            "paramountplus.com",
        ],
        "sni_patterns": ["paramountplus.com"],
    },

    # ======================================================================
    # MUSIC STREAMING
    # ======================================================================
    "spotify": {
        "name": "Spotify",
        "category": "streaming_music",
        "domains": [
            "*.spotify.com", "*.scdn.co", "*.spotifycdn.com",
            "*.spotilocal.com", "*.spotify.design",
            "spotify.com",
            # Mobile app / API
            "*.api.spotify.com", "*.apresolve.spotify.com",
            "*.audio-sp-tyo.pscdn.co", "*.audio-ak.spotify.com.edgesuite.net",
            "*.heads-fa.spotify.com", "*.dealer.spotify.com",
            "*.spclient.wg.spotify.com", "*.wg.spotify.com",
            "*.audio4-fa.scdn.co",
        ],
        "sni_patterns": ["spotify.com", "scdn.co", "spotifycdn.com"],
    },
    "applemusic": {
        "name": "Apple Music",
        "category": "streaming_music",
        "domains": [
            "*.music.apple.com", "*.itunes.apple.com",
            "*.mzstatic.com", "*.applemusic.com",
            "*.audio.itunes.apple.com",
            "*.aod.itunes.apple.com",
            "*.streamingaudio.itunes.apple.com",
            "*.play.itunes.apple.com",
        ],
        "sni_patterns": ["music.apple.com", "itunes.apple.com"],
    },
    "amazonmusic": {
        "name": "Amazon Music",
        "category": "streaming_music",
        "domains": [
            "*.music.amazon.com", "*.music.amazon.co.uk",
            "*.amazonmp3.com",
            "*.music.amazon.de",
        ],
        "sni_patterns": ["music.amazon.com"],
    },
    "soundcloud": {
        "name": "SoundCloud",
        "category": "streaming_music",
        "domains": [
            "*.soundcloud.com", "*.sndcdn.com",
            "soundcloud.com",
            "*.api.soundcloud.com", "*.api-v2.soundcloud.com",
        ],
        "sni_patterns": ["soundcloud.com", "sndcdn.com"],
    },
    "deezer": {
        "name": "Deezer",
        "category": "streaming_music",
        "domains": [
            "*.deezer.com", "*.dzcdn.net",
            "deezer.com",
            "*.api.deezer.com", "*.e-cdns-files.dzcdn.net",
        ],
        "sni_patterns": ["deezer.com", "dzcdn.net"],
    },
    "tidal": {
        "name": "Tidal",
        "category": "streaming_music",
        "domains": [
            "*.tidal.com", "*.tidalhifi.com",
            "tidal.com",
            "*.api.tidal.com", "*.resources.tidal.com",
        ],
        "sni_patterns": ["tidal.com"],
    },

    # ======================================================================
    # GAMING
    # ======================================================================
    "steam": {
        "name": "Steam",
        "category": "gaming",
        "domains": [
            "*.steampowered.com", "*.steamcommunity.com",
            "*.steamcontent.com", "*.steamstatic.com",
            "*.steamgames.com", "*.steamusercontent.com",
            "*.steamchina.com",
            "steampowered.com", "steamcommunity.com",
            # Mobile & client API
            "*.api.steampowered.com", "*.store.steampowered.com",
            "*.cdn.steampowered.com", "*.media.steampowered.com",
            "*.steamcdn-a.akamaihd.net",
            "*.client-download.steampowered.com",
            "*.steambroadcast.akamaized.net",
        ],
        "sni_patterns": [
            "steampowered.com", "steamcommunity.com",
            "steamcontent.com", "steamstatic.com",
        ],
    },
    "epicgames": {
        "name": "Epic Games / Fortnite",
        "category": "gaming",
        "domains": [
            "*.epicgames.com", "*.unrealengine.com",
            "*.epicgames.dev", "*.fortnite.com",
            "*.ol.epicgames.com",
            "epicgames.com", "fortnite.com",
            # CDN & download
            "*.download.epicgames.com", "*.epicgames-download1.akamaized.net",
            "*.fastly-download.epicgames.com",
        ],
        "sni_patterns": ["epicgames.com", "unrealengine.com", "fortnite.com"],
    },
    "xboxlive": {
        "name": "Xbox / Xbox Live",
        "category": "gaming",
        "domains": [
            "*.xboxlive.com", "*.xbox.com", "*.xboxab.com",
            "*.xboxservices.com",
            "xboxlive.com", "xbox.com",
            # API & matchmaking
            "*.xsts.auth.xboxlive.com", "*.title.auth.xboxlive.com",
            "*.device.auth.xboxlive.com",
            "*.xbox.gamepass.com", "*.gamepass.com",
            "*.assets.xbox.com", "*.images.xbox.com",
        ],
        "sni_patterns": ["xboxlive.com", "xbox.com", "xboxservices.com"],
    },
    "playstation": {
        "name": "PlayStation Network",
        "category": "gaming",
        "domains": [
            "*.playstation.net", "*.playstation.com",
            "*.sonyentertainmentnetwork.com", "*.sie.com",
            "playstation.net", "playstation.com",
            # Store & API
            "*.store.playstation.com", "*.auth.api.sonyentertainmentnetwork.com",
            "*.web.np.playstation.net", "*.gs2.ww.prod.dl.playstation.net",
            "*.trophy.api.playstation.com",
        ],
        "sni_patterns": [
            "playstation.net", "playstation.com",
            "sonyentertainmentnetwork.com",
        ],
    },
    "roblox": {
        "name": "Roblox",
        "category": "gaming",
        "domains": [
            "*.roblox.com", "*.rbxcdn.com", "*.robloxlabs.com",
            "*.rbx.com", "*.roblox.qq.com",
            "roblox.com",
            # Mobile API & asset delivery
            "*.api.roblox.com", "*.auth.roblox.com",
            "*.catalog.roblox.com", "*.economy.roblox.com",
            "*.thumbnails.roblox.com", "*.assetdelivery.roblox.com",
            "*.setup.rbxcdn.com", "*.tr.rbxcdn.com",
            "*.css.rbxcdn.com", "*.js.rbxcdn.com",
            "*.images.rbxcdn.com",
        ],
        "sni_patterns": ["roblox.com", "rbxcdn.com"],
    },
    "discord": {
        "name": "Discord",
        "category": "gaming",
        "domains": [
            "*.discord.com", "*.discordapp.com", "*.discord.gg",
            "*.discordcdn.com", "*.discord.media",
            "*.discordapp.net", "*.discord.dev",
            "discord.com", "discord.gg",
            # Mobile API & real-time
            "*.gateway.discord.gg", "*.media.discordapp.net",
            "*.images-ext-1.discordapp.net",
            "*.cdn.discordapp.com",
            "*.status.discord.com",
            "*.dl.discordapp.net",
        ],
        "sni_patterns": [
            "discord.com", "discordapp.com", "discord.gg",
            "discordcdn.com", "discordapp.net",
        ],
    },
    "minecraft": {
        "name": "Minecraft",
        "category": "gaming",
        "domains": [
            "*.minecraft.net", "*.mojang.com",
            "minecraft.net", "mojang.com",
            "*.minecraftservices.com", "*.minecraftprod.rtep.msgamestudios.com",
            "*.launchermeta.mojang.com", "*.libraries.minecraft.net",
            "*.resources.download.minecraft.net",
        ],
        "sni_patterns": ["minecraft.net", "mojang.com", "minecraftservices.com"],
    },
    "ea_games": {
        "name": "EA / Electronic Arts",
        "category": "gaming",
        "domains": [
            "*.ea.com", "*.origin.com", "*.tnt-ea.com",
            "ea.com", "origin.com",
            "*.api.origin.com", "*.eaassets-a.akamaihd.net",
            "*.cdn.ea.com",
        ],
        "sni_patterns": ["ea.com", "origin.com"],
    },
    "riot_games": {
        "name": "Riot Games / League of Legends / Valorant",
        "category": "gaming",
        "domains": [
            "*.riotgames.com", "*.leagueoflegends.com",
            "*.playvalorant.com", "*.riotcdn.net",
            "riotgames.com",
            "*.lol.riotgames.com", "*.valorant.riotgames.com",
            "*.auth.riotgames.com",
        ],
        "sni_patterns": ["riotgames.com", "leagueoflegends.com", "playvalorant.com"],
    },
    "activision_blizzard": {
        "name": "Activision Blizzard / Battle.net",
        "category": "gaming",
        "domains": [
            "*.blizzard.com", "*.battle.net", "*.activision.com",
            "*.blz-contentstack.com",
            "blizzard.com", "battle.net", "activision.com",
            "*.actual.battle.net", "*.bnet.battle.net",
        ],
        "sni_patterns": ["blizzard.com", "battle.net", "activision.com"],
    },

    # ======================================================================
    # COMMUNICATION & MESSAGING
    # ======================================================================
    "whatsapp": {
        "name": "WhatsApp",
        "category": "communication",
        "domains": [
            "*.whatsapp.com", "*.whatsapp.net",
            "whatsapp.com", "whatsapp.net",
            "*.wa.me", "wa.me",
            # Mobile app infrastructure (critical for blocking)
            "*.web.whatsapp.com", "*.w1.web.whatsapp.com",
            "*.mmg.whatsapp.net", "*.media.whatsapp.com",
            "*.static.whatsapp.net", "*.pps.whatsapp.net",
            "*.crashlogs.whatsapp.net",
            # WhatsApp connects via Facebook infra too
            "*.graph.whatsapp.com",
        ],
        "sni_patterns": ["whatsapp.com", "whatsapp.net", "wa.me"],
    },
    "telegram": {
        "name": "Telegram",
        "category": "communication",
        "domains": [
            "*.telegram.org", "*.t.me", "*.telegram.me",
            "*.telegra.ph", "*.telesco.pe",
            "telegram.org", "t.me",
            # Mobile app backend (IP-based too, but domain coverage)
            "*.core.telegram.org", "*.api.telegram.org",
            "*.web.telegram.org",
            # CDN for media
            "*.cdn.telegram.org", "*.updates.telegram.org",
        ],
        "sni_patterns": ["telegram.org", "t.me", "telegram.me"],
    },
    "signal": {
        "name": "Signal",
        "category": "communication",
        "domains": [
            "*.signal.org", "*.signal.art",
            "signal.org",
            # Mobile infrastructure
            "*.textsecure-service.whispersystems.org",
            "*.storage.signal.org", "*.cdn.signal.org",
            "*.cdn2.signal.org", "*.contentproxy.signal.org",
            "*.sfu.voip.signal.org", "*.updates.signal.org",
            "*.updates2.signal.org",
        ],
        "sni_patterns": ["signal.org", "whispersystems.org"],
    },
    "zoom": {
        "name": "Zoom",
        "category": "communication",
        "domains": [
            "*.zoom.us", "*.zoom.com", "*.zoomgov.com",
            "*.zoomcdn.com", "*.zoominfo.com",
            "zoom.us", "zoom.com",
            # Mobile / client
            "*.web.zoom.us", "*.us02web.zoom.us",
            "*.us04web.zoom.us", "*.us06web.zoom.us",
            "*.logfiles.zoom.us", "*.post.zoom.us",
        ],
        "sni_patterns": ["zoom.us", "zoom.com", "zoomcdn.com"],
    },
    "msteams": {
        "name": "Microsoft Teams",
        "category": "communication",
        "domains": [
            "*.teams.microsoft.com", "*.teams.cloud.microsoft",
            "*.teams.live.com", "*.teams.office.com",
            "teams.microsoft.com",
            # Infrastructure
            "*.api.teams.skype.com", "*.trouter.teams.microsoft.com",
            "*.presence.teams.microsoft.com",
            "*.statics.teams.cdn.office.net",
            "*.config.teams.microsoft.com",
            "*.teams.events.data.microsoft.com",
        ],
        "sni_patterns": ["teams.microsoft.com", "teams.cloud.microsoft"],
    },
    "slack": {
        "name": "Slack",
        "category": "communication",
        "domains": [
            "*.slack.com", "*.slack-msgs.com", "*.slackb.com",
            "*.slack-edge.com", "*.slack-files.com",
            "*.slack-imgs.com", "*.slack-redir.net",
            "slack.com",
            # API & realtime
            "*.api.slack.com", "*.wss-primary.slack.com",
            "*.files.slack.com", "*.edgeapi.slack.com",
        ],
        "sni_patterns": ["slack.com", "slack-edge.com"],
    },
    "viber": {
        "name": "Viber",
        "category": "communication",
        "domains": [
            "*.viber.com", "*.vbrcdn.com",
            "viber.com",
            "*.dl.viber.com", "*.share.viber.com",
        ],
        "sni_patterns": ["viber.com", "vbrcdn.com"],
    },
    "wechat": {
        "name": "WeChat",
        "category": "communication",
        "domains": [
            "*.wechat.com", "*.weixin.qq.com", "*.wx.qq.com",
            "*.weixinbridge.com",
            "wechat.com",
            "*.res.wx.qq.com", "*.open.weixin.qq.com",
            "*.api.weixin.qq.com",
        ],
        "sni_patterns": ["wechat.com", "weixin.qq.com"],
    },
    "line": {
        "name": "LINE",
        "category": "communication",
        "domains": [
            "*.line.me", "*.line-apps.com", "*.line-scdn.net",
            "*.linecorp.com", "*.naver.jp",
            "line.me",
        ],
        "sni_patterns": ["line.me", "line-apps.com"],
    },
    "skype": {
        "name": "Skype",
        "category": "communication",
        "domains": [
            "*.skype.com", "*.skypedata.akadns.net",
            "*.skypeassets.com", "*.skypeecs-prod-usw-0.cloudapp.net",
            "skype.com",
            "*.api.skype.com", "*.trouter.skype.com",
        ],
        "sni_patterns": ["skype.com"],
    },
    "facetime": {
        "name": "FaceTime / iMessage",
        "category": "communication",
        "domains": [
            "*.ess.apple.com", "*.identity.apple.com",
            "*.push.apple.com", "*.courier.push.apple.com",
            "*.imessage.apple.com",
            # iCloud messaging
            "*.keyvalueservice.icloud.com",
        ],
        "sni_patterns": ["push.apple.com", "identity.apple.com"],
    },

    # ======================================================================
    # VPN & PROXY SERVICES
    # ======================================================================
    "nordvpn": {
        "name": "NordVPN",
        "category": "vpn_proxy",
        "domains": [
            "*.nordvpn.com", "*.nordvpn.net", "*.nordcdn.com",
            "*.nordvpnteams.com", "*.nordpass.com",
            "*.nordlocker.com", "*.nordaccount.com",
            "*.nordsec.com", "*.nordlayer.com",
            "nordvpn.com",
        ],
        "sni_patterns": ["nordvpn.com", "nordcdn.com", "nordsec.com"],
    },
    "expressvpn": {
        "name": "ExpressVPN",
        "category": "vpn_proxy",
        "domains": [
            "*.expressvpn.com", "*.xvpn.io", "*.expressapisv2.net",
            "*.expressobutiolem.com",
            "expressvpn.com",
        ],
        "sni_patterns": ["expressvpn.com", "xvpn.io"],
    },
    "surfshark": {
        "name": "Surfshark",
        "category": "vpn_proxy",
        "domains": [
            "*.surfshark.com", "*.surfsharkstatus.com",
            "surfshark.com",
        ],
        "sni_patterns": ["surfshark.com"],
    },
    "protonvpn": {
        "name": "ProtonVPN / Proton",
        "category": "vpn_proxy",
        "domains": [
            "*.protonvpn.com", "*.proton.me", "*.protonmail.com",
            "*.protonmail.ch", "*.pm.me",
            "protonvpn.com", "proton.me",
            "*.api.protonvpn.ch", "*.api.protonmail.ch",
        ],
        "sni_patterns": ["protonvpn.com", "proton.me", "protonmail.com"],
    },
    "mullvad": {
        "name": "Mullvad VPN",
        "category": "vpn_proxy",
        "domains": [
            "*.mullvad.net", "mullvad.net",
            "*.am.i.mullvad.net",
        ],
        "sni_patterns": ["mullvad.net"],
    },
    "pia": {
        "name": "Private Internet Access",
        "category": "vpn_proxy",
        "domains": [
            "*.privateinternetaccess.com", "*.piaproxy.net",
            "privateinternetaccess.com",
        ],
        "sni_patterns": ["privateinternetaccess.com"],
    },
    "cyberghost": {
        "name": "CyberGhost VPN",
        "category": "vpn_proxy",
        "domains": [
            "*.cyberghostvpn.com", "*.cg-dialup.net",
            "cyberghostvpn.com",
        ],
        "sni_patterns": ["cyberghostvpn.com"],
    },
    "ipvanish": {
        "name": "IPVanish",
        "category": "vpn_proxy",
        "domains": [
            "*.ipvanish.com", "ipvanish.com",
        ],
        "sni_patterns": ["ipvanish.com"],
    },
    "cloudflarewarp": {
        "name": "Cloudflare WARP / 1.1.1.1",
        "category": "vpn_proxy",
        "domains": [
            "*.cloudflareclient.com", "*.cloudflaregateway.com",
            "*.cloudflare-dns.com", "*.one.one.one.one",
            "*.1dot1dot1dot1.cloudflare-dns.com",
            "cloudflareclient.com",
        ],
        "sni_patterns": [
            "cloudflareclient.com", "cloudflare-dns.com",
            "cloudflaregateway.com",
        ],
    },
    "ivpn": {
        "name": "IVPN",
        "category": "vpn_proxy",
        "domains": [
            "*.ivpn.net", "ivpn.net",
        ],
        "sni_patterns": ["ivpn.net"],
    },
    "windscribe": {
        "name": "Windscribe VPN",
        "category": "vpn_proxy",
        "domains": [
            "*.windscribe.com", "*.windscribe.net",
            "*.totallyacdn.com",
            "windscribe.com",
        ],
        "sni_patterns": ["windscribe.com"],
    },
    "tor": {
        "name": "Tor Project",
        "category": "vpn_proxy",
        "domains": [
            "*.torproject.org", "*.torbrowser.org",
            "torproject.org",
            "*.dist.torproject.org", "*.bridges.torproject.org",
        ],
        "sni_patterns": ["torproject.org"],
    },
    "tunnelbear": {
        "name": "TunnelBear",
        "category": "vpn_proxy",
        "domains": [
            "*.tunnelbear.com", "tunnelbear.com",
        ],
        "sni_patterns": ["tunnelbear.com"],
    },
    "hotspotshield": {
        "name": "Hotspot Shield",
        "category": "vpn_proxy",
        "domains": [
            "*.hotspotshield.com", "*.anchorfree.com",
            "*.hsselite.com",
            "hotspotshield.com",
        ],
        "sni_patterns": ["hotspotshield.com", "anchorfree.com"],
    },
    "shadowsocks": {
        "name": "Shadowsocks / V2Ray / Xray",
        "category": "vpn_proxy",
        "domains": [
            "*.shadowsocks.org", "*.v2ray.com", "*.xray.com",
            "*.v2fly.org",
            "shadowsocks.org", "v2ray.com",
        ],
        "sni_patterns": ["shadowsocks.org", "v2ray.com", "v2fly.org"],
    },
    "outline_vpn": {
        "name": "Outline VPN",
        "category": "vpn_proxy",
        "domains": [
            "*.getoutline.org", "getoutline.org",
        ],
        "sni_patterns": ["getoutline.org"],
    },
    "psiphon": {
        "name": "Psiphon",
        "category": "vpn_proxy",
        "domains": [
            "*.psiphon.ca", "*.psiphon3.com",
            "psiphon.ca", "psiphon3.com",
        ],
        "sni_patterns": ["psiphon.ca", "psiphon3.com"],
    },

    # ======================================================================
    # CRYPTOCURRENCY
    # ======================================================================
    "coinbase": {
        "name": "Coinbase",
        "category": "cryptocurrency",
        "domains": [
            "*.coinbase.com", "*.coinbase.pro", "*.coinbasecloud.net",
            "*.cbhubspot.net",
            "coinbase.com",
        ],
        "sni_patterns": ["coinbase.com"],
    },
    "binance": {
        "name": "Binance",
        "category": "cryptocurrency",
        "domains": [
            "*.binance.com", "*.binance.org", "*.binance.us",
            "*.bnbstatic.com", "*.binanceapi.com",
            "binance.com", "binance.us",
        ],
        "sni_patterns": ["binance.com", "bnbstatic.com"],
    },
    "kraken": {
        "name": "Kraken",
        "category": "cryptocurrency",
        "domains": [
            "*.kraken.com", "*.kraken.io",
            "kraken.com",
        ],
        "sni_patterns": ["kraken.com"],
    },
    "crypto_com": {
        "name": "Crypto.com",
        "category": "cryptocurrency",
        "domains": [
            "*.crypto.com", "*.cryptocom-cdn.azureedge.net",
            "crypto.com",
        ],
        "sni_patterns": ["crypto.com"],
    },
    "metamask": {
        "name": "MetaMask",
        "category": "cryptocurrency",
        "domains": [
            "*.metamask.io", "*.infura.io",
            "metamask.io", "infura.io",
        ],
        "sni_patterns": ["metamask.io", "infura.io"],
    },
    "opensea": {
        "name": "OpenSea (NFT)",
        "category": "cryptocurrency",
        "domains": [
            "*.opensea.io", "*.seadn.io",
            "opensea.io",
        ],
        "sni_patterns": ["opensea.io"],
    },

    # ======================================================================
    # P2P / TORRENTS
    # ======================================================================
    "bittorrent": {
        "name": "BitTorrent / uTorrent",
        "category": "p2p",
        "domains": [
            "*.bittorrent.com", "*.utorrent.com",
            "*.bt.co",
            "bittorrent.com", "utorrent.com",
        ],
        "sni_patterns": ["bittorrent.com", "utorrent.com"],
    },
    "qbittorrent": {
        "name": "qBittorrent",
        "category": "p2p",
        "domains": [
            "*.qbittorrent.org", "qbittorrent.org",
        ],
        "sni_patterns": ["qbittorrent.org"],
    },
    "thepiratebay": {
        "name": "The Pirate Bay",
        "category": "p2p",
        "domains": [
            "*.thepiratebay.org", "*.piratebay.live",
            "*.pirate-bay.net", "*.pirate-bays.net",
            "thepiratebay.org",
        ],
        "sni_patterns": ["thepiratebay.org", "piratebay"],
    },

    # ======================================================================
    # SHOPPING & E-COMMERCE
    # ======================================================================
    "amazon": {
        "name": "Amazon Shopping",
        "category": "shopping",
        "domains": [
            "*.amazon.com", "*.amazon.co.uk", "*.amazon.de",
            "*.amazon.fr", "*.amazon.ca", "*.amazon.com.au",
            "*.amazon.co.jp", "*.amazon.in", "*.amazon.es",
            "*.amazon.it", "*.amazon.sa", "*.amazon.ae",
            "*.ssl-images-amazon.com", "*.images-amazon.com",
            "*.media-amazon.com", "*.fls-na.amazon.com",
            "amazon.com", "amazon.co.uk",
        ],
        "sni_patterns": ["amazon.com", "amazon.co.uk", "images-amazon.com"],
    },
    "ebay": {
        "name": "eBay",
        "category": "shopping",
        "domains": [
            "*.ebay.com", "*.ebayimg.com", "*.ebaystatic.com",
            "*.ebayrtm.com", "*.ebay.co.uk", "*.ebay.de",
            "ebay.com",
        ],
        "sni_patterns": ["ebay.com", "ebayimg.com"],
    },
    "aliexpress": {
        "name": "AliExpress / Alibaba",
        "category": "shopping",
        "domains": [
            "*.aliexpress.com", "*.aliexpress.us", "*.alicdn.com",
            "*.alibaba.com", "*.alibabacg.com",
            "*.alipay.com", "*.alipayobjects.com",
            "aliexpress.com", "alibaba.com",
        ],
        "sni_patterns": ["aliexpress.com", "alibaba.com", "alicdn.com"],
    },
    "shopify_stores": {
        "name": "Shopify Stores",
        "category": "shopping",
        "domains": [
            "*.myshopify.com", "*.shopify.com", "*.shopifycdn.com",
            "*.cdn.shopify.com",
            "shopify.com",
        ],
        "sni_patterns": ["shopify.com", "myshopify.com"],
    },
    "wish": {
        "name": "Wish",
        "category": "shopping",
        "domains": [
            "*.wish.com", "*.contextlogic.com",
            "wish.com",
        ],
        "sni_patterns": ["wish.com"],
    },
    "shein": {
        "name": "SHEIN",
        "category": "shopping",
        "domains": [
            "*.shein.com", "*.shein.co.uk", "*.sheingsp.com",
            "*.ltwebstatic.com",
            "shein.com",
        ],
        "sni_patterns": ["shein.com", "ltwebstatic.com"],
    },
    "temu": {
        "name": "Temu",
        "category": "shopping",
        "domains": [
            "*.temu.com", "*.kwcdn.com",
            "temu.com",
        ],
        "sni_patterns": ["temu.com"],
    },

    # ======================================================================
    # PRODUCTIVITY & BUSINESS
    # ======================================================================
    "microsoft365": {
        "name": "Microsoft 365 / Office",
        "category": "productivity",
        "domains": [
            "*.office.com", "*.office365.com", "*.office.net",
            "*.microsoftonline.com", "*.sharepoint.com",
            "*.onedrive.com", "*.onedrive.live.com",
            "*.onenote.com", "*.onenote.net",
            "*.sway-cdn.com", "*.sway-extensions.com",
            "office.com", "office365.com",
            "*.outlook.office365.com", "*.outlook.office.com",
            "*.officeclient.microsoft.com",
            "*.cdn.office.net",
        ],
        "sni_patterns": [
            "office.com", "office365.com", "microsoftonline.com",
            "sharepoint.com", "onedrive.com",
        ],
    },
    "googleworkspace": {
        "name": "Google Workspace",
        "category": "productivity",
        "domains": [
            "docs.google.com", "drive.google.com",
            "sheets.google.com", "slides.google.com",
            "mail.google.com", "calendar.google.com",
            "meet.google.com", "forms.google.com",
            "classroom.google.com", "chat.google.com",
            "admin.google.com",
            "*.googleusercontent.com",
            "*.googleapis.com",
        ],
        "sni_patterns": [
            "docs.google.com", "drive.google.com",
            "sheets.google.com", "mail.google.com",
            "meet.google.com",
        ],
    },
    "notion": {
        "name": "Notion",
        "category": "productivity",
        "domains": [
            "*.notion.so", "*.notion.site", "*.notion.com",
            "notion.so",
            "*.api.notion.com", "*.msgstore.www.notion.so",
        ],
        "sni_patterns": ["notion.so", "notion.com"],
    },
    "github": {
        "name": "GitHub",
        "category": "productivity",
        "domains": [
            "*.github.com", "*.githubusercontent.com",
            "*.githubassets.com", "*.github.io",
            "*.github.dev", "*.copilot.github.com",
            "github.com",
            "*.api.github.com", "*.raw.githubusercontent.com",
            "*.objects.githubusercontent.com",
            "*.codeload.github.com",
        ],
        "sni_patterns": [
            "github.com", "githubusercontent.com", "githubassets.com",
        ],
    },
    "chatgpt": {
        "name": "ChatGPT / OpenAI",
        "category": "ai_tools",
        "domains": [
            "*.openai.com", "*.chatgpt.com", "*.oaiusercontent.com",
            "*.oaistatic.com",
            "openai.com", "chatgpt.com",
            "*.api.openai.com", "*.cdn.openai.com",
        ],
        "sni_patterns": ["openai.com", "chatgpt.com"],
    },
    "claude_ai": {
        "name": "Claude / Anthropic",
        "category": "ai_tools",
        "domains": [
            "*.anthropic.com", "*.claude.ai",
            "anthropic.com", "claude.ai",
            "*.api.anthropic.com",
        ],
        "sni_patterns": ["anthropic.com", "claude.ai"],
    },
    "gemini_ai": {
        "name": "Google Gemini",
        "category": "ai_tools",
        "domains": [
            "*.gemini.google.com", "gemini.google.com",
            "*.bard.google.com", "*.aistudio.google.com",
        ],
        "sni_patterns": ["gemini.google.com"],
    },

    # ======================================================================
    # CLOUD STORAGE
    # ======================================================================
    "dropbox": {
        "name": "Dropbox",
        "category": "cloud_storage",
        "domains": [
            "*.dropbox.com", "*.dropboxapi.com",
            "*.dropboxstatic.com", "*.dropboxusercontent.com",
            "*.db.tt",
            "dropbox.com",
        ],
        "sni_patterns": ["dropbox.com", "dropboxapi.com"],
    },
    "googledrive": {
        "name": "Google Drive",
        "category": "cloud_storage",
        "domains": [
            "drive.google.com", "*.drive.google.com",
            "*.docs.google.com",
            "*.clients6.google.com",
            "*.googleapis.com",
        ],
        "sni_patterns": ["drive.google.com"],
    },
    "icloud": {
        "name": "Apple iCloud",
        "category": "cloud_storage",
        "domains": [
            "*.icloud.com", "*.icloud-content.com",
            "*.apple-cloudkit.com",
            "icloud.com",
            "*.setup.icloud.com", "*.p-setup.icloud.com",
            "*.gateway.icloud.com",
        ],
        "sni_patterns": ["icloud.com", "apple-cloudkit.com"],
    },
    "mega": {
        "name": "MEGA",
        "category": "cloud_storage",
        "domains": [
            "*.mega.nz", "*.mega.co.nz", "*.mega.io",
            "mega.nz",
        ],
        "sni_patterns": ["mega.nz", "mega.co.nz"],
    },

    # ======================================================================
    # NEWS & MEDIA
    # ======================================================================
    "cnn": {
        "name": "CNN",
        "category": "news",
        "domains": [
            "*.cnn.com", "*.cnn.io", "*.cnn.net",
            "cnn.com",
        ],
        "sni_patterns": ["cnn.com"],
    },
    "bbc": {
        "name": "BBC",
        "category": "news",
        "domains": [
            "*.bbc.com", "*.bbc.co.uk", "*.bbci.co.uk",
            "bbc.com",
        ],
        "sni_patterns": ["bbc.com", "bbc.co.uk"],
    },

    # ======================================================================
    # DATING
    # ======================================================================
    "tinder": {
        "name": "Tinder",
        "category": "dating",
        "domains": [
            "*.tinder.com", "*.gotinder.com", "*.tindersparks.com",
            "tinder.com",
            "*.api.gotinder.com", "*.etl.tindersparks.com",
        ],
        "sni_patterns": ["tinder.com", "gotinder.com"],
    },
    "bumble": {
        "name": "Bumble",
        "category": "dating",
        "domains": [
            "*.bumble.com", "*.thebeehive.bumble.com",
            "bumble.com",
        ],
        "sni_patterns": ["bumble.com"],
    },
    "hinge": {
        "name": "Hinge",
        "category": "dating",
        "domains": [
            "*.hinge.co", "*.hingeaws.net",
            "hinge.co",
        ],
        "sni_patterns": ["hinge.co"],
    },

    # ======================================================================
    # GAMBLING
    # ======================================================================
    "bet365": {
        "name": "Bet365",
        "category": "gambling",
        "domains": [
            "*.bet365.com", "*.bet365.es",
            "bet365.com",
        ],
        "sni_patterns": ["bet365.com"],
    },
    "draftkings": {
        "name": "DraftKings",
        "category": "gambling",
        "domains": [
            "*.draftkings.com", "*.dkimg.com",
            "draftkings.com",
        ],
        "sni_patterns": ["draftkings.com"],
    },
    "fanduel": {
        "name": "FanDuel",
        "category": "gambling",
        "domains": [
            "*.fanduel.com", "fanduel.com",
        ],
        "sni_patterns": ["fanduel.com"],
    },
}

# ============================================================================
# Internal helpers
# ============================================================================

def _domain_matches(pattern: str, domain: str) -> bool:
    """Match a domain against a pattern. *.example.com matches sub.example.com AND example.com."""
    domain = domain.lower().rstrip(".")
    pattern = pattern.lower().rstrip(".")
    if pattern.startswith("*."):
        suffix = pattern[2:]
        return domain == suffix or domain.endswith("." + suffix)
    return domain == pattern


def _sni_matches(pattern: str, sni: str) -> bool:
    """Case-insensitive substring match for SNI patterns."""
    return pattern.lower() in sni.lower()


# ============================================================================
# Public API
# ============================================================================

def get_all_signatures() -> Dict[str, Dict]:
    """Return merged dict of built-in + custom app signatures. Custom overrides built-in by key."""
    apps = dict(DEFAULT_APPS)
    if os.path.isfile(CUSTOM_SIGNATURES_PATH):
        try:
            with open(CUSTOM_SIGNATURES_PATH, "r", encoding="utf-8") as fh:
                custom = json.load(fh)
            if isinstance(custom, dict):
                apps.update(custom)
                log.debug("Loaded %d custom signatures", len(custom))
        except (json.JSONDecodeError, OSError) as exc:
            log.warning("Failed to load custom signatures: %s", exc)
    return apps


def get_categories() -> Dict[str, str]:
    """Return app category ID -> display name mapping."""
    return dict(APP_CATEGORIES)


def get_apps_by_category(category: str) -> List[Dict]:
    """Return all apps in a given category."""
    apps = get_all_signatures()
    return [app for app in apps.values() if app.get("category") == category]


def match_domain(domain: str) -> Optional[Tuple[str, str]]:
    """Match a domain against all known app signatures. Returns (app_name, category) or None."""
    if not domain:
        return None
    domain = domain.lower().rstrip(".")
    apps = get_all_signatures()
    custom_keys = set(apps.keys()) - set(DEFAULT_APPS.keys())
    check_order = list(custom_keys) + list(DEFAULT_APPS.keys())
    for key in check_order:
        app = apps.get(key)
        if app is None:
            continue
        for pattern in app.get("domains", []):
            if _domain_matches(pattern, domain):
                return (app["name"], app["category"])
    return None


def match_sni(sni: str) -> Optional[Tuple[str, str]]:
    """Match a TLS SNI value against all known apps. Returns (app_name, category) or None."""
    if not sni:
        return None
    sni = sni.lower().rstrip(".")
    apps = get_all_signatures()
    for app in apps.values():
        for pattern in app.get("sni_patterns", []):
            if _sni_matches(pattern, sni):
                return (app["name"], app["category"])
    return None


def get_app_domains(app_name: str) -> List[str]:
    """Return all domain patterns for the given app name (case-insensitive)."""
    apps = get_all_signatures()
    for app in apps.values():
        if app.get("name", "").lower() == app_name.lower():
            return list(app.get("domains", []))
    return []


def get_all_domains_for_category(category: str) -> List[str]:
    """Return all domain patterns for all apps in a category."""
    domains = []
    for app in get_apps_by_category(category):
        domains.extend(app.get("domains", []))
    return domains


def save_custom_signatures(signatures: Dict[str, Dict]) -> bool:
    """Persist custom app signatures. Returns True on success."""
    if not isinstance(signatures, dict):
        log.error("save_custom_signatures: expected dict, got %s", type(signatures))
        return False
    for key, app in signatures.items():
        if not isinstance(app, dict):
            log.error("save_custom_signatures: entry '%s' is not a dict", key)
            return False
        for required in ("name", "category", "domains"):
            if required not in app:
                log.error("save_custom_signatures: entry '%s' missing '%s'", key, required)
                return False
    db_dir = os.path.dirname(CUSTOM_SIGNATURES_PATH)
    if db_dir and not os.path.isdir(db_dir):
        try:
            os.makedirs(db_dir, mode=0o750, exist_ok=True)
        except OSError as exc:
            log.error("Cannot create directory %s: %s", db_dir, exc)
            return False
    try:
        with open(CUSTOM_SIGNATURES_PATH, "w", encoding="utf-8") as fh:
            json.dump(signatures, fh, indent=2)
        log.info("Saved %d custom signatures to %s", len(signatures), CUSTOM_SIGNATURES_PATH)
        return True
    except OSError as exc:
        log.error("Failed to save custom signatures: %s", exc)
        return False


# ============================================================================
# Engine wrapper class (for manage_appsignatures.py compatibility)
# ============================================================================

class AppSignaturesEngine:
    """Wrapper class around module-level functions for backward compatibility."""

    def get_all_apps(self):
        apps = get_all_signatures()
        result = []
        for app_id, app in apps.items():
            entry = dict(app)
            entry["id"] = app_id
            entry["domain_count"] = len(app.get("domains", []))
            entry["risk"] = app.get("risk", "low")
            entry["builtin"] = app_id in DEFAULT_APPS
            if "domains" not in entry:
                entry["domains"] = []
            if "sni_patterns" not in entry:
                entry["sni_patterns"] = []
            if "ports" not in entry:
                entry["ports"] = []
            result.append(entry)
        return result

    def get_categories(self):
        return get_categories()

    def match_domain(self, domain):
        result = match_domain(domain)
        if result:
            return {"app": result[0], "category": result[1]}
        return None

    def match_port(self, port, protocol="tcp"):
        # Port matching not in current version - return empty
        return []

    def search_apps(self, query):
        query = query.lower()
        apps = self.get_all_apps()
        return [a for a in apps if query in a.get("name", "").lower()
                or query in a.get("id", "").lower()
                or query in a.get("category", "").lower()
                or any(query in d.lower() for d in a.get("domains", []))]

    def get_apps_by_category(self, category):
        return [dict(a, id=k) for k, a in get_all_signatures().items()
                if a.get("category") == category]

    def add_custom_signature(self, app_id, name, category, domains, ports=None, risk="low"):
        try:
            sigs = {}
            if os.path.isfile(CUSTOM_SIGNATURES_PATH):
                import json as _json
                with open(CUSTOM_SIGNATURES_PATH, "r") as f:
                    sigs = _json.load(f)
            sigs[app_id] = {
                "name": name,
                "category": category,
                "domains": domains if isinstance(domains, list) else domains.split(","),
                "sni_patterns": [],
                "ports": ports or [],
                "risk": risk,
            }
            return save_custom_signatures(sigs)
        except Exception as e:
            log.error("add_custom_signature failed: %s", e)
            return False

    def remove_custom_signature(self, app_id):
        try:
            if not os.path.isfile(CUSTOM_SIGNATURES_PATH):
                return False
            import json as _json
            with open(CUSTOM_SIGNATURES_PATH, "r") as f:
                sigs = _json.load(f)
            if app_id in sigs:
                del sigs[app_id]
                return save_custom_signatures(sigs)
            return False
        except Exception as e:
            log.error("remove_custom_signature failed: %s", e)
            return False

    def get_stats(self):
        apps = get_all_signatures()
        cats = set(a.get("category", "") for a in apps.values())
        total_domains = sum(len(a.get("domains", [])) for a in apps.values())
        custom_count = len(apps) - len(DEFAULT_APPS)
        cats_count = {}
        for a in apps.values():
            c = a.get("category", "other")
            cats_count[c] = cats_count.get(c, 0) + 1
        return {
            "total_apps": len(apps),
            "builtin_apps": len(DEFAULT_APPS),
            "custom_apps": max(0, custom_count),
            "categories": len(cats),
            "indexed_domains": total_domains,
            "indexed_ports": 0,
            "apps_per_category": cats_count,
        }
