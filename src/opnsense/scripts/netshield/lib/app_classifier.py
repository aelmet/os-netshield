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
Application Classifier — Maps DPI results + SNI + DNS to application names.
Maintains a database of known applications and their signatures.
"""

import fnmatch
import logging
from typing import Any, Dict, List, Optional, Tuple

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Signature database
# ---------------------------------------------------------------------------

# Domain glob patterns → application name
APP_SIGNATURES: Dict[str, str] = {
    # Streaming
    "*.netflix.com":            "Netflix",
    "*.nflxvideo.net":          "Netflix",
    "*.nflxext.com":            "Netflix",
    "*.youtube.com":            "YouTube",
    "*.googlevideo.com":        "YouTube",
    "*.ytimg.com":              "YouTube",
    "*.youtu.be":               "YouTube",
    "*.twitch.tv":              "Twitch",
    "*.twitchsvc.net":          "Twitch",
    "*.jtvnw.net":              "Twitch",
    "*.twitchdisrupt.com":      "Twitch",
    "*.spotify.com":            "Spotify",
    "*.scdn.co":                "Spotify",
    "*.spotifycdn.com":         "Spotify",
    "*.hulu.com":               "Hulu",
    "*.hulustream.com":         "Hulu",
    "*.disneyplus.com":         "Disney+",
    "*.bamgrid.com":            "Disney+",
    "*.primevideo.com":         "Amazon Prime Video",
    "*.aiv-cdn.net":            "Amazon Prime Video",
    "*.hbomax.com":             "Max (HBO)",
    "*.warnermediacdn.com":     "Max (HBO)",
    "*.peacocktv.com":          "Peacock",
    "*.paramountplus.com":      "Paramount+",
    "*.vimeo.com":              "Vimeo",
    "*.vimeocdn.com":           "Vimeo",
    "*.dailymotion.com":        "Dailymotion",
    # Social Media
    "*.tiktok.com":             "TikTok",
    "*.tiktokcdn.com":          "TikTok",
    "*.tiktokv.com":            "TikTok",
    "*.facebook.com":           "Facebook",
    "*.fbcdn.net":              "Facebook",
    "*.fb.com":                 "Facebook",
    "*.instagram.com":          "Instagram",
    "*.cdninstagram.com":       "Instagram",
    "*.twitter.com":            "Twitter/X",
    "*.x.com":                  "Twitter/X",
    "*.twimg.com":              "Twitter/X",
    "*.reddit.com":             "Reddit",
    "*.redd.it":                "Reddit",
    "*.redditmedia.com":        "Reddit",
    "*.reddituploads.com":      "Reddit",
    "*.linkedin.com":           "LinkedIn",
    "*.licdn.com":              "LinkedIn",
    "*.snapchat.com":           "Snapchat",
    "*.sc-cdn.net":             "Snapchat",
    "*.pinterest.com":          "Pinterest",
    "*.pinimg.com":             "Pinterest",
    "*.tumblr.com":             "Tumblr",
    # Communication
    "*.whatsapp.net":           "WhatsApp",
    "*.whatsapp.com":           "WhatsApp",
    "*.telegram.org":           "Telegram",
    "*.t.me":                   "Telegram",
    "*.zoom.us":                "Zoom",
    "*.zoomgov.com":            "Zoom",
    "*.zoomcdn.com":            "Zoom",
    "*.teams.microsoft.com":    "Microsoft Teams",
    "*.skype.com":              "Skype",
    "*.sfbassets.com":          "Skype",
    "*.discord.com":            "Discord",
    "*.discordapp.com":         "Discord",
    "*.discordapp.net":         "Discord",
    "*.signal.org":             "Signal",
    "*.slack.com":              "Slack",
    "*.slack-edge.com":         "Slack",
    "*.slackb.com":             "Slack",
    "*.viber.com":              "Viber",
    "*.line.me":                "LINE",
    "*.line-scdn.net":          "LINE",
    "*.meet.google.com":        "Google Meet",
    "*.webex.com":              "Cisco Webex",
    "*.wbx2.com":               "Cisco Webex",
    # Gaming
    "*.steampowered.com":       "Steam",
    "*.steamcontent.com":       "Steam",
    "*.steamstatic.com":        "Steam",
    "*.steamgames.com":         "Steam",
    "*.epicgames.com":          "Epic Games",
    "*.unrealengine.com":       "Epic Games",
    "*.riotgames.com":          "Riot Games",
    "*.leagueoflegends.com":    "League of Legends",
    "*.battlenet.com":          "Battle.net",
    "*.blizzard.com":           "Battle.net",
    "*.ea.com":                 "EA Games",
    "*.origin.com":             "EA Games",
    "*.playstation.com":        "PlayStation Network",
    "*.playstation.net":        "PlayStation Network",
    "*.xboxlive.com":           "Xbox Live",
    "*.nintendo.com":           "Nintendo",
    "*.roblox.com":             "Roblox",
    "*.rbxcdn.com":             "Roblox",
    "*.minecraft.net":          "Minecraft",
    "*.mojang.com":             "Minecraft",
    "*.gog.com":                "GOG",
    "*.gogcdn.net":             "GOG",
    # Cloud / Productivity
    "*.amazonaws.com":          "AWS",
    "*.awsstatic.com":          "AWS",
    "*.cloudfront.net":         "AWS CloudFront",
    "*.googleapis.com":         "Google APIs",
    "*.gstatic.com":            "Google",
    "*.google.com":             "Google",
    "*.googleusercontent.com":  "Google",
    "*.windows.net":            "Azure",
    "*.azure.com":              "Azure",
    "*.microsoftonline.com":    "Microsoft 365",
    "*.office.com":             "Microsoft 365",
    "*.office365.com":          "Microsoft 365",
    "*.live.com":               "Microsoft Live",
    "*.cloudflare.com":         "Cloudflare",
    "*.cloudflare-dns.com":     "Cloudflare DNS",
    "*.1dot1dot1dot1.cloudflare-dns.com": "Cloudflare DNS",
    "*.apple.com":              "Apple",
    "*.icloud.com":             "iCloud",
    "*.mzstatic.com":           "Apple App Store",
    "*.dropbox.com":            "Dropbox",
    "*.dropboxstatic.com":      "Dropbox",
    "*.box.com":                "Box",
    "*.onedrive.com":           "OneDrive",
    "*.sharepoint.com":         "SharePoint",
    "*.google.com/drive":       "Google Drive",
    "*.docs.google.com":        "Google Docs",
    # Development
    "*.github.com":             "GitHub",
    "*.githubusercontent.com":  "GitHub",
    "*.gitlab.com":             "GitLab",
    "*.bitbucket.org":          "Bitbucket",
    "*.npmjs.com":              "npm",
    "*.pypi.org":               "PyPI",
    "*.docker.com":             "Docker Hub",
    "*.dockerhub.io":           "Docker Hub",
    # CDN / Infrastructure
    "*.akamaihd.net":           "Akamai CDN",
    "*.akamai.net":             "Akamai CDN",
    "*.fastly.net":             "Fastly CDN",
    "*.fastly.com":             "Fastly CDN",
    "*.edgecastcdn.net":        "EdgeCast CDN",
    "*.llnwd.net":              "Limelight CDN",
    # VPN / Proxy
    "*.nordvpn.com":            "NordVPN",
    "*.expressvpn.com":         "ExpressVPN",
    "*.ipvanish.com":           "IPVanish",
    "*.protonvpn.com":          "ProtonVPN",
    "*.mullvad.net":            "Mullvad VPN",
    "*.torproject.org":         "Tor",
    # Adult content (category matters for policy)
    "*.pornhub.com":            "PornHub",
    "*.xvideos.com":            "XVideos",
    "*.xhamster.com":           "xHamster",
    "*.onlyfans.com":           "OnlyFans",
}

# Application name → category
APP_CATEGORIES: Dict[str, str] = {
    # Streaming
    "Netflix":              "Streaming",
    "YouTube":              "Streaming",
    "Twitch":               "Streaming",
    "Spotify":              "Streaming",
    "Hulu":                 "Streaming",
    "Disney+":              "Streaming",
    "Amazon Prime Video":   "Streaming",
    "Max (HBO)":            "Streaming",
    "Peacock":              "Streaming",
    "Paramount+":           "Streaming",
    "Vimeo":                "Streaming",
    "Dailymotion":          "Streaming",
    # Social Media
    "TikTok":               "Social",
    "Facebook":             "Social",
    "Instagram":            "Social",
    "Twitter/X":            "Social",
    "Reddit":               "Social",
    "LinkedIn":             "Social",
    "Snapchat":             "Social",
    "Pinterest":            "Social",
    "Tumblr":               "Social",
    # Communication
    "WhatsApp":             "Communication",
    "Telegram":             "Communication",
    "Zoom":                 "Communication",
    "Microsoft Teams":      "Communication",
    "Skype":                "Communication",
    "Discord":              "Communication",
    "Signal":               "Communication",
    "Slack":                "Communication",
    "Viber":                "Communication",
    "LINE":                 "Communication",
    "Google Meet":          "Communication",
    "Cisco Webex":          "Communication",
    # Gaming
    "Steam":                "Gaming",
    "Epic Games":           "Gaming",
    "Riot Games":           "Gaming",
    "League of Legends":    "Gaming",
    "Battle.net":           "Gaming",
    "EA Games":             "Gaming",
    "PlayStation Network":  "Gaming",
    "Xbox Live":            "Gaming",
    "Nintendo":             "Gaming",
    "Roblox":               "Gaming",
    "Minecraft":            "Gaming",
    "GOG":                  "Gaming",
    # Cloud
    "AWS":                  "Cloud",
    "AWS CloudFront":       "Cloud",
    "Google APIs":          "Cloud",
    "Google":               "Cloud",
    "Azure":                "Cloud",
    "Microsoft 365":        "Cloud",
    "Microsoft Live":       "Cloud",
    "Cloudflare":           "Cloud",
    "Cloudflare DNS":       "Network",
    "Apple":                "Cloud",
    "iCloud":               "Cloud",
    "Apple App Store":      "Cloud",
    "Dropbox":              "Cloud",
    "Box":                  "Cloud",
    "OneDrive":             "Cloud",
    "SharePoint":           "Cloud",
    "Google Drive":         "Cloud",
    "Google Docs":          "Cloud",
    # Development
    "GitHub":               "Development",
    "GitLab":               "Development",
    "Bitbucket":            "Development",
    "npm":                  "Development",
    "PyPI":                 "Development",
    "Docker Hub":           "Development",
    # CDN / Infrastructure
    "Akamai CDN":           "CDN",
    "Fastly CDN":           "CDN",
    "EdgeCast CDN":         "CDN",
    "Limelight CDN":        "CDN",
    # VPN
    "NordVPN":              "VPN",
    "ExpressVPN":           "VPN",
    "IPVanish":             "VPN",
    "ProtonVPN":            "VPN",
    "Mullvad VPN":          "VPN",
    "Tor":                  "VPN",
    # Adult
    "PornHub":              "Adult",
    "XVideos":              "Adult",
    "xHamster":             "Adult",
    "OnlyFans":             "Adult",
    # Fallback protocols
    "HTTP":                 "Web",
    "HTTPS":                "Web",
    "DNS":                  "Network",
    "SSH":                  "Network",
    "FTP":                  "File Transfer",
    "SMTP":                 "Email",
    "SMTP/TLS":             "Email",
    "SMTPS":                "Email",
    "POP3":                 "Email",
    "POP3S":                "Email",
    "IMAP":                 "Email",
    "IMAPS":                "Email",
    "MySQL":                "Database",
    "PostgreSQL":           "Database",
    "Redis":                "Database",
    "MongoDB":              "Database",
    "OpenVPN":              "VPN",
    "WireGuard":            "VPN",
    "PPTP":                 "VPN",
    "IKE/IPsec":            "VPN",
    "BitTorrent":           "P2P",
    "RTSP":                 "Streaming",
    "RTMP":                 "Streaming",
    "SIP":                  "VoIP",
    "SIPS":                 "VoIP",
    "RDP":                  "Remote Desktop",
    "VNC":                  "Remote Desktop",
    "DHCP":                 "Network",
    "NTP":                  "Network",
    "SNMP":                 "Network",
    "SNMP-Trap":            "Network",
    "LDAP":                 "Directory",
    "LDAPS":                "Directory",
    "Kerberos":             "Authentication",
    "Syslog":               "Logging",
    "Elasticsearch":        "Database",
    "Kubernetes-API":       "Cloud",
}

# Port → (app_name, confidence)
_PORT_FALLBACK: Dict[int, Tuple[str, float]] = {
    80:    ("HTTP",          0.5),
    443:   ("HTTPS",         0.5),
    53:    ("DNS",           0.9),
    22:    ("SSH",           0.9),
    21:    ("FTP",           0.9),
    25:    ("SMTP",          0.9),
    587:   ("SMTP/TLS",      0.9),
    465:   ("SMTPS",         0.9),
    110:   ("POP3",          0.9),
    995:   ("POP3S",         0.9),
    143:   ("IMAP",          0.9),
    993:   ("IMAPS",         0.9),
    3306:  ("MySQL",         0.9),
    5432:  ("PostgreSQL",    0.9),
    6379:  ("Redis",         0.9),
    27017: ("MongoDB",       0.9),
    1194:  ("OpenVPN",       0.9),
    51820: ("WireGuard",     0.9),
    1723:  ("PPTP",          0.9),
    500:   ("IKE/IPsec",     0.9),
    4500:  ("IPsec-NAT",     0.9),
    6881:  ("BitTorrent",    0.7),
    6969:  ("BitTorrent",    0.7),
    554:   ("RTSP",          0.9),
    1935:  ("RTMP",          0.9),
    5060:  ("SIP",           0.9),
    5061:  ("SIPS",          0.9),
    3389:  ("RDP",           0.9),
    5900:  ("VNC",           0.9),
    67:    ("DHCP",          0.9),
    123:   ("NTP",           0.9),
    161:   ("SNMP",          0.9),
    162:   ("SNMP-Trap",     0.9),
    389:   ("LDAP",          0.9),
    636:   ("LDAPS",         0.9),
    88:    ("Kerberos",      0.9),
    514:   ("Syslog",        0.9),
    9200:  ("Elasticsearch", 0.8),
    6443:  ("Kubernetes-API",0.8),
}


# ---------------------------------------------------------------------------
# AppClassifier
# ---------------------------------------------------------------------------


class AppClassifier:
    """Classify traffic to named applications using SNI, IP, port, and nDPI results."""

    def __init__(self) -> None:
        # Pre-split patterns for faster matching
        self._exact_patterns: Dict[str, str] = {}
        self._suffix_patterns: List[Tuple[str, str]] = []
        self._build_index()

    def _build_index(self) -> None:
        """Split APP_SIGNATURES into exact and suffix pattern sets."""
        for pattern, app_name in APP_SIGNATURES.items():
            if pattern.startswith("*."):
                # Suffix match: strip the '*' so we match '.domain.tld'
                self._suffix_patterns.append((pattern[1:], app_name))
            else:
                # Strip any '*' and treat as substring/exact
                self._exact_patterns[pattern.lower()] = app_name

    def classify(
        self,
        sni: Optional[str] = None,
        dst_ip: Optional[str] = None,
        dst_port: Optional[int] = None,
        ndpi_result: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Return classification dict: app_name, category, confidence.

        Priority order:
          1. SNI match (highest confidence)
          2. nDPI result (if confidence >= 0.7)
          3. Port-based fallback
          4. Unknown
        """
        # 1. SNI match
        if sni:
            matched = self._match_sni(sni)
            if matched:
                app_name = matched
                return {
                    "app_name": app_name,
                    "category": APP_CATEGORIES.get(app_name, "Unknown"),
                    "confidence": 0.95,
                }
            # SNI present but unrecognised — still HTTPS
            if dst_port in (443, 8443, 993, 995, 465):
                return {
                    "app_name": "HTTPS",
                    "category": "Web",
                    "confidence": 0.6,
                    "sni": sni,
                }

        # 2. nDPI result
        if ndpi_result and ndpi_result.get("confidence", 0) >= 0.7:
            app_name = ndpi_result.get("app_name", "Unknown")
            if app_name != "Unknown":
                return {
                    "app_name": app_name,
                    "category": APP_CATEGORIES.get(app_name, ndpi_result.get("category", "Unknown")),
                    "confidence": ndpi_result["confidence"],
                }

        # 3. Port-based fallback
        if dst_port is not None:
            port_match = self._match_port(dst_port)
            if port_match:
                app_name, confidence = port_match
                return {
                    "app_name": app_name,
                    "category": APP_CATEGORIES.get(app_name, "Unknown"),
                    "confidence": confidence,
                }

        return {"app_name": "Unknown", "category": "Unknown", "confidence": 0.0}

    def _match_sni(self, sni: str) -> Optional[str]:
        """Match an SNI hostname against APP_SIGNATURES. Returns app name or None."""
        sni_lower = sni.lower()

        # Exact match first
        if sni_lower in self._exact_patterns:
            return self._exact_patterns[sni_lower]

        # Suffix match: pattern is '.domain.tld', sni must end with it
        # or equal 'domain.tld' (i.e. strip the leading dot for bare match)
        for suffix, app_name in self._suffix_patterns:
            # suffix starts with '.' (e.g. '.netflix.com')
            if sni_lower.endswith(suffix) or sni_lower == suffix[1:]:
                return app_name

        return None

    def _match_port(self, port: int) -> Optional[Tuple[str, float]]:
        """Return (app_name, confidence) for a known port, or None."""
        return _PORT_FALLBACK.get(port)

    def get_app_stats(self, flows: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
        """Aggregate per-app statistics from a list of flow dicts.

        Each flow dict must have: app_name, bytes_sent, bytes_recv, category.
        Returns mapping of app_name → {bytes, connections, category}.
        """
        stats: Dict[str, Dict[str, Any]] = {}
        for flow in flows:
            app = flow.get("app_name", "Unknown") or "Unknown"
            category = flow.get("category", APP_CATEGORIES.get(app, "Unknown"))
            bytes_total = (
                flow.get("bytes_sent", 0) + flow.get("bytes_recv", 0)
            )
            if app not in stats:
                stats[app] = {"bytes": 0, "connections": 0, "category": category}
            stats[app]["bytes"] += bytes_total
            stats[app]["connections"] += 1
        return stats

    def enrich_flow(self, flow: Dict[str, Any]) -> Dict[str, Any]:
        """Enrich a flow dict in-place with classification if app_name is Unknown."""
        if flow.get("app_name", "Unknown") == "Unknown":
            result = self.classify(
                sni=flow.get("sni"),
                dst_ip=flow.get("dst_ip"),
                dst_port=flow.get("dst_port"),
            )
            flow["app_name"] = result["app_name"]
            flow["category"] = result["category"]
            flow["confidence"] = result["confidence"]
        elif not flow.get("category"):
            flow["category"] = APP_CATEGORIES.get(flow["app_name"], "Unknown")
        return flow
