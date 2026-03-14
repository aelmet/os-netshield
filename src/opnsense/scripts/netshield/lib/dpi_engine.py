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
DPI Engine — Passive traffic classification using nDPI.
Uses BPF (Berkeley Packet Filter) to tap traffic without inline disruption.
Falls back to flow heuristics if nDPI library is not available.
"""

import ctypes
import errno
import fcntl
import logging
import os
import socket
import struct
import time
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

try:
    from .tls_inspector import extract_sni
except ImportError:
    from tls_inspector import extract_sni

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

NDPI_LIB_PATH = "/usr/local/lib/libndpi.so"

# BPF ioctl codes (FreeBSD)
BIOCSETIF = 0x8020426c
BIOCGBLEN = 0x40044266
BIOCSBLEN = 0x80044266
BIOCIMMEDIATE = 0x80044270
BIOCPROMISC = 0x20004269
BIOCGDLT = 0x4004426a
BIOCSHDRCMPLT = 0x80044275

# BPF header size on FreeBSD (bpf_hdr struct)
BPF_HDR_SIZE = 18  # tv_sec(4) + tv_usec(4) + caplen(4) + datalen(4) + hdrlen(2)

# Ethernet frame offsets
ETH_HEADER_LEN = 14
ETH_TYPE_IPV4 = 0x0800
ETH_TYPE_IPV6 = 0x86DD

# IP protocol numbers
PROTO_TCP = 6
PROTO_UDP = 17

# ---------------------------------------------------------------------------
# nDPI ctypes wrapper
# ---------------------------------------------------------------------------


class NDPIWrapper:
    """Thin ctypes wrapper around libndpi for traffic classification."""

    def __init__(self) -> None:
        self._lib: Optional[ctypes.CDLL] = None
        self._ndpi_struct: Optional[ctypes.c_void_p] = None
        self._available = False
        self._load()

    def _load(self) -> None:
        if not os.path.exists(NDPI_LIB_PATH):
            log.warning("nDPI library not found at %s — using heuristic fallback", NDPI_LIB_PATH)
            return
        try:
            self._lib = ctypes.CDLL(NDPI_LIB_PATH)
            self._setup_prototypes()
            self._ndpi_struct = self._lib.ndpi_init_detection_module(
                ctypes.c_uint32(0)  # detection_bitmask (0 = all)
            )
            if not self._ndpi_struct:
                raise RuntimeError("ndpi_init_detection_module returned NULL")
            self._available = True
            log.info("nDPI library loaded successfully from %s", NDPI_LIB_PATH)
        except OSError as exc:
            log.warning("Failed to load nDPI library: %s — using heuristic fallback", exc)
        except Exception as exc:  # pylint: disable=broad-except
            log.warning("nDPI init error: %s — using heuristic fallback", exc)

    def _setup_prototypes(self) -> None:
        """Declare C function signatures for safety."""
        lib = self._lib
        # ndpi_init_detection_module
        lib.ndpi_init_detection_module.restype = ctypes.c_void_p
        lib.ndpi_init_detection_module.argtypes = [ctypes.c_uint32]
        # ndpi_exit_detection_module
        lib.ndpi_exit_detection_module.restype = None
        lib.ndpi_exit_detection_module.argtypes = [ctypes.c_void_p]
        # ndpi_get_proto_name
        lib.ndpi_get_proto_name.restype = ctypes.c_char_p
        lib.ndpi_get_proto_name.argtypes = [ctypes.c_void_p, ctypes.c_uint16]
        # ndpi_get_category_name
        lib.ndpi_get_category_name.restype = ctypes.c_char_p
        lib.ndpi_get_category_name.argtypes = [ctypes.c_void_p, ctypes.c_int]

    @property
    def available(self) -> bool:
        return self._available

    def classify_packet(
        self,
        packet_data: bytes,
        packet_len: int,
        src_ip: str,
        dst_ip: str,
        src_port: int,
        dst_port: int,
        protocol: int,
    ) -> Dict[str, Any]:
        """Classify a packet using nDPI.

        Returns a dict with keys: app_name, category, confidence.
        If nDPI is unavailable, returns unknown classification.
        """
        if not self._available or not self._lib:
            return {"app_name": "Unknown", "category": "Unknown", "confidence": 0.0}

        try:
            # nDPI detection is stateful per-flow; here we do a best-effort
            # single-packet query via ndpi_detection_process_packet.
            # A proper implementation would maintain per-flow ndpi_flow_struct.
            # This simplified version uses protocol name lookup after port-hint.
            result = {"app_name": "Unknown", "category": "Unknown", "confidence": 0.5}

            # Attempt to get proto name from nDPI for common ports
            proto_id = self._port_to_ndpi_proto(dst_port, protocol)
            if proto_id is not None:
                name_bytes = self._lib.ndpi_get_proto_name(
                    ctypes.c_void_p(self._ndpi_struct), ctypes.c_uint16(proto_id)
                )
                if name_bytes:
                    result["app_name"] = name_bytes.decode("utf-8", errors="replace")
                    result["confidence"] = 0.8

            return result
        except Exception as exc:  # pylint: disable=broad-except
            log.debug("nDPI classify error: %s", exc)
            return {"app_name": "Unknown", "category": "Unknown", "confidence": 0.0}

    def _port_to_ndpi_proto(self, port: int, protocol: int) -> Optional[int]:
        """Map well-known port to nDPI protocol ID (simplified lookup)."""
        # nDPI protocol IDs for common services
        _PORT_MAP: Dict[int, int] = {
            80: 7,    # HTTP
            443: 91,  # HTTPS/TLS
            53: 5,    # DNS
            22: 102,  # SSH
            21: 3,    # FTP
            25: 6,    # SMTP
            110: 8,   # POP3
            143: 9,   # IMAP
            3306: 31, # MySQL
            5432: 48, # PostgreSQL
        }
        return _PORT_MAP.get(port)

    def cleanup(self) -> None:
        """Free the nDPI detection module."""
        if self._available and self._lib and self._ndpi_struct:
            try:
                self._lib.ndpi_exit_detection_module(ctypes.c_void_p(self._ndpi_struct))
            except Exception as exc:  # pylint: disable=broad-except
                log.debug("nDPI cleanup error: %s", exc)
            finally:
                self._ndpi_struct = None
                self._available = False


# ---------------------------------------------------------------------------
# Flow heuristics (fallback)
# ---------------------------------------------------------------------------


class FlowHeuristics:
    """Port-based and SNI-based traffic classification fallback."""

    # Port → (app_name, category)
    _PORT_MAP: Dict[int, Tuple[str, str]] = {
        80:   ("HTTP",          "Web"),
        443:  ("HTTPS",         "Web"),
        53:   ("DNS",           "Network"),
        22:   ("SSH",           "Network"),
        21:   ("FTP",           "File Transfer"),
        25:   ("SMTP",          "Email"),
        587:  ("SMTP/TLS",      "Email"),
        465:  ("SMTPS",         "Email"),
        110:  ("POP3",          "Email"),
        995:  ("POP3S",         "Email"),
        143:  ("IMAP",          "Email"),
        993:  ("IMAPS",         "Email"),
        3306: ("MySQL",         "Database"),
        5432: ("PostgreSQL",    "Database"),
        6379: ("Redis",         "Database"),
        27017:("MongoDB",       "Database"),
        1194: ("OpenVPN",       "VPN"),
        1723: ("PPTP",          "VPN"),
        500:  ("IKE/IPsec",     "VPN"),
        4500: ("IPsec-NAT",     "VPN"),
        51820:("WireGuard",     "VPN"),
        8080: ("HTTP-Alt",      "Web"),
        8443: ("HTTPS-Alt",     "Web"),
        554:  ("RTSP",          "Streaming"),
        1935: ("RTMP",          "Streaming"),
        5004: ("RTP",           "Streaming"),
        3478: ("STUN",          "Communication"),
        5349: ("STUNS",         "Communication"),
        5060: ("SIP",           "VoIP"),
        5061: ("SIPS",          "VoIP"),
        3389: ("RDP",           "Remote Desktop"),
        5900: ("VNC",           "Remote Desktop"),
        6881: ("BitTorrent",    "P2P"),
        6969: ("BitTorrent",    "P2P"),
        67:   ("DHCP",          "Network"),
        68:   ("DHCP",          "Network"),
        123:  ("NTP",           "Network"),
        161:  ("SNMP",          "Network"),
        162:  ("SNMP-Trap",     "Network"),
        389:  ("LDAP",          "Directory"),
        636:  ("LDAPS",         "Directory"),
        88:   ("Kerberos",      "Authentication"),
        514:  ("Syslog",        "Logging"),
        9200: ("Elasticsearch", "Database"),
        6443: ("Kubernetes-API","Cloud"),
    }

    # SNI domain pattern → (app_name, category)
    _SNI_MAP: List[Tuple[str, str, str]] = [
        ("netflix.com",          "Netflix",           "Streaming"),
        ("nflxvideo.net",        "Netflix",           "Streaming"),
        ("youtube.com",          "YouTube",           "Streaming"),
        ("googlevideo.com",      "YouTube",           "Streaming"),
        ("ytimg.com",            "YouTube",           "Streaming"),
        ("twitch.tv",            "Twitch",            "Streaming"),
        ("twitchsvc.net",        "Twitch",            "Streaming"),
        ("spotify.com",          "Spotify",           "Streaming"),
        ("scdn.co",              "Spotify",           "Streaming"),
        ("tiktok.com",           "TikTok",            "Social"),
        ("tiktokcdn.com",        "TikTok",            "Social"),
        ("facebook.com",         "Facebook",          "Social"),
        ("fbcdn.net",            "Facebook",          "Social"),
        ("instagram.com",        "Instagram",         "Social"),
        ("cdninstagram.com",     "Instagram",         "Social"),
        ("twitter.com",          "Twitter/X",         "Social"),
        ("x.com",                "Twitter/X",         "Social"),
        ("twimg.com",            "Twitter/X",         "Social"),
        ("reddit.com",           "Reddit",            "Social"),
        ("redd.it",              "Reddit",            "Social"),
        ("whatsapp.net",         "WhatsApp",          "Communication"),
        ("whatsapp.com",         "WhatsApp",          "Communication"),
        ("telegram.org",         "Telegram",          "Communication"),
        ("zoom.us",              "Zoom",              "Communication"),
        ("zoomgov.com",          "Zoom",              "Communication"),
        ("teams.microsoft.com",  "Microsoft Teams",   "Communication"),
        ("skype.com",            "Skype",             "Communication"),
        ("discord.com",          "Discord",           "Communication"),
        ("discordapp.com",       "Discord",           "Communication"),
        ("signal.org",           "Signal",            "Communication"),
        ("steampowered.com",     "Steam",             "Gaming"),
        ("steamcontent.com",     "Steam",             "Gaming"),
        ("epicgames.com",        "Epic Games",        "Gaming"),
        ("riotgames.com",        "Riot Games",        "Gaming"),
        ("battlenet.com",        "Battle.net",        "Gaming"),
        ("blizzard.com",         "Battle.net",        "Gaming"),
        ("ea.com",               "EA Games",          "Gaming"),
        ("amazonaws.com",        "AWS",               "Cloud"),
        ("awsstatic.com",        "AWS",               "Cloud"),
        ("googleapis.com",       "Google APIs",       "Cloud"),
        ("gstatic.com",          "Google",            "Cloud"),
        ("google.com",           "Google",            "Cloud"),
        ("windows.net",          "Azure",             "Cloud"),
        ("azure.com",            "Azure",             "Cloud"),
        ("microsoftonline.com",  "Microsoft 365",     "Cloud"),
        ("office.com",           "Microsoft 365",     "Cloud"),
        ("cloudflare.com",       "Cloudflare",        "Cloud"),
        ("cloudflare-dns.com",   "Cloudflare DNS",    "Network"),
        ("apple.com",            "Apple",             "Cloud"),
        ("icloud.com",           "iCloud",            "Cloud"),
        ("dropbox.com",          "Dropbox",           "Cloud"),
        ("box.com",              "Box",               "Cloud"),
        ("onedrive.com",         "OneDrive",          "Cloud"),
        ("github.com",           "GitHub",            "Development"),
        ("gitlab.com",           "GitLab",            "Development"),
        ("slack.com",            "Slack",             "Communication"),
        ("slack-edge.com",       "Slack",             "Communication"),
    ]

    # DNS IP → domain reverse cache (populated at runtime)
    _dns_cache: Dict[str, str] = {}

    def classify(
        self,
        src_port: int,
        dst_port: int,
        protocol: int,
        packet_data: bytes = b"",
        dst_ip: str = "",
    ) -> Dict[str, Any]:
        """Return best-effort classification for a flow."""
        result: Dict[str, Any] = {
            "app_name": "Unknown",
            "category": "Unknown",
            "confidence": 0.0,
        }

        # 1. Try SNI extraction from TLS ClientHello
        if dst_port in (443, 8443, 993, 995, 465) and packet_data:
            sni = extract_sni(packet_data)
            if sni:
                matched = self._match_sni(sni)
                if matched:
                    result.update(matched)
                    result["confidence"] = 0.95
                    result["sni"] = sni
                    return result
                result["app_name"] = "HTTPS"
                result["category"] = "Web"
                result["confidence"] = 0.7
                result["sni"] = sni
                return result

        # 2. Check DNS reverse cache
        if dst_ip and dst_ip in self._dns_cache:
            domain = self._dns_cache[dst_ip]
            matched = self._match_sni(domain)
            if matched:
                result.update(matched)
                result["confidence"] = 0.85
                return result

        # 3. Port-based fallback
        for port in (dst_port, src_port):
            if port in self._PORT_MAP:
                app_name, category = self._PORT_MAP[port]
                result["app_name"] = app_name
                result["category"] = category
                result["confidence"] = 0.6
                return result

        return result

    def _match_sni(self, sni: str) -> Optional[Dict[str, str]]:
        """Match SNI against known domain patterns."""
        sni_lower = sni.lower()
        for pattern, app_name, category in self._SNI_MAP:
            if sni_lower == pattern or sni_lower.endswith("." + pattern):
                return {"app_name": app_name, "category": category}
        return None

    def record_dns(self, ip: str, domain: str) -> None:
        """Cache a DNS resolution for later IP-based lookup."""
        if ip and domain:
            self._dns_cache[ip] = domain.rstrip(".")

    def extract_dns_from_packet(self, packet_data: bytes, src_ip: str) -> None:
        """Attempt to parse DNS response and populate reverse cache."""
        # Minimal DNS response parsing: skip UDP header (8 bytes) then parse
        try:
            if len(packet_data) < 12:
                return
            # DNS header: ID(2) FLAGS(2) QDCOUNT(2) ANCOUNT(2) NSCOUNT(2) ARCOUNT(2)
            flags = struct.unpack("!H", packet_data[2:4])[0]
            is_response = (flags & 0x8000) != 0
            if not is_response:
                return
            # We don't parse full DNS here — just note that src_ip is a DNS server
        except Exception:  # pylint: disable=broad-except
            pass


# ---------------------------------------------------------------------------
# DPI Engine
# ---------------------------------------------------------------------------


class DPIEngine:
    """Passive traffic classification engine using BPF capture."""

    def __init__(self, interface: str = "em0", bpf_filter: str = "") -> None:
        self.interface = interface
        self.bpf_filter = bpf_filter
        self._bpf_fd: int = -1
        self._ndpi = NDPIWrapper()
        self._heuristics = FlowHeuristics()
        self._flows: Dict[Tuple, Dict[str, Any]] = {}
        self._running = False

    def start(self) -> None:
        """Open a BPF device and attach it to the configured interface."""
        if self._running:
            log.warning("DPIEngine already running")
            return

        fd = self._open_bpf_device()
        if fd < 0:
            log.error("Failed to open BPF device — DPI capture unavailable")
            return

        try:
            # Attach interface
            ifreq = struct.pack("16s", self.interface.encode("ascii")[:15])
            fcntl.ioctl(fd, BIOCSETIF, ifreq)

            # Set immediate mode (deliver packets as they arrive)
            fcntl.ioctl(fd, BIOCIMMEDIATE, struct.pack("I", 1))

            # Enable promiscuous mode
            fcntl.ioctl(fd, BIOCPROMISC, b"")

            self._bpf_fd = fd
            self._running = True
            log.info("DPIEngine started on interface %s (BPF fd=%d)", self.interface, fd)
        except OSError as exc:
            os.close(fd)
            log.error("BPF attach failed on %s: %s", self.interface, exc)

    def stop(self) -> None:
        """Close the BPF device and release nDPI resources."""
        self._running = False
        if self._bpf_fd >= 0:
            try:
                os.close(self._bpf_fd)
            except OSError:
                pass
            self._bpf_fd = -1
        self._ndpi.cleanup()
        log.info("DPIEngine stopped")

    def _open_bpf_device(self) -> int:
        """Find and open an available /dev/bpfN device."""
        for n in range(16):
            path = f"/dev/bpf{n}"
            try:
                fd = os.open(path, os.O_RDWR | os.O_NONBLOCK)
                log.debug("Opened BPF device %s", path)
                return fd
            except OSError as exc:
                if exc.errno == errno.EBUSY:
                    continue
                if exc.errno == errno.ENOENT:
                    break
                log.debug("Cannot open %s: %s", path, exc)
        return -1

    def process_packet(self, raw_data: bytes) -> Optional[Dict[str, Any]]:
        """Parse a raw Ethernet frame and classify it.

        Returns a flow dict with DPI results, or None if the packet cannot
        be parsed (e.g. non-IPv4/IPv6, malformed header).
        """
        try:
            return self._parse_and_classify(raw_data)
        except Exception as exc:  # pylint: disable=broad-except
            log.debug("Packet parse error: %s", exc)
            return None

    def _parse_and_classify(self, raw_data: bytes) -> Optional[Dict[str, Any]]:
        if len(raw_data) < ETH_HEADER_LEN + 20:
            return None

        # Ethernet header
        eth_type = struct.unpack("!H", raw_data[12:14])[0]
        payload = raw_data[ETH_HEADER_LEN:]

        src_ip = dst_ip = ""
        src_port = dst_port = 0
        protocol = 0
        transport_payload = b""

        if eth_type == ETH_TYPE_IPV4:
            if len(payload) < 20:
                return None
            ihl = (payload[0] & 0x0F) * 4
            protocol = payload[9]
            src_ip = socket.inet_ntoa(payload[12:16])
            dst_ip = socket.inet_ntoa(payload[16:20])
            ip_payload = payload[ihl:]

            if protocol == PROTO_TCP and len(ip_payload) >= 20:
                src_port, dst_port = struct.unpack("!HH", ip_payload[0:4])
                data_offset = ((ip_payload[12] >> 4) & 0xF) * 4
                transport_payload = ip_payload[data_offset:]
            elif protocol == PROTO_UDP and len(ip_payload) >= 8:
                src_port, dst_port = struct.unpack("!HH", ip_payload[0:4])
                transport_payload = ip_payload[8:]

        elif eth_type == ETH_TYPE_IPV6:
            if len(payload) < 40:
                return None
            protocol = payload[6]
            src_ip = socket.inet_ntop(socket.AF_INET6, payload[8:24])
            dst_ip = socket.inet_ntop(socket.AF_INET6, payload[24:40])
            ip_payload = payload[40:]

            if protocol == PROTO_TCP and len(ip_payload) >= 20:
                src_port, dst_port = struct.unpack("!HH", ip_payload[0:4])
                data_offset = ((ip_payload[12] >> 4) & 0xF) * 4
                transport_payload = ip_payload[data_offset:]
            elif protocol == PROTO_UDP and len(ip_payload) >= 8:
                src_port, dst_port = struct.unpack("!HH", ip_payload[0:4])
                transport_payload = ip_payload[8:]
        else:
            return None

        # Build flow key (canonical: smaller IP first)
        if (src_ip, src_port) > (dst_ip, dst_port):
            flow_key = (dst_ip, src_ip, dst_port, src_port, protocol)
            is_reverse = True
        else:
            flow_key = (src_ip, dst_ip, src_port, dst_port, protocol)
            is_reverse = False

        pkt_len = len(raw_data)
        now_iso = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")

        # Update or create flow record
        flow = self._flows.get(flow_key)
        if flow is None:
            # Classify new flow
            if self._ndpi.available:
                classification = self._ndpi.classify_packet(
                    transport_payload, len(transport_payload),
                    src_ip, dst_ip, src_port, dst_port, protocol
                )
            else:
                proto_num = PROTO_TCP if protocol == PROTO_TCP else PROTO_UDP
                classification = self._heuristics.classify(
                    src_port, dst_port, proto_num, transport_payload, dst_ip
                )

            flow = {
                "src_ip":     flow_key[0],
                "dst_ip":     flow_key[1],
                "src_port":   flow_key[2],
                "dst_port":   flow_key[3],
                "protocol":   "TCP" if protocol == PROTO_TCP else "UDP" if protocol == PROTO_UDP else str(protocol),
                "bytes_sent": 0,
                "bytes_recv": 0,
                "packets":    0,
                "app_name":   classification.get("app_name", "Unknown"),
                "category":   classification.get("category", "Unknown"),
                "confidence": classification.get("confidence", 0.0),
                "sni":        classification.get("sni", ""),
                "first_seen": now_iso,
                "last_seen":  now_iso,
            }
            self._flows[flow_key] = flow
        else:
            flow["last_seen"] = now_iso

        if is_reverse:
            flow["bytes_recv"] += pkt_len
        else:
            flow["bytes_sent"] += pkt_len
        flow["packets"] += 1

        return dict(flow)

    def get_active_flows(self) -> List[Dict[str, Any]]:
        """Return a snapshot of all currently tracked flows."""
        return [dict(f) for f in self._flows.values()]

    def expire_old_flows(self, max_idle_seconds: int = 300) -> int:
        """Remove flows idle for longer than *max_idle_seconds*. Returns count removed."""
        cutoff = time.time() - max_idle_seconds
        expired_keys = []
        for key, flow in self._flows.items():
            try:
                ts = datetime.strptime(flow["last_seen"], "%Y-%m-%dT%H:%M:%SZ")
                if ts.timestamp() < cutoff:
                    expired_keys.append(key)
            except (ValueError, KeyError):
                expired_keys.append(key)
        for key in expired_keys:
            del self._flows[key]
        if expired_keys:
            log.debug("Expired %d idle flows", len(expired_keys))
        return len(expired_keys)
