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

NetShield geoip.py — GeoIP blocking using MaxMind MMDB files.

Pure-Python MMDB reader: implements the MaxMind DB binary format spec
(https://maxmind.github.io/MaxMind-DB/) sufficient for country lookups.
No external dependencies required.
"""

import ipaddress
import logging
import os
import struct
import subprocess
import tempfile
from typing import Dict, List, Optional, Tuple

log = logging.getLogger(__name__)

# Common GeoLite2 database paths on FreeBSD
MMDB_PATHS: List[str] = [
    "/usr/local/share/GeoIP/GeoLite2-Country.mmdb",
    "/var/db/GeoIP/GeoLite2-Country.mmdb",
    "/usr/share/GeoIP/GeoLite2-Country.mmdb",
    "/usr/local/etc/GeoIP/GeoLite2-Country.mmdb",
    "/var/lib/GeoIP/GeoLite2-Country.mmdb",
]

PF_TABLE_NAME = "netshield_geoip"

# ---------------------------------------------------------------------------
# Pure-Python MMDB reader
# ---------------------------------------------------------------------------
# This is a minimal implementation covering IPv4/IPv6 country lookups.
# It supports MMDB format version 2.x.

_DATA_TYPE_EXTENDED = 0
_DATA_TYPE_POINTER  = 1
_DATA_TYPE_STRING   = 2
_DATA_TYPE_DOUBLE   = 3
_DATA_TYPE_BYTES    = 4
_DATA_TYPE_UINT16   = 5
_DATA_TYPE_UINT32   = 6
_DATA_TYPE_MAP      = 7
_DATA_TYPE_INT32    = 8
_DATA_TYPE_UINT64   = 9
_DATA_TYPE_UINT128  = 10
_DATA_TYPE_ARRAY    = 11
_DATA_TYPE_DATACACHE_CONTAINER = 12
_DATA_TYPE_END_MARKER = 13
_DATA_TYPE_BOOLEAN  = 14
_DATA_TYPE_FLOAT    = 15

_METADATA_MARKER = b"\xab\xcd\xefMaxMind.com"


class _MMDBReader:
    """
    Minimal MaxMind DB reader for country lookups.
    Supports MMDB format version 2.x, IPv4 and IPv6.
    """

    def __init__(self, path: str) -> None:
        with open(path, "rb") as fh:
            self._buf = fh.read()
        self._parse_metadata()

    def _parse_metadata(self) -> None:
        idx = self._buf.rfind(_METADATA_MARKER)
        if idx == -1:
            raise ValueError("MMDB metadata marker not found")
        meta_start = idx + len(_METADATA_MARKER)
        meta_map = self._decode(meta_start)[0]
        self._node_count = meta_map["node_count"]
        self._record_size = meta_map["record_size"]
        self._ip_version = meta_map["ip_version"]
        self._node_byte_size = (self._record_size * 2) // 8
        self._search_tree_size = self._node_count * self._node_byte_size
        self._data_section_start = self._search_tree_size + 16  # 16-byte separator

    def _get_node(self, node_num: int, bit: int) -> int:
        rs = self._record_size
        offset = node_num * self._node_byte_size

        if rs == 24:
            b = self._buf[offset: offset + 6]
            if bit == 0:
                return (b[0] << 16) | (b[1] << 8) | b[2]
            else:
                return (b[3] << 16) | (b[4] << 8) | b[5]
        elif rs == 28:
            b = self._buf[offset: offset + 7]
            if bit == 0:
                return ((b[3] & 0xF0) << 20) | (b[0] << 16) | (b[1] << 8) | b[2]
            else:
                return ((b[3] & 0x0F) << 24) | (b[4] << 16) | (b[5] << 8) | b[6]
        elif rs == 32:
            b = self._buf[offset: offset + 8]
            if bit == 0:
                return struct.unpack(">I", b[0:4])[0]
            else:
                return struct.unpack(">I", b[4:8])[0]
        else:
            raise ValueError(f"Unsupported record size: {rs}")

    def _search(self, ip_int: int, bit_count: int) -> Optional[int]:
        node = 0
        if self._ip_version == 6 and bit_count == 32:
            # IPv4 mapped into IPv6 tree — follow IPv4 subtree
            for _ in range(96):
                node = self._get_node(node, 0)
                if node >= self._node_count:
                    return None
        for i in range(bit_count - 1, -1, -1):
            bit = (ip_int >> i) & 1
            node = self._get_node(node, bit)
            if node >= self._node_count:
                if node == self._node_count:
                    return None  # Empty record
                return node
        return None

    def _decode(self, offset: int) -> Tuple[object, int]:
        """Decode a data field. Returns (value, new_offset)."""
        ctrl_byte = self._buf[offset]
        offset += 1
        dtype = ctrl_byte >> 5
        size = ctrl_byte & 0x1F

        if dtype == _DATA_TYPE_EXTENDED:
            dtype = self._buf[offset] + 7
            offset += 1

        if dtype == _DATA_TYPE_POINTER:
            ptr_size = ((ctrl_byte >> 3) & 0x3) + 1
            b = self._buf[offset: offset + ptr_size]
            offset += ptr_size
            if ptr_size == 1:
                ptr = ((size & 0x7) << 8) | b[0]
            elif ptr_size == 2:
                ptr = ((size & 0x7) << 16) | (b[0] << 8) | b[1]
            elif ptr_size == 3:
                ptr = ((size & 0x7) << 24) | (b[0] << 16) | (b[1] << 8) | b[2]
            else:
                ptr = (b[0] << 24) | (b[1] << 16) | (b[2] << 8) | b[3]
                ptr += 526336
            if ptr_size < 4:
                if ptr_size == 1:
                    ptr += 0
                elif ptr_size == 2:
                    ptr += 2048
                elif ptr_size == 3:
                    ptr += 526336
            val, _ = self._decode(self._data_section_start + ptr)
            return val, offset

        if size >= 29:
            extra_bytes = size - 28
            extra = self._buf[offset: offset + extra_bytes]
            offset += extra_bytes
            if size == 29:
                size = 29 + extra[0]
            elif size == 30:
                size = 285 + (extra[0] << 8) | extra[1]
            elif size == 31:
                size = 65821 + (extra[0] << 16) | (extra[1] << 8) | extra[2]

        if dtype == _DATA_TYPE_STRING:
            val = self._buf[offset: offset + size].decode("utf-8", errors="replace")
            return val, offset + size

        if dtype == _DATA_TYPE_MAP:
            d: Dict = {}
            for _ in range(size):
                key, offset = self._decode(offset)
                val, offset = self._decode(offset)
                d[key] = val
            return d, offset

        if dtype == _DATA_TYPE_ARRAY:
            arr = []
            for _ in range(size):
                val, offset = self._decode(offset)
                arr.append(val)
            return arr, offset

        if dtype == _DATA_TYPE_UINT16:
            b = self._buf[offset: offset + size]
            val = int.from_bytes(b, "big")
            return val, offset + size

        if dtype == _DATA_TYPE_UINT32:
            b = self._buf[offset: offset + size]
            return int.from_bytes(b, "big"), offset + size

        if dtype == _DATA_TYPE_UINT64:
            b = self._buf[offset: offset + size]
            return int.from_bytes(b, "big"), offset + size

        if dtype == _DATA_TYPE_UINT128:
            b = self._buf[offset: offset + size]
            return int.from_bytes(b, "big"), offset + size

        if dtype == _DATA_TYPE_INT32:
            b = self._buf[offset: offset + size]
            val = int.from_bytes(b, "big", signed=True)
            return val, offset + size

        if dtype == _DATA_TYPE_DOUBLE:
            val = struct.unpack(">d", self._buf[offset: offset + 8])[0]
            return val, offset + 8

        if dtype == _DATA_TYPE_FLOAT:
            val = struct.unpack(">f", self._buf[offset: offset + 4])[0]
            return val, offset + 4

        if dtype == _DATA_TYPE_BOOLEAN:
            return bool(size), offset

        if dtype == _DATA_TYPE_BYTES:
            return self._buf[offset: offset + size], offset + size

        if dtype == _DATA_TYPE_END_MARKER:
            return None, offset

        log.debug("MMDB: unknown dtype %d", dtype)
        return None, offset + size

    def lookup(self, ip_str: str) -> Optional[Dict]:
        """
        Look up an IP address and return the data record dict, or None.
        """
        try:
            addr = ipaddress.ip_address(ip_str)
        except ValueError:
            return None

        if isinstance(addr, ipaddress.IPv4Address):
            ip_int = int(addr)
            bit_count = 32
        else:
            ip_int = int(addr)
            bit_count = 128

        record_offset = self._search(ip_int, bit_count)
        if record_offset is None:
            return None

        data_offset = record_offset - self._node_count + self._data_section_start
        if data_offset < self._data_section_start or data_offset >= len(self._buf):
            return None

        try:
            record, _ = self._decode(data_offset)
            return record if isinstance(record, dict) else None
        except Exception as exc:
            log.debug("MMDB decode error for %s: %s", ip_str, exc)
            return None


# ---------------------------------------------------------------------------
# Module-level reader cache
# ---------------------------------------------------------------------------

_reader: Optional[_MMDBReader] = None
_reader_path: Optional[str] = None


def _get_reader() -> Optional[_MMDBReader]:
    global _reader, _reader_path
    if _reader is not None:
        return _reader
    for path in MMDB_PATHS:
        if os.path.isfile(path):
            try:
                _reader = _MMDBReader(path)
                _reader_path = path
                log.info("Loaded GeoIP database from %s", path)
                return _reader
            except Exception as exc:
                log.warning("Failed to load MMDB %s: %s", path, exc)
    log.warning("No GeoIP MMDB file found. Tried: %s", MMDB_PATHS)
    return None


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def lookup_ip(ip: str) -> Tuple[str, str]:
    """
    Look up the country for an IP address.
    Returns (country_iso_code, country_name) or ("", "") if not found.
    """
    reader = _get_reader()
    if reader is None:
        return ("", "")
    try:
        record = reader.lookup(ip)
        if record is None:
            return ("", "")
        country = record.get("country", {})
        if not country:
            # Some MMDB builds use registered_country
            country = record.get("registered_country", {})
        iso = country.get("iso_code", "")
        names = country.get("names", {})
        name = names.get("en", iso)
        return (iso, name)
    except Exception as exc:
        log.debug("lookup_ip %s error: %s", ip, exc)
        return ("", "")


def get_country_list() -> List[Dict[str, str]]:
    """
    Return a static list of ISO 3166-1 alpha-2 country codes and names.
    Used for UI display — does not depend on MMDB.
    """
    return [
        {"code": "AD", "name": "Andorra"},
        {"code": "AE", "name": "United Arab Emirates"},
        {"code": "AF", "name": "Afghanistan"},
        {"code": "AG", "name": "Antigua and Barbuda"},
        {"code": "AL", "name": "Albania"},
        {"code": "AM", "name": "Armenia"},
        {"code": "AO", "name": "Angola"},
        {"code": "AR", "name": "Argentina"},
        {"code": "AT", "name": "Austria"},
        {"code": "AU", "name": "Australia"},
        {"code": "AZ", "name": "Azerbaijan"},
        {"code": "BA", "name": "Bosnia and Herzegovina"},
        {"code": "BB", "name": "Barbados"},
        {"code": "BD", "name": "Bangladesh"},
        {"code": "BE", "name": "Belgium"},
        {"code": "BF", "name": "Burkina Faso"},
        {"code": "BG", "name": "Bulgaria"},
        {"code": "BH", "name": "Bahrain"},
        {"code": "BI", "name": "Burundi"},
        {"code": "BJ", "name": "Benin"},
        {"code": "BN", "name": "Brunei"},
        {"code": "BO", "name": "Bolivia"},
        {"code": "BR", "name": "Brazil"},
        {"code": "BS", "name": "Bahamas"},
        {"code": "BT", "name": "Bhutan"},
        {"code": "BW", "name": "Botswana"},
        {"code": "BY", "name": "Belarus"},
        {"code": "BZ", "name": "Belize"},
        {"code": "CA", "name": "Canada"},
        {"code": "CD", "name": "Democratic Republic of the Congo"},
        {"code": "CF", "name": "Central African Republic"},
        {"code": "CG", "name": "Republic of the Congo"},
        {"code": "CH", "name": "Switzerland"},
        {"code": "CI", "name": "Ivory Coast"},
        {"code": "CL", "name": "Chile"},
        {"code": "CM", "name": "Cameroon"},
        {"code": "CN", "name": "China"},
        {"code": "CO", "name": "Colombia"},
        {"code": "CR", "name": "Costa Rica"},
        {"code": "CU", "name": "Cuba"},
        {"code": "CV", "name": "Cape Verde"},
        {"code": "CY", "name": "Cyprus"},
        {"code": "CZ", "name": "Czech Republic"},
        {"code": "DE", "name": "Germany"},
        {"code": "DJ", "name": "Djibouti"},
        {"code": "DK", "name": "Denmark"},
        {"code": "DM", "name": "Dominica"},
        {"code": "DO", "name": "Dominican Republic"},
        {"code": "DZ", "name": "Algeria"},
        {"code": "EC", "name": "Ecuador"},
        {"code": "EE", "name": "Estonia"},
        {"code": "EG", "name": "Egypt"},
        {"code": "ER", "name": "Eritrea"},
        {"code": "ES", "name": "Spain"},
        {"code": "ET", "name": "Ethiopia"},
        {"code": "FI", "name": "Finland"},
        {"code": "FJ", "name": "Fiji"},
        {"code": "FM", "name": "Micronesia"},
        {"code": "FR", "name": "France"},
        {"code": "GA", "name": "Gabon"},
        {"code": "GB", "name": "United Kingdom"},
        {"code": "GD", "name": "Grenada"},
        {"code": "GE", "name": "Georgia"},
        {"code": "GH", "name": "Ghana"},
        {"code": "GM", "name": "Gambia"},
        {"code": "GN", "name": "Guinea"},
        {"code": "GQ", "name": "Equatorial Guinea"},
        {"code": "GR", "name": "Greece"},
        {"code": "GT", "name": "Guatemala"},
        {"code": "GW", "name": "Guinea-Bissau"},
        {"code": "GY", "name": "Guyana"},
        {"code": "HN", "name": "Honduras"},
        {"code": "HR", "name": "Croatia"},
        {"code": "HT", "name": "Haiti"},
        {"code": "HU", "name": "Hungary"},
        {"code": "ID", "name": "Indonesia"},
        {"code": "IE", "name": "Ireland"},
        {"code": "IL", "name": "Israel"},
        {"code": "IN", "name": "India"},
        {"code": "IQ", "name": "Iraq"},
        {"code": "IR", "name": "Iran"},
        {"code": "IS", "name": "Iceland"},
        {"code": "IT", "name": "Italy"},
        {"code": "JM", "name": "Jamaica"},
        {"code": "JO", "name": "Jordan"},
        {"code": "JP", "name": "Japan"},
        {"code": "KE", "name": "Kenya"},
        {"code": "KG", "name": "Kyrgyzstan"},
        {"code": "KH", "name": "Cambodia"},
        {"code": "KI", "name": "Kiribati"},
        {"code": "KM", "name": "Comoros"},
        {"code": "KN", "name": "Saint Kitts and Nevis"},
        {"code": "KP", "name": "North Korea"},
        {"code": "KR", "name": "South Korea"},
        {"code": "KW", "name": "Kuwait"},
        {"code": "KZ", "name": "Kazakhstan"},
        {"code": "LA", "name": "Laos"},
        {"code": "LB", "name": "Lebanon"},
        {"code": "LC", "name": "Saint Lucia"},
        {"code": "LI", "name": "Liechtenstein"},
        {"code": "LK", "name": "Sri Lanka"},
        {"code": "LR", "name": "Liberia"},
        {"code": "LS", "name": "Lesotho"},
        {"code": "LT", "name": "Lithuania"},
        {"code": "LU", "name": "Luxembourg"},
        {"code": "LV", "name": "Latvia"},
        {"code": "LY", "name": "Libya"},
        {"code": "MA", "name": "Morocco"},
        {"code": "MC", "name": "Monaco"},
        {"code": "MD", "name": "Moldova"},
        {"code": "ME", "name": "Montenegro"},
        {"code": "MG", "name": "Madagascar"},
        {"code": "MH", "name": "Marshall Islands"},
        {"code": "MK", "name": "North Macedonia"},
        {"code": "ML", "name": "Mali"},
        {"code": "MM", "name": "Myanmar"},
        {"code": "MN", "name": "Mongolia"},
        {"code": "MR", "name": "Mauritania"},
        {"code": "MT", "name": "Malta"},
        {"code": "MU", "name": "Mauritius"},
        {"code": "MV", "name": "Maldives"},
        {"code": "MW", "name": "Malawi"},
        {"code": "MX", "name": "Mexico"},
        {"code": "MY", "name": "Malaysia"},
        {"code": "MZ", "name": "Mozambique"},
        {"code": "NA", "name": "Namibia"},
        {"code": "NE", "name": "Niger"},
        {"code": "NG", "name": "Nigeria"},
        {"code": "NI", "name": "Nicaragua"},
        {"code": "NL", "name": "Netherlands"},
        {"code": "NO", "name": "Norway"},
        {"code": "NP", "name": "Nepal"},
        {"code": "NR", "name": "Nauru"},
        {"code": "NZ", "name": "New Zealand"},
        {"code": "OM", "name": "Oman"},
        {"code": "PA", "name": "Panama"},
        {"code": "PE", "name": "Peru"},
        {"code": "PG", "name": "Papua New Guinea"},
        {"code": "PH", "name": "Philippines"},
        {"code": "PK", "name": "Pakistan"},
        {"code": "PL", "name": "Poland"},
        {"code": "PT", "name": "Portugal"},
        {"code": "PW", "name": "Palau"},
        {"code": "PY", "name": "Paraguay"},
        {"code": "QA", "name": "Qatar"},
        {"code": "RO", "name": "Romania"},
        {"code": "RS", "name": "Serbia"},
        {"code": "RU", "name": "Russia"},
        {"code": "RW", "name": "Rwanda"},
        {"code": "SA", "name": "Saudi Arabia"},
        {"code": "SB", "name": "Solomon Islands"},
        {"code": "SC", "name": "Seychelles"},
        {"code": "SD", "name": "Sudan"},
        {"code": "SE", "name": "Sweden"},
        {"code": "SG", "name": "Singapore"},
        {"code": "SI", "name": "Slovenia"},
        {"code": "SK", "name": "Slovakia"},
        {"code": "SL", "name": "Sierra Leone"},
        {"code": "SM", "name": "San Marino"},
        {"code": "SN", "name": "Senegal"},
        {"code": "SO", "name": "Somalia"},
        {"code": "SR", "name": "Suriname"},
        {"code": "SS", "name": "South Sudan"},
        {"code": "ST", "name": "Sao Tome and Principe"},
        {"code": "SV", "name": "El Salvador"},
        {"code": "SY", "name": "Syria"},
        {"code": "SZ", "name": "Eswatini"},
        {"code": "TD", "name": "Chad"},
        {"code": "TG", "name": "Togo"},
        {"code": "TH", "name": "Thailand"},
        {"code": "TJ", "name": "Tajikistan"},
        {"code": "TL", "name": "Timor-Leste"},
        {"code": "TM", "name": "Turkmenistan"},
        {"code": "TN", "name": "Tunisia"},
        {"code": "TO", "name": "Tonga"},
        {"code": "TR", "name": "Turkey"},
        {"code": "TT", "name": "Trinidad and Tobago"},
        {"code": "TV", "name": "Tuvalu"},
        {"code": "TZ", "name": "Tanzania"},
        {"code": "UA", "name": "Ukraine"},
        {"code": "UG", "name": "Uganda"},
        {"code": "US", "name": "United States"},
        {"code": "UY", "name": "Uruguay"},
        {"code": "UZ", "name": "Uzbekistan"},
        {"code": "VA", "name": "Vatican City"},
        {"code": "VC", "name": "Saint Vincent and the Grenadines"},
        {"code": "VE", "name": "Venezuela"},
        {"code": "VN", "name": "Vietnam"},
        {"code": "VU", "name": "Vanuatu"},
        {"code": "WS", "name": "Samoa"},
        {"code": "YE", "name": "Yemen"},
        {"code": "ZA", "name": "South Africa"},
        {"code": "ZM", "name": "Zambia"},
        {"code": "ZW", "name": "Zimbabwe"},
    ]


def generate_pf_table(blocked_countries: List[str]) -> str:
    """
    Generate pf table entries by reading the MMDB and iterating over
    well-known IP ranges.

    In practice, full GeoIP blocking via pf tables requires a pre-built
    per-country IP list (pfSense/OPNsense typically ships these as .txt files
    alongside the MMDB).  This function checks for pre-built files first,
    then falls back to a placeholder comment.

    Pre-built files expected at: /usr/local/share/GeoIP/GeoLite2-Country-<CC>.txt
    Each file contains one CIDR per line.

    Returns pf table content as a string.
    """
    if not blocked_countries:
        return ""

    lines: List[str] = []
    cidr_dir = "/usr/local/share/GeoIP"

    for cc in blocked_countries:
        cc = cc.upper().strip()
        if len(cc) != 2:
            continue
        cidr_file = os.path.join(cidr_dir, f"GeoLite2-Country-{cc}.txt")
        if os.path.isfile(cidr_file):
            try:
                with open(cidr_file, "r", encoding="utf-8") as fh:
                    for line in fh:
                        cidr = line.strip()
                        if cidr and not cidr.startswith("#"):
                            try:
                                ipaddress.ip_network(cidr, strict=False)
                                lines.append(cidr)
                            except ValueError:
                                pass
            except OSError as exc:
                log.warning("Cannot read GeoIP CIDR file %s: %s", cidr_file, exc)
        else:
            log.debug("No pre-built CIDR file for country %s at %s", cc, cidr_file)

    return "\n".join(lines) + ("\n" if lines else "")


def apply_geoip_rules(
    blocked_countries: List[str],
    table_name: str = PF_TABLE_NAME,
    anchor: str = "netshield",
) -> bool:
    """
    Build pf table from country CIDR lists and activate block rules.
    Returns True on success.
    """
    table_content = generate_pf_table(blocked_countries)
    if not table_content.strip():
        log.info("apply_geoip_rules: no CIDR data found for %s", blocked_countries)
        return True

    # Write table file
    table_file = f"/tmp/netshield_geoip_{table_name}.txt"
    try:
        with open(table_file, "w", encoding="utf-8") as fh:
            fh.write(table_content)
    except OSError as exc:
        log.error("Cannot write GeoIP table file: %s", exc)
        return False

    try:
        # Flush and reload the table
        subprocess.run(
            ["/sbin/pfctl", "-a", anchor, "-t", table_name, "-T", "flush"],
            capture_output=True, timeout=10,
        )
        result = subprocess.run(
            ["/sbin/pfctl", "-a", anchor, "-t", table_name, "-T", "add", "-f", table_file],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.returncode != 0:
            log.error("pfctl table load failed: %s", result.stderr.strip())
            return False
        log.info(
            "GeoIP table '%s' loaded for countries: %s",
            table_name, blocked_countries,
        )
        return True
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError) as exc:
        log.error("apply_geoip_rules pfctl error: %s", exc)
        return False
