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
TLS Inspector — Extract Server Name Indication from TLS ClientHello.
Passive inspection only — does not decrypt traffic.
"""

import hashlib
import logging
import struct
from typing import List, Optional, Tuple

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# TLS record / handshake constants
# ---------------------------------------------------------------------------

TLS_CONTENT_HANDSHAKE = 0x16
TLS_HANDSHAKE_CLIENT_HELLO = 0x01

# TLS extension type codes
EXT_SNI = 0x0000
EXT_SUPPORTED_GROUPS = 0x000A          # elliptic_curves
EXT_EC_POINT_FORMATS = 0x000B
EXT_SESSION_TICKET = 0x0023
EXT_ENCRYPT_THEN_MAC = 0x0016
EXT_EXTENDED_MASTER_SECRET = 0x0017
EXT_SIGNATURE_ALGORITHMS = 0x000D

# GREASE values to skip in JA3 (RFC 8701)
_GREASE_TABLE = {
    0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A, 0x4A4A, 0x5A5A,
    0x6A6A, 0x7A7A, 0x8A8A, 0x9A9A, 0xAAAA, 0xBABA,
    0xCACA, 0xDADA, 0xEAEA, 0xFAFA,
}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def extract_sni(packet_data: bytes) -> Optional[str]:
    """Extract the SNI hostname from a TLS ClientHello in *packet_data*.

    *packet_data* should be the TCP payload (i.e. starting at the TLS record
    layer).  Returns the hostname string on success, or None if the packet is
    not a ClientHello or the SNI extension is absent.
    """
    try:
        return _parse_client_hello_sni(packet_data)
    except Exception as exc:  # pylint: disable=broad-except
        log.debug("SNI extraction failed: %s", exc)
        return None


def extract_ja3(packet_data: bytes) -> Optional[str]:
    """Compute the JA3 fingerprint of a TLS ClientHello.

    JA3 = MD5(SSLVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats)

    Returns the hex MD5 string, or None if the packet is not a valid
    ClientHello.
    """
    try:
        return _compute_ja3(packet_data)
    except Exception as exc:  # pylint: disable=broad-except
        log.debug("JA3 extraction failed: %s", exc)
        return None


# ---------------------------------------------------------------------------
# Internal parsers
# ---------------------------------------------------------------------------


def _parse_client_hello_sni(data: bytes) -> Optional[str]:
    """Walk the TLS record and handshake headers to reach the extensions."""
    offset = 0
    length = len(data)

    # ---- TLS Record Layer ----
    # content_type (1) + legacy_version (2) + record_length (2) = 5 bytes
    if length < offset + 5:
        return None

    content_type = data[offset]
    if content_type != TLS_CONTENT_HANDSHAKE:
        return None

    # legacy_version — accept any (TLS 1.0-1.3 and SSLv3)
    # record_length
    record_len = struct.unpack_from("!H", data, offset + 3)[0]
    offset += 5

    if length < offset + record_len:
        return None

    # ---- Handshake Layer ----
    # msg_type (1) + length (3) = 4 bytes
    if length < offset + 4:
        return None

    msg_type = data[offset]
    if msg_type != TLS_HANDSHAKE_CLIENT_HELLO:
        return None

    hs_len = struct.unpack_from("!I", bytes([0]) + data[offset + 1: offset + 4])[0]
    offset += 4

    if length < offset + hs_len:
        return None

    hs_end = offset + hs_len

    # ---- ClientHello Body ----
    # client_version (2)
    if offset + 2 > hs_end:
        return None
    offset += 2

    # random (32)
    if offset + 32 > hs_end:
        return None
    offset += 32

    # session_id length (1) + session_id
    if offset + 1 > hs_end:
        return None
    session_id_len = data[offset]
    offset += 1 + session_id_len

    # cipher_suites length (2) + cipher_suites
    if offset + 2 > hs_end:
        return None
    cipher_suites_len = struct.unpack_from("!H", data, offset)[0]
    offset += 2 + cipher_suites_len

    # compression_methods length (1) + compression_methods
    if offset + 1 > hs_end:
        return None
    compression_len = data[offset]
    offset += 1 + compression_len

    # extensions length (2)
    if offset + 2 > hs_end:
        return None
    extensions_len = struct.unpack_from("!H", data, offset)[0]
    offset += 2

    ext_end = offset + extensions_len
    if ext_end > hs_end:
        return None

    # ---- Parse extensions to find SNI ----
    extensions = _parse_tls_extensions(data, offset, ext_end)
    for ext_type, ext_data in extensions:
        if ext_type == EXT_SNI:
            sni = _parse_sni_extension(ext_data)
            if sni:
                return sni

    return None


def _parse_tls_extensions(
    data: bytes, offset: int, end: int
) -> List[Tuple[int, bytes]]:
    """Parse TLS extensions from *data[offset:end]*.

    Returns a list of (extension_type, extension_data) tuples.
    """
    extensions: List[Tuple[int, bytes]] = []
    while offset + 4 <= end:
        ext_type = struct.unpack_from("!H", data, offset)[0]
        ext_len = struct.unpack_from("!H", data, offset + 2)[0]
        offset += 4
        if offset + ext_len > end:
            break
        ext_data = data[offset: offset + ext_len]
        extensions.append((ext_type, ext_data))
        offset += ext_len
    return extensions


def _parse_sni_extension(ext_data: bytes) -> Optional[str]:
    """Extract the hostname from an SNI extension value.

    SNI extension value layout:
      server_name_list_length (2)
      for each entry:
        name_type (1) — 0x00 = host_name
        name_length (2)
        name (name_length bytes)
    """
    if len(ext_data) < 5:
        return None

    list_len = struct.unpack_from("!H", ext_data, 0)[0]
    offset = 2
    end = 2 + list_len

    while offset + 3 <= end:
        name_type = ext_data[offset]
        name_len = struct.unpack_from("!H", ext_data, offset + 1)[0]
        offset += 3
        if offset + name_len > end:
            break
        if name_type == 0x00:  # host_name
            try:
                return ext_data[offset: offset + name_len].decode("ascii")
            except UnicodeDecodeError:
                return None
        offset += name_len

    return None


def _compute_ja3(data: bytes) -> Optional[str]:
    """Build a JA3 fingerprint string from a TLS ClientHello."""
    offset = 0
    length = len(data)

    # TLS Record header
    if length < 5:
        return None
    if data[offset] != TLS_CONTENT_HANDSHAKE:
        return None
    record_len = struct.unpack_from("!H", data, offset + 3)[0]
    offset += 5
    if length < offset + record_len:
        return None

    # Handshake header
    if length < offset + 4:
        return None
    if data[offset] != TLS_HANDSHAKE_CLIENT_HELLO:
        return None
    hs_len = struct.unpack_from("!I", bytes([0]) + data[offset + 1: offset + 4])[0]
    offset += 4
    hs_end = offset + hs_len
    if length < hs_end:
        return None

    # client_version
    if offset + 2 > hs_end:
        return None
    tls_version = struct.unpack_from("!H", data, offset)[0]
    offset += 2

    # random
    if offset + 32 > hs_end:
        return None
    offset += 32

    # session_id
    if offset + 1 > hs_end:
        return None
    session_id_len = data[offset]
    offset += 1 + session_id_len

    # cipher_suites
    if offset + 2 > hs_end:
        return None
    cipher_suites_len = struct.unpack_from("!H", data, offset)[0]
    offset += 2
    cipher_suite_end = offset + cipher_suites_len
    ciphers: List[int] = []
    cs_off = offset
    while cs_off + 2 <= cipher_suite_end:
        cs = struct.unpack_from("!H", data, cs_off)[0]
        if cs not in _GREASE_TABLE:
            ciphers.append(cs)
        cs_off += 2
    offset = cipher_suite_end

    # compression_methods
    if offset + 1 > hs_end:
        return None
    comp_len = data[offset]
    offset += 1 + comp_len

    # extensions
    if offset + 2 > hs_end:
        # No extensions — JA3 with empty extension fields
        ja3_str = (
            f"{tls_version},{'-'.join(str(c) for c in ciphers)},,,"
        )
        return hashlib.md5(ja3_str.encode()).hexdigest()

    ext_len = struct.unpack_from("!H", data, offset)[0]
    offset += 2
    ext_end = offset + ext_len
    if ext_end > hs_end:
        return None

    extensions = _parse_tls_extensions(data, offset, ext_end)

    ext_types: List[int] = []
    elliptic_curves: List[int] = []
    ec_point_formats: List[int] = []

    for ext_type, ext_data in extensions:
        if ext_type in _GREASE_TABLE:
            continue
        ext_types.append(ext_type)

        if ext_type == EXT_SUPPORTED_GROUPS:
            # supported_groups_list_length (2) + list of uint16
            if len(ext_data) >= 2:
                sg_len = struct.unpack_from("!H", ext_data, 0)[0]
                sg_off = 2
                sg_end = 2 + sg_len
                while sg_off + 2 <= sg_end and sg_off + 2 <= len(ext_data):
                    curve = struct.unpack_from("!H", ext_data, sg_off)[0]
                    if curve not in _GREASE_TABLE:
                        elliptic_curves.append(curve)
                    sg_off += 2

        elif ext_type == EXT_EC_POINT_FORMATS:
            # ec_point_format_list_length (1) + list of uint8
            if len(ext_data) >= 1:
                epf_len = ext_data[0]
                for i in range(1, 1 + epf_len):
                    if i < len(ext_data):
                        ec_point_formats.append(ext_data[i])

    # JA3 format: SSLVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats
    ja3_str = "-".join([
        str(tls_version),
        "-".join(str(c) for c in ciphers),
        "-".join(str(e) for e in ext_types),
        "-".join(str(g) for g in elliptic_curves),
        "-".join(str(p) for p in ec_point_formats),
    ])

    return hashlib.md5(ja3_str.encode()).hexdigest()
