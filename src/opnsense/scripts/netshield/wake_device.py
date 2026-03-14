#!/usr/local/bin/python3

# Copyright (c) 2025-2026, NetShield Contributors
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice,
#    this list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
# SPDX-License-Identifier: BSD-2-Clause

"""configd script: send a Wake-on-LAN magic packet.

Pure Python implementation — no external dependencies required.
Magic packet format: 6 bytes of 0xFF followed by 16 repetitions of the target MAC.
"""

import sys
import json
import socket
import argparse
import re


WOL_PORT = 9


def build_magic_packet(mac: str) -> bytes:
    """Build a WoL magic packet for the given MAC address.

    Args:
        mac: MAC address in any of the common formats:
             aa:bb:cc:dd:ee:ff, aa-bb-cc-dd-ee-ff, aabbccddeeff

    Returns:
        102-byte magic packet as bytes object.

    Raises:
        ValueError: if the MAC address is malformed.
    """
    # Normalize: strip separators and validate
    mac_clean = re.sub(r'[:\-\.]', '', mac).upper()
    if len(mac_clean) != 12 or not re.fullmatch(r'[0-9A-F]{12}', mac_clean):
        raise ValueError(f'Invalid MAC address: {mac!r}')

    mac_bytes = bytes.fromhex(mac_clean)
    # 6 bytes of 0xFF + 16 repetitions of the 6-byte MAC
    return b'\xff' * 6 + mac_bytes * 16


def send_wol(mac: str, broadcast: str = '255.255.255.255') -> dict:
    """Send a Wake-on-LAN magic packet via UDP broadcast.

    Args:
        mac: Target device MAC address.
        broadcast: Broadcast IP address (default: 255.255.255.255).

    Returns:
        Result dict with 'result' key ('ok' or 'error') and optional 'message'.
    """
    try:
        packet = build_magic_packet(mac)
    except ValueError as exc:
        return {'result': 'error', 'message': str(exc)}

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            sock.settimeout(5)
            sock.sendto(packet, (broadcast, WOL_PORT))
    except OSError as exc:
        return {'result': 'error', 'message': f'Socket error: {exc}'}

    return {
        'result': 'ok',
        'mac': mac,
        'broadcast': broadcast,
        'packet_size': len(packet),
    }


def main():
    # configd passes all parameters as a single comma-delimited token
    if len(sys.argv) == 2:
        arg = sys.argv[1]
        parts = arg.replace(',', ' ').split()
        sys.argv = [sys.argv[0]] + [p.strip("'\"") for p in parts]
    parser = argparse.ArgumentParser(description='Send Wake-on-LAN magic packet')
    parser.add_argument('mac', help='Target device MAC address (e.g. aa:bb:cc:dd:ee:ff)')
    parser.add_argument('broadcast', nargs='?', default='255.255.255.255',
                        help='Broadcast IP address (default: 255.255.255.255)')
    args = parser.parse_args()

    result = send_wol(args.mac, args.broadcast)
    print(json.dumps(result, indent=2))
    sys.exit(0 if result['result'] == 'ok' else 1)


if __name__ == '__main__':
    main()
