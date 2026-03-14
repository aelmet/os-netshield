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

"""configd script: run vulnerability scans or retrieve results."""

import sys
import os
import json
import argparse

sys.path.insert(0, os.path.dirname(__file__))

from lib.db import Database
from lib.vuln_scanner import VulnScanner
from urllib.parse import unquote


def main():
    # configd passes all parameters as a single comma-delimited token
    if len(sys.argv) == 2:
        arg = sys.argv[1]
        parts = arg.replace(',', ' ').split()
        sys.argv = [sys.argv[0]] + [unquote(p.strip("'\"")) for p in parts]
    parser = argparse.ArgumentParser(description='NetShield vulnerability scanner')
    sub = parser.add_subparsers(dest='cmd')

    # target <ip> [ports]
    p_target = sub.add_parser('target', help='Scan a single device by IP')
    p_target.add_argument('ip', help='Target IP address')
    p_target.add_argument('ports', nargs='?', default='1-1024',
                          help='Port range (default: 1-1024)')

    # network <subnet>
    p_network = sub.add_parser('network', help='Scan an entire subnet')
    p_network.add_argument('subnet', help='Subnet in CIDR notation')

    # results [limit]
    p_results = sub.add_parser('results', help='Get recent scan results')
    p_results.add_argument('limit', nargs='?', type=int, default=50,
                           help='Number of results to return (default: 50)')

    args = parser.parse_args()

    if not args.cmd:
        print(json.dumps({'result': 'failed', 'message': 'no action specified'}))
        sys.exit(0)

    db = Database()
    scanner = VulnScanner(db)

    if args.cmd == 'target':
        result = scanner.scan_device(args.ip, ports=args.ports)
        print(json.dumps(result, indent=2))

    elif args.cmd == 'network':
        results = scanner.scan_network(args.subnet)
        print(json.dumps(results, indent=2))

    elif args.cmd == 'results':
        results = scanner.get_scan_results(limit=args.limit)
        print(json.dumps(results, indent=2))


if __name__ == '__main__':
    main()
