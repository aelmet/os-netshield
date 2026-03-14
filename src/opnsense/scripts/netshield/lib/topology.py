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

"""Network topology discovery for D3.js visualization."""

import subprocess
import json
import re
import logging
import socket

log = logging.getLogger(__name__)


class TopologyMapper:
    """Discover and model network topology as a D3.js-compatible graph."""

    def discover(self) -> dict:
        """Run full topology discovery.

        Returns a dict with 'nodes' and 'edges' suitable for D3.js
        force-directed graph rendering.
        """
        interfaces = self._get_interfaces()
        arp = self._get_arp_neighbors()
        lldp = self._get_lldp_neighbors()
        routes = self._get_route_table()
        return self._build_graph(interfaces, arp, lldp, routes)

    def _get_interfaces(self) -> list:
        """Return list of local network interfaces with IPs and subnets.

        Each entry: {name, ip, netmask, mac}
        """
        interfaces = []
        try:
            out = subprocess.check_output(['ifconfig'], text=True, timeout=10)
        except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired) as exc:
            log.warning("ifconfig failed: %s", exc)
            return interfaces

        current = None
        for line in out.splitlines():
            iface_match = re.match(r'^(\S+):', line)
            if iface_match:
                if current:
                    interfaces.append(current)
                current = {'name': iface_match.group(1), 'ip': '', 'netmask': '', 'mac': ''}
                continue

            if current is None:
                continue

            inet_match = re.search(r'inet\s+(\d+\.\d+\.\d+\.\d+)\s+netmask\s+(\S+)', line)
            if inet_match:
                current['ip'] = inet_match.group(1)
                current['netmask'] = inet_match.group(2)

            mac_match = re.search(r'ether\s+([0-9a-f:]{17})', line, re.I)
            if mac_match:
                current['mac'] = mac_match.group(1).lower()

        if current:
            interfaces.append(current)

        # Filter out loopback and interfaces without IPs
        return [i for i in interfaces if i.get('ip') and not i['ip'].startswith('127.')]

    def _get_arp_neighbors(self) -> list:
        """Return list of ARP table neighbors.

        Each entry: {mac, ip, interface}
        """
        neighbors = []
        try:
            out = subprocess.check_output(['arp', '-an'], text=True, timeout=10)
        except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired) as exc:
            log.warning("arp failed: %s", exc)
            return neighbors

        # Format: ? (192.168.1.1) at aa:bb:cc:dd:ee:ff on em0 [ethernet]
        pattern = re.compile(
            r'\((\d+\.\d+\.\d+\.\d+)\)\s+at\s+([0-9a-f:]{17})\s+on\s+(\S+)',
            re.I
        )
        for line in out.splitlines():
            m = pattern.search(line)
            if m:
                neighbors.append({
                    'ip': m.group(1),
                    'mac': m.group(2).lower(),
                    'interface': m.group(3),
                })
        return neighbors

    def _get_lldp_neighbors(self) -> list:
        """Return LLDP neighbors using lldpctl if available.

        Each entry: {chassis_id, port_id, system_name, mgmt_ip, interface}
        Returns empty list if lldpctl is not installed.
        """
        neighbors = []
        try:
            out = subprocess.check_output(
                ['lldpctl', '-f', 'json'], text=True, timeout=10
            )
        except FileNotFoundError:
            log.debug("lldpctl not available, skipping LLDP discovery")
            return neighbors
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
            log.warning("lldpctl failed: %s", exc)
            return neighbors

        try:
            data = json.loads(out)
        except json.JSONDecodeError:
            return neighbors

        lldp_data = data.get('lldp', {})
        interfaces = lldp_data.get('interface', {})
        if isinstance(interfaces, list):
            iface_list = interfaces
        elif isinstance(interfaces, dict):
            iface_list = [interfaces]
        else:
            return neighbors

        for iface in iface_list:
            iface_name = list(iface.keys())[0] if isinstance(iface, dict) else ''
            iface_data = iface.get(iface_name, {}) if isinstance(iface, dict) else {}
            chassis = iface_data.get('chassis', {})
            port = iface_data.get('port', {})

            chassis_name = list(chassis.keys())[0] if isinstance(chassis, dict) else ''
            chassis_data = chassis.get(chassis_name, {}) if isinstance(chassis, dict) else {}

            mgmt_ip = ''
            mgmt = chassis_data.get('mgmt-ip', '')
            if isinstance(mgmt, list) and mgmt:
                mgmt_ip = mgmt[0]
            elif isinstance(mgmt, str):
                mgmt_ip = mgmt

            neighbors.append({
                'chassis_id': chassis_data.get('id', {}).get('value', '') if isinstance(chassis_data.get('id'), dict) else '',
                'port_id': port.get('id', {}).get('value', '') if isinstance(port.get('id'), dict) else '',
                'system_name': chassis_name,
                'mgmt_ip': mgmt_ip,
                'interface': iface_name,
            })

        return neighbors

    def _get_route_table(self) -> list:
        """Return list of routes from the routing table.

        Each entry: {destination, gateway, flags, interface}
        """
        routes = []
        try:
            out = subprocess.check_output(['netstat', '-rn'], text=True, timeout=10)
        except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired) as exc:
            log.warning("netstat -rn failed: %s", exc)
            return routes

        # Parse IPv4 section
        in_inet = False
        for line in out.splitlines():
            if 'Internet:' in line or 'Routing tables' in line:
                in_inet = 'Internet' in line
                continue
            if not in_inet:
                continue

            parts = line.split()
            if len(parts) < 4:
                continue

            dest = parts[0]
            gateway = parts[1]
            flags = parts[2]
            iface = parts[-1] if len(parts) >= 4 else ''

            # Skip header lines
            if dest in ('Destination', 'Network', 'default') or dest.startswith('---'):
                if dest == 'default':
                    routes.append({
                        'destination': 'default',
                        'gateway': gateway,
                        'flags': flags,
                        'interface': iface,
                    })
                continue

            routes.append({
                'destination': dest,
                'gateway': gateway,
                'flags': flags,
                'interface': iface,
            })

        return routes

    def _build_graph(self, interfaces: list, arp: list, lldp: list, routes: list) -> dict:
        """Build a D3.js compatible graph from discovered topology data.

        Returns:
            {
              "nodes": [{"id", "type", "label", "ip", "mac"}],
              "edges": [{"source", "target", "type", "interface"}]
            }
        """
        nodes = {}  # id -> node dict
        edges = []

        # Detect gateway from default route
        gateway_ip = ''
        for route in routes:
            if route['destination'] == 'default':
                gateway_ip = route['gateway']
                break

        # Add local interface nodes as router type
        local_router_id = 'local'
        nodes[local_router_id] = {
            'id': local_router_id,
            'type': 'router',
            'label': socket.gethostname(),
            'ip': interfaces[0]['ip'] if interfaces else '',
            'mac': interfaces[0]['mac'] if interfaces else '',
            'interfaces': [i['name'] for i in interfaces],
        }

        # Add gateway node
        if gateway_ip:
            gw_id = f'gw_{gateway_ip}'
            nodes[gw_id] = {
                'id': gw_id,
                'type': 'gateway',
                'label': 'Gateway',
                'ip': gateway_ip,
                'mac': '',
            }
            edges.append({
                'source': local_router_id,
                'target': gw_id,
                'type': 'route',
                'interface': '',
            })

        # Add ARP neighbors as devices
        for neighbor in arp:
            ip = neighbor['ip']
            mac = neighbor['mac']
            iface = neighbor['interface']

            node_id = mac if mac else ip
            if node_id in nodes:
                continue

            # Classify: if this is the gateway, skip (already added)
            if ip == gateway_ip:
                gw_id = f'gw_{ip}'
                if gw_id in nodes:
                    nodes[gw_id]['mac'] = mac
                continue

            try:
                label = socket.gethostbyaddr(ip)[0]
            except (socket.herror, socket.gaierror):
                label = ip

            nodes[node_id] = {
                'id': node_id,
                'type': 'device',
                'label': label,
                'ip': ip,
                'mac': mac,
            }

            edges.append({
                'source': local_router_id,
                'target': node_id,
                'type': 'direct',
                'interface': iface,
            })

        # Add LLDP neighbors (may be switches or routers)
        for neighbor in lldp:
            mgmt_ip = neighbor.get('mgmt_ip', '')
            chassis_id = neighbor.get('chassis_id', '')
            node_id = chassis_id if chassis_id else mgmt_ip
            if not node_id:
                continue

            if node_id not in nodes:
                nodes[node_id] = {
                    'id': node_id,
                    'type': 'switch',
                    'label': neighbor.get('system_name', node_id),
                    'ip': mgmt_ip,
                    'mac': chassis_id,
                }

            edges.append({
                'source': local_router_id,
                'target': node_id,
                'type': 'lldp',
                'interface': neighbor.get('interface', ''),
            })

        return {
            'nodes': list(nodes.values()),
            'edges': edges,
        }
