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

"""Vulnerability scanner using nmap and default credentials checking."""

import subprocess
import json
import logging
import time
import socket
import xml.etree.ElementTree as ET

log = logging.getLogger(__name__)

# Default credentials to check per service
DEFAULT_CREDS = {
    'ssh': [
        ('root', 'root'),
        ('admin', 'admin'),
        ('admin', 'password'),
    ],
    'http': [
        ('admin', 'admin'),
        ('admin', 'password'),
    ],
    'ftp': [
        ('anonymous', 'anonymous'),
    ],
}

CREATE_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS scan_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp INTEGER,
    target_ip TEXT,
    target_mac TEXT,
    open_ports TEXT,
    services TEXT,
    os_guess TEXT,
    vulns TEXT,
    scan_type TEXT
)
"""


class VulnScanner:
    """Perform vulnerability scans using nmap and default credential checks."""

    def __init__(self, db_module):
        """Initialize scanner with a db module instance."""
        self.db = db_module
        self.db.execute(CREATE_TABLE_SQL)

    def scan_device(self, ip: str, ports: str = '1-1024') -> dict:
        """Scan a single device using nmap.

        Uses nmap -sV -O to detect services and OS. Returns a dict with:
          {ip, open_ports, services, os_guess, vulns, timestamp}

        Requires nmap to be installed on the system.
        """
        log.info("scan_device: scanning %s ports=%s", ip, ports)
        result = {
            'ip': ip,
            'mac': self._get_mac_for_ip(ip),
            'open_ports': [],
            'services': {},
            'os_guess': '',
            'vulns': [],
            'timestamp': int(time.time()),
            'error': '',
        }

        try:
            proc = subprocess.run(
                [
                    'nmap', '-sV', '-O', '--top-ports', '1000',
                    '-p', ports,
                    '-oX', '-',
                    '--host-timeout', '60s',
                    ip,
                ],
                capture_output=True, text=True, timeout=120
            )
            xml_output = proc.stdout
        except FileNotFoundError:
            result['error'] = 'nmap not installed'
            log.error("scan_device: nmap not found")
            return result
        except subprocess.TimeoutExpired:
            result['error'] = 'scan timed out'
            log.warning("scan_device: timeout for %s", ip)
            return result

        self._parse_nmap_xml(xml_output, result)

        # Check default credentials for detected services
        for port_num, svc_info in result['services'].items():
            svc_name = svc_info.get('name', '').lower()
            for known_svc in DEFAULT_CREDS:
                if known_svc in svc_name:
                    has_default = self.check_default_creds(ip, int(port_num), known_svc)
                    if has_default:
                        result['vulns'].append(
                            f'Default credentials found on {known_svc} port {port_num}'
                        )

        self._save_result(result, 'device')
        return result

    def scan_network(self, subnet: str = '192.168.1.0/24') -> list:
        """Scan an entire subnet. Returns list of per-device scan results."""
        log.info("scan_network: scanning subnet %s", subnet)

        # First do a fast host discovery
        try:
            proc = subprocess.run(
                ['nmap', '-sn', '-oX', '-', subnet],
                capture_output=True, text=True, timeout=120
            )
            xml_output = proc.stdout
        except FileNotFoundError:
            log.error("scan_network: nmap not found")
            return []
        except subprocess.TimeoutExpired:
            log.warning("scan_network: host discovery timed out for %s", subnet)
            return []

        live_hosts = self._parse_live_hosts(xml_output)
        log.info("scan_network: found %d live hosts in %s", len(live_hosts), subnet)

        results = []
        for host_ip in live_hosts:
            result = self.scan_device(host_ip)
            results.append(result)

        return results

    def check_default_creds(self, ip: str, port: int, service: str) -> bool:
        """Check if a service accepts any known default credentials.

        Only attempts connection if the service name is recognized.
        Returns True if default credentials are accepted, False otherwise.
        """
        service = service.lower()
        creds = DEFAULT_CREDS.get(service, [])
        if not creds:
            return False

        for username, password in creds:
            if service == 'ssh':
                if self._try_ssh(ip, port, username, password):
                    log.warning(
                        "DEFAULT CREDS: %s:%d ssh %s/%s", ip, port, username, password
                    )
                    return True
            elif service == 'http':
                if self._try_http_basic(ip, port, username, password):
                    log.warning(
                        "DEFAULT CREDS: %s:%d http %s/%s", ip, port, username, password
                    )
                    return True
            elif service == 'ftp':
                if self._try_ftp(ip, port, username, password):
                    log.warning(
                        "DEFAULT CREDS: %s:%d ftp %s/%s", ip, port, username, password
                    )
                    return True

        return False

    def get_scan_results(self, limit: int = 50) -> list:
        """Return recent scan results from the database."""
        rows = self.db.query(
            "SELECT * FROM scan_results ORDER BY timestamp DESC LIMIT ?",
            (limit,)
        )
        results = []
        for row in rows:
            results.append({
                'id': row['id'],
                'timestamp': row['timestamp'],
                'target_ip': row['target_ip'],
                'target_mac': row['target_mac'],
                'open_ports': json.loads(row['open_ports'] or '[]'),
                'services': json.loads(row['services'] or '{}'),
                'os_guess': row['os_guess'],
                'vulns': json.loads(row['vulns'] or '[]'),
                'scan_type': row['scan_type'],
            })
        return results

    def schedule_scan(self, target: str, scan_type: str = 'device') -> dict:
        """Queue a scan for later execution.

        Currently executes immediately; returns a task record.
        """
        log.info("schedule_scan: queuing %s scan for %s", scan_type, target)
        if scan_type == 'network':
            results = self.scan_network(target)
            return {'queued': True, 'target': target, 'scan_type': scan_type, 'results': len(results)}
        else:
            result = self.scan_device(target)
            return {'queued': True, 'target': target, 'scan_type': scan_type, 'result': result}

    # --- Private helpers ---

    def _parse_nmap_xml(self, xml_output: str, result: dict):
        """Parse nmap XML output and populate result dict in-place."""
        if not xml_output.strip():
            return

        try:
            root = ET.fromstring(xml_output)
        except ET.ParseError as exc:
            log.error("nmap XML parse error: %s", exc)
            return

        for host in root.findall('host'):
            # OS detection
            os_elem = host.find('os')
            if os_elem is not None:
                osmatch = os_elem.find('osmatch')
                if osmatch is not None:
                    result['os_guess'] = osmatch.get('name', '')

            # Ports and services
            ports_elem = host.find('ports')
            if ports_elem is None:
                continue

            for port in ports_elem.findall('port'):
                state = port.find('state')
                if state is None or state.get('state') != 'open':
                    continue

                portid = port.get('portid', '')
                result['open_ports'].append(int(portid))

                service = port.find('service')
                if service is not None:
                    result['services'][portid] = {
                        'name': service.get('name', ''),
                        'product': service.get('product', ''),
                        'version': service.get('version', ''),
                    }

    def _parse_live_hosts(self, xml_output: str) -> list:
        """Parse nmap -sn XML output and return list of live IPs."""
        hosts = []
        if not xml_output.strip():
            return hosts

        try:
            root = ET.fromstring(xml_output)
        except ET.ParseError:
            return hosts

        for host in root.findall('host'):
            status = host.find('status')
            if status is None or status.get('state') != 'up':
                continue
            addr = host.find('address[@addrtype="ipv4"]')
            if addr is not None:
                hosts.append(addr.get('addr', ''))

        return [h for h in hosts if h]

    def _get_mac_for_ip(self, ip: str) -> str:
        """Attempt to resolve MAC from ARP table."""
        try:
            out = subprocess.check_output(['arp', '-n', ip], text=True, timeout=5)
            m_match = __import__('re').search(r'([0-9a-f:]{17})', out, __import__('re').I)
            if m_match:
                return m_match.group(1).lower()
        except Exception:
            pass
        return ''

    def _try_ssh(self, ip: str, port: int, username: str, password: str) -> bool:
        """Attempt SSH login with given credentials. Returns True if successful."""
        try:
            import paramiko  # type: ignore
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(ip, port=port, username=username, password=password,
                           timeout=5, allow_agent=False, look_for_keys=False)
            client.close()
            return True
        except Exception:
            return False

    def _try_http_basic(self, ip: str, port: int, username: str, password: str) -> bool:
        """Attempt HTTP Basic Auth. Returns True if response is 200."""
        try:
            import urllib.request
            import base64
            url = f'http://{ip}:{port}/'
            credentials = base64.b64encode(f'{username}:{password}'.encode()).decode()
            req = urllib.request.Request(url)
            req.add_header('Authorization', f'Basic {credentials}')
            with urllib.request.urlopen(req, timeout=5) as resp:
                return resp.status == 200
        except Exception:
            return False

    def _try_ftp(self, ip: str, port: int, username: str, password: str) -> bool:
        """Attempt FTP login. Returns True if successful."""
        try:
            import ftplib
            ftp = ftplib.FTP()
            ftp.connect(ip, port, timeout=5)
            ftp.login(username, password)
            ftp.quit()
            return True
        except Exception:
            return False

    def _save_result(self, result: dict, scan_type: str):
        """Persist scan result to database."""
        self.db.execute(
            """INSERT INTO scan_results
               (timestamp, target_ip, target_mac, open_ports, services, os_guess, vulns, scan_type)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                result['timestamp'],
                result['ip'],
                result.get('mac', ''),
                json.dumps(result['open_ports']),
                json.dumps(result['services']),
                result['os_guess'],
                json.dumps(result['vulns']),
                scan_type,
            )
        )
