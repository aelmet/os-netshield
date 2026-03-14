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

"""Device quarantine management via pf rules."""

import subprocess
import logging
import time
import ipaddress
import os

log = logging.getLogger(__name__)

QUARANTINE_CONF = '/tmp/netshield_quarantine.conf'
PF_ANCHOR = 'netshield/quarantine'


class QuarantineManager:
    """Manage device quarantine using pf anchor rules."""

    def __init__(self, db_module):
        """Initialize with a db module instance and load existing quarantined devices."""
        self.db = db_module
        self._ensure_table()
        self._quarantined = {}  # mac -> {ip, reason, timestamp}
        self._load_from_db()

    def _ensure_table(self):
        """Create quarantine table if it does not exist."""
        self.db.execute("""
            CREATE TABLE IF NOT EXISTS quarantine (
                mac TEXT PRIMARY KEY,
                ip TEXT,
                reason TEXT,
                timestamp INTEGER
            )
        """)

    def _load_from_db(self):
        """Load quarantined devices from persistent DB."""
        rows = self.db.fetchall("SELECT mac, ip, reason, timestamp FROM quarantine")
        for row in rows:
            self._quarantined[row['mac']] = {
                'mac': row['mac'],
                'ip': row['ip'],
                'reason': row['reason'],
                'timestamp': row['timestamp'],
            }

    def quarantine(self, mac: str, reason: str = '') -> bool:
        """Quarantine a device by MAC address.

        Resolves IP from ARP, adds pf block rule via anchor, updates DB,
        and writes an audit log entry.

        Returns True on success, False on failure.
        """
        mac = mac.lower().strip()
        ip = self._get_ip_for_mac(mac)
        if not ip:
            log.warning("quarantine: no ARP entry found for MAC %s", mac)
            return False

        self._quarantined[mac] = {
            'mac': mac,
            'ip': ip,
            'reason': reason,
            'timestamp': int(time.time()),
        }

        self.db.execute(
            "INSERT OR REPLACE INTO quarantine (mac, ip, reason, timestamp) VALUES (?, ?, ?, ?)",
            (mac, ip, reason, int(time.time()))
        )

        self._apply_rules()

        log.info("AUDIT quarantine mac=%s ip=%s reason=%s", mac, ip, reason)
        return True

    def unquarantine(self, mac: str) -> bool:
        """Remove a device from quarantine.

        Removes the pf rule, updates DB, and writes an audit log entry.

        Returns True on success, False if device was not quarantined.
        """
        mac = mac.lower().strip()
        if mac not in self._quarantined:
            log.warning("unquarantine: MAC %s is not quarantined", mac)
            return False

        entry = self._quarantined.pop(mac)
        self.db.execute("DELETE FROM quarantine WHERE mac = ?", (mac,))
        self._apply_rules()

        log.info("AUDIT unquarantine mac=%s ip=%s", mac, entry.get('ip', ''))
        return True

    def is_quarantined(self, mac: str) -> bool:
        """Return True if the given MAC is currently quarantined."""
        return mac.lower().strip() in self._quarantined

    def get_quarantined(self) -> list:
        """Return list of quarantined device dicts."""
        return list(self._quarantined.values())

    def enforce_all(self):
        """Reapply all quarantine rules — call on daemon startup."""
        self._load_from_db()
        self._apply_rules()
        log.info("quarantine: enforced %d rules on startup", len(self._quarantined))

    def _get_ip_for_mac(self, mac: str) -> str:
        """Resolve IP address for a given MAC from the ARP table.

        Returns empty string if not found.
        """
        try:
            out = subprocess.check_output(['arp', '-an'], text=True, timeout=5)
        except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired) as exc:
            log.error("arp lookup failed: %s", exc)
            return ''

        mac_norm = mac.lower()
        for line in out.splitlines():
            # typical format: ? (192.168.1.5) at aa:bb:cc:dd:ee:ff on em0
            if mac_norm in line.lower():
                parts = line.split()
                for part in parts:
                    ip = part.strip('()')
                    if ip.count('.') == 3:
                        return ip
        return ''

    def _validate_ip(self, ip: str) -> bool:
        """Validate IP address to prevent injection into pf rules."""
        if not ip:
            return False
        try:
            addr = ipaddress.ip_address(ip)
            # Reject loopback, unspecified, or broadcast
            if addr.is_loopback or addr.is_unspecified:
                log.warning("quarantine: rejected invalid IP %s", ip)
                return False
            return True
        except ValueError:
            log.warning("quarantine: rejected malformed IP %s", ip)
            return False

    def _apply_rules(self):
        """Regenerate quarantine pf rules file and load via pfctl anchor."""
        lines = ['# NetShield quarantine rules — auto-generated\n']
        for entry in self._quarantined.values():
            ip = entry.get('ip', '')
            if self._validate_ip(ip):
                lines.append(f'block in quick from {ip} to any\n')
                lines.append(f'block out quick from any to {ip}\n')

        # Atomic write: write to temp file then rename
        tmp_file = QUARANTINE_CONF + '.tmp'
        try:
            with open(tmp_file, 'w') as fh:
                fh.writelines(lines)
            os.replace(tmp_file, QUARANTINE_CONF)
        except OSError as exc:
            log.error("quarantine: failed to write rules file: %s", exc)
            return

        try:
            subprocess.run(
                ['pfctl', '-a', PF_ANCHOR, '-f', QUARANTINE_CONF],
                check=True, capture_output=True, timeout=10
            )
            log.debug("quarantine: loaded %d IP rules into anchor %s", len(self._quarantined), PF_ANCHOR)
        except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired) as exc:
            log.error("quarantine: pfctl failed: %s", exc)
