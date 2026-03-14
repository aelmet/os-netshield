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

"""
Behavioral IDS — Detects anomalous network patterns without signatures.
Detection types: port scanning, data exfiltration, beaconing, lateral movement.
"""

import ipaddress
import logging
import math
import time
from collections import defaultdict
from datetime import datetime, timezone

log = logging.getLogger(__name__)

SEVERITY_MAP = {
    "port_scan": "high",
    "data_exfil": "critical",
    "beaconing": "high",
    "lateral_movement": "critical",
    "dns_tunneling": "medium",
}

# Ports considered sensitive for lateral movement detection
SENSITIVE_PORTS = {22, 445, 3389, 5985}

# Thresholds
PORT_SCAN_THRESHOLD = 20       # unique dst ports in window
PORT_SCAN_WINDOW = 60          # seconds
EXFIL_THRESHOLD = 100 * 1024 * 1024   # 100 MB
BEACON_MIN_CONNS = 10
BEACON_CV_THRESHOLD = 0.1     # coefficient of variation
LATERAL_UNIQUE_HOSTS = 5       # distinct internal hosts
DNS_QUERY_LEN_THRESHOLD = 100  # characters in DNS name
DNS_QUERY_RATE_THRESHOLD = 50  # queries per minute to same domain

# RFC-1918 private ranges
_PRIVATE = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
]


def _is_private(ip_str):
    try:
        addr = ipaddress.ip_address(ip_str)
        return any(addr in net for net in _PRIVATE)
    except ValueError:
        return False


def _stdev(values):
    n = len(values)
    if n < 2:
        return 0.0
    mean = sum(values) / n
    variance = sum((v - mean) ** 2 for v in values) / (n - 1)
    return math.sqrt(variance)


class BehavioralIDS:
    """
    Stateful behavioral IDS engine.

    Tracks per-source connection patterns and fires alert callbacks when
    anomalous behaviour is detected. All state is in-memory; call reset()
    to clear between test runs or after a daemon restart.
    """

    # Memory limits to prevent unbounded growth
    MAX_TRACKED_IPS = 10000
    MAX_ENTRIES_PER_IP = 1000
    STATE_TTL_SECONDS = 3600  # 1 hour

    def __init__(self, alert_callback=None):
        self._callback = alert_callback or (lambda alert: None)
        self._detections = []  # list of detection dicts
        self._last_cleanup = time.time()

        # Port scan: {src_ip: [(timestamp, dst_port), ...]}
        self._scan_state = defaultdict(list)

        # Data exfil: {src_ip: bytes_out_total}
        self._exfil_state = defaultdict(float)

        # Beaconing: {(src_ip, dst_ip): [timestamps]}
        self._beacon_state = defaultdict(list)

        # Lateral movement: {src_ip: {dst_ip: set(ports)}}
        self._lateral_state = defaultdict(lambda: defaultdict(set))

        # DNS tunneling: {src_ip: {domain: [timestamps]}}
        self._dns_state = defaultdict(lambda: defaultdict(list))

        # Configurable whitelist: list of ip/cidr strings to ignore
        self.whitelist = []

    def _cleanup_stale_state(self):
        """Remove old entries to prevent memory exhaustion."""
        now = time.time()
        if now - self._last_cleanup < 300:  # Run every 5 min max
            return
        self._last_cleanup = now
        cutoff = now - self.STATE_TTL_SECONDS

        # Clean scan state
        for ip in list(self._scan_state.keys()):
            self._scan_state[ip] = [(t, p) for t, p in self._scan_state[ip] if t > cutoff]
            if not self._scan_state[ip]:
                del self._scan_state[ip]

        # Clean beacon state
        for key in list(self._beacon_state.keys()):
            self._beacon_state[key] = [t for t in self._beacon_state[key] if t > cutoff]
            if not self._beacon_state[key]:
                del self._beacon_state[key]

        # Clean DNS state
        for ip in list(self._dns_state.keys()):
            for domain in list(self._dns_state[ip].keys()):
                self._dns_state[ip][domain] = [t for t in self._dns_state[ip][domain] if t > cutoff]
                if not self._dns_state[ip][domain]:
                    del self._dns_state[ip][domain]
            if not self._dns_state[ip]:
                del self._dns_state[ip]

        # Enforce max IPs limit (LRU-style: just drop if over limit)
        for state_dict in [self._scan_state, self._exfil_state, self._lateral_state]:
            if len(state_dict) > self.MAX_TRACKED_IPS:
                excess = len(state_dict) - self.MAX_TRACKED_IPS
                for key in list(state_dict.keys())[:excess]:
                    del state_dict[key]

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def analyze_flow(self, flow):
        """
        Analyse a single network flow dict.

        Expected flow keys (all optional with sensible defaults):
          src_ip, dst_ip, dst_port, protocol, bytes_out,
          dns_query (str), timestamp (float epoch)
        """
        # Periodic cleanup to prevent memory exhaustion
        self._cleanup_stale_state()

        if self._is_whitelisted(flow.get("src_ip", "")):
            return
        self._detect_port_scan(flow)
        self._detect_data_exfil(flow)
        self._detect_beaconing(flow)
        self._detect_lateral_movement(flow)
        self._detect_dns_tunneling(flow)

    def get_detections(self, hours=24):
        """Return detections from the last `hours` hours."""
        cutoff = time.time() - hours * 3600
        return [d for d in self._detections if d["_ts"] >= cutoff]

    def reset(self):
        """Clear all tracking state."""
        self._scan_state.clear()
        self._exfil_state.clear()
        self._beacon_state.clear()
        self._lateral_state.clear()
        self._dns_state.clear()
        self._detections.clear()

    # ------------------------------------------------------------------
    # Detectors
    # ------------------------------------------------------------------

    def _detect_port_scan(self, flow):
        src = flow.get("src_ip", "")
        dst_port = flow.get("dst_port")
        if not src or dst_port is None:
            return

        now = flow.get("timestamp", time.time())
        window_start = now - PORT_SCAN_WINDOW

        entries = self._scan_state[src]
        entries.append((now, dst_port))
        # Prune old entries
        self._scan_state[src] = [(t, p) for t, p in entries if t >= window_start]

        unique_ports = {p for _, p in self._scan_state[src]}
        if len(unique_ports) >= PORT_SCAN_THRESHOLD:
            self._fire_alert(
                detection_type="port_scan",
                src_ip=src,
                dst_ip=flow.get("dst_ip", ""),
                detail=f"{len(unique_ports)} unique ports scanned in {PORT_SCAN_WINDOW}s",
                timestamp=now,
            )
            # Reset after alert to avoid spam
            self._scan_state[src] = []

    def _detect_data_exfil(self, flow):
        src = flow.get("src_ip", "")
        dst = flow.get("dst_ip", "")
        bytes_out = flow.get("bytes_out", 0)

        if not src or not dst or not bytes_out:
            return
        # Only flag outbound to external destinations
        if _is_private(dst):
            return

        self._exfil_state[src] += bytes_out
        total = self._exfil_state[src]

        if total >= EXFIL_THRESHOLD:
            mb = total / (1024 * 1024)
            self._fire_alert(
                detection_type="data_exfil",
                src_ip=src,
                dst_ip=dst,
                detail=f"{mb:.1f} MB sent to external host",
                timestamp=flow.get("timestamp", time.time()),
            )
            self._exfil_state[src] = 0.0  # Reset counter

    def _detect_beaconing(self, flow):
        src = flow.get("src_ip", "")
        dst = flow.get("dst_ip", "")
        if not src or not dst:
            return

        now = flow.get("timestamp", time.time())
        key = (src, dst)
        self._beacon_state[key].append(now)

        timestamps = self._beacon_state[key]
        if len(timestamps) < BEACON_MIN_CONNS:
            return

        # Calculate inter-arrival times
        intervals = [timestamps[i] - timestamps[i - 1] for i in range(1, len(timestamps))]
        if not intervals:
            return
        mean_interval = sum(intervals) / len(intervals)
        if mean_interval <= 0:
            return
        cv = _stdev(intervals) / mean_interval

        if cv < BEACON_CV_THRESHOLD:
            self._fire_alert(
                detection_type="beaconing",
                src_ip=src,
                dst_ip=dst,
                detail=(
                    f"Beaconing detected: {len(timestamps)} connections, "
                    f"interval={mean_interval:.1f}s, CV={cv:.3f}"
                ),
                timestamp=now,
            )
            # Keep only last few entries to allow re-detection later
            self._beacon_state[key] = timestamps[-5:]

    def _detect_lateral_movement(self, flow):
        src = flow.get("src_ip", "")
        dst = flow.get("dst_ip", "")
        dst_port = flow.get("dst_port")

        if not src or not dst or dst_port is None:
            return
        # Must be internal-to-internal
        if not _is_private(src) or not _is_private(dst):
            return
        if dst_port not in SENSITIVE_PORTS:
            return

        self._lateral_state[src][dst].add(dst_port)
        unique_hosts = len(self._lateral_state[src])

        if unique_hosts >= LATERAL_UNIQUE_HOSTS:
            self._fire_alert(
                detection_type="lateral_movement",
                src_ip=src,
                dst_ip=dst,
                detail=(
                    f"Lateral movement: {unique_hosts} internal hosts targeted "
                    f"on sensitive ports"
                ),
                timestamp=flow.get("timestamp", time.time()),
            )
            self._lateral_state[src].clear()

    def _detect_dns_tunneling(self, flow):
        src = flow.get("src_ip", "")
        dns_query = flow.get("dns_query", "")
        if not src or not dns_query:
            return

        now = flow.get("timestamp", time.time())

        # Long DNS query heuristic
        if len(dns_query) >= DNS_QUERY_LEN_THRESHOLD:
            self._fire_alert(
                detection_type="dns_tunneling",
                src_ip=src,
                dst_ip="",
                detail=f"Suspiciously long DNS query: {len(dns_query)} chars",
                timestamp=now,
            )
            return

        # High query rate to same domain
        # Use the registered domain (last two labels) as the key
        parts = dns_query.rstrip(".").split(".")
        domain_key = ".".join(parts[-2:]) if len(parts) >= 2 else dns_query

        minute_start = now - 60
        self._dns_state[src][domain_key] = [
            t for t in self._dns_state[src][domain_key] if t >= minute_start
        ]
        self._dns_state[src][domain_key].append(now)

        if len(self._dns_state[src][domain_key]) >= DNS_QUERY_RATE_THRESHOLD:
            self._fire_alert(
                detection_type="dns_tunneling",
                src_ip=src,
                dst_ip="",
                detail=(
                    f"High DNS query rate to {domain_key}: "
                    f"{len(self._dns_state[src][domain_key])} queries/min"
                ),
                timestamp=now,
            )
            self._dns_state[src][domain_key] = []

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _is_whitelisted(self, ip_str):
        if not ip_str:
            return False
        try:
            addr = ipaddress.ip_address(ip_str)
        except ValueError:
            return False
        for entry in self.whitelist:
            try:
                if "/" in entry:
                    if addr in ipaddress.ip_network(entry, strict=False):
                        return True
                else:
                    if addr == ipaddress.ip_address(entry):
                        return True
            except ValueError:
                continue
        return False

    def _fire_alert(self, detection_type, src_ip, dst_ip, detail, timestamp):
        severity = SEVERITY_MAP.get(detection_type, "medium")
        alert = {
            "_ts": timestamp,
            "time": datetime.fromtimestamp(timestamp, tz=timezone.utc).isoformat(),
            "detection_type": detection_type,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "severity": severity,
            "detail": detail,
        }
        self._detections.append(alert)
        log.warning(
            "BehavioralIDS [%s] src=%s dst=%s sev=%s: %s",
            detection_type, src_ip, dst_ip, severity, detail,
        )
        try:
            self._callback(alert)
        except Exception as exc:
            log.error("Alert callback error: %s", exc)
