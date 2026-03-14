#!/usr/local/bin/python3
# Copyright (c) 2025-2026, NetShield Project
# All rights reserved.
#
# Suricata Integration — Read-only integration with existing Suricata IDS

"""
Suricata Integration for NetShield.

This module provides SAFE, READ-ONLY integration with Suricata:
- Reads eve.json alerts (does NOT modify Suricata config)
- Correlates alerts with NetShield devices
- Triggers enforcement via NetShield (not Suricata)
- Provides unified alert view

SAFETY: This module NEVER modifies suricata.yaml or rules.
All blocking is done via NetShield's pf/Unbound integration.
"""

import json
import logging
import os
import re
import subprocess
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, Generator, List, Optional, Set

log = logging.getLogger(__name__)

# Suricata paths (OPNsense defaults)
SURICATA_EVE_LOG = "/var/log/suricata/eve.json"
SURICATA_STATS_LOG = "/var/log/suricata/stats.log"
SURICATA_SOCKET = "/var/run/suricata/suricata-command.socket"

# Alert severity mapping
SEVERITY_MAP = {
    1: "critical",
    2: "high",
    3: "medium",
    4: "low",
}


@dataclass
class SuricataAlert:
    """Represents a Suricata alert."""
    timestamp: str
    flow_id: int
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    protocol: str
    alert_signature: str
    alert_signature_id: int
    alert_severity: int
    alert_category: str
    alert_action: str  # "allowed" or "blocked" (if IPS mode)
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def severity_name(self) -> str:
        return SEVERITY_MAP.get(self.alert_severity, "unknown")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "flow_id": self.flow_id,
            "src_ip": self.src_ip,
            "src_port": self.src_port,
            "dst_ip": self.dst_ip,
            "dst_port": self.dst_port,
            "protocol": self.protocol,
            "signature": self.alert_signature,
            "signature_id": self.alert_signature_id,
            "severity": self.alert_severity,
            "severity_name": self.severity_name,
            "category": self.alert_category,
            "action": self.alert_action,
        }


class SuricataIntegration:
    """
    Safe, read-only Suricata integration.

    This class:
    - Tails eve.json for new alerts
    - Correlates with NetShield device tracking
    - Can trigger NetShield enforcement (via separate modules)
    - NEVER modifies Suricata configuration
    """

    def __init__(self, db_module: Any, device_tracker: Any = None):
        self._db = db_module
        self._device_tracker = device_tracker
        self._last_position = 0
        self._processed_flow_ids: Set[int] = set()
        self._init_tables()

    def _init_tables(self) -> None:
        """Create alert tracking tables."""
        self._db.execute("""
            CREATE TABLE IF NOT EXISTS suricata_alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                flow_id INTEGER,
                src_ip TEXT,
                src_port INTEGER,
                dst_ip TEXT,
                dst_port INTEGER,
                protocol TEXT,
                signature TEXT,
                signature_id INTEGER,
                severity INTEGER,
                category TEXT,
                action TEXT,
                device_mac TEXT,
                device_name TEXT,
                netshield_action TEXT,
                raw_json TEXT
            )
        """)
        self._db.execute("""
            CREATE INDEX IF NOT EXISTS idx_suricata_timestamp
            ON suricata_alerts(timestamp)
        """)
        self._db.execute("""
            CREATE INDEX IF NOT EXISTS idx_suricata_src_ip
            ON suricata_alerts(src_ip)
        """)
        self._db.execute("""
            CREATE INDEX IF NOT EXISTS idx_suricata_severity
            ON suricata_alerts(severity)
        """)
        self._db.commit()

    def check_suricata_running(self) -> Dict[str, Any]:
        """Check if Suricata is running."""
        try:
            result = subprocess.run(
                ["pgrep", "-x", "suricata"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            running = result.returncode == 0
            pid = result.stdout.strip() if running else None

            # Check eve.json exists and is being written
            eve_exists = os.path.exists(SURICATA_EVE_LOG)
            eve_size = os.path.getsize(SURICATA_EVE_LOG) if eve_exists else 0

            return {
                "running": running,
                "pid": pid,
                "eve_log_exists": eve_exists,
                "eve_log_size": eve_size,
                "socket_exists": os.path.exists(SURICATA_SOCKET),
            }
        except Exception as exc:
            return {"running": False, "error": str(exc)}

    def read_recent_alerts(self, limit: int = 100) -> List[SuricataAlert]:
        """Read recent alerts from eve.json."""
        alerts = []

        if not os.path.exists(SURICATA_EVE_LOG):
            log.warning("Suricata eve.json not found at %s", SURICATA_EVE_LOG)
            return alerts

        try:
            # Read last N lines efficiently
            result = subprocess.run(
                ["tail", "-n", str(limit * 10), SURICATA_EVE_LOG],
                capture_output=True,
                text=True,
                timeout=10,
            )

            for line in result.stdout.splitlines():
                if not line.strip():
                    continue

                try:
                    event = json.loads(line)

                    # Only process alert events
                    if event.get("event_type") != "alert":
                        continue

                    alert_data = event.get("alert", {})
                    alert = SuricataAlert(
                        timestamp=event.get("timestamp", ""),
                        flow_id=event.get("flow_id", 0),
                        src_ip=event.get("src_ip", ""),
                        src_port=event.get("src_port", 0),
                        dst_ip=event.get("dest_ip", ""),
                        dst_port=event.get("dest_port", 0),
                        protocol=event.get("proto", ""),
                        alert_signature=alert_data.get("signature", ""),
                        alert_signature_id=alert_data.get("signature_id", 0),
                        alert_severity=alert_data.get("severity", 4),
                        alert_category=alert_data.get("category", ""),
                        alert_action=alert_data.get("action", "allowed"),
                        metadata=alert_data.get("metadata", {}),
                    )
                    alerts.append(alert)

                    if len(alerts) >= limit:
                        break

                except json.JSONDecodeError:
                    continue

        except Exception as exc:
            log.error("Error reading Suricata alerts: %s", exc)

        return alerts

    def tail_alerts(self, callback: callable = None) -> Generator[SuricataAlert, None, None]:
        """
        Generator that yields new alerts as they appear.

        Usage:
            for alert in integration.tail_alerts():
                process_alert(alert)
        """
        if not os.path.exists(SURICATA_EVE_LOG):
            log.error("Suricata eve.json not found")
            return

        # Start from end of file
        with open(SURICATA_EVE_LOG, "r") as fh:
            fh.seek(0, 2)  # Go to end
            self._last_position = fh.tell()

        while True:
            try:
                with open(SURICATA_EVE_LOG, "r") as fh:
                    fh.seek(self._last_position)

                    for line in fh:
                        if not line.strip():
                            continue

                        try:
                            event = json.loads(line)

                            if event.get("event_type") != "alert":
                                continue

                            flow_id = event.get("flow_id", 0)
                            if flow_id in self._processed_flow_ids:
                                continue

                            self._processed_flow_ids.add(flow_id)

                            # Keep set size bounded
                            if len(self._processed_flow_ids) > 10000:
                                self._processed_flow_ids = set(
                                    list(self._processed_flow_ids)[-5000:]
                                )

                            alert_data = event.get("alert", {})
                            alert = SuricataAlert(
                                timestamp=event.get("timestamp", ""),
                                flow_id=flow_id,
                                src_ip=event.get("src_ip", ""),
                                src_port=event.get("src_port", 0),
                                dst_ip=event.get("dest_ip", ""),
                                dst_port=event.get("dest_port", 0),
                                protocol=event.get("proto", ""),
                                alert_signature=alert_data.get("signature", ""),
                                alert_signature_id=alert_data.get("signature_id", 0),
                                alert_severity=alert_data.get("severity", 4),
                                alert_category=alert_data.get("category", ""),
                                alert_action=alert_data.get("action", "allowed"),
                            )

                            if callback:
                                callback(alert)

                            yield alert

                        except json.JSONDecodeError:
                            continue

                    self._last_position = fh.tell()

            except Exception as exc:
                log.error("Error tailing Suricata log: %s", exc)

            time.sleep(1)  # Poll interval

    def store_alert(
        self,
        alert: SuricataAlert,
        device_mac: str = None,
        device_name: str = None,
        netshield_action: str = None,
    ) -> int:
        """Store alert in database with device correlation."""
        # Try to resolve device if not provided
        if not device_mac and self._device_tracker:
            device = self._device_tracker.get_device_by_ip(alert.src_ip)
            if device:
                device_mac = device.get("mac", "")
                device_name = device.get("name", "")

        self._db.execute(
            """
            INSERT INTO suricata_alerts
            (timestamp, flow_id, src_ip, src_port, dst_ip, dst_port,
             protocol, signature, signature_id, severity, category,
             action, device_mac, device_name, netshield_action, raw_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                alert.timestamp,
                alert.flow_id,
                alert.src_ip,
                alert.src_port,
                alert.dst_ip,
                alert.dst_port,
                alert.protocol,
                alert.alert_signature,
                alert.alert_signature_id,
                alert.alert_severity,
                alert.alert_category,
                alert.alert_action,
                device_mac,
                device_name,
                netshield_action,
                json.dumps(alert.to_dict()),
            ),
        )
        self._db.commit()
        return self._db.lastrowid

    def get_alerts(
        self,
        limit: int = 100,
        severity: int = None,
        device_mac: str = None,
        since: str = None,
    ) -> List[Dict[str, Any]]:
        """Query stored alerts with filters."""
        query = "SELECT * FROM suricata_alerts WHERE 1=1"
        params = []

        if severity:
            query += " AND severity <= ?"
            params.append(severity)

        if device_mac:
            query += " AND device_mac = ?"
            params.append(device_mac.upper())

        if since:
            query += " AND timestamp >= ?"
            params.append(since)

        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)

        rows = self._db.fetchall(query, tuple(params))
        return [dict(r) for r in rows]

    def get_alert_stats(self) -> Dict[str, Any]:
        """Get alert statistics."""
        # Total alerts
        total = self._db.fetchone(
            "SELECT COUNT(*) as c FROM suricata_alerts"
        )

        # Today's alerts
        today = self._db.fetchone(
            """
            SELECT COUNT(*) as c FROM suricata_alerts
            WHERE timestamp >= datetime('now', 'start of day')
            """
        )

        # By severity
        by_severity = self._db.fetchall(
            """
            SELECT severity, COUNT(*) as c FROM suricata_alerts
            GROUP BY severity ORDER BY severity
            """
        )

        # By category
        by_category = self._db.fetchall(
            """
            SELECT category, COUNT(*) as c FROM suricata_alerts
            GROUP BY category ORDER BY c DESC LIMIT 10
            """
        )

        # Top signatures
        top_sigs = self._db.fetchall(
            """
            SELECT signature, signature_id, COUNT(*) as c
            FROM suricata_alerts
            GROUP BY signature_id
            ORDER BY c DESC LIMIT 10
            """
        )

        # Top source IPs
        top_sources = self._db.fetchall(
            """
            SELECT src_ip, COUNT(*) as c FROM suricata_alerts
            GROUP BY src_ip ORDER BY c DESC LIMIT 10
            """
        )

        return {
            "total_alerts": total["c"] if total else 0,
            "today_alerts": today["c"] if today else 0,
            "by_severity": {
                SEVERITY_MAP.get(r["severity"], "unknown"): r["c"]
                for r in by_severity
            },
            "by_category": {r["category"]: r["c"] for r in by_category},
            "top_signatures": [
                {"signature": r["signature"], "id": r["signature_id"], "count": r["c"]}
                for r in top_sigs
            ],
            "top_sources": [
                {"ip": r["src_ip"], "count": r["c"]}
                for r in top_sources
            ],
            "suricata_status": self.check_suricata_running(),
        }

    def get_rules_info(self) -> Dict[str, Any]:
        """Get info about loaded Suricata rules (read-only)."""
        rules_dir = "/usr/local/etc/suricata/rules"
        info = {
            "rules_directory": rules_dir,
            "rule_files": [],
            "total_rules": 0,
        }

        if not os.path.exists(rules_dir):
            return info

        for filename in os.listdir(rules_dir):
            if filename.endswith(".rules"):
                filepath = os.path.join(rules_dir, filename)
                try:
                    with open(filepath, "r") as fh:
                        lines = fh.readlines()
                        rule_count = sum(
                            1 for line in lines
                            if line.strip() and not line.startswith("#")
                        )
                        info["rule_files"].append({
                            "name": filename,
                            "rules": rule_count,
                            "size": os.path.getsize(filepath),
                        })
                        info["total_rules"] += rule_count
                except Exception:
                    continue

        return info

    def should_block_ip(self, alert: SuricataAlert) -> bool:
        """
        Determine if an alert should trigger IP blocking.

        Criteria:
        - Severity 1 (critical) or 2 (high)
        - Categories: malware, trojan, exploit, etc.
        - Not from internal network (to avoid self-blocking)
        """
        # Don't block critical/high from internal
        internal_prefixes = ("192.168.", "10.", "172.16.", "172.17.", "172.18.",
                             "172.19.", "172.20.", "172.21.", "172.22.", "172.23.",
                             "172.24.", "172.25.", "172.26.", "172.27.", "172.28.",
                             "172.29.", "172.30.", "172.31.")

        # Check source - don't block internal devices
        if alert.src_ip.startswith(internal_prefixes):
            # For internal sources, we might quarantine the device instead
            return False

        # Check severity
        if alert.alert_severity > 2:  # Only critical and high
            return False

        # Check category
        block_categories = {
            "Malware Command and Control Activity Detected",
            "A Network Trojan was detected",
            "Attempted Information Leak",
            "Web Application Attack",
            "Exploit Kit Activity Detected",
            "Crypto Currency Mining Activity Detected",
        }

        for cat in block_categories:
            if cat.lower() in alert.alert_category.lower():
                return True

        return alert.alert_severity == 1  # Always block critical
