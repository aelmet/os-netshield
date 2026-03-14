#!/usr/local/bin/python3
# Copyright (c) 2025-2026, NetShield Project
# All rights reserved.
#
# IDS/IPS Engine - Suricata integration with signature management,
# alert correlation, and auto-blocking capabilities.
# Based on Zenarmor IPS architecture.

"""
IDS/IPS Engine for NetShield.

Features:
- Suricata EVE JSON log parsing
- Real-time alert processing
- Signature management (enable/disable/custom)
- Auto-blocking on high-severity alerts
- Alert correlation and deduplication
- Integration with quarantine system
"""

import json
import logging
import os
import re
import socket
import subprocess
import threading
import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

SURICATA_EVE_LOG = "/var/log/suricata/eve.json"
SURICATA_RULES_DIR = "/usr/local/etc/suricata/rules"
SURICATA_CONFIG = "/usr/local/etc/suricata/suricata.yaml"
CUSTOM_RULES_FILE = "/usr/local/etc/suricata/rules/netshield-custom.rules"
DISABLED_SIDS_FILE = "/usr/local/etc/suricata/rules/netshield-disabled.conf"

# Alert severity mapping
SEVERITY_MAP = {
    1: "critical",
    2: "high",
    3: "medium",
    4: "low",
    5: "info",
}

# Auto-block thresholds
AUTO_BLOCK_SEVERITY = 2  # Block on high or critical
AUTO_BLOCK_THRESHOLD = 3  # Number of alerts before auto-block
AUTO_BLOCK_WINDOW = 300  # Seconds

# ---------------------------------------------------------------------------
# Data Classes
# ---------------------------------------------------------------------------


@dataclass
class IDSAlert:
    """Represents a single IDS alert from Suricata."""
    timestamp: str
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    protocol: str
    signature_id: int
    signature: str
    category: str
    severity: int
    action: str = "allowed"
    flow_id: int = 0
    payload: str = ""
    packet_info: Dict[str, Any] = field(default_factory=dict)

    @property
    def severity_name(self) -> str:
        return SEVERITY_MAP.get(self.severity, "unknown")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "src_ip": self.src_ip,
            "src_port": self.src_port,
            "dst_ip": self.dst_ip,
            "dst_port": self.dst_port,
            "protocol": self.protocol,
            "signature_id": self.signature_id,
            "signature": self.signature,
            "category": self.category,
            "severity": self.severity,
            "severity_name": self.severity_name,
            "action": self.action,
            "flow_id": self.flow_id,
        }


@dataclass
class IDSSignature:
    """Represents an IDS rule/signature."""
    sid: int
    msg: str
    classtype: str
    severity: int
    enabled: bool = True
    source: str = "emerging-threats"
    rev: int = 1
    raw_rule: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "sid": self.sid,
            "msg": self.msg,
            "classtype": self.classtype,
            "severity": self.severity,
            "enabled": self.enabled,
            "source": self.source,
            "rev": self.rev,
        }


# ---------------------------------------------------------------------------
# Suricata Control
# ---------------------------------------------------------------------------


class SuricataController:
    """Controls Suricata service operations."""

    @staticmethod
    def status() -> Dict[str, Any]:
        """Get Suricata service status."""
        try:
            result = subprocess.run(
                ["service", "suricata", "status"],
                capture_output=True,
                text=True,
                timeout=10
            )
            running = result.returncode == 0
            return {
                "status": "running" if running else "stopped",
                "pid": SuricataController._get_pid() if running else None,
                "uptime": SuricataController._get_uptime() if running else None,
            }
        except Exception as e:
            log.error("Failed to get Suricata status: %s", e)
            return {"status": "unknown", "error": str(e)}

    @staticmethod
    def _get_pid() -> Optional[int]:
        """Get Suricata PID."""
        try:
            result = subprocess.run(
                ["pgrep", "-f", "suricata"],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                return int(result.stdout.strip().split()[0])
        except Exception:
            pass
        return None

    @staticmethod
    def _get_uptime() -> Optional[str]:
        """Get Suricata process uptime."""
        pid = SuricataController._get_pid()
        if not pid:
            return None
        try:
            result = subprocess.run(
                ["ps", "-o", "etime=", "-p", str(pid)],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                return result.stdout.strip()
        except Exception:
            pass
        return None

    @staticmethod
    def start() -> Dict[str, Any]:
        """Start Suricata service."""
        try:
            result = subprocess.run(
                ["service", "suricata", "start"],
                capture_output=True,
                text=True,
                timeout=30
            )
            return {
                "status": "ok" if result.returncode == 0 else "error",
                "message": result.stdout + result.stderr,
            }
        except Exception as e:
            return {"status": "error", "message": str(e)}

    @staticmethod
    def stop() -> Dict[str, Any]:
        """Stop Suricata service."""
        try:
            result = subprocess.run(
                ["service", "suricata", "stop"],
                capture_output=True,
                text=True,
                timeout=30
            )
            return {
                "status": "ok" if result.returncode == 0 else "error",
                "message": result.stdout + result.stderr,
            }
        except Exception as e:
            return {"status": "error", "message": str(e)}

    @staticmethod
    def reload_rules() -> Dict[str, Any]:
        """Reload Suricata rules without restart."""
        try:
            # Send SIGUSR2 to reload rules
            pid = SuricataController._get_pid()
            if not pid:
                return {"status": "error", "message": "Suricata not running"}

            os.kill(pid, 12)  # SIGUSR2
            return {"status": "ok", "message": "Rules reload signal sent"}
        except Exception as e:
            return {"status": "error", "message": str(e)}


# ---------------------------------------------------------------------------
# EVE Log Parser
# ---------------------------------------------------------------------------


class EVELogParser:
    """Parses Suricata EVE JSON logs."""

    def __init__(self, log_path: str = SURICATA_EVE_LOG):
        self.log_path = log_path
        self._position = 0
        self._inode = None

    def _check_rotation(self) -> None:
        """Check if log file was rotated."""
        try:
            stat = os.stat(self.log_path)
            if self._inode is not None and stat.st_ino != self._inode:
                # File rotated, reset position
                self._position = 0
            self._inode = stat.st_ino
        except FileNotFoundError:
            self._position = 0
            self._inode = None

    def read_new_events(self, event_types: Optional[Set[str]] = None) -> List[Dict[str, Any]]:
        """Read new events from EVE log since last read."""
        if event_types is None:
            event_types = {"alert", "dns", "http", "tls", "flow"}

        self._check_rotation()
        events = []

        try:
            with open(self.log_path, "r") as f:
                f.seek(self._position)
                for line in f:
                    try:
                        event = json.loads(line.strip())
                        if event.get("event_type") in event_types:
                            events.append(event)
                    except json.JSONDecodeError:
                        continue
                self._position = f.tell()
        except FileNotFoundError:
            log.warning("EVE log not found: %s", self.log_path)
        except Exception as e:
            log.error("Error reading EVE log: %s", e)

        return events

    def parse_alert(self, event: Dict[str, Any]) -> Optional[IDSAlert]:
        """Parse an alert event into IDSAlert."""
        if event.get("event_type") != "alert":
            return None

        alert_info = event.get("alert", {})

        return IDSAlert(
            timestamp=event.get("timestamp", ""),
            src_ip=event.get("src_ip", ""),
            src_port=event.get("src_port", 0),
            dst_ip=event.get("dest_ip", ""),
            dst_port=event.get("dest_port", 0),
            protocol=event.get("proto", ""),
            signature_id=alert_info.get("signature_id", 0),
            signature=alert_info.get("signature", ""),
            category=alert_info.get("category", ""),
            severity=alert_info.get("severity", 3),
            action=alert_info.get("action", "allowed"),
            flow_id=event.get("flow_id", 0),
        )


# ---------------------------------------------------------------------------
# Signature Manager
# ---------------------------------------------------------------------------


class SignatureManager:
    """Manages IDS signatures/rules."""

    def __init__(self, rules_dir: str = SURICATA_RULES_DIR):
        self.rules_dir = Path(rules_dir)
        self._signatures: Dict[int, IDSSignature] = {}
        self._disabled_sids: Set[int] = set()
        self._load_disabled_sids()

    def _load_disabled_sids(self) -> None:
        """Load list of disabled SIDs."""
        try:
            if os.path.exists(DISABLED_SIDS_FILE):
                with open(DISABLED_SIDS_FILE, "r") as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith("#"):
                            try:
                                self._disabled_sids.add(int(line))
                            except ValueError:
                                continue
        except Exception as e:
            log.error("Error loading disabled SIDs: %s", e)

    def _save_disabled_sids(self) -> None:
        """Save list of disabled SIDs."""
        try:
            with open(DISABLED_SIDS_FILE, "w") as f:
                f.write("# NetShield disabled signatures\n")
                f.write(f"# Updated: {datetime.now().isoformat()}\n")
                for sid in sorted(self._disabled_sids):
                    f.write(f"{sid}\n")
        except Exception as e:
            log.error("Error saving disabled SIDs: %s", e)

    def scan_rules(self) -> int:
        """Scan rule files and index signatures."""
        self._signatures.clear()
        count = 0

        # Separate patterns for individual fields (order-independent)
        sid_re = re.compile(r'sid:(\d+)')
        msg_re = re.compile(r'msg:"([^"]+)"')
        classtype_re = re.compile(r'classtype:([^;]+)')
        priority_re = re.compile(r'priority:(\d+)')
        rev_re = re.compile(r'rev:(\d+)')

        for rule_file in self.rules_dir.glob("*.rules"):
            try:
                with open(rule_file, "r") as f:
                    source = rule_file.stem
                    for line in f:
                        line = line.strip()
                        if not line or line.startswith("#"):
                            continue

                        sid_m = sid_re.search(line)
                        if sid_m:
                            sid = int(sid_m.group(1))
                            msg_m = msg_re.search(line)
                            ct_m = classtype_re.search(line)
                            pri_m = priority_re.search(line)
                            rev_m = rev_re.search(line)

                            self._signatures[sid] = IDSSignature(
                                sid=sid,
                                msg=msg_m.group(1) if msg_m else "",
                                classtype=ct_m.group(1) if ct_m else "unknown",
                                severity=int(pri_m.group(1)) if pri_m else 3,
                                enabled=sid not in self._disabled_sids,
                                source=source,
                                rev=int(rev_m.group(1)) if rev_m else 1,
                                raw_rule=line,
                            )
                            count += 1
            except Exception as e:
                log.error("Error parsing rule file %s: %s", rule_file, e)

        log.info("Indexed %d signatures from %d rule files", count, len(list(self.rules_dir.glob("*.rules"))))
        return count

    def get_signature(self, sid: int) -> Optional[IDSSignature]:
        """Get a signature by SID."""
        return self._signatures.get(sid)

    def list_signatures(
        self,
        category: Optional[str] = None,
        enabled_only: bool = False,
        search: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> Tuple[List[IDSSignature], int]:
        """List signatures with filtering."""
        results = []

        for sig in self._signatures.values():
            if enabled_only and not sig.enabled:
                continue
            if category and sig.classtype != category:
                continue
            if search and search.lower() not in sig.msg.lower():
                continue
            results.append(sig)

        total = len(results)
        results = results[offset:offset + limit]
        return results, total

    def enable_signature(self, sid: int) -> bool:
        """Enable a signature."""
        if sid in self._signatures:
            self._signatures[sid].enabled = True
            self._disabled_sids.discard(sid)
            self._save_disabled_sids()
            return True
        return False

    def disable_signature(self, sid: int) -> bool:
        """Disable a signature."""
        if sid in self._signatures:
            self._signatures[sid].enabled = False
            self._disabled_sids.add(sid)
            self._save_disabled_sids()
            return True
        return False

    def add_custom_rule(
        self,
        action: str,
        protocol: str,
        src: str,
        dst: str,
        msg: str,
        classtype: str = "misc-activity",
        priority: int = 3,
    ) -> Optional[int]:
        """Add a custom rule."""
        try:
            # Generate new SID (custom rules start at 9000000)
            existing_custom = [s.sid for s in self._signatures.values() if s.sid >= 9000000]
            new_sid = max(existing_custom, default=8999999) + 1

            # Build rule
            rule = (
                f'{action} {protocol} {src} -> {dst} '
                f'(msg:"{msg}"; classtype:{classtype}; '
                f'sid:{new_sid}; rev:1; priority:{priority};)'
            )

            # Append to custom rules file
            with open(CUSTOM_RULES_FILE, "a") as f:
                f.write(f"\n# Added by NetShield: {datetime.now().isoformat()}\n")
                f.write(f"{rule}\n")

            # Add to index
            self._signatures[new_sid] = IDSSignature(
                sid=new_sid,
                msg=msg,
                classtype=classtype,
                severity=priority,
                enabled=True,
                source="netshield-custom",
                rev=1,
                raw_rule=rule,
            )

            return new_sid
        except Exception as e:
            log.error("Error adding custom rule: %s", e)
            return None

    def delete_custom_rule(self, sid: int) -> bool:
        """Delete a custom rule."""
        if sid < 9000000:
            return False  # Can only delete custom rules

        sig = self._signatures.get(sid)
        if not sig or sig.source != "netshield-custom":
            return False

        try:
            # Read and filter custom rules file
            lines = []
            skip_next = False
            with open(CUSTOM_RULES_FILE, "r") as f:
                for line in f:
                    if f"sid:{sid};" in line:
                        skip_next = True
                        continue
                    if skip_next and line.startswith("#"):
                        skip_next = False
                        continue
                    lines.append(line)

            with open(CUSTOM_RULES_FILE, "w") as f:
                f.writelines(lines)

            del self._signatures[sid]
            return True
        except Exception as e:
            log.error("Error deleting custom rule: %s", e)
            return False

    def get_categories(self) -> List[Dict[str, Any]]:
        """Get list of signature categories with counts."""
        categories = defaultdict(lambda: {"total": 0, "enabled": 0})

        for sig in self._signatures.values():
            categories[sig.classtype]["total"] += 1
            if sig.enabled:
                categories[sig.classtype]["enabled"] += 1

        return [
            {"name": name, "total": data["total"], "enabled": data["enabled"]}
            for name, data in sorted(categories.items())
        ]


# ---------------------------------------------------------------------------
# Alert Processor
# ---------------------------------------------------------------------------


class AlertProcessor:
    """Processes IDS alerts with correlation and auto-blocking."""

    def __init__(self, db_module, quarantine_module=None):
        self._db = db_module
        self._quarantine = quarantine_module
        self._alert_counts: Dict[str, List[float]] = defaultdict(list)
        self._init_tables()

    def _init_tables(self) -> None:
        """Initialize database tables."""
        self._db.execute("""
            CREATE TABLE IF NOT EXISTS ids_alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                src_ip TEXT NOT NULL,
                src_port INTEGER,
                dst_ip TEXT NOT NULL,
                dst_port INTEGER,
                protocol TEXT,
                signature_id INTEGER NOT NULL,
                signature TEXT,
                category TEXT,
                severity INTEGER NOT NULL,
                action TEXT,
                flow_id INTEGER,
                acknowledged INTEGER DEFAULT 0,
                auto_blocked INTEGER DEFAULT 0,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """)

        self._db.execute("""
            CREATE INDEX IF NOT EXISTS idx_ids_alerts_timestamp
            ON ids_alerts(timestamp DESC)
        """)

        self._db.execute("""
            CREATE INDEX IF NOT EXISTS idx_ids_alerts_src_ip
            ON ids_alerts(src_ip)
        """)

    def process_alert(self, alert: IDSAlert) -> Dict[str, Any]:
        """Process a single alert."""
        # Store in database
        self._db.execute(
            """
            INSERT INTO ids_alerts
            (timestamp, src_ip, src_port, dst_ip, dst_port, protocol,
             signature_id, signature, category, severity, action, flow_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                alert.timestamp, alert.src_ip, alert.src_port,
                alert.dst_ip, alert.dst_port, alert.protocol,
                alert.signature_id, alert.signature, alert.category,
                alert.severity, alert.action, alert.flow_id,
            )
        )

        result = {"stored": True, "auto_blocked": False}

        # Check for auto-block
        if alert.severity <= AUTO_BLOCK_SEVERITY:
            should_block = self._check_auto_block(alert.src_ip)
            if should_block and self._quarantine:
                self._quarantine.quarantine_ip(alert.src_ip, f"IDS: {alert.signature}")
                result["auto_blocked"] = True
                log.warning("Auto-blocked IP %s due to IDS alert: %s", alert.src_ip, alert.signature)

        return result

    def _check_auto_block(self, ip: str) -> bool:
        """Check if IP should be auto-blocked based on alert frequency."""
        now = time.time()
        cutoff = now - AUTO_BLOCK_WINDOW

        # Clean old entries
        self._alert_counts[ip] = [t for t in self._alert_counts[ip] if t > cutoff]

        # Add current
        self._alert_counts[ip].append(now)

        return len(self._alert_counts[ip]) >= AUTO_BLOCK_THRESHOLD

    def get_alerts(
        self,
        limit: int = 100,
        offset: int = 0,
        severity: Optional[int] = None,
        src_ip: Optional[str] = None,
        since: Optional[str] = None,
    ) -> Tuple[List[Dict[str, Any]], int]:
        """Get alerts with filtering."""
        where_clauses = []
        params = []

        if severity is not None:
            where_clauses.append("severity <= ?")
            params.append(severity)

        if src_ip:
            where_clauses.append("src_ip = ?")
            params.append(src_ip)

        if since:
            where_clauses.append("timestamp >= ?")
            params.append(since)

        where_sql = " AND ".join(where_clauses) if where_clauses else "1=1"

        # Get total count
        count_result = self._db.query(
            f"SELECT COUNT(*) as cnt FROM ids_alerts WHERE {where_sql}",
            tuple(params)
        )
        total = count_result[0]["cnt"] if count_result else 0

        # Get alerts
        alerts = self._db.query(
            f"""
            SELECT * FROM ids_alerts
            WHERE {where_sql}
            ORDER BY timestamp DESC
            LIMIT ? OFFSET ?
            """,
            tuple(params) + (limit, offset)
        )

        return alerts, total

    def get_stats(self) -> Dict[str, Any]:
        """Get alert statistics."""
        result = self._db.query("""
            SELECT
                COUNT(*) as total,
                SUM(CASE WHEN severity = 1 THEN 1 ELSE 0 END) as critical,
                SUM(CASE WHEN severity = 2 THEN 1 ELSE 0 END) as high,
                SUM(CASE WHEN severity = 3 THEN 1 ELSE 0 END) as medium,
                SUM(CASE WHEN severity = 4 THEN 1 ELSE 0 END) as low,
                SUM(CASE WHEN auto_blocked = 1 THEN 1 ELSE 0 END) as auto_blocked
            FROM ids_alerts
            WHERE timestamp >= datetime('now', '-24 hours')
        """)

        if result:
            return result[0]
        return {"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0, "auto_blocked": 0}

    def get_top_signatures(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Get most frequent signatures."""
        return self._db.query("""
            SELECT signature_id, signature, category, COUNT(*) as count,
                   MAX(severity) as max_severity
            FROM ids_alerts
            WHERE timestamp >= datetime('now', '-24 hours')
            GROUP BY signature_id
            ORDER BY count DESC
            LIMIT ?
        """, (limit,))

    def get_top_attackers(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Get most frequent source IPs."""
        return self._db.query("""
            SELECT src_ip, COUNT(*) as alert_count,
                   COUNT(DISTINCT signature_id) as unique_signatures,
                   MAX(severity) as max_severity
            FROM ids_alerts
            WHERE timestamp >= datetime('now', '-24 hours')
            GROUP BY src_ip
            ORDER BY alert_count DESC
            LIMIT ?
        """, (limit,))

    def acknowledge_alert(self, alert_id: int) -> bool:
        """Acknowledge an alert."""
        self._db.execute(
            "UPDATE ids_alerts SET acknowledged = 1 WHERE id = ?",
            (alert_id,)
        )
        return True

    def bulk_acknowledge(self, alert_ids: List[int]) -> int:
        """Acknowledge multiple alerts."""
        placeholders = ",".join("?" * len(alert_ids))
        self._db.execute(
            f"UPDATE ids_alerts SET acknowledged = 1 WHERE id IN ({placeholders})",
            tuple(alert_ids)
        )
        return len(alert_ids)


# ---------------------------------------------------------------------------
# IDS Engine (Main Class)
# ---------------------------------------------------------------------------


class IDSEngine:
    """Main IDS/IPS engine coordinating all components."""

    def __init__(self, db_module, quarantine_module=None):
        self.suricata = SuricataController()
        self.parser = EVELogParser()
        self.signatures = SignatureManager()
        self.processor = AlertProcessor(db_module, quarantine_module)
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._callbacks: List[Callable[[IDSAlert], None]] = []

    def start(self) -> Dict[str, Any]:
        """Start the IDS engine."""
        if self._running:
            return {"status": "ok", "message": "Already running"}

        # Ensure Suricata is running
        status = self.suricata.status()
        if status["status"] != "running":
            start_result = self.suricata.start()
            if start_result["status"] != "ok":
                return {"status": "error", "message": f"Failed to start Suricata: {start_result['message']}"}

        # Scan signatures
        sig_count = self.signatures.scan_rules()

        # Start processing thread
        self._running = True
        self._thread = threading.Thread(target=self._process_loop, daemon=True)
        self._thread.start()

        return {
            "status": "ok",
            "message": f"IDS engine started with {sig_count} signatures",
            "signatures_loaded": sig_count,
        }

    def stop(self) -> Dict[str, Any]:
        """Stop the IDS engine."""
        self._running = False
        if self._thread:
            self._thread.join(timeout=5)
        return {"status": "ok", "message": "IDS engine stopped"}

    def _process_loop(self) -> None:
        """Background loop to process EVE events."""
        while self._running:
            try:
                events = self.parser.read_new_events({"alert"})
                for event in events:
                    alert = self.parser.parse_alert(event)
                    if alert:
                        self.processor.process_alert(alert)
                        for callback in self._callbacks:
                            try:
                                callback(alert)
                            except Exception as e:
                                log.error("Alert callback error: %s", e)
            except Exception as e:
                log.error("IDS process loop error: %s", e)

            time.sleep(1)

    def register_callback(self, callback: Callable[[IDSAlert], None]) -> None:
        """Register a callback for new alerts."""
        self._callbacks.append(callback)

    def _is_running(self):
        """Check if IDS engine (suricata) is running."""
        import subprocess as _sp
        try:
            r = _sp.run(['pgrep', '-x', 'suricata'], capture_output=True, text=True, timeout=5)
            return r.returncode == 0
        except Exception:
            return False

    def get_status(self) -> Dict[str, Any]:
        """Get IDS engine status."""
        suricata_status = self.suricata.status()
        alert_stats = self.processor.get_stats()

        # Scan rules if not yet indexed
        if not self.signatures._signatures:
            self.signatures.scan_rules()

        return {
            'engine_running': self._is_running(),
            "suricata": suricata_status,
            "alerts_24h": alert_stats,
            "signatures_loaded": len(self.signatures._signatures),
        }

    def _ensure_signatures_loaded(self):
        """Ensure signatures are indexed."""
        if not self.signatures._signatures:
            self.signatures.scan_rules()

    # Signature management wrappers
    def list_signatures(self, **kwargs) -> Dict[str, Any]:
        self._ensure_signatures_loaded()
        sigs, total = self.signatures.list_signatures(**kwargs)
        return {
            "rows": [s.to_dict() for s in sigs],
            "total": total,
        }

    def enable_signature(self, sid: int) -> Dict[str, Any]:
        success = self.signatures.enable_signature(sid)
        if success:
            self.suricata.reload_rules()
        return {"status": "ok" if success else "error"}

    def disable_signature(self, sid: int) -> Dict[str, Any]:
        success = self.signatures.disable_signature(sid)
        if success:
            self.suricata.reload_rules()
        return {"status": "ok" if success else "error"}

    def add_custom_rule(self, **kwargs) -> Dict[str, Any]:
        sid = self.signatures.add_custom_rule(**kwargs)
        if sid:
            self.suricata.reload_rules()
            return {"status": "ok", "sid": sid}
        return {"status": "error", "message": "Failed to add rule"}

    def delete_custom_rule(self, sid: int) -> Dict[str, Any]:
        success = self.signatures.delete_custom_rule(sid)
        if success:
            self.suricata.reload_rules()
        return {"status": "ok" if success else "error"}

    # Alert wrappers
    def get_alerts(self, **kwargs) -> Dict[str, Any]:
        alerts, total = self.processor.get_alerts(**kwargs)
        return {"rows": alerts, "total": total}

    def get_alert_stats(self) -> Dict[str, Any]:
        return self.processor.get_stats()

    def get_top_signatures(self, limit: int = 10) -> List[Dict[str, Any]]:
        return self.processor.get_top_signatures(limit)

    def get_top_attackers(self, limit: int = 10) -> List[Dict[str, Any]]:
        return self.processor.get_top_attackers(limit)

    def acknowledge_alert(self, alert_id: int) -> Dict[str, Any]:
        success = self.processor.acknowledge_alert(alert_id)
        return {"status": "ok" if success else "error"}

    def get_categories(self) -> List[Dict[str, Any]]:
        self._ensure_signatures_loaded()
        return self.signatures.get_categories()
