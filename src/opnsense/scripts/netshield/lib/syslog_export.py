#!/usr/local/bin/python3
"""Syslog/SIEM export for NetShield alerts and events."""

import json
import logging
import socket
from datetime import datetime
from typing import Any, Dict, Optional

log = logging.getLogger("netshield.syslog_export")

# Syslog severity levels
SEVERITY_MAP = {
    "critical": 2,
    "high": 3,
    "medium": 4,
    "low": 5,
    "info": 6,
}

# Syslog facility: local0 = 16
FACILITY = 16


class SyslogExporter:
    """Exports NetShield events to remote syslog/SIEM systems."""

    def __init__(self, host: str = "", port: int = 514, protocol: str = "udp", enabled: bool = False):
        self._host = host
        self._port = port
        self._protocol = protocol.lower()
        self._enabled = enabled and bool(host)
        self._sock: Optional[socket.socket] = None

    def _connect(self) -> None:
        if self._sock:
            return
        if self._protocol == "tcp":
            self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._sock.settimeout(5)
            self._sock.connect((self._host, self._port))
        else:
            self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    def _send(self, message: str, severity: int = 6) -> bool:
        if not self._enabled:
            return False
        try:
            self._connect()
            pri = FACILITY * 8 + severity
            timestamp = datetime.utcnow().strftime("%b %d %H:%M:%S")
            syslog_msg = f"<{pri}>{timestamp} netshield: {message}"
            data = syslog_msg.encode("utf-8")
            if self._protocol == "tcp":
                self._sock.sendall(data + b"\n")
            else:
                self._sock.sendto(data, (self._host, self._port))
            return True
        except Exception as exc:
            log.warning("Syslog send failed: %s", exc)
            self._sock = None
            return False

    def export_alert(self, alert: Dict[str, Any]) -> bool:
        severity = SEVERITY_MAP.get(alert.get("severity", "info"), 6)
        msg = json.dumps({
            "event_type": "alert",
            "alert_type": alert.get("alert_type", ""),
            "device_mac": alert.get("device_mac", ""),
            "device_name": alert.get("device_name", ""),
            "severity": alert.get("severity", "info"),
            "message": alert.get("message", ""),
            "timestamp": alert.get("timestamp", ""),
        })
        return self._send(f"ALERT {msg}", severity)

    def export_flow(self, flow: Dict[str, Any]) -> bool:
        msg = json.dumps({
            "event_type": "flow",
            "src_mac": flow.get("src_mac", ""),
            "dst_ip": flow.get("dst_ip", ""),
            "dst_port": flow.get("dst_port", 0),
            "protocol": flow.get("protocol", ""),
            "app": flow.get("app", ""),
            "action": flow.get("action", "allow"),
            "bytes": flow.get("bytes", 0),
        })
        return self._send(f"FLOW {msg}")

    def export_threat(self, threat: Dict[str, Any]) -> bool:
        severity = SEVERITY_MAP.get(threat.get("severity", "high"), 3)
        msg = json.dumps({
            "event_type": "threat",
            "threat_type": threat.get("type", ""),
            "source_ip": threat.get("source_ip", ""),
            "dest_ip": threat.get("dest_ip", ""),
            "feed": threat.get("feed", ""),
            "indicator": threat.get("indicator", ""),
        })
        return self._send(f"THREAT {msg}", severity)

    def export_device_event(self, event_type: str, device: Dict[str, Any]) -> bool:
        msg = json.dumps({
            "event_type": f"device_{event_type}",
            "mac": device.get("mac", ""),
            "ip": device.get("ip", ""),
            "hostname": device.get("hostname", ""),
        })
        return self._send(f"DEVICE {msg}")

    def close(self) -> None:
        if self._sock:
            try:
                self._sock.close()
            except Exception:
                pass
            self._sock = None
