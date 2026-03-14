#!/usr/local/bin/python3
# Copyright (c) 2025-2026, NetShield Project
# Fusion VPN Engine - Asus VPN Fusion style multi-VPN management

"""
Fusion VPN Engine for NetShield.

Provides Asus VPN Fusion-style functionality:
- Multiple VPN profiles (OpenVPN, WireGuard)
- Per-device VPN assignment
- Exception lists (devices that bypass VPN)
- VPN Kill Switch
- Multiple simultaneous VPN connections
"""

import ipaddress
import json
import logging
import os
import re
import sqlite3
import subprocess
import time
from dataclasses import dataclass, asdict
from datetime import datetime
from typing import List, Dict, Optional, Any

log = logging.getLogger(__name__)

FUSION_DB = "/var/netshield/fusion_vpn.db"
OVPN_CONFIG_DIR = "/var/etc/openvpn-fusion"
WG_CONFIG_DIR = "/var/etc/wireguard-fusion"
PF_ANCHOR = "netshield_fusion_vpn"
PF_ANCHOR_FILE = "/var/etc/netshield_fusion_vpn.rules"
OPENVPN_BIN = "/usr/local/sbin/openvpn"
WG_BIN = "/usr/local/bin/wg"
RESOLV_BACKUP = "/var/etc/resolv.conf.fusion.bak"


@dataclass
class VpnProfile:
    """VPN Profile configuration."""
    id: int
    name: str
    protocol: str  # openvpn, wireguard
    config_file: str
    username: Optional[str]
    password: Optional[str]
    enabled: bool
    apply_to_all: bool
    kill_switch: bool
    status: str  # disconnected, connecting, connected, error
    interface: Optional[str]
    bytes_in: int
    bytes_out: int
    connected_since: Optional[str]
    created_at: str
    updated_at: str

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class DeviceAssignment:
    """Device to VPN profile assignment."""
    id: int
    device_mac: str
    device_name: Optional[str]
    profile_id: int
    profile_name: str
    enabled: bool
    created_at: str

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class ExceptionDevice:
    """Device that always bypasses VPN."""
    id: int
    device_mac: str
    device_name: Optional[str]
    reason: Optional[str]
    created_at: str

    def to_dict(self) -> dict:
        return asdict(self)


class FusionVpnEngine:
    """Manages Fusion VPN profiles and device assignments."""

    def __init__(self, db_path: str = FUSION_DB):
        self.db_path = db_path
        self._init_db()
        self._ensure_dirs()

    def _get_conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):
        """Initialize database schema."""
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        conn = self._get_conn()

        # VPN Profiles table
        conn.execute("""
            CREATE TABLE IF NOT EXISTS vpn_profiles (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE,
                protocol TEXT NOT NULL DEFAULT 'openvpn',
                config_file TEXT,
                username TEXT,
                password TEXT,
                enabled INTEGER DEFAULT 0,
                apply_to_all INTEGER DEFAULT 1,
                kill_switch INTEGER DEFAULT 0,
                status TEXT DEFAULT 'disconnected',
                interface TEXT,
                bytes_in INTEGER DEFAULT 0,
                bytes_out INTEGER DEFAULT 0,
                connected_since TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # Device assignments table
        conn.execute("""
            CREATE TABLE IF NOT EXISTS device_assignments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                device_mac TEXT NOT NULL,
                device_name TEXT,
                profile_id INTEGER NOT NULL,
                enabled INTEGER DEFAULT 1,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (profile_id) REFERENCES vpn_profiles(id) ON DELETE CASCADE,
                UNIQUE(device_mac, profile_id)
            )
        """)

        # Exception devices table (bypass VPN)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS exception_devices (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                device_mac TEXT NOT NULL UNIQUE,
                device_name TEXT,
                reason TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # Connection logs table
        conn.execute("""
            CREATE TABLE IF NOT EXISTS connection_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                profile_id INTEGER NOT NULL,
                event TEXT NOT NULL,
                details TEXT,
                timestamp TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """)

        conn.commit()
        conn.close()

    def _ensure_dirs(self):
        """Ensure config directories exist."""
        os.makedirs(OVPN_CONFIG_DIR, exist_ok=True)
        os.makedirs(WG_CONFIG_DIR, exist_ok=True)

    # ========== Profile Management ==========

    def get_profiles(self) -> List[VpnProfile]:
        """Get all VPN profiles."""
        conn = self._get_conn()
        cursor = conn.execute("SELECT * FROM vpn_profiles ORDER BY name")
        profiles = []
        for row in cursor:
            profiles.append(VpnProfile(
                id=row["id"],
                name=row["name"],
                protocol=row["protocol"],
                config_file=row["config_file"],
                username=row["username"],
                password="***" if row["password"] else None,  # Mask password
                enabled=bool(row["enabled"]),
                apply_to_all=bool(row["apply_to_all"]),
                kill_switch=bool(row["kill_switch"]),
                status=row["status"],
                interface=row["interface"],
                bytes_in=row["bytes_in"] or 0,
                bytes_out=row["bytes_out"] or 0,
                connected_since=row["connected_since"],
                created_at=row["created_at"],
                updated_at=row["updated_at"],
            ))
        conn.close()
        return profiles

    def get_profile(self, profile_id: int) -> Optional[VpnProfile]:
        """Get a single VPN profile."""
        conn = self._get_conn()
        cursor = conn.execute("SELECT * FROM vpn_profiles WHERE id = ?", (profile_id,))
        row = cursor.fetchone()
        conn.close()
        if not row:
            return None
        return VpnProfile(
            id=row["id"],
            name=row["name"],
            protocol=row["protocol"],
            config_file=row["config_file"],
            username=row["username"],
            password="***" if row["password"] else None,  # Mask password
            enabled=bool(row["enabled"]),
            apply_to_all=bool(row["apply_to_all"]),
            kill_switch=bool(row["kill_switch"]),
            status=row["status"],
            interface=row["interface"],
            bytes_in=row["bytes_in"] or 0,
            bytes_out=row["bytes_out"] or 0,
            connected_since=row["connected_since"],
            created_at=row["created_at"],
            updated_at=row["updated_at"],
        )

    def _get_profile_raw(self, profile_id: int) -> Optional[VpnProfile]:
        """Get profile with real password (for internal connect operations only)."""
        conn = self._get_conn()
        cursor = conn.execute("SELECT * FROM vpn_profiles WHERE id = ?", (profile_id,))
        row = cursor.fetchone()
        conn.close()
        if not row:
            return None
        return VpnProfile(
            id=row["id"], name=row["name"], protocol=row["protocol"],
            config_file=row["config_file"], username=row["username"],
            password=row["password"],  # Real password for auth
            enabled=bool(row["enabled"]), apply_to_all=bool(row["apply_to_all"]),
            kill_switch=bool(row["kill_switch"]), status=row["status"],
            interface=row["interface"], bytes_in=row["bytes_in"] or 0,
            bytes_out=row["bytes_out"] or 0, connected_since=row["connected_since"],
            created_at=row["created_at"], updated_at=row["updated_at"],
        )

    def create_profile(self, name: str, protocol: str, config_content: str,
                       username: str = None, password: str = None,
                       apply_to_all: bool = True, kill_switch: bool = False) -> dict:
        """Create a new VPN profile."""
        if protocol not in ("openvpn", "wireguard"):
            return {"status": "error", "message": f"Unsupported protocol: {protocol}"}

        # Save config file
        if protocol == "openvpn":
            config_path = os.path.join(OVPN_CONFIG_DIR, f"{name}.ovpn")
        else:
            config_path = os.path.join(WG_CONFIG_DIR, f"{name}.conf")

        try:
            with open(config_path, "w") as f:
                f.write(config_content)
        except Exception as e:
            return {"status": "error", "message": f"Failed to save config: {e}"}

        conn = self._get_conn()
        try:
            cursor = conn.execute("""
                INSERT INTO vpn_profiles (name, protocol, config_file, username, password,
                                          apply_to_all, kill_switch)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (name, protocol, config_path, username, password, int(apply_to_all), int(kill_switch)))
            conn.commit()
            profile_id = cursor.lastrowid
            conn.close()
            return {"status": "ok", "id": profile_id}
        except sqlite3.IntegrityError:
            conn.close()
            return {"status": "error", "message": f"Profile '{name}' already exists"}

    def update_profile(self, profile_id: int, **kwargs) -> dict:
        """Update a VPN profile."""
        allowed = {"name", "username", "password", "apply_to_all", "kill_switch", "enabled"}
        updates = {k: v for k, v in kwargs.items() if k in allowed}
        if not updates:
            return {"status": "error", "message": "No valid fields to update"}

        set_clause = ", ".join(f"{k} = ?" for k in updates.keys())
        values = list(updates.values()) + [profile_id]

        conn = self._get_conn()
        conn.execute(f"UPDATE vpn_profiles SET {set_clause}, updated_at = CURRENT_TIMESTAMP WHERE id = ?", values)
        conn.commit()
        conn.close()
        return {"status": "ok"}

    def delete_profile(self, profile_id: int) -> dict:
        """Delete a VPN profile."""
        profile = self.get_profile(profile_id)
        if not profile:
            return {"status": "error", "message": "Profile not found"}

        # Disconnect first if connected
        if profile.enabled:
            self.disconnect_profile(profile_id)

        # Remove config file
        if profile.config_file and os.path.exists(profile.config_file):
            try:
                os.remove(profile.config_file)
            except Exception:
                pass

        conn = self._get_conn()
        conn.execute("DELETE FROM vpn_profiles WHERE id = ?", (profile_id,))
        conn.commit()
        conn.close()
        return {"status": "ok"}

    # ========== Connection Management ==========

    def connect_profile(self, profile_id: int) -> dict:
        """Connect a VPN profile."""
        profile = self._get_profile_raw(profile_id)  # Need real password
        if not profile:
            return {"status": "error", "message": "Profile not found"}

        if profile.status == "connected":
            return {"status": "ok", "message": "Already connected"}

        # Check binary availability
        if profile.protocol == "openvpn" and not os.path.exists(OPENVPN_BIN):
            return {"status": "error", "message": f"OpenVPN not found at {OPENVPN_BIN}. Install: pkg install openvpn"}
        if profile.protocol == "wireguard" and not os.path.exists(WG_BIN):
            return {"status": "error", "message": f"WireGuard tools not found at {WG_BIN}. Install: pkg install wireguard-tools"}

        # Update status to connecting
        conn = self._get_conn()
        conn.execute("UPDATE vpn_profiles SET status = 'connecting', enabled = 1 WHERE id = ?", (profile_id,))
        conn.commit()
        conn.close()

        try:
            if profile.protocol == "openvpn":
                result = self._connect_openvpn(profile)
            elif profile.protocol == "wireguard":
                result = self._connect_wireguard(profile)
            else:
                result = {"status": "error", "message": "Unsupported protocol"}

            if result.get("status") == "ok":
                conn = self._get_conn()
                conn.execute("""
                    UPDATE vpn_profiles
                    SET status = 'connected', interface = ?, connected_since = CURRENT_TIMESTAMP
                    WHERE id = ?
                """, (result.get("interface", ""), profile_id))
                conn.commit()
                conn.close()
                self._apply_routing_rules()
            else:
                conn = self._get_conn()
                conn.execute("UPDATE vpn_profiles SET status = 'error', enabled = 0 WHERE id = ?", (profile_id,))
                conn.commit()
                conn.close()

            return result
        except Exception as e:
            conn = self._get_conn()
            conn.execute("UPDATE vpn_profiles SET status = 'error', enabled = 0 WHERE id = ?", (profile_id,))
            conn.commit()
            conn.close()
            return {"status": "error", "message": str(e)}

    def disconnect_profile(self, profile_id: int) -> dict:
        """Disconnect a VPN profile."""
        profile = self.get_profile(profile_id)
        if not profile:
            return {"status": "error", "message": "Profile not found"}

        try:
            if profile.protocol == "openvpn":
                self._disconnect_openvpn(profile)
            elif profile.protocol == "wireguard":
                self._disconnect_wireguard(profile)

            conn = self._get_conn()
            conn.execute("""
                UPDATE vpn_profiles
                SET status = 'disconnected', enabled = 0, interface = NULL, connected_since = NULL
                WHERE id = ?
            """, (profile_id,))
            conn.commit()
            conn.close()

            self._apply_routing_rules()
            return {"status": "ok"}
        except Exception as e:
            return {"status": "error", "message": str(e)}

    def _connect_openvpn(self, profile: VpnProfile) -> dict:
        """Start OpenVPN connection."""
        if not profile.config_file or not os.path.exists(profile.config_file):
            return {"status": "error", "message": "Config file not found"}

        # Create auth file if credentials provided
        auth_file = None
        if profile.username and profile.password:
            auth_file = f"/tmp/ovpn_auth_{profile.id}"
            with open(auth_file, "w") as f:
                f.write(f"{profile.username}\n{profile.password}\n")
            os.chmod(auth_file, 0o600)

        # Build command
        interface = f"tun_fusion{profile.id}"
        cmd = [
            OPENVPN_BIN,
            "--config", profile.config_file,
            "--dev", interface,
            "--dev-type", "tun",
            "--daemon", f"fusion_vpn_{profile.id}",
            "--writepid", f"/var/run/openvpn_fusion_{profile.id}.pid",
            "--status", f"/var/etc/openvpn-fusion/{profile.name}.status", "30",
            "--log-append", f"/var/log/openvpn_fusion_{profile.id}.log",
        ]
        if auth_file:
            cmd.extend(["--auth-user-pass", auth_file])

        log_file = f"/var/log/openvpn_fusion_{profile.id}.log"
        try:
            result = subprocess.run(cmd, capture_output=True, timeout=30)
            time.sleep(3)  # Wait for connection to establish

            # Check if process actually started
            pid_file = f"/var/run/openvpn_fusion_{profile.id}.pid"
            if result.returncode != 0 or not os.path.exists(pid_file):
                # Read log for real error
                err_msg = result.stderr.decode().strip() if result.stderr else ""
                if not err_msg and os.path.exists(log_file):
                    with open(log_file) as f:
                        lines = f.readlines()
                        err_msg = lines[-1].strip() if lines else "Unknown error"
                return {"status": "error", "message": f"OpenVPN failed: {err_msg}"}

            return {"status": "ok", "interface": interface}
        except subprocess.TimeoutExpired:
            return {"status": "error", "message": "OpenVPN connection timed out (30s)"}
        except Exception as e:
            return {"status": "error", "message": f"OpenVPN error: {str(e)}"}

    def _disconnect_openvpn(self, profile: VpnProfile):
        """Stop OpenVPN connection."""
        pid_file = f"/var/run/openvpn_fusion_{profile.id}.pid"
        if os.path.exists(pid_file):
            try:
                with open(pid_file) as f:
                    pid = int(f.read().strip())
                subprocess.run(["kill", str(pid)], capture_output=True)
                os.remove(pid_file)
            except Exception:
                pass
        # Also try to kill by name
        subprocess.run(["pkill", "-f", f"fusion_vpn_{profile.id}"], capture_output=True)

    def _connect_wireguard(self, profile: VpnProfile) -> dict:
        """Start WireGuard connection using native FreeBSD/OPNsense commands."""
        if not profile.config_file or not os.path.exists(profile.config_file):
            return {"status": "error", "message": "Config file not found"}

        interface = f"wg{profile.id + 1}"
        try:
            # Parse WireGuard config file
            wg_conf = self._parse_wg_config(profile.config_file)
            if not wg_conf:
                return {"status": "error", "message": "Failed to parse WireGuard config"}

            # Destroy interface if it exists
            subprocess.run(["ifconfig", interface, "destroy"], capture_output=True, timeout=5)

            # Create WireGuard interface
            subprocess.run(["ifconfig", interface, "create"], check=True, capture_output=True, timeout=10)

            # Write a stripped config (no [Interface] Address/DNS lines) for wg setconf
            wg_only_conf = f"/var/etc/wireguard-fusion/{interface}.conf"
            os.makedirs("/var/etc/wireguard-fusion", exist_ok=True)
            self._write_wg_stripped_config(wg_conf, wg_only_conf)

            # Apply WireGuard config
            subprocess.run([WG_BIN, "setconf", interface, wg_only_conf], check=True, capture_output=True, timeout=10)

            # Set interface address
            if wg_conf.get("address"):
                addr = wg_conf["address"].split(",")[0].strip()
                subprocess.run(["ifconfig", interface, "inet", addr], check=True, capture_output=True, timeout=5)

            # Set MTU
            mtu = wg_conf.get("mtu", "1420")
            subprocess.run(["ifconfig", interface, "mtu", str(mtu)], capture_output=True, timeout=5)

            # Bring interface up
            subprocess.run(["ifconfig", interface, "up"], check=True, capture_output=True, timeout=5)

            # Add routes for AllowedIPs
            endpoint_ip = wg_conf.get("endpoint_host")
            for allowed in wg_conf.get("allowed_ips", []):
                allowed = allowed.strip()
                if allowed == "0.0.0.0/0":
                    # Default route - add via interface with lower priority
                    subprocess.run(
                        ["route", "add", "-net", "0.0.0.0/1", "-interface", interface],
                        capture_output=True, timeout=5
                    )
                    subprocess.run(
                        ["route", "add", "-net", "128.0.0.0/1", "-interface", interface],
                        capture_output=True, timeout=5
                    )
                    # Route endpoint through default gateway to prevent loop
                    if endpoint_ip:
                        default_gw = self._get_default_gateway()
                        if default_gw:
                            subprocess.run(
                                ["route", "add", "-host", endpoint_ip, default_gw],
                                capture_output=True, timeout=5
                            )
                elif allowed:
                    subprocess.run(
                        ["route", "add", "-net", allowed, "-interface", interface],
                        capture_output=True, timeout=5
                    )

            # Set DNS if specified
            if wg_conf.get("dns"):
                self._set_wg_dns(wg_conf["dns"], interface)

            return {"status": "ok", "interface": interface}
        except subprocess.CalledProcessError as e:
            # Cleanup on failure
            subprocess.run(["ifconfig", interface, "destroy"], capture_output=True, timeout=5)
            stderr = e.stderr.decode() if e.stderr else str(e)
            return {"status": "error", "message": f"WireGuard failed: {stderr}"}
        except Exception as e:
            subprocess.run(["ifconfig", interface, "destroy"], capture_output=True, timeout=5)
            return {"status": "error", "message": f"WireGuard error: {str(e)}"}

    def _disconnect_wireguard(self, profile: VpnProfile):
        """Stop WireGuard connection."""
        interface = f"wg{profile.id + 1}"
        try:
            # Remove routes first
            if profile.config_file and os.path.exists(profile.config_file):
                wg_conf = self._parse_wg_config(profile.config_file)
                if wg_conf:
                    for allowed in wg_conf.get("allowed_ips", []):
                        allowed = allowed.strip()
                        if allowed == "0.0.0.0/0":
                            subprocess.run(["route", "delete", "-net", "0.0.0.0/1"], capture_output=True, timeout=5)
                            subprocess.run(["route", "delete", "-net", "128.0.0.0/1"], capture_output=True, timeout=5)
                            if wg_conf.get("endpoint_host"):
                                subprocess.run(["route", "delete", "-host", wg_conf["endpoint_host"]], capture_output=True, timeout=5)
                        elif allowed:
                            subprocess.run(["route", "delete", "-net", allowed], capture_output=True, timeout=5)
                    # Restore DNS
                    if wg_conf.get("dns"):
                        self._restore_dns()
            # Destroy interface
            subprocess.run(["ifconfig", interface, "destroy"], capture_output=True, timeout=5)
        except Exception:
            # Force destroy even if route cleanup fails
            subprocess.run(["ifconfig", interface, "destroy"], capture_output=True, timeout=5)

    # ========== Device Assignment ==========

    def get_device_assignments(self, profile_id: int = None) -> List[DeviceAssignment]:
        """Get device assignments, optionally filtered by profile."""
        conn = self._get_conn()
        if profile_id:
            cursor = conn.execute("""
                SELECT da.*, vp.name as profile_name
                FROM device_assignments da
                JOIN vpn_profiles vp ON da.profile_id = vp.id
                WHERE da.profile_id = ?
                ORDER BY da.device_name, da.device_mac
            """, (profile_id,))
        else:
            cursor = conn.execute("""
                SELECT da.*, vp.name as profile_name
                FROM device_assignments da
                JOIN vpn_profiles vp ON da.profile_id = vp.id
                ORDER BY vp.name, da.device_name, da.device_mac
            """)

        assignments = []
        for row in cursor:
            assignments.append(DeviceAssignment(
                id=row["id"],
                device_mac=row["device_mac"],
                device_name=row["device_name"],
                profile_id=row["profile_id"],
                profile_name=row["profile_name"],
                enabled=bool(row["enabled"]),
                created_at=row["created_at"],
            ))
        conn.close()
        return assignments

    def assign_device(self, profile_id: int, device_mac: str, device_name: str = None) -> dict:
        """Assign a device to a VPN profile."""
        conn = self._get_conn()
        try:
            conn.execute("""
                INSERT OR REPLACE INTO device_assignments (device_mac, device_name, profile_id, enabled)
                VALUES (?, ?, ?, 1)
            """, (device_mac.lower(), device_name, profile_id))
            conn.commit()
            conn.close()
            self._apply_routing_rules()
            return {"status": "ok"}
        except Exception as e:
            conn.close()
            return {"status": "error", "message": str(e)}

    def unassign_device(self, assignment_id: int) -> dict:
        """Remove a device assignment."""
        conn = self._get_conn()
        conn.execute("DELETE FROM device_assignments WHERE id = ?", (assignment_id,))
        conn.commit()
        conn.close()
        self._apply_routing_rules()
        return {"status": "ok"}

    # ========== Exception Devices ==========

    def get_exception_devices(self) -> List[ExceptionDevice]:
        """Get devices that bypass VPN."""
        conn = self._get_conn()
        cursor = conn.execute("SELECT * FROM exception_devices ORDER BY device_name, device_mac")
        exceptions = []
        for row in cursor:
            exceptions.append(ExceptionDevice(
                id=row["id"],
                device_mac=row["device_mac"],
                device_name=row["device_name"],
                reason=row["reason"],
                created_at=row["created_at"],
            ))
        conn.close()
        return exceptions

    def add_exception_device(self, device_mac: str, device_name: str = None, reason: str = None) -> dict:
        """Add a device to exception list (bypass VPN)."""
        conn = self._get_conn()
        try:
            conn.execute("""
                INSERT OR REPLACE INTO exception_devices (device_mac, device_name, reason)
                VALUES (?, ?, ?)
            """, (device_mac.lower(), device_name, reason))
            conn.commit()
            conn.close()
            self._apply_routing_rules()
            return {"status": "ok"}
        except Exception as e:
            conn.close()
            return {"status": "error", "message": str(e)}

    def remove_exception_device(self, exception_id: int) -> dict:
        """Remove a device from exception list."""
        conn = self._get_conn()
        conn.execute("DELETE FROM exception_devices WHERE id = ?", (exception_id,))
        conn.commit()
        conn.close()
        self._apply_routing_rules()
        return {"status": "ok"}

    # ========== Routing & Firewall ==========

    def _mac_to_ip(self, mac: str) -> Optional[str]:
        """Resolve MAC address to IP via ARP table."""
        try:
            r = subprocess.run(["arp", "-an"], capture_output=True, text=True, timeout=5)
            # Format: ? (192.168.1.10) at aa:bb:cc:dd:ee:ff on em0
            for line in r.stdout.splitlines():
                if mac.lower() in line.lower():
                    m = re.search(r'\((\d+\.\d+\.\d+\.\d+)\)', line)
                    if m:
                        return m.group(1)
        except Exception:
            pass
        return None

    def _apply_routing_rules(self):
        """Generate and load PF anchor rules for per-device VPN routing.

        Rules logic:
        1. Exception devices → pass out on WAN gateway (skip VPN)
        2. Assigned devices → route-to VPN interface
        3. apply_to_all profiles → all LAN traffic routes through VPN
        4. Kill switch → block traffic if VPN interface is down
        """
        rules = []
        rules.append("# NetShield Fusion VPN routing rules")
        rules.append(f"# Generated {datetime.now().isoformat()}")
        rules.append("")

        conn = self._get_conn()

        # Get connected profiles with interfaces
        profiles = {}
        for row in conn.execute(
            "SELECT * FROM vpn_profiles WHERE status = 'connected' AND interface IS NOT NULL"
        ):
            profiles[row["id"]] = dict(row)

        if not profiles:
            # No connected VPNs — flush anchor and return
            conn.close()
            self._load_pf_rules("")
            return

        # 1. Exception devices — always bypass VPN
        exception_ips = []
        for row in conn.execute("SELECT device_mac FROM exception_devices"):
            ip = self._mac_to_ip(row["device_mac"])
            if ip:
                exception_ips.append(ip)

        if exception_ips:
            rules.append("# Exception devices — bypass VPN")
            for ip in exception_ips:
                rules.append(f"pass out quick on egress from {ip} to any")
            rules.append("")

        # 2. Per-device assignments — route specific devices through specific VPNs
        rules.append("# Per-device VPN assignments")
        for row in conn.execute("""
            SELECT da.device_mac, da.profile_id
            FROM device_assignments da
            WHERE da.enabled = 1
        """):
            pid = row["profile_id"]
            if pid not in profiles:
                continue
            iface = profiles[pid]["interface"]
            ip = self._mac_to_ip(row["device_mac"])
            if ip and iface:
                rules.append(f"pass out quick on {iface} route-to ({iface}) from {ip} to any")
        rules.append("")

        # 3. apply_to_all profiles — route all remaining LAN traffic
        for pid, p in profiles.items():
            if p["apply_to_all"] and p["interface"]:
                iface = p["interface"]
                rules.append(f"# Profile '{p['name']}' — route all traffic")
                rules.append(f"pass out on {iface} route-to ({iface}) from any to any")

                # 4. Kill switch — block if VPN down
                if p["kill_switch"]:
                    rules.append(f"# Kill switch for '{p['name']}'")
                    rules.append(f"block drop out quick on egress from any to any")

        conn.close()

        rule_text = "\n".join(rules) + "\n"
        self._load_pf_rules(rule_text)

    def _load_pf_rules(self, rule_text: str):
        """Write rules to file and load into PF anchor."""
        try:
            os.makedirs(os.path.dirname(PF_ANCHOR_FILE), exist_ok=True)
            with open(PF_ANCHOR_FILE, "w") as f:
                f.write(rule_text)

            if rule_text.strip():
                # Load rules into the anchor
                subprocess.run(
                    ["pfctl", "-a", PF_ANCHOR, "-f", PF_ANCHOR_FILE],
                    capture_output=True, timeout=10
                )
                log.info("Fusion VPN PF rules loaded into anchor %s", PF_ANCHOR)
            else:
                # Flush the anchor
                subprocess.run(
                    ["pfctl", "-a", PF_ANCHOR, "-F", "rules"],
                    capture_output=True, timeout=10
                )
                log.info("Fusion VPN PF anchor flushed (no connected profiles)")
        except Exception as e:
            log.error("Failed to load PF rules: %s", e)


    def _parse_wg_config(self, config_file):
        """Parse a WireGuard .conf file into a dict."""
        result = {
            "private_key": "", "address": "", "dns": "", "mtu": "1420",
            "public_key": "", "preshared_key": "", "endpoint": "",
            "endpoint_host": "", "allowed_ips": [], "persistent_keepalive": "",
        }
        section = ""
        try:
            with open(config_file) as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    if line.startswith("["):
                        section = line.strip("[]").lower()
                        continue
                    if "=" not in line:
                        continue
                    key, value = line.split("=", 1)
                    key = key.strip().lower()
                    value = value.strip()
                    if section == "interface":
                        if key == "privatekey":
                            result["private_key"] = value
                        elif key == "address":
                            result["address"] = value
                        elif key == "dns":
                            result["dns"] = value
                        elif key == "mtu":
                            result["mtu"] = value
                    elif section == "peer":
                        if key == "publickey":
                            result["public_key"] = value
                        elif key == "presharedkey":
                            result["preshared_key"] = value
                        elif key == "endpoint":
                            result["endpoint"] = value
                            if ":" in value:
                                result["endpoint_host"] = value.rsplit(":", 1)[0]
                        elif key == "allowedips":
                            result["allowed_ips"] = [ip.strip() for ip in value.split(",")]
                        elif key == "persistentkeepalive":
                            result["persistent_keepalive"] = value
        except Exception:
            return None
        return result

    def _write_wg_stripped_config(self, wg_conf, output_path):
        """Write a wg-compatible config (no Interface Address/DNS/MTU)."""
        lines = ["[Interface]"]
        if wg_conf.get("private_key"):
            lines.append("PrivateKey = " + wg_conf["private_key"])
        lines.append("")
        lines.append("[Peer]")
        if wg_conf.get("public_key"):
            lines.append("PublicKey = " + wg_conf["public_key"])
        if wg_conf.get("preshared_key"):
            lines.append("PresharedKey = " + wg_conf["preshared_key"])
        if wg_conf.get("endpoint"):
            lines.append("Endpoint = " + wg_conf["endpoint"])
        if wg_conf.get("allowed_ips"):
            lines.append("AllowedIPs = " + ", ".join(wg_conf["allowed_ips"]))
        if wg_conf.get("persistent_keepalive"):
            lines.append("PersistentKeepalive = " + wg_conf["persistent_keepalive"])
        lines.append("")
        with open(output_path, "w") as f:
            f.write("\n".join(lines))

    def _get_default_gateway(self):
        """Get the current default gateway."""
        try:
            r = subprocess.run(
                ["route", "-n", "get", "default"],
                capture_output=True, text=True, timeout=5
            )
            for line in r.stdout.splitlines():
                if "gateway:" in line:
                    return line.split("gateway:")[1].strip()
        except Exception:
            pass
        return ""

    def _set_wg_dns(self, dns_str, interface):
        """Configure DNS forwarding for WireGuard tunnel via Unbound."""
        dns_servers = [d.strip() for d in dns_str.split(",") if d.strip()]
        if not dns_servers:
            return

        # On OPNsense, Unbound handles DNS. Add forward-zone for tunnel DNS.
        fwd_conf = "/var/unbound/forward-fusion.conf"
        try:
            # Backup existing resolv.conf
            if os.path.exists("/etc/resolv.conf") and not os.path.exists(RESOLV_BACKUP):
                with open("/etc/resolv.conf") as f:
                    with open(RESOLV_BACKUP, "w") as bak:
                        bak.write(f.read())

            # Write Unbound forward config for all zones through VPN DNS
            lines = ["# Fusion VPN DNS forwarding\n", "forward-zone:\n", '    name: "."\n']
            for dns in dns_servers:
                lines.append(f"    forward-addr: {dns}\n")
            with open(fwd_conf, "w") as f:
                f.writelines(lines)

            # Reload Unbound to pick up new forwards
            subprocess.run(
                ["configctl", "dns", "reload"],
                capture_output=True, timeout=15
            )
            log.info("DNS forwarding set to %s via interface %s", dns_servers, interface)
        except Exception as e:
            log.error("Failed to set WireGuard DNS: %s", e)

    def _restore_dns(self):
        """Remove Fusion VPN DNS forwarding and restore defaults."""
        fwd_conf = "/var/unbound/forward-fusion.conf"
        try:
            if os.path.exists(fwd_conf):
                os.remove(fwd_conf)
            # Restore original resolv.conf if we backed it up
            if os.path.exists(RESOLV_BACKUP):
                with open(RESOLV_BACKUP) as bak:
                    with open("/etc/resolv.conf", "w") as f:
                        f.write(bak.read())
                os.remove(RESOLV_BACKUP)
            # Reload Unbound
            subprocess.run(
                ["configctl", "dns", "reload"],
                capture_output=True, timeout=15
            )
            log.info("DNS restored to defaults")
        except Exception as e:
            log.error("Failed to restore DNS: %s", e)

    # ========== Status & Stats ==========

    def get_status(self) -> dict:
        """Get overall Fusion VPN status."""
        profiles = self.get_profiles()
        connected = [p for p in profiles if p.status == "connected"]
        total_bytes_in = sum(p.bytes_in for p in profiles)
        total_bytes_out = sum(p.bytes_out for p in profiles)

        return {
            "total_profiles": len(profiles),
            "connected_profiles": len(connected),
            "total_bytes_in": total_bytes_in,
            "total_bytes_out": total_bytes_out,
            "profiles": [p.to_dict() for p in profiles],
        }

    def update_traffic_stats(self):
        """Update traffic statistics for connected profiles."""
        profiles = [p for p in self.get_profiles() if p.status == "connected"]
        for profile in profiles:
            if profile.protocol == "openvpn":
                stats = self._get_openvpn_stats(profile)
            elif profile.protocol == "wireguard":
                stats = self._get_wireguard_stats(profile)
            else:
                continue

            if stats:
                conn = self._get_conn()
                conn.execute("""
                    UPDATE vpn_profiles SET bytes_in = ?, bytes_out = ? WHERE id = ?
                """, (stats.get("bytes_in", 0), stats.get("bytes_out", 0), profile.id))
                conn.commit()
                conn.close()

    def _get_openvpn_stats(self, profile: VpnProfile) -> dict:
        """Get OpenVPN traffic stats from status file."""
        status_file = f"/var/etc/openvpn-fusion/{profile.name}.status"
        if not os.path.exists(status_file):
            return {}
        try:
            with open(status_file) as f:
                content = f.read()
            # Parse status file for traffic stats
            bytes_in = 0
            bytes_out = 0
            for line in content.split("\n"):
                if line.startswith("TCP/UDP read bytes"):
                    bytes_in = int(line.split(",")[1]) if "," in line else 0
                elif line.startswith("TCP/UDP write bytes"):
                    bytes_out = int(line.split(",")[1]) if "," in line else 0
            return {"bytes_in": bytes_in, "bytes_out": bytes_out}
        except Exception:
            return {}

    def _get_wireguard_stats(self, profile: VpnProfile) -> dict:
        """Get WireGuard traffic stats."""
        try:
            result = subprocess.run(
                [WG_BIN, "show", f"wg{profile.id + 1}", "transfer"],
                capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0:
                # Format: <peer>\t<bytes_rx>\t<bytes_tx>
                parts = result.stdout.strip().split("\t")
                if len(parts) >= 3:
                    return {"bytes_in": int(parts[1]), "bytes_out": int(parts[2])}
        except Exception:
            pass
        return {}
