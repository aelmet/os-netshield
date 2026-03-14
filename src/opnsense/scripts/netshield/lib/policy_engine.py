#!/usr/local/bin/python3
# Copyright (c) 2025-2026, NetShield Contributors
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice,
#    this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright notice,
#    this list of conditions and the following disclaimer in the documentation
#    and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
# SPDX-License-Identifier: BSD-2-Clause

"""
Policy Engine — Evaluate and enforce network policies.
Policies can block, throttle, or log traffic by app, category, device, or schedule.
Enforcement via pf rules (block) and ipfw/dummynet (throttle).
"""

import logging
import os
import subprocess
import time
import re
import ipaddress
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional

# Validation patterns for pf/ipfw rule components
VALID_INTERFACE = re.compile(r'^[a-z][a-z0-9_]{0,15}$')
VALID_PROTOCOLS = {'tcp', 'udp', 'icmp', 'any'}


def validate_ip(ip: str) -> bool:
    """Validate IP address for safe use in firewall rules."""
    if ip == 'any':
        return True
    try:
        addr = ipaddress.ip_address(ip)
        return not (addr.is_loopback or addr.is_unspecified)
    except ValueError:
        return False


def validate_interface(iface: str) -> bool:
    """Validate interface name."""
    return bool(VALID_INTERFACE.match(iface))


def validate_protocol(proto: str) -> bool:
    """Validate protocol name."""
    return proto.lower() in VALID_PROTOCOLS


def validate_port(port: int) -> bool:
    """Validate port number."""
    return isinstance(port, int) and 0 <= port <= 65535

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

VALID_ACTIONS = ("block", "throttle", "log", "allow")
PF_CONF_PATH = "/tmp/netshield_pf.conf"
IPFW_BIN = "/sbin/ipfw"
PFCTL_BIN = "/sbin/pfctl"

# Base ipfw pipe number to avoid collision with other rules
PIPE_BASE = 10000


# ---------------------------------------------------------------------------
# Policy dataclass
# ---------------------------------------------------------------------------


@dataclass
class Policy:
    """Represents a single traffic policy rule."""

    id: int
    name: str
    action: str                      # block | throttle | log | allow
    targets: Dict[str, List[str]]    # {"apps": [...], "categories": [...], "devices": [...]}
    schedule: str = ""               # cron-style expression, empty = always active
    priority: int = 100              # lower = higher priority
    enabled: bool = True
    bandwidth_kbps: int = 0          # only used when action == "throttle"
    created: str = ""
    updated: str = ""

    def matches(self, flow: Dict[str, Any]) -> bool:
        """Return True if this policy applies to *flow*.

        Checks: enabled flag, schedule, then target (app/category/device).
        """
        if not self.enabled:
            return False

        if self.schedule and not self._schedule_active():
            return False

        return self._target_matches(flow)

    def _target_matches(self, flow: Dict[str, Any]) -> bool:
        """Check if any target spec in the policy matches the flow."""
        app_name = flow.get("app_name", "Unknown")
        category = flow.get("category", "Unknown")
        device_mac = flow.get("device_mac", "")
        src_ip = flow.get("src_ip", "")

        # If no targets specified the policy matches everything
        apps = self.targets.get("apps", [])
        categories = self.targets.get("categories", [])
        devices = self.targets.get("devices", [])

        if not apps and not categories and not devices:
            return True

        if apps and app_name in apps:
            return True

        if categories and category in categories:
            return True

        if devices and (device_mac in devices or src_ip in devices):
            return True

        return False

    def _schedule_active(self) -> bool:
        """Check if the current time falls within the policy schedule.

        Simple day-of-week + hour range parser.
        Format examples:
          "mon-fri 08:00-18:00"  — weekdays business hours
          "sat,sun"              — weekends all day
          "daily 22:00-06:00"   — nightly (wraps midnight)
          ""                     — always active (handled by caller)
        """
        schedule = self.schedule.strip().lower()
        if not schedule:
            return True

        now = datetime.now()
        parts = schedule.split()

        # Parse day spec
        day_spec = parts[0] if parts else ""
        time_spec = parts[1] if len(parts) > 1 else ""

        if not self._day_matches(day_spec, now):
            return False

        if time_spec:
            return self._time_in_range(time_spec, now)

        return True

    def _day_matches(self, day_spec: str, now: datetime) -> bool:
        """Check if today matches the day specification."""
        _DAY_MAP = {
            "mon": 0, "tue": 1, "wed": 2, "thu": 3,
            "fri": 4, "sat": 5, "sun": 6,
            "weekday": None, "weekend": None, "daily": None,
        }
        weekday = now.weekday()  # 0=Monday

        if day_spec == "daily":
            return True
        if day_spec == "weekday":
            return weekday < 5
        if day_spec == "weekend":
            return weekday >= 5

        # Range like "mon-fri"
        if "-" in day_spec:
            parts = day_spec.split("-", 1)
            start_day = _DAY_MAP.get(parts[0])
            end_day = _DAY_MAP.get(parts[1])
            if start_day is not None and end_day is not None:
                if start_day <= end_day:
                    return start_day <= weekday <= end_day
                else:  # wraps: e.g. "fri-mon"
                    return weekday >= start_day or weekday <= end_day

        # Comma list like "sat,sun"
        if "," in day_spec:
            days = [d.strip() for d in day_spec.split(",")]
            return any(_DAY_MAP.get(d) == weekday for d in days)

        # Single day
        day_num = _DAY_MAP.get(day_spec)
        return day_num == weekday

    def _time_in_range(self, time_spec: str, now: datetime) -> bool:
        """Check if current time is within 'HH:MM-HH:MM' range."""
        try:
            start_str, end_str = time_spec.split("-", 1)
            sh, sm = map(int, start_str.split(":"))
            eh, em = map(int, end_str.split(":"))
            start_minutes = sh * 60 + sm
            end_minutes = eh * 60 + em
            now_minutes = now.hour * 60 + now.minute

            if start_minutes <= end_minutes:
                return start_minutes <= now_minutes <= end_minutes
            else:  # wraps midnight
                return now_minutes >= start_minutes or now_minutes <= end_minutes
        except (ValueError, IndexError):
            log.warning("Invalid time range spec: %s", time_spec)
            return True  # Fail open

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id":            self.id,
            "name":          self.name,
            "action":        self.action,
            "targets":       self.targets,
            "schedule":      self.schedule,
            "priority":      self.priority,
            "enabled":       self.enabled,
            "bandwidth_kbps":self.bandwidth_kbps,
            "created":       self.created,
            "updated":       self.updated,
        }


# ---------------------------------------------------------------------------
# Active rule tracker
# ---------------------------------------------------------------------------


@dataclass
class ActiveRule:
    """Tracks an enforced pf/ipfw rule for cleanup purposes."""
    policy_id: int
    flow_key: str
    rule_type: str          # "pf" or "dummynet"
    rule_text: str
    pipe_id: int = 0
    created: float = field(default_factory=time.time)


# ---------------------------------------------------------------------------
# PolicyEngine
# ---------------------------------------------------------------------------


class PolicyEngine:
    """Load policies from DB, evaluate against flows, and enforce via pf/ipfw."""

    def __init__(self, db_module: Any) -> None:
        """
        Args:
            db_module: The netshield db module (or compatible object) that
                       provides get_db() for policy persistence.
        """
        self._db = db_module
        self._policies: List[Policy] = []
        self._active_rules: Dict[str, ActiveRule] = {}
        self._pipe_counter: int = PIPE_BASE
        self._ensure_policy_table()
        self.reload_policies()

    # ------------------------------------------------------------------
    # DB schema
    # ------------------------------------------------------------------

    def _ensure_policy_table(self) -> None:
        """Create the policies table if it does not exist."""
        ddl = """
        CREATE TABLE IF NOT EXISTS policies (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            action TEXT NOT NULL DEFAULT 'log',
            targets TEXT NOT NULL DEFAULT '{}',
            schedule TEXT NOT NULL DEFAULT '',
            priority INTEGER NOT NULL DEFAULT 100,
            enabled INTEGER NOT NULL DEFAULT 1,
            bandwidth_kbps INTEGER NOT NULL DEFAULT 0,
            created TEXT NOT NULL,
            updated TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_policies_priority ON policies(priority);
        CREATE INDEX IF NOT EXISTS idx_policies_enabled ON policies(enabled);
        """
        try:
            with self._db.get_db() as conn:
                conn.executescript(ddl)
        except Exception as exc:  # pylint: disable=broad-except
            log.error("Failed to create policies table: %s", exc)

    # ------------------------------------------------------------------
    # Policy CRUD
    # ------------------------------------------------------------------

    def reload_policies(self) -> None:
        """Reload all enabled policies from the database, sorted by priority."""
        import json
        try:
            with self._db.get_db() as conn:
                rows = conn.execute(
                    "SELECT * FROM policies ORDER BY priority ASC"
                ).fetchall()
            self._policies = []
            for row in rows:
                try:
                    targets = json.loads(row["targets"]) if isinstance(row["targets"], str) else row["targets"]
                except (ValueError, TypeError):
                    targets = {}
                self._policies.append(Policy(
                    id=row["id"],
                    name=row["name"],
                    action=row["action"],
                    targets=targets,
                    schedule=row["schedule"],
                    priority=row["priority"],
                    enabled=bool(row["enabled"]),
                    bandwidth_kbps=row["bandwidth_kbps"],
                    created=row["created"],
                    updated=row["updated"],
                ))
            log.debug("Loaded %d policies from DB", len(self._policies))
        except Exception as exc:  # pylint: disable=broad-except
            log.error("Failed to reload policies: %s", exc)

    def add_policy(
        self,
        name: str,
        action: str,
        targets: Dict[str, List[str]],
        schedule: str = "",
        priority: int = 100,
        bandwidth_kbps: int = 0,
    ) -> int:
        """Insert a new policy and return its ID."""
        import json
        if action not in VALID_ACTIONS:
            raise ValueError(f"Invalid action '{action}'. Must be one of: {VALID_ACTIONS}")
        now = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
        with self._db.get_db() as conn:
            cur = conn.execute(
                """
                INSERT INTO policies (name, action, targets, schedule, priority,
                                      enabled, bandwidth_kbps, created, updated)
                VALUES (?, ?, ?, ?, ?, 1, ?, ?, ?)
                """,
                (name, action, json.dumps(targets), schedule, priority, bandwidth_kbps, now, now),
            )
            policy_id = cur.lastrowid
        self.reload_policies()
        log.info("Added policy id=%d name=%r action=%s", policy_id, name, action)
        return policy_id

    def update_policy(self, policy_id: int, **kwargs: Any) -> bool:
        """Update one or more fields of a policy. Returns True on success."""
        import json
        allowed = {"name", "action", "targets", "schedule", "priority", "enabled", "bandwidth_kbps"}
        updates = {k: v for k, v in kwargs.items() if k in allowed}
        if not updates:
            return False
        if "action" in updates and updates["action"] not in VALID_ACTIONS:
            raise ValueError(f"Invalid action: {updates['action']}")
        if "targets" in updates and isinstance(updates["targets"], dict):
            updates["targets"] = json.dumps(updates["targets"])
        if "enabled" in updates:
            updates["enabled"] = 1 if updates["enabled"] else 0
        now = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
        updates["updated"] = now
        set_clause = ", ".join(f"{k} = ?" for k in updates)
        values = list(updates.values()) + [policy_id]
        with self._db.get_db() as conn:
            cur = conn.execute(
                f"UPDATE policies SET {set_clause} WHERE id = ?", values
            )
            if cur.rowcount == 0:
                return False
        self.reload_policies()
        log.info("Updated policy id=%d fields=%s", policy_id, list(updates.keys()))
        return True

    def delete_policy(self, policy_id: int) -> bool:
        """Delete a policy by ID. Returns True on success."""
        with self._db.get_db() as conn:
            cur = conn.execute("DELETE FROM policies WHERE id = ?", (policy_id,))
            if cur.rowcount == 0:
                return False
        self.reload_policies()
        log.info("Deleted policy id=%d", policy_id)
        return True

    def toggle_policy(self, policy_id: int) -> Optional[bool]:
        """Toggle enabled/disabled. Returns the new enabled state, or None if not found."""
        with self._db.get_db() as conn:
            row = conn.execute(
                "SELECT enabled FROM policies WHERE id = ?", (policy_id,)
            ).fetchone()
            if not row:
                return None
            new_state = 0 if row["enabled"] else 1
            now = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
            conn.execute(
                "UPDATE policies SET enabled = ?, updated = ? WHERE id = ?",
                (new_state, now, policy_id)
            )
        self.reload_policies()
        return bool(new_state)

    def reorder_policy(self, policy_id: int, priority: int) -> bool:
        """Change the priority of a policy. Returns True on success."""
        return self.update_policy(policy_id, priority=priority)

    def list_policies(self) -> List[Dict[str, Any]]:
        """Return all policies as a list of dicts."""
        return [p.to_dict() for p in self._policies]

    # ------------------------------------------------------------------
    # Evaluation
    # ------------------------------------------------------------------

    def evaluate(self, flow: Dict[str, Any]) -> Optional[Policy]:
        """Find the highest-priority matching policy for *flow*.

        Policies are pre-sorted by priority (ascending = higher priority).
        Returns the first matching Policy, or None if no policy applies.
        """
        for policy in self._policies:
            if policy.matches(flow):
                return policy
        return None

    # ------------------------------------------------------------------
    # Enforcement
    # ------------------------------------------------------------------

    def enforce(self, flow: Dict[str, Any]) -> Optional[str]:
        """Evaluate and enforce the appropriate policy for *flow*.

        Returns the action taken ('block', 'throttle', 'log', 'allow', None).
        """
        policy = self.evaluate(flow)
        if policy is None:
            return None

        if policy.action == "block":
            self.enforce_block(flow, policy)
            return "block"
        elif policy.action == "throttle":
            self.enforce_throttle(flow, policy.bandwidth_kbps, policy)
            return "throttle"
        elif policy.action == "log":
            log.info(
                "POLICY LOG: policy=%r flow=%s->%s app=%s category=%s",
                policy.name,
                flow.get("src_ip", "?"),
                flow.get("dst_ip", "?"),
                flow.get("app_name", "Unknown"),
                flow.get("category", "Unknown"),
            )
            return "log"
        elif policy.action == "allow":
            return "allow"

        return None

    def enforce_block(self, flow: Dict[str, Any], policy: Optional[Policy] = None) -> bool:
        """Generate and apply a pf block rule for the flow."""
        src = flow.get("src_ip", "any")
        dst = flow.get("dst_ip", "any")
        dst_port = flow.get("dst_port", 0)
        iface = flow.get("interface", "em0")
        proto = flow.get("protocol", "tcp").lower()

        # SECURITY: Validate all inputs before building pf rule
        if not validate_ip(src):
            log.warning("BLOCK rejected: invalid src_ip %s", src)
            return False
        if not validate_ip(dst):
            log.warning("BLOCK rejected: invalid dst_ip %s", dst)
            return False
        if not validate_interface(iface):
            log.warning("BLOCK rejected: invalid interface %s", iface)
            return False
        if not validate_protocol(proto):
            log.warning("BLOCK rejected: invalid protocol %s", proto)
            return False
        if not validate_port(dst_port):
            log.warning("BLOCK rejected: invalid port %s", dst_port)
            return False

        if dst_port:
            rule = (
                f"block quick on {iface} proto {proto} "
                f"from {src} to {dst} port {dst_port}"
            )
        else:
            rule = f"block quick on {iface} proto {proto} from {src} to {dst}"

        success = self._apply_pf_rule(rule)
        if success:
            flow_key = f"{src}:{dst}:{dst_port}"
            self._active_rules[flow_key] = ActiveRule(
                policy_id=policy.id if policy else 0,
                flow_key=flow_key,
                rule_type="pf",
                rule_text=rule,
            )
            log.info("BLOCK applied: %s", rule)
        return success

    def enforce_throttle(
        self, flow: Dict[str, Any], bandwidth_kbps: int, policy: Optional[Policy] = None
    ) -> bool:
        """Create an ipfw dummynet pipe to throttle *flow* to *bandwidth_kbps*."""
        if bandwidth_kbps <= 0:
            log.warning("Throttle requested but bandwidth_kbps=%d is invalid", bandwidth_kbps)
            return False

        src = flow.get("src_ip", "any")
        dst = flow.get("dst_ip", "any")
        dst_port = flow.get("dst_port", 0)
        proto = flow.get("protocol", "tcp").lower()

        # SECURITY: Validate all inputs before building ipfw rule
        if not validate_ip(src):
            log.warning("THROTTLE rejected: invalid src_ip %s", src)
            return False
        if not validate_ip(dst):
            log.warning("THROTTLE rejected: invalid dst_ip %s", dst)
            return False
        if not validate_protocol(proto):
            log.warning("THROTTLE rejected: invalid protocol %s", proto)
            return False
        if not validate_port(dst_port):
            log.warning("THROTTLE rejected: invalid port %s", dst_port)
            return False

        pipe_id = self._pipe_counter
        self._pipe_counter += 1

        # Configure pipe bandwidth
        pipe_config = f"pipe {pipe_id} config bw {bandwidth_kbps}Kbit/s"
        if not self._apply_dummynet(pipe_config):
            return False

        # SECURITY: Build command as list, NOT string split (prevents injection)
        if dst_port:
            cmd_args = [IPFW_BIN, 'add', 'pipe', str(pipe_id), proto,
                        'from', src, 'to', dst, str(dst_port)]
            rule = f"add pipe {pipe_id} {proto} from {src} to {dst} {dst_port}"
        else:
            cmd_args = [IPFW_BIN, 'add', 'pipe', str(pipe_id), proto,
                        'from', src, 'to', dst]
            rule = f"add pipe {pipe_id} {proto} from {src} to {dst}"

        try:
            result = subprocess.run(
                cmd_args,
                capture_output=True, text=True, timeout=5
            )
            if result.returncode != 0:
                log.error("ipfw rule failed: %s | stderr: %s", rule, result.stderr.strip())
                return False
        except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
            log.error("ipfw not available: %s", exc)
            return False

        flow_key = f"{src}:{dst}:{dst_port}"
        self._active_rules[flow_key] = ActiveRule(
            policy_id=policy.id if policy else 0,
            flow_key=flow_key,
            rule_type="dummynet",
            rule_text=rule,
            pipe_id=pipe_id,
        )
        log.info("THROTTLE applied: pipe=%d bw=%dKbit/s for %s->%s", pipe_id, bandwidth_kbps, src, dst)
        return True

    def _apply_pf_rule(self, rule_text: str) -> bool:
        """Append *rule_text* to the netshield pf anchor and reload it."""
        try:
            # Read existing rules
            existing = ""
            if os.path.exists(PF_CONF_PATH):
                with open(PF_CONF_PATH, "r", encoding="utf-8") as fh:
                    existing = fh.read()

            # Avoid duplicate rules
            if rule_text in existing:
                return True

            with open(PF_CONF_PATH, "a", encoding="utf-8") as fh:
                fh.write(rule_text + "\n")

            # Load into the netshield anchor
            result = subprocess.run(
                [PFCTL_BIN, "-a", "netshield", "-f", PF_CONF_PATH],
                capture_output=True, text=True, timeout=5,
            )
            if result.returncode != 0:
                log.error("pfctl failed: %s", result.stderr.strip())
                return False
            return True
        except FileNotFoundError:
            log.error("pfctl not found at %s — pf enforcement unavailable", PFCTL_BIN)
            return False
        except subprocess.TimeoutExpired:
            log.error("pfctl timed out")
            return False
        except OSError as exc:
            log.error("Failed to write pf rule: %s", exc)
            return False

    def _apply_dummynet(self, pipe_config: str) -> bool:
        """Configure an ipfw dummynet pipe."""
        try:
            result = subprocess.run(
                [IPFW_BIN, "pipe"] + pipe_config.split()[1:],
                capture_output=True, text=True, timeout=5,
            )
            if result.returncode != 0:
                log.error("ipfw pipe config failed: %s | stderr: %s",
                          pipe_config, result.stderr.strip())
                return False
            return True
        except FileNotFoundError:
            log.error("ipfw not found at %s — dummynet unavailable", IPFW_BIN)
            return False
        except subprocess.TimeoutExpired:
            log.error("ipfw pipe config timed out")
            return False

    def flush_rules(self) -> int:
        """Remove all netshield pf rules and dummynet pipes. Returns count removed."""
        removed = 0

        # Clear pf anchor
        try:
            result = subprocess.run(
                [PFCTL_BIN, "-a", "netshield", "-F", "rules"],
                capture_output=True, text=True, timeout=5,
            )
            if result.returncode == 0:
                if os.path.exists(PF_CONF_PATH):
                    os.unlink(PF_CONF_PATH)
                log.info("Flushed netshield pf anchor")
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError) as exc:
            log.warning("Could not flush pf rules: %s", exc)

        # Remove dummynet pipes
        for rule_key, active_rule in list(self._active_rules.items()):
            if active_rule.rule_type == "dummynet" and active_rule.pipe_id:
                try:
                    subprocess.run(
                        [IPFW_BIN, "pipe", str(active_rule.pipe_id), "delete"],
                        capture_output=True, timeout=5,
                    )
                except (FileNotFoundError, subprocess.TimeoutExpired):
                    pass
            removed += 1
            del self._active_rules[rule_key]

        return removed

    def get_active_rules(self) -> List[Dict[str, Any]]:
        """Return a list of currently enforced rule dicts."""
        return [
            {
                "policy_id": r.policy_id,
                "flow_key":  r.flow_key,
                "rule_type": r.rule_type,
                "rule_text": r.rule_text,
                "pipe_id":   r.pipe_id,
                "created":   datetime.utcfromtimestamp(r.created).strftime("%Y-%m-%dT%H:%M:%SZ"),
            }
            for r in self._active_rules.values()
        ]
