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
Parental Engine — Profile-based parental controls.
Supports time limits, bedtime windows, and category-based blocking.
Enforcement uses pf anchor rules keyed by device MAC address.
"""

import json
import logging
import subprocess
from dataclasses import dataclass, field
from datetime import date, datetime, time as dtime
from typing import Any, Dict, List, Optional

log = logging.getLogger(__name__)

# Valid content categories for parental filtering
VALID_CATEGORIES = {
    "adult", "gambling", "social", "gaming", "streaming", "vpn",
}

# pf anchor name used for parental enforcement
PF_ANCHOR = "netshield/parental"


@dataclass
class ParentalProfile:
    id: int
    name: str
    time_limit_daily_min: int = 0          # 0 means unlimited
    bedtime_start: Optional[str] = None    # "HH:MM" 24-h
    bedtime_end: Optional[str] = None      # "HH:MM" 24-h
    blocked_categories: List[str] = field(default_factory=list)
    allowed_categories: List[str] = field(default_factory=list)
    enabled: bool = True

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "time_limit_daily_min": self.time_limit_daily_min,
            "bedtime_start": self.bedtime_start,
            "bedtime_end": self.bedtime_end,
            "blocked_categories": self.blocked_categories,
            "allowed_categories": self.allowed_categories,
            "enabled": self.enabled,
        }


class ParentalEngine:
    """Manages parental control profiles and device assignments."""

    def __init__(self, db_module: Any) -> None:
        self._db = db_module
        self._init_tables()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _init_tables(self) -> None:
        self._db.execute("""
            CREATE TABLE IF NOT EXISTS parental_profiles (
                id                  INTEGER PRIMARY KEY AUTOINCREMENT,
                name                TEXT    NOT NULL UNIQUE,
                time_limit_daily_min INTEGER NOT NULL DEFAULT 0,
                bedtime_start       TEXT,
                bedtime_end         TEXT,
                blocked_categories  TEXT    NOT NULL DEFAULT '[]',
                allowed_categories  TEXT    NOT NULL DEFAULT '[]',
                enabled             INTEGER NOT NULL DEFAULT 1,
                created             TEXT    NOT NULL
            )
        """)
        self._db.execute("""
            CREATE TABLE IF NOT EXISTS parental_assignments (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                profile_id  INTEGER NOT NULL,
                device_mac  TEXT    NOT NULL UNIQUE,
                assigned    TEXT    NOT NULL
            )
        """)
        self._db.execute("""
            CREATE TABLE IF NOT EXISTS parental_usage (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                profile_id  INTEGER NOT NULL,
                date        TEXT    NOT NULL,
                minutes_used INTEGER NOT NULL DEFAULT 0,
                UNIQUE(profile_id, date)
            )
        """)
        self._db.commit()

    @staticmethod
    def _now() -> str:
        return datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")

    @staticmethod
    def _today() -> str:
        return date.today().strftime("%Y-%m-%d")

    @staticmethod
    def _current_time() -> dtime:
        return datetime.now().time().replace(second=0, microsecond=0)

    def _row_to_profile(self, row: Dict[str, Any]) -> ParentalProfile:
        return ParentalProfile(
            id=row["id"],
            name=row["name"],
            time_limit_daily_min=row["time_limit_daily_min"],
            bedtime_start=row["bedtime_start"],
            bedtime_end=row["bedtime_end"],
            blocked_categories=json.loads(row.get("blocked_categories", "[]") or "[]"),
            allowed_categories=json.loads(row.get("allowed_categories", "[]") or "[]"),
            enabled=bool(row["enabled"]),
        )

    @staticmethod
    def _parse_time(value: str) -> Optional[dtime]:
        if not value:
            return None
        try:
            parts = value.split(":")
            return dtime(int(parts[0]), int(parts[1]))
        except (ValueError, IndexError):
            return None

    @staticmethod
    def _is_in_bedtime(start_str: Optional[str], end_str: Optional[str]) -> bool:
        """Return True if current time falls within the bedtime window."""
        start = ParentalEngine._parse_time(start_str)
        end = ParentalEngine._parse_time(end_str)
        if start is None or end is None:
            return False
        now = ParentalEngine._current_time()
        if start <= end:
            # e.g. 22:00 -> 06:00 crosses midnight; handle both cases
            return start <= now <= end
        else:
            # Window crosses midnight: 22:00 -> 06:00
            return now >= start or now <= end

    # ------------------------------------------------------------------
    # Profile CRUD
    # ------------------------------------------------------------------

    def add_profile(
        self,
        name: str,
        time_limit_daily_min: int = 0,
        bedtime_start: Optional[str] = None,
        bedtime_end: Optional[str] = None,
        blocked_categories: Optional[List[str]] = None,
        allowed_categories: Optional[List[str]] = None,
        enabled: bool = True,
    ) -> Dict[str, Any]:
        if not name:
            return {"result": "failed", "message": "name is required"}

        blocked = [c for c in (blocked_categories or []) if c in VALID_CATEGORIES]
        allowed = [c for c in (allowed_categories or []) if c in VALID_CATEGORIES]

        self._db.execute(
            "INSERT INTO parental_profiles "
            "(name, time_limit_daily_min, bedtime_start, bedtime_end, "
            "blocked_categories, allowed_categories, enabled, created) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                name,
                int(time_limit_daily_min),
                bedtime_start,
                bedtime_end,
                json.dumps(blocked),
                json.dumps(allowed),
                1 if enabled else 0,
                self._now(),
            ),
        )
        self._db.commit()
        row = self._db.query(
            "SELECT id FROM parental_profiles WHERE name = ?", (name,)
        )
        profile_id = row[0]["id"] if row else None
        return {"result": "ok", "id": profile_id}

    def update_profile(
        self,
        profile_id: int,
        name: Optional[str] = None,
        time_limit_daily_min: Optional[int] = None,
        bedtime_start: Optional[str] = None,
        bedtime_end: Optional[str] = None,
        blocked_categories: Optional[List[str]] = None,
        allowed_categories: Optional[List[str]] = None,
        enabled: Optional[bool] = None,
    ) -> Dict[str, Any]:
        row = self._db.query(
            "SELECT * FROM parental_profiles WHERE id = ?", (profile_id,)
        )
        if not row:
            return {"result": "failed", "message": "profile not found"}

        existing = row[0]
        updates: Dict[str, Any] = {}

        if name is not None:
            updates["name"] = name
        if time_limit_daily_min is not None:
            updates["time_limit_daily_min"] = int(time_limit_daily_min)
        if bedtime_start is not None:
            updates["bedtime_start"] = bedtime_start
        if bedtime_end is not None:
            updates["bedtime_end"] = bedtime_end
        if blocked_categories is not None:
            updates["blocked_categories"] = json.dumps(
                [c for c in blocked_categories if c in VALID_CATEGORIES]
            )
        if allowed_categories is not None:
            updates["allowed_categories"] = json.dumps(
                [c for c in allowed_categories if c in VALID_CATEGORIES]
            )
        if enabled is not None:
            updates["enabled"] = 1 if enabled else 0

        if not updates:
            return {"result": "ok", "message": "no changes"}

        set_clause = ", ".join("{} = ?".format(k) for k in updates)
        values = list(updates.values()) + [profile_id]
        self._db.execute(
            "UPDATE parental_profiles SET {} WHERE id = ?".format(set_clause),
            values,
        )
        self._db.commit()
        return {"result": "ok", "id": profile_id}

    def delete_profile(self, profile_id: int) -> Dict[str, Any]:
        self._db.execute(
            "DELETE FROM parental_assignments WHERE profile_id = ?", (profile_id,)
        )
        self._db.execute(
            "DELETE FROM parental_usage WHERE profile_id = ?", (profile_id,)
        )
        self._db.execute(
            "DELETE FROM parental_profiles WHERE id = ?", (profile_id,)
        )
        self._db.commit()
        return {"result": "ok"}

    def get_profiles(self, search: Optional[str] = None) -> List[Dict[str, Any]]:
        if search:
            rows = self._db.query(
                "SELECT * FROM parental_profiles WHERE name LIKE ? ORDER BY name",
                ("%{}%".format(search),),
            )
        else:
            rows = self._db.query(
                "SELECT * FROM parental_profiles ORDER BY name"
            )
        return [self._row_to_profile(dict(r)).to_dict() for r in rows]

    # ------------------------------------------------------------------
    # Device assignment
    # ------------------------------------------------------------------

    def assign_device(self, profile_id: int, device_mac: str) -> Dict[str, Any]:
        device_mac = device_mac.upper().strip()
        self._db.execute(
            "INSERT INTO parental_assignments (profile_id, device_mac, assigned) "
            "VALUES (?, ?, ?) "
            "ON CONFLICT(device_mac) DO UPDATE SET profile_id = excluded.profile_id, "
            "assigned = excluded.assigned",
            (profile_id, device_mac, self._now()),
        )
        self._db.commit()
        return {"result": "ok", "profile_id": profile_id, "device_mac": device_mac}

    def unassign_device(self, device_mac: str) -> Dict[str, Any]:
        device_mac = device_mac.upper().strip()
        self._db.execute(
            "DELETE FROM parental_assignments WHERE device_mac = ?", (device_mac,)
        )
        self._db.commit()
        return {"result": "ok", "device_mac": device_mac}

    def get_device_profile(self, device_mac: str) -> Optional[ParentalProfile]:
        device_mac = device_mac.upper().strip()
        row = self._db.query(
            "SELECT p.* FROM parental_profiles p "
            "JOIN parental_assignments a ON a.profile_id = p.id "
            "WHERE a.device_mac = ?",
            (device_mac,),
        )
        if not row:
            return None
        return self._row_to_profile(dict(row[0]))

    # ------------------------------------------------------------------
    # Access control
    # ------------------------------------------------------------------

    def check_access(
        self,
        device_mac: str,
        domain: Optional[str] = None,
        category: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Check whether access should be granted for a device.
        Returns dict with keys: allowed (bool), reason (str).
        """
        profile = self.get_device_profile(device_mac)
        if profile is None:
            return {"allowed": True, "reason": "no profile assigned"}

        if not profile.enabled:
            return {"allowed": True, "reason": "profile disabled"}

        # Bedtime check
        if self._is_in_bedtime(profile.bedtime_start, profile.bedtime_end):
            return {"allowed": False, "reason": "bedtime restriction"}

        # Daily time limit
        if profile.time_limit_daily_min > 0:
            usage = self._get_today_usage(profile.id)
            if usage >= profile.time_limit_daily_min:
                return {
                    "allowed": False,
                    "reason": "daily time limit reached ({} min)".format(
                        profile.time_limit_daily_min
                    ),
                }

        # Category check
        if category and category in profile.blocked_categories:
            return {"allowed": False, "reason": "category blocked: {}".format(category)}

        return {"allowed": True, "reason": "access granted"}

    def _get_today_usage(self, profile_id: int) -> int:
        row = self._db.query(
            "SELECT minutes_used FROM parental_usage WHERE profile_id = ? AND date = ?",
            (profile_id, self._today()),
        )
        return row[0]["minutes_used"] if row else 0

    # ------------------------------------------------------------------
    # Usage tracking
    # ------------------------------------------------------------------

    def get_usage(self, profile_id: int, days: int = 7) -> List[Dict[str, Any]]:
        rows = self._db.query(
            "SELECT date, minutes_used FROM parental_usage "
            "WHERE profile_id = ? ORDER BY date DESC LIMIT ?",
            (profile_id, days),
        )
        return [dict(r) for r in rows]

    def record_usage(self, profile_id: int, minutes: int) -> None:
        today = self._today()
        self._db.execute(
            "INSERT INTO parental_usage (profile_id, date, minutes_used) VALUES (?, ?, ?) "
            "ON CONFLICT(profile_id, date) DO UPDATE SET "
            "minutes_used = minutes_used + excluded.minutes_used",
            (profile_id, today, minutes),
        )
        self._db.commit()

    # ------------------------------------------------------------------
    # pf enforcement
    # ------------------------------------------------------------------

    def enforce(self, device_mac: str) -> Dict[str, Any]:
        """Block internet access for a device by adding a pf rule."""
        device_mac = device_mac.upper().strip()
        profile = self.get_device_profile(device_mac)
        if profile is None:
            return {"result": "failed", "message": "no profile for device"}

        # Derive IP from ARP table
        ip = self._mac_to_ip(device_mac)
        if not ip:
            return {"result": "failed", "message": "cannot resolve IP for MAC"}

        rule = "block out quick from {} to any\n".format(ip)
        try:
            result = subprocess.run(
                ["pfctl", "-a", PF_ANCHOR, "-f", "-"],
                input=rule,
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode == 0:
                log.info("pf block applied for %s (%s)", device_mac, ip)
                return {"result": "ok", "device_mac": device_mac, "ip": ip}
            return {"result": "failed", "message": result.stderr.strip()}
        except Exception as exc:
            log.warning("pf enforce failed for %s: %s", device_mac, exc)
            return {"result": "failed", "message": str(exc)}

    def release(self, device_mac: str) -> Dict[str, Any]:
        """Remove pf block rule for a device."""
        try:
            result = subprocess.run(
                ["pfctl", "-a", PF_ANCHOR, "-F", "rules"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode == 0:
                log.info("pf rules flushed for anchor %s (device: %s)", PF_ANCHOR, device_mac)
                return {"result": "ok", "device_mac": device_mac}
            return {"result": "failed", "message": result.stderr.strip()}
        except Exception as exc:
            log.warning("pf release failed for %s: %s", device_mac, exc)
            return {"result": "failed", "message": str(exc)}

    @staticmethod
    def _mac_to_ip(device_mac: str) -> Optional[str]:
        """Look up IP address from ARP cache for a given MAC."""
        try:
            result = subprocess.run(
                ["arp", "-an"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            mac_lower = device_mac.lower().replace("-", ":")
            for line in result.stdout.splitlines():
                if mac_lower in line.lower():
                    # Format: "? (192.168.1.10) at aa:bb:cc:dd:ee:ff on em0"
                    parts = line.split()
                    if len(parts) >= 2:
                        return parts[1].strip("()")
        except Exception as exc:
            log.debug("ARP lookup failed: %s", exc)
        return None
