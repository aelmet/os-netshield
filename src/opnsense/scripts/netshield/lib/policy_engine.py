"""
SPDX-License-Identifier: BSD-2-Clause

Copyright (c) 2024 NetShield Contributors
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice,
   this list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
POSSIBILITY OF SUCH DAMAGE.

NetShield policy_engine.py — Policy loading and evaluation from OPNsense config.xml.

Policy schema (as stored in config.xml under OPNsense/NetShield/policies/policy):
  <policy>
    <uuid>...</uuid>
    <enabled>1</enabled>
    <name>Block Social Media</name>
    <description>...</description>
    <action>block</action>               <!-- block | allow | throttle | log -->
    <scope_type>network</scope_type>     <!-- network | vlan | device | device_category -->
    <scope_value></scope_value>          <!-- comma-sep VLAN IDs / MACs / IPs / categories -->
    <target_type>apps</target_type>      <!-- apps | web_categories | targetlists | all -->
    <target_value>facebook,instagram</target_value>  <!-- comma-sep names -->
    <schedule_days>mon,tue,wed,thu,fri</schedule_days>  <!-- or empty = always -->
    <schedule_start>08:00</schedule_start>  <!-- HH:MM, or empty -->
    <schedule_end>17:00</schedule_end>      <!-- HH:MM, or empty -->
    <throttle_kbps>512</throttle_kbps>     <!-- only for action=throttle -->
    <priority>100</priority>               <!-- lower = higher priority -->
  </policy>
"""

import logging
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from .config import get_netshield_model, load_config_xml

log = logging.getLogger(__name__)

# Valid action values
VALID_ACTIONS = {"block", "allow", "throttle", "log"}

# Valid scope types
VALID_SCOPE_TYPES = {"network", "vlan", "device", "device_category"}

# Valid target types
VALID_TARGET_TYPES = {"apps", "web_categories", "targetlists", "all"}

# Day-of-week name to Python weekday number (Monday=0)
_DAY_MAP = {
    "mon": 0, "monday": 0,
    "tue": 1, "tuesday": 1,
    "wed": 2, "wednesday": 2,
    "thu": 3, "thursday": 3,
    "fri": 4, "friday": 4,
    "sat": 5, "saturday": 5,
    "sun": 6, "sunday": 6,
}


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _text(elem: Optional[ET.Element], tag: str, default: str = "") -> str:
    """Safely get text of a child element."""
    if elem is None:
        return default
    child = elem.find(tag)
    if child is None or child.text is None:
        return default
    return child.text.strip()


def _parse_policy(policy_elem: ET.Element) -> Optional[Dict[str, Any]]:
    """Parse a <policy> XML element into a dict. Returns None if invalid."""
    uuid = policy_elem.get("uuid", "").strip()
    enabled = _text(policy_elem, "enabled", "1")
    name = _text(policy_elem, "name")
    action = _text(policy_elem, "action", "block").lower()
    scope_type = _text(policy_elem, "scope_type", "network").lower()
    scope_value = _text(policy_elem, "scope_value", "")
    target_type = _text(policy_elem, "target_type", "all").lower()
    target_value = _text(policy_elem, "target_value", "")
    schedule_days = _text(policy_elem, "schedule_days", "")
    schedule_start = _text(policy_elem, "schedule_start", "")
    schedule_end = _text(policy_elem, "schedule_end", "")
    throttle_kbps_str = _text(policy_elem, "throttle_kbps", "0")
    priority_str = _text(policy_elem, "priority", "100")

    if action not in VALID_ACTIONS:
        log.warning("Policy '%s': unknown action '%s', skipping", name, action)
        return None
    if scope_type not in VALID_SCOPE_TYPES:
        log.warning("Policy '%s': unknown scope_type '%s', skipping", name, scope_type)
        return None
    if target_type not in VALID_TARGET_TYPES:
        log.warning("Policy '%s': unknown target_type '%s', skipping", name, target_type)
        return None

    try:
        throttle_kbps = int(throttle_kbps_str)
    except ValueError:
        throttle_kbps = 0

    try:
        priority = int(priority_str)
    except ValueError:
        priority = 100

    scope_values = [s.strip() for s in scope_value.split(",") if s.strip()]
    target_values = [t.strip() for t in target_value.split(",") if t.strip()]
    schedule_day_list = [d.strip().lower() for d in schedule_days.split(",") if d.strip()]

    return {
        "uuid": uuid,
        "enabled": enabled in ("1", "true", "yes"),
        "name": name,
        "description": _text(policy_elem, "description", ""),
        "action": action,
        "scope_type": scope_type,
        "scope_values": scope_values,
        "target_type": target_type,
        "target_values": target_values,
        "schedule_days": schedule_day_list,
        "schedule_start": schedule_start,
        "schedule_end": schedule_end,
        "throttle_kbps": throttle_kbps,
        "priority": priority,
    }


def _is_in_schedule(policy: Dict[str, Any], now: Optional[datetime] = None) -> bool:
    """
    Check if a policy's schedule is currently active.
    An empty schedule means always-active.
    """
    if now is None:
        now = datetime.now(timezone.utc)

    # Day-of-week check (empty = any day)
    if policy["schedule_days"]:
        current_weekday = now.weekday()  # Monday=0
        allowed_days = set()
        for day_str in policy["schedule_days"]:
            wd = _DAY_MAP.get(day_str)
            if wd is not None:
                allowed_days.add(wd)
        if allowed_days and current_weekday not in allowed_days:
            return False

    # Time range check (empty = any time)
    start_str = policy.get("schedule_start", "")
    end_str = policy.get("schedule_end", "")
    if start_str and end_str:
        try:
            start_h, start_m = (int(x) for x in start_str.split(":"))
            end_h, end_m = (int(x) for x in end_str.split(":"))
        except ValueError:
            log.warning("Policy '%s': invalid schedule time '%s'-'%s'",
                        policy.get("name"), start_str, end_str)
            return True  # Fail open on bad data

        current_minutes = now.hour * 60 + now.minute
        start_minutes = start_h * 60 + start_m
        end_minutes = end_h * 60 + end_m

        if start_minutes <= end_minutes:
            # Normal range (e.g. 08:00–17:00)
            if not (start_minutes <= current_minutes <= end_minutes):
                return False
        else:
            # Overnight range (e.g. 22:00–06:00)
            if not (current_minutes >= start_minutes or current_minutes <= end_minutes):
                return False

    return True


def _applies_to_device(policy: Dict[str, Any], context: Dict[str, Any]) -> bool:
    """Check if the policy scope matches the device context."""
    scope_type = policy["scope_type"]
    scope_values = policy["scope_values"]

    if scope_type == "network":
        return True  # Applies to all

    if scope_type == "vlan":
        device_vlan = str(context.get("vlan", ""))
        return not scope_values or device_vlan in scope_values

    if scope_type == "device":
        device_mac = context.get("mac", "").lower()
        device_ip = context.get("ip", "")
        if not scope_values:
            return True
        return device_mac in [v.lower() for v in scope_values] or device_ip in scope_values

    if scope_type == "device_category":
        device_category = context.get("category", "").lower()
        if not scope_values:
            return True
        return device_category in [v.lower() for v in scope_values]

    return False


def _applies_to_target(policy: Dict[str, Any], context: Dict[str, Any]) -> bool:
    """Check if the policy target matches the request context."""
    target_type = policy["target_type"]
    target_values = policy["target_values"]

    if target_type == "all":
        return True

    if target_type == "apps":
        request_app = context.get("app", "").lower()
        return not target_values or request_app in [v.lower() for v in target_values]

    if target_type == "web_categories":
        request_category = context.get("web_category", "").lower()
        return not target_values or request_category in [v.lower() for v in target_values]

    if target_type == "targetlists":
        request_list = context.get("targetlist", "").lower()
        return not target_values or request_list in [v.lower() for v in target_values]

    return False


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def load_policies(root: Optional[ET.Element] = None) -> List[Dict[str, Any]]:
    """
    Load all policies from OPNsense config.xml.
    Returns a list of policy dicts sorted by priority (lowest number first).
    """
    if root is None:
        root = load_config_xml()
    ns_model = get_netshield_model(root)
    if ns_model is None:
        log.debug("No NetShield model in config.xml — no policies loaded")
        return []

    policies = []
    for pol_elem in ns_model.findall(".//policies/policy"):
        parsed = _parse_policy(pol_elem)
        if parsed is not None:
            policies.append(parsed)

    # Sort by priority ascending (lower = higher priority)
    policies.sort(key=lambda p: p["priority"])
    log.debug("Loaded %d policies from config.xml", len(policies))
    return policies


def get_active_policies(
    root: Optional[ET.Element] = None,
    now: Optional[datetime] = None,
) -> List[Dict[str, Any]]:
    """
    Return only the enabled policies whose schedule is currently active.
    """
    if now is None:
        now = datetime.now(timezone.utc)
    all_policies = load_policies(root)
    active = [
        p for p in all_policies
        if p["enabled"] and _is_in_schedule(p, now)
    ]
    log.debug("get_active_policies: %d/%d policies active", len(active), len(all_policies))
    return active


def evaluate_policy(
    policy: Dict[str, Any],
    context: Dict[str, Any],
    now: Optional[datetime] = None,
) -> bool:
    """
    Check if a single policy applies to the given context.

    Context dict keys:
      mac          (str)  — device MAC address
      ip           (str)  — device IP address
      vlan         (str)  — VLAN ID the device is on
      category     (str)  — device category (smartphone, laptop, etc.)
      app          (str)  — identified application name
      web_category (str)  — web content category
      targetlist   (str)  — matched target list name

    Returns True if the policy applies (all conditions match), False otherwise.
    Note: Does NOT check enabled/schedule — call get_active_policies() first.
    """
    if not _applies_to_device(policy, context):
        return False
    if not _applies_to_target(policy, context):
        return False
    return True


def evaluate_request(
    context: Dict[str, Any],
    root: Optional[ET.Element] = None,
    now: Optional[datetime] = None,
) -> Optional[Dict[str, Any]]:
    """
    Evaluate all active policies against a context and return the first matching
    policy dict (highest priority), or None if no policy matches.

    The returned dict includes an "action" key indicating what to do.
    """
    if now is None:
        now = datetime.now(timezone.utc)
    active = get_active_policies(root, now)
    for policy in active:
        if evaluate_policy(policy, context, now):
            return policy
    return None
