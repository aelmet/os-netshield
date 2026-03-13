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

NetShield enforcement.py — Policy enforcement via pf rules and ipfw dummynet.

All pf rules are written to a named anchor "netshield" so that OPNsense's
own rules are never overwritten.  Anchor is expected to be declared in the
main /etc/pf.conf or via OPNsense plugin hooks.
"""

import logging
import os
import subprocess
import tempfile
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from . import db

log = logging.getLogger(__name__)

# pf anchor name (must be declared in parent ruleset)
PF_ANCHOR = "netshield"

# Paths
PF_RULES_PATH = "/tmp/netshield_pf.conf"
DUMMYNET_SCRIPT = "/tmp/netshield_dummynet.sh"

# Pipe ID base for dummynet (we use IDs 10000+)
DUMMYNET_PIPE_BASE = 10000

# ---------------------------------------------------------------------------
# pf rule generation
# ---------------------------------------------------------------------------

_PF_HEADER = """\
# NetShield pf anchor rules — generated file, do not edit.
# Loaded into anchor: {anchor}
#
# Generated: {ts}

"""

_QUARANTINE_HEADER = """\
# NetShield quarantine rules
#

"""


def _validate_mac(mac: str) -> bool:
    """Validate MAC address format."""
    import re
    return bool(re.fullmatch(r"[0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5}", mac))


def _validate_ip(ip: str) -> bool:
    """Validate IPv4 address."""
    import re
    return bool(re.fullmatch(
        r"(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)",
        ip,
    ))


def generate_pf_rules(policies: List[Dict[str, Any]]) -> str:
    """
    Generate pf anchor rule text from a list of active policy dicts
    (as returned by policy_engine.get_active_policies).

    Only block and log actions produce pf rules.
    Throttle rules are handled separately via dummynet.
    Allow rules are implicit (pf default pass).

    Returns the rule file content as a string.
    """
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    lines = [_PF_HEADER.format(anchor=PF_ANCHOR, ts=ts)]

    # Build per-device block tables
    device_block_macs: List[str] = []
    device_block_ips: List[str] = []

    for policy in policies:
        action = policy.get("action", "")
        scope_type = policy.get("scope_type", "network")
        scope_values = policy.get("scope_values", [])
        name = policy.get("name", "unnamed").replace('"', "'")

        if action not in ("block", "log"):
            continue

        pf_action = "block drop" if action == "block" else "pass log"

        if scope_type == "network":
            # Block/log all traffic matching this policy's target
            # (DNS is the primary enforcement path; pf rules supplement)
            lines.append(f'# Policy: {name}')
            lines.append(f'{pf_action} out quick')
            lines.append("")

        elif scope_type == "device":
            for val in scope_values:
                val = val.strip()
                if _validate_ip(val):
                    device_block_ips.append(val)
                elif _validate_mac(val):
                    device_block_macs.append(val)

        elif scope_type == "vlan":
            for vlan_id in scope_values:
                vlan_id = vlan_id.strip()
                if vlan_id.isdigit():
                    lines.append(f'# Policy: {name} (VLAN {vlan_id})')
                    lines.append(
                        f'{pf_action} out quick on vlan{vlan_id}'
                    )
                    lines.append("")

    # Emit per-device block rules using tables for efficiency
    if device_block_ips:
        safe_ips = [ip for ip in device_block_ips if _validate_ip(ip)]
        if safe_ips:
            ip_list = ", ".join(safe_ips)
            lines.append(f"table <netshield_blocked_devices> {{ {ip_list} }}")
            lines.append("block drop out quick from <netshield_blocked_devices>")
            lines.append("")

    return "\n".join(lines)


def generate_quarantine_rules(quarantined_macs: List[str]) -> str:
    """
    Generate pf rules to block all traffic for quarantined devices.
    Uses a pf table for efficient MAC/IP matching.

    quarantined_macs — list of MAC address strings (validated before use)
    """
    lines = [_QUARANTINE_HEADER]
    # pf does not filter on MAC directly; we need IP.
    # The quarantine table will be populated with IPs resolved from MACs
    # by the caller (after looking up the devices table).
    # Here we generate a table placeholder that callers fill at apply time.
    lines.append("# Quarantine table — populated at apply time by netshield_daemon")
    lines.append("table <netshield_quarantine> persist")
    lines.append("block drop quick from <netshield_quarantine>")
    lines.append("block drop quick to <netshield_quarantine>")
    lines.append("")
    return "\n".join(lines)


def apply_pf_rules(rules_content: str, anchor: str = PF_ANCHOR) -> bool:
    """
    Write rules to a temp file and load them into the pf anchor.
    Returns True on success.
    """
    if not rules_content.strip():
        log.debug("apply_pf_rules: empty rules, flushing anchor instead")
        return _flush_anchor(anchor)

    try:
        # Write to known path (not user-controlled)
        with open(PF_RULES_PATH, "w", encoding="utf-8") as fh:
            fh.write(rules_content)
    except OSError as exc:
        log.error("Cannot write pf rules to %s: %s", PF_RULES_PATH, exc)
        return False

    # Validate with pfctl -nf first
    try:
        check = subprocess.run(
            ["/sbin/pfctl", "-a", anchor, "-nf", PF_RULES_PATH],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if check.returncode != 0:
            log.error(
                "pf rules validation failed: %s", check.stderr.strip()
            )
            return False
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError) as exc:
        log.error("pfctl validation failed: %s", exc)
        return False

    # Load rules
    try:
        result = subprocess.run(
            ["/sbin/pfctl", "-a", anchor, "-f", PF_RULES_PATH],
            capture_output=True,
            text=True,
            timeout=15,
        )
        if result.returncode != 0:
            log.error("pfctl load failed: %s", result.stderr.strip())
            return False
        log.info("pf anchor '%s' loaded from %s", anchor, PF_RULES_PATH)
        _log_enforcement("pf_rules", anchor, "apply", f"loaded {PF_RULES_PATH}")
        return True
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError) as exc:
        log.error("pfctl load error: %s", exc)
        return False


def _flush_anchor(anchor: str) -> bool:
    """Flush all rules from a pf anchor."""
    try:
        subprocess.run(
            ["/sbin/pfctl", "-a", anchor, "-F", "rules"],
            capture_output=True,
            timeout=10,
        )
        log.debug("Flushed pf anchor '%s'", anchor)
        return True
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError) as exc:
        log.warning("Failed to flush pf anchor '%s': %s", anchor, exc)
        return False


# ---------------------------------------------------------------------------
# dummynet / throttling
# ---------------------------------------------------------------------------

def generate_dummynet_pipes(throttle_policies: List[Dict[str, Any]]) -> str:
    """
    Generate ipfw dummynet pipe configuration for throttle policies.

    Each policy gets a unique pipe ID based on DUMMYNET_PIPE_BASE + index.
    Returns a shell script string (to be run via /bin/sh).
    """
    lines = [
        "#!/bin/sh",
        "# NetShield dummynet pipe configuration — generated, do not edit",
        "",
        "# Flush existing NetShield pipes",
        f"ipfw pipe {DUMMYNET_PIPE_BASE} delete 2>/dev/null || true",
        "",
    ]

    for idx, policy in enumerate(throttle_policies):
        if policy.get("action") != "throttle":
            continue
        pipe_id = DUMMYNET_PIPE_BASE + idx
        bw_kbps = policy.get("throttle_kbps", 512)
        # Clamp to reasonable range
        bw_kbps = max(64, min(int(bw_kbps), 1_000_000))
        name = policy.get("name", f"policy_{idx}").replace("'", "")

        lines.append(f"# Pipe for policy: {name}")
        lines.append(f"ipfw pipe {pipe_id} config bw {bw_kbps}Kbit/s queue 100")

        # Apply to scope
        scope_type = policy.get("scope_type", "network")
        scope_values = policy.get("scope_values", [])

        if scope_type == "network":
            lines.append(f"ipfw add pipe {pipe_id} ip from any to any out")
        elif scope_type == "device":
            for val in scope_values:
                val = val.strip()
                if _validate_ip(val):
                    lines.append(f"ipfw add pipe {pipe_id} ip from {val} to any out")
                    lines.append(f"ipfw add pipe {pipe_id} ip from any to {val} in")
        elif scope_type == "vlan":
            for vlan_id in scope_values:
                vlan_id = vlan_id.strip()
                if vlan_id.isdigit():
                    lines.append(
                        f"ipfw add pipe {pipe_id} ip from any to any out via vlan{vlan_id}"
                    )
        lines.append("")

    return "\n".join(lines)


def apply_dummynet(pipes_content: str) -> bool:
    """
    Write the dummynet script and execute it via /bin/sh.
    Returns True on success.
    """
    if not pipes_content.strip():
        log.debug("apply_dummynet: empty script, nothing to do")
        return True

    try:
        with open(DUMMYNET_SCRIPT, "w", encoding="utf-8") as fh:
            fh.write(pipes_content)
        os.chmod(DUMMYNET_SCRIPT, 0o700)
    except OSError as exc:
        log.error("Cannot write dummynet script: %s", exc)
        return False

    try:
        result = subprocess.run(
            ["/bin/sh", DUMMYNET_SCRIPT],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.returncode != 0:
            log.error("Dummynet script failed: %s", result.stderr.strip())
            return False
        log.info("Dummynet pipes applied")
        _log_enforcement("dummynet", "pipes", "apply", "ok")
        return True
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError) as exc:
        log.error("Dummynet apply error: %s", exc)
        return False


# ---------------------------------------------------------------------------
# Status & logging
# ---------------------------------------------------------------------------

def get_enforcement_status() -> Dict[str, Any]:
    """
    Return a dict describing current enforcement state:
      pf_anchor_rules — number of rules in the netshield anchor
      quarantine_count — number of entries in quarantine table
      last_applied     — timestamp of last rule application from DB
    """
    status: Dict[str, Any] = {
        "pf_anchor_rules": 0,
        "quarantine_count": 0,
        "last_applied": None,
    }

    # Count pf rules in anchor
    try:
        result = subprocess.run(
            ["/sbin/pfctl", "-a", PF_ANCHOR, "-s", "rules"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode == 0:
            status["pf_anchor_rules"] = len(
                [l for l in result.stdout.splitlines() if l.strip()]
            )
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        pass

    # Count quarantine entries
    try:
        result = subprocess.run(
            ["/sbin/pfctl", "-a", PF_ANCHOR, "-t", "netshield_quarantine", "-T", "show"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode == 0:
            status["quarantine_count"] = len(
                [l for l in result.stdout.splitlines() if l.strip()]
            )
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        pass

    # Last applied timestamp from DB
    try:
        db.init_db()
        row = db.fetchone(
            "SELECT timestamp FROM enforcement_log ORDER BY id DESC LIMIT 1"
        )
        if row:
            status["last_applied"] = row["timestamp"]
    except Exception:
        pass

    return status


def _log_enforcement(rule_type: str, target: str, action: str, detail: str) -> None:
    """Persist an enforcement event to the DB enforcement_log table."""
    try:
        db.init_db()
        db.execute(
            """
            INSERT INTO enforcement_log (timestamp, rule_type, target, action, detail)
            VALUES (datetime('now','utc'), ?, ?, ?, ?)
            """,
            (rule_type, target, action, detail),
        )
    except Exception as exc:
        log.debug("_log_enforcement failed: %s", exc)
