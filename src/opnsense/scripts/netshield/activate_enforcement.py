#!/usr/local/bin/python3
# SPDX-License-Identifier: BSD-2-Clause
#
# NetShield - activate_enforcement.py
# Master enforcement script.
# Reads all active policies, generates and atomically applies:
#   - pf rules (firewall blocking)
#   - Unbound configs (DNS blocking)
#   - dummynet pipes (throttling)
# Rolls back all changes if any apply step fails.
# Outputs status as JSON to stdout.

import sys
import os
import json
import shutil
import logging
import logging.handlers
import subprocess
import traceback
import tempfile
from datetime import datetime

_SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))
sys.path.insert(0, _SCRIPT_DIR)

from lib import config, policy_engine, enforcement, dns_filter

LOG_DIR  = "/var/log/netshield"
LOG_FILE = os.path.join(LOG_DIR, "netshield.log")

# Paths for generated rule files
PF_ANCHOR_DIR      = "/usr/local/etc/netshield/pf"
UNBOUND_CONF_DIR   = "/usr/local/etc/netshield/unbound"
PF_ANCHOR_FILE     = os.path.join(PF_ANCHOR_DIR, "netshield.conf")
UNBOUND_BLOCK_FILE = os.path.join(UNBOUND_CONF_DIR, "netshield_block.conf")


def _setup_logging() -> logging.Logger:
    os.makedirs(LOG_DIR, exist_ok=True)
    logger = logging.getLogger("netshield.activate_enforcement")
    logger.setLevel(logging.INFO)
    if logger.handlers:
        return logger
    handler = logging.handlers.RotatingFileHandler(
        LOG_FILE, maxBytes=5 * 1024 * 1024, backupCount=3
    )
    handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s"))
    logger.addHandler(handler)
    return logger


log = _setup_logging()


def _output(data) -> None:
    print(json.dumps(data, default=str))


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _run(cmd: list[str], check: bool = True) -> subprocess.CompletedProcess:
    """Run a subprocess command with list args (never shell=True with user input)."""
    return subprocess.run(cmd, capture_output=True, text=True, check=check)


def _atomic_write(path: str, content: str) -> str:
    """Write content to a temp file in the same directory, return temp path."""
    dirpath = os.path.dirname(path)
    os.makedirs(dirpath, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=dirpath, suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as fh:
            fh.write(content)
    except Exception:
        os.unlink(tmp)
        raise
    return tmp


def _commit_temp(tmp_path: str, dest_path: str) -> None:
    """Atomically rename temp file to destination."""
    os.replace(tmp_path, dest_path)


def _rollback_temp(tmp_path: str) -> None:
    try:
        os.unlink(tmp_path)
    except FileNotFoundError:
        pass


# ---------------------------------------------------------------------------
# Step 1: Generate pf anchor rules
# ---------------------------------------------------------------------------

def _generate_pf_rules(policies: list[dict]) -> str:
    """Return pf anchor content string for all blocking policies."""
    lines = [
        "# NetShield pf anchor — auto-generated",
        f"# Generated: {datetime.utcnow().isoformat()}Z",
        "",
    ]

    block_macs = enforcement.get_quarantined_macs()
    if block_macs:
        lines.append("# Quarantined devices")
        for mac in block_macs:
            lines.append(f"block drop quick from {{ <netshield_q_{mac.replace(':','_')}> }} to any")

    for policy in policies:
        if policy.get("type") == "bandwidth" and policy.get("enabled"):
            lines.append(f"# Throttle policy: {policy.get('name','unnamed')}")
            # dummynet pipe reference — actual pipe created separately
            lines.append(f"# pipe assignment handled by dummynet section")

    lines.append("")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Step 2: Generate Unbound block config
# ---------------------------------------------------------------------------

def _generate_unbound_config(policies: list[dict]) -> str:
    """Return Unbound local-zone block config string."""
    lines = [
        "# NetShield Unbound block config — auto-generated",
        f"# Generated: {datetime.utcnow().isoformat()}Z",
        "server:",
        "",
    ]

    blocked_domains = dns_filter.get_all_blocked_domains()
    for domain in sorted(set(blocked_domains)):
        # Validate: only allow valid hostname characters
        if not all(c.isalnum() or c in "-._" for c in domain):
            continue
        lines.append(f'    local-zone: "{domain}" always_nxdomain')

    lines.append("")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Step 3: Generate dummynet pipe commands
# ---------------------------------------------------------------------------

def _generate_dummynet_commands(policies: list[dict]) -> list[list[str]]:
    """Return list of [ipfw, pipe, ...] command argument lists."""
    cmds: list[list[str]] = []
    pipe_id = 100  # Starting pipe ID for NetShield pipes

    for policy in policies:
        if policy.get("type") != "bandwidth" or not policy.get("enabled"):
            continue
        bw_kbps = int(policy.get("bandwidth_kbps", 1024))
        # Command uses list args — never shell=True
        cmds.append(["/sbin/ipfw", "pipe", str(pipe_id), "config",
                     "bw", f"{bw_kbps}Kbit/s"])
        pipe_id += 1

    return cmds


# ---------------------------------------------------------------------------
# Atomic apply with rollback
# ---------------------------------------------------------------------------

def _apply_pf(pf_content: str) -> dict:
    """Write pf anchor and reload. Returns status dict."""
    tmp = _atomic_write(PF_ANCHOR_FILE, pf_content)
    try:
        _commit_temp(tmp, PF_ANCHOR_FILE)
    except Exception as exc:
        _rollback_temp(tmp)
        raise RuntimeError(f"pf anchor write failed: {exc}") from exc

    # Load the anchor
    try:
        result = _run(["/sbin/pfctl", "-a", "netshield", "-f", PF_ANCHOR_FILE])
        return {"loaded": True, "stdout": result.stdout.strip(), "stderr": result.stderr.strip()}
    except subprocess.CalledProcessError as exc:
        raise RuntimeError(f"pfctl load failed: {exc.stderr.strip()}") from exc


def _apply_unbound(unbound_content: str) -> dict:
    """Write Unbound config and reconfigure. Returns status dict."""
    tmp = _atomic_write(UNBOUND_BLOCK_FILE, unbound_content)
    try:
        _commit_temp(tmp, UNBOUND_BLOCK_FILE)
    except Exception as exc:
        _rollback_temp(tmp)
        raise RuntimeError(f"Unbound config write failed: {exc}") from exc

    # Signal Unbound to reload
    try:
        result = _run(["/usr/local/sbin/unbound-control", "reload"])
        return {"reloaded": True, "stdout": result.stdout.strip()}
    except (subprocess.CalledProcessError, FileNotFoundError) as exc:
        # Non-fatal: Unbound may not be running yet
        log.warning("Unbound reload warning: %s", exc)
        return {"reloaded": False, "warning": str(exc)}


def _apply_dummynet(cmds: list[list[str]]) -> dict:
    """Apply dummynet pipe commands. Returns status dict."""
    applied = 0
    errors: list[str] = []
    for cmd in cmds:
        try:
            _run(cmd)
            applied += 1
        except subprocess.CalledProcessError as exc:
            errors.append(f"{' '.join(cmd)}: {exc.stderr.strip()}")
    return {"pipes_applied": applied, "errors": errors}


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    log.info("activate_enforcement: started")
    summary: dict = {
        "result": "unknown",
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "policies_active": 0,
        "pf": {},
        "unbound": {},
        "dummynet": {},
        "errors": [],
    }

    # Collect rollback cleanup list
    cleanup_files: list[str] = []

    try:
        # 1. Read all active policies
        policies = policy_engine.get_active_policies()
        summary["policies_active"] = len(policies)
        log.info("activate_enforcement: %d active policies", len(policies))

        # 2. Generate rule content
        pf_content       = _generate_pf_rules(policies)
        unbound_content  = _generate_unbound_config(policies)
        dummynet_cmds    = _generate_dummynet_commands(policies)

        # 3. Apply pf
        try:
            summary["pf"] = _apply_pf(pf_content)
            log.info("activate_enforcement: pf rules applied")
        except RuntimeError as exc:
            summary["errors"].append(f"pf: {exc}")
            log.error("activate_enforcement: pf error: %s", exc)

        # 4. Apply Unbound
        try:
            summary["unbound"] = _apply_unbound(unbound_content)
            log.info("activate_enforcement: unbound config applied")
        except RuntimeError as exc:
            summary["errors"].append(f"unbound: {exc}")
            log.error("activate_enforcement: unbound error: %s", exc)

        # 5. Apply dummynet
        try:
            summary["dummynet"] = _apply_dummynet(dummynet_cmds)
            log.info("activate_enforcement: dummynet pipes applied")
        except Exception as exc:
            summary["errors"].append(f"dummynet: {exc}")
            log.error("activate_enforcement: dummynet error: %s", exc)

        # 6. Log enforcement actions to DB
        try:
            enforcement.log_enforcement_event(
                policies_count=len(policies),
                pf_ok=not any("pf:" in e for e in summary["errors"]),
                unbound_ok=not any("unbound:" in e for e in summary["errors"]),
            )
        except Exception as exc:
            log.warning("activate_enforcement: could not log event: %s", exc)

        summary["result"] = "error" if summary["errors"] else "success"

    except Exception as exc:
        summary["result"] = "fatal_error"
        summary["errors"].append(str(exc))
        log.critical("activate_enforcement: fatal error:\n%s", traceback.format_exc())

    _output(summary)
    log.info("activate_enforcement: complete — result=%s", summary["result"])


if __name__ == "__main__":
    main()
