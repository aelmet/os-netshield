#!/usr/local/bin/python3
# SPDX-License-Identifier: BSD-2-Clause
#
# NetShield - manage_dns.py
# DNS filtering management via Unbound.
# Called by configd.  First positional arg is action.
# Actions: reconfigure | safe_search | status

import sys
import os
import json
import logging
import logging.handlers
import traceback

_SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))
sys.path.insert(0, _SCRIPT_DIR)

from lib import config, dns_filter

LOG_DIR  = "/var/log/netshield"
LOG_FILE = os.path.join(LOG_DIR, "netshield.log")


def _setup_logging() -> logging.Logger:
    os.makedirs(LOG_DIR, exist_ok=True)
    logger = logging.getLogger("netshield.manage_dns")
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
# Action: reconfigure
# ---------------------------------------------------------------------------

def action_reconfigure() -> None:
    """Regenerate all Unbound config files from current policy/filter state."""
    log.info("manage_dns: reconfigure started")
    try:
        result = dns_filter.reconfigure_unbound()
        log.info("manage_dns: reconfigure complete — %s", result)
        _output({"result": "reconfigured", "details": result})
    except Exception as exc:
        log.error("manage_dns reconfigure error: %s\n%s", exc, traceback.format_exc())
        _output({"error": str(exc)})


# ---------------------------------------------------------------------------
# Action: safe_search
# ---------------------------------------------------------------------------

def action_safe_search() -> None:
    """Enable or disable safe search enforcement.
    Second arg: 'enable' or 'disable'.  Defaults to querying current state.
    """
    try:
        if len(sys.argv) >= 3:
            toggle = sys.argv[2].lower()
            if toggle not in ("enable", "disable"):
                _output({"error": "safe_search requires 'enable' or 'disable' as second argument"})
                return
            enabled = toggle == "enable"
            dns_filter.set_safe_search(enabled)
            dns_filter.reconfigure_unbound()
            _output({"result": "safe_search_updated", "enabled": enabled})
        else:
            # Return current state
            state = dns_filter.get_safe_search_state()
            _output({"safe_search_enabled": state})
    except Exception as exc:
        log.error("manage_dns safe_search error: %s\n%s", exc, traceback.format_exc())
        _output({"error": str(exc)})


# ---------------------------------------------------------------------------
# Action: status
# ---------------------------------------------------------------------------

def action_status() -> None:
    """Return DNS filtering statistics as JSON."""
    try:
        stats = dns_filter.get_stats()
        _output(stats)
    except Exception as exc:
        log.error("manage_dns status error: %s\n%s", exc, traceback.format_exc())
        _output({"error": str(exc)})


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

ACTIONS = {
    "reconfigure": action_reconfigure,
    "safe_search": action_safe_search,
    "status":      action_status,
}


def main() -> None:
    if len(sys.argv) < 2:
        _output({"error": "No action specified. Use: reconfigure | safe_search | status"})
        return

    action = sys.argv[1].lower()
    fn = ACTIONS.get(action)
    if fn is None:
        _output({"error": f"Unknown action: {action}"})
        return

    fn()


if __name__ == "__main__":
    main()
