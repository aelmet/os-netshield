#!/usr/local/bin/python3
# SPDX-License-Identifier: BSD-2-Clause
#
# NetShield - manage_geoip.py
# GeoIP-based country blocking via pf tables.
# Called by configd.  First positional arg is action.
# Actions: setup | countries | toggle | apply | stats | db_status

import sys
import os
import json
import re
import logging
import logging.handlers
import traceback

_SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))
sys.path.insert(0, _SCRIPT_DIR)

from lib import geoip

LOG_DIR  = "/var/log/netshield"
LOG_FILE = os.path.join(LOG_DIR, "netshield.log")

# ISO 3166-1 alpha-2 country code pattern
_CC_RE = re.compile(r'^[A-Z]{2}$')


def _setup_logging() -> logging.Logger:
    os.makedirs(LOG_DIR, exist_ok=True)
    logger = logging.getLogger("netshield.manage_geoip")
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


def _validate_cc(cc: str) -> bool:
    return bool(_CC_RE.match(cc.upper()))


# ---------------------------------------------------------------------------
# Action: setup
# ---------------------------------------------------------------------------

def action_setup() -> None:
    """Initialize GeoIP database (create tables, download if configured)."""
    log.info("manage_geoip: setup started")
    try:
        result = geoip.setup()
        _output({"result": "setup_complete", "details": result})
    except Exception as exc:
        log.error("manage_geoip setup error: %s\n%s", exc, traceback.format_exc())
        _output({"error": str(exc)})


# ---------------------------------------------------------------------------
# Action: countries
# ---------------------------------------------------------------------------

def action_countries() -> None:
    """List available countries with their current block status."""
    try:
        countries = geoip.list_countries()
        _output(countries)
    except Exception as exc:
        log.error("manage_geoip countries error: %s\n%s", exc, traceback.format_exc())
        _output({"error": str(exc)})


# ---------------------------------------------------------------------------
# Action: toggle
# ---------------------------------------------------------------------------

def action_toggle() -> None:
    """Toggle blocking for a country code.
    Second arg: ISO 3166-1 alpha-2 country code (e.g. CN, RU).
    """
    if len(sys.argv) < 3:
        _output({"error": "toggle requires a COUNTRY_CODE argument"})
        return

    cc = sys.argv[2].upper()
    if not _validate_cc(cc):
        _output({"error": "COUNTRY_CODE must be a 2-letter ISO 3166-1 alpha-2 code"})
        return

    try:
        new_state = geoip.toggle_country(cc)
        log.info("manage_geoip: toggled %s -> blocked=%s", cc, new_state)
        _output({
            "result": "toggled",
            "country_code": cc,
            "blocked": new_state,
        })
    except Exception as exc:
        log.error("manage_geoip toggle error for %s: %s\n%s", cc, exc, traceback.format_exc())
        _output({"error": str(exc)})


# ---------------------------------------------------------------------------
# Action: apply
# ---------------------------------------------------------------------------

def action_apply() -> None:
    """Apply current GeoIP block rules via pf tables."""
    log.info("manage_geoip: apply started")
    try:
        result = geoip.apply_pf_rules()
        log.info("manage_geoip: apply complete — %s", result)
        _output({"result": "applied", "details": result})
    except Exception as exc:
        log.error("manage_geoip apply error: %s\n%s", exc, traceback.format_exc())
        _output({"error": str(exc)})


# ---------------------------------------------------------------------------
# Action: stats
# ---------------------------------------------------------------------------

def action_stats() -> None:
    """GeoIP statistics: blocked countries count, total IPs blocked, etc."""
    try:
        stats = geoip.get_stats()
        _output(stats)
    except Exception as exc:
        log.error("manage_geoip stats error: %s\n%s", exc, traceback.format_exc())
        _output({"error": str(exc)})


# ---------------------------------------------------------------------------
# Action: db_status
# ---------------------------------------------------------------------------

def action_db_status() -> None:
    """Check whether the MaxMind MMDB database file is present and valid."""
    try:
        status = geoip.db_status()
        _output(status)
    except Exception as exc:
        log.error("manage_geoip db_status error: %s\n%s", exc, traceback.format_exc())
        _output({"error": str(exc)})


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

ACTIONS = {
    "setup":     action_setup,
    "countries": action_countries,
    "toggle":    action_toggle,
    "apply":     action_apply,
    "stats":     action_stats,
    "db_status": action_db_status,
}


def main() -> None:
    if len(sys.argv) < 2:
        _output({"error": "No action specified. Use: setup | countries | toggle | apply | stats | db_status"})
        return

    action = sys.argv[1].lower()
    fn = ACTIONS.get(action)
    if fn is None:
        _output({"error": f"Unknown action: {action}"})
        return

    fn()


if __name__ == "__main__":
    main()
