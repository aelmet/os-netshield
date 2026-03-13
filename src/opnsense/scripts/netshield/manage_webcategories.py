#!/usr/local/bin/python3
# SPDX-License-Identifier: BSD-2-Clause
#
# NetShield - manage_webcategories.py
# Manage web category block lists.
# Called by configd.  First positional arg is action.
# Actions: list | update | sync | stats

import sys
import os
import json
import logging
import logging.handlers
import traceback
from datetime import datetime

_SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))
sys.path.insert(0, _SCRIPT_DIR)

from lib import web_categories

LOG_DIR  = "/var/log/netshield"
LOG_FILE = os.path.join(LOG_DIR, "netshield.log")


def _setup_logging() -> logging.Logger:
    os.makedirs(LOG_DIR, exist_ok=True)
    logger = logging.getLogger("netshield.manage_webcategories")
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
# Action: list
# ---------------------------------------------------------------------------

def action_list() -> None:
    """Output all categories as JSON array."""
    try:
        categories = web_categories.list_categories()
        _output(categories)
    except Exception as exc:
        log.error("manage_webcategories list error: %s\n%s", exc, traceback.format_exc())
        _output({"error": str(exc)})


# ---------------------------------------------------------------------------
# Action: update
# ---------------------------------------------------------------------------

def action_update() -> None:
    """Update category database from configured upstream sources."""
    log.info("manage_webcategories: update started")
    try:
        result = web_categories.update_from_sources()
        log.info("manage_webcategories: update complete — %s", result)
        _output({"result": "updated", "details": result, "timestamp": datetime.utcnow().isoformat() + "Z"})
    except Exception as exc:
        log.error("manage_webcategories update error: %s\n%s", exc, traceback.format_exc())
        _output({"error": str(exc)})


# ---------------------------------------------------------------------------
# Action: sync
# ---------------------------------------------------------------------------

def action_sync() -> None:
    """Sync all enabled category block lists to the DNS filter."""
    log.info("manage_webcategories: sync started")
    try:
        result = web_categories.sync_enabled()
        log.info("manage_webcategories: sync complete — %s", result)
        _output({"result": "synced", "details": result, "timestamp": datetime.utcnow().isoformat() + "Z"})
    except Exception as exc:
        log.error("manage_webcategories sync error: %s\n%s", exc, traceback.format_exc())
        _output({"error": str(exc)})


# ---------------------------------------------------------------------------
# Action: stats
# ---------------------------------------------------------------------------

def action_stats() -> None:
    """Output category statistics."""
    try:
        stats = web_categories.get_stats()
        _output(stats)
    except Exception as exc:
        log.error("manage_webcategories stats error: %s\n%s", exc, traceback.format_exc())
        _output({"error": str(exc)})


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

ACTIONS = {
    "list":   action_list,
    "update": action_update,
    "sync":   action_sync,
    "stats":  action_stats,
}


def main() -> None:
    if len(sys.argv) < 2:
        _output({"error": "No action specified. Use: list | update | sync | stats"})
        return

    action = sys.argv[1].lower()
    fn = ACTIONS.get(action)
    if fn is None:
        _output({"error": f"Unknown action: {action}"})
        return

    fn()


if __name__ == "__main__":
    main()
