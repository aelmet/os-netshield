#!/usr/local/bin/python3
# SPDX-License-Identifier: BSD-2-Clause
#
# NetShield - manage_appsignatures.py
# Manage application signature library (built-in + custom).
# Called by configd.  First positional arg is action.
# Actions: list | search | stats

import sys
import os
import json
import re
import logging
import logging.handlers
import traceback

_SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))
sys.path.insert(0, _SCRIPT_DIR)

from lib import app_signatures

LOG_DIR  = "/var/log/netshield"
LOG_FILE = os.path.join(LOG_DIR, "netshield.log")

# Maximum search term length
_MAX_SEARCH_LEN = 128


def _setup_logging() -> logging.Logger:
    os.makedirs(LOG_DIR, exist_ok=True)
    logger = logging.getLogger("netshield.manage_appsignatures")
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
    """Output all app signatures (built-in and custom) as JSON array."""
    try:
        sigs = app_signatures.list_all()
        _output(sigs)
    except Exception as exc:
        log.error("manage_appsignatures list error: %s\n%s", exc, traceback.format_exc())
        _output({"error": str(exc)})


# ---------------------------------------------------------------------------
# Action: search
# ---------------------------------------------------------------------------

def action_search() -> None:
    """Search apps by name or domain pattern.
    Second arg: search term (sanitized to _MAX_SEARCH_LEN chars).
    """
    if len(sys.argv) < 3:
        _output({"error": "search requires a TERM argument"})
        return

    term = sys.argv[2][:_MAX_SEARCH_LEN]  # Truncate — never trust user input length

    # Strip characters that could cause issues in downstream regex/SQL
    term = re.sub(r'[^\w\s\.\-\*\?]', '', term).strip()
    if not term:
        _output({"error": "Search term is empty after sanitization"})
        return

    try:
        results = app_signatures.search(term)
        _output({
            "term": term,
            "count": len(results),
            "results": results,
        })
    except Exception as exc:
        log.error("manage_appsignatures search error: %s\n%s", exc, traceback.format_exc())
        _output({"error": str(exc)})


# ---------------------------------------------------------------------------
# Action: stats
# ---------------------------------------------------------------------------

def action_stats() -> None:
    """Output app detection statistics."""
    try:
        stats = app_signatures.get_stats()
        _output(stats)
    except Exception as exc:
        log.error("manage_appsignatures stats error: %s\n%s", exc, traceback.format_exc())
        _output({"error": str(exc)})


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

ACTIONS = {
    "list":   action_list,
    "search": action_search,
    "stats":  action_stats,
}


def main() -> None:
    if len(sys.argv) < 2:
        _output({"error": "No action specified. Use: list | search | stats"})
        return

    action = sys.argv[1].lower()
    fn = ACTIONS.get(action)
    if fn is None:
        _output({"error": f"Unknown action: {action}"})
        return

    fn()


if __name__ == "__main__":
    main()
