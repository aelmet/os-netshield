#!/usr/local/bin/python3
# SPDX-License-Identifier: BSD-2-Clause
#
# NetShield - manage_targetlists.py
# Manage external block-list feeds (threat intel, ad-block, custom).
# Called by configd.  First positional arg is action.
# Actions: list | sync | import | stats

import sys
import os
import json
import re
import logging
import logging.handlers
import traceback
from datetime import datetime

_SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))
sys.path.insert(0, _SCRIPT_DIR)

from lib import target_lists

LOG_DIR  = "/var/log/netshield"
LOG_FILE = os.path.join(LOG_DIR, "netshield.log")

# Allowed URL schemes for import
_ALLOWED_URL_SCHEMES = ("http://", "https://")

# Allowed list types
_ALLOWED_TYPES = {"domain", "ip", "cidr", "regex"}


def _setup_logging() -> logging.Logger:
    os.makedirs(LOG_DIR, exist_ok=True)
    logger = logging.getLogger("netshield.manage_targetlists")
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


def _safe_name(name: str) -> bool:
    """Validate list name: alphanumeric, dashes, underscores only."""
    return bool(re.match(r'^[A-Za-z0-9_\-]{1,64}$', name))


# ---------------------------------------------------------------------------
# Action: list
# ---------------------------------------------------------------------------

def action_list() -> None:
    """Output all target lists as JSON array."""
    try:
        lists = target_lists.list_all()
        _output(lists)
    except Exception as exc:
        log.error("manage_targetlists list error: %s\n%s", exc, traceback.format_exc())
        _output({"error": str(exc)})


# ---------------------------------------------------------------------------
# Action: sync
# ---------------------------------------------------------------------------

def action_sync() -> None:
    """Download and update all enabled target lists from their URLs."""
    log.info("manage_targetlists: sync started")
    try:
        result = target_lists.sync_all_enabled()
        log.info("manage_targetlists: sync complete — %s", result)
        _output({
            "result": "synced",
            "details": result,
            "timestamp": datetime.utcnow().isoformat() + "Z",
        })
    except Exception as exc:
        log.error("manage_targetlists sync error: %s\n%s", exc, traceback.format_exc())
        _output({"error": str(exc)})


# ---------------------------------------------------------------------------
# Action: import
# ---------------------------------------------------------------------------

def action_import() -> None:
    """Import a new target list.
    Expected args: import <URL> <NAME> <TYPE>
    TYPE must be one of: domain | ip | cidr | regex
    """
    if len(sys.argv) < 5:
        _output({"error": "import requires URL, NAME, and TYPE arguments"})
        return

    url  = sys.argv[2]
    name = sys.argv[3]
    ltype = sys.argv[4].lower()

    # Validate URL scheme
    if not any(url.startswith(s) for s in _ALLOWED_URL_SCHEMES):
        _output({"error": "URL must start with http:// or https://"})
        return

    # Validate name
    if not _safe_name(name):
        _output({"error": "NAME must be 1-64 chars, alphanumeric/dashes/underscores only"})
        return

    # Validate type
    if ltype not in _ALLOWED_TYPES:
        _output({"error": f"TYPE must be one of: {', '.join(sorted(_ALLOWED_TYPES))}"})
        return

    log.info("manage_targetlists: import %s (%s) from %s", name, ltype, url)
    try:
        result = target_lists.import_list(url=url, name=name, list_type=ltype)
        _output({"result": "imported", "name": name, "type": ltype, "details": result})
    except Exception as exc:
        log.error("manage_targetlists import error: %s\n%s", exc, traceback.format_exc())
        _output({"error": str(exc)})


# ---------------------------------------------------------------------------
# Action: stats
# ---------------------------------------------------------------------------

def action_stats() -> None:
    """Output target list statistics."""
    try:
        stats = target_lists.get_stats()
        _output(stats)
    except Exception as exc:
        log.error("manage_targetlists stats error: %s\n%s", exc, traceback.format_exc())
        _output({"error": str(exc)})


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

ACTIONS = {
    "list":   action_list,
    "sync":   action_sync,
    "import": action_import,
    "stats":  action_stats,
}


def main() -> None:
    if len(sys.argv) < 2:
        _output({"error": "No action specified. Use: list | sync | import | stats"})
        return

    action = sys.argv[1].lower()
    fn = ACTIONS.get(action)
    if fn is None:
        _output({"error": f"Unknown action: {action}"})
        return

    fn()


if __name__ == "__main__":
    main()
