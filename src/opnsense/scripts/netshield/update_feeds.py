#!/usr/local/bin/python3
# SPDX-License-Identifier: BSD-2-Clause
#
# NetShield - update_feeds.py
# Update all external data feeds:
#   1. Web category lists (from configured URLs)
#   2. Target lists (from configured URLs)
#   3. GeoIP database (if configured)
#   4. App signature updates (from configured URL, if any)
# Outputs a JSON summary of what was updated.

import sys
import os
import json
import logging
import logging.handlers
import traceback
from datetime import datetime

_SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))
sys.path.insert(0, _SCRIPT_DIR)

from lib import config, web_categories, target_lists, geoip, app_signatures

LOG_DIR  = "/var/log/netshield"
LOG_FILE = os.path.join(LOG_DIR, "netshield.log")


def _setup_logging() -> logging.Logger:
    os.makedirs(LOG_DIR, exist_ok=True)
    logger = logging.getLogger("netshield.update_feeds")
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
# Individual feed updaters
# ---------------------------------------------------------------------------

def _update_web_categories(cfg: dict) -> dict:
    """Update web category lists from configured sources."""
    if not cfg.get("web_categories", {}).get("enabled", True):
        return {"skipped": True, "reason": "web_categories disabled in config"}
    try:
        result = web_categories.update_from_sources()
        log.info("update_feeds: web_categories updated — %s", result)
        return {"updated": True, "details": result}
    except Exception as exc:
        log.error("update_feeds: web_categories error: %s\n%s", exc, traceback.format_exc())
        return {"updated": False, "error": str(exc)}


def _update_target_lists(cfg: dict) -> dict:
    """Download and update all enabled target lists."""
    try:
        result = target_lists.sync_all_enabled()
        log.info("update_feeds: target_lists synced — %s", result)
        return {"updated": True, "details": result}
    except Exception as exc:
        log.error("update_feeds: target_lists error: %s\n%s", exc, traceback.format_exc())
        return {"updated": False, "error": str(exc)}


def _update_geoip(cfg: dict) -> dict:
    """Update GeoIP MMDB database if a download URL is configured."""
    geoip_cfg = cfg.get("geoip", {})
    if not geoip_cfg.get("enabled", False):
        return {"skipped": True, "reason": "geoip disabled in config"}
    if not geoip_cfg.get("download_url"):
        return {"skipped": True, "reason": "no geoip download_url configured"}
    try:
        result = geoip.update_db(url=geoip_cfg["download_url"])
        log.info("update_feeds: geoip updated — %s", result)
        return {"updated": True, "details": result}
    except Exception as exc:
        log.error("update_feeds: geoip error: %s\n%s", exc, traceback.format_exc())
        return {"updated": False, "error": str(exc)}


def _update_app_signatures(cfg: dict) -> dict:
    """Update app signature database from configured URL, if any."""
    sig_cfg = cfg.get("app_signatures", {})
    if not sig_cfg.get("auto_update", False):
        return {"skipped": True, "reason": "app_signatures auto_update disabled"}
    update_url = sig_cfg.get("update_url")
    if not update_url:
        return {"skipped": True, "reason": "no app_signatures update_url configured"}
    # Validate URL scheme before passing to lib
    if not (update_url.startswith("https://") or update_url.startswith("http://")):
        return {"skipped": True, "reason": "invalid update_url scheme"}
    try:
        result = app_signatures.update_from_url(update_url)
        log.info("update_feeds: app_signatures updated — %s", result)
        return {"updated": True, "details": result}
    except Exception as exc:
        log.error("update_feeds: app_signatures error: %s\n%s", exc, traceback.format_exc())
        return {"updated": False, "error": str(exc)}


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    log.info("update_feeds: started")

    try:
        cfg = config.load()
    except Exception as exc:
        log.error("update_feeds: could not load config: %s", exc)
        cfg = {}

    started_at = datetime.utcnow().isoformat() + "Z"

    summary = {
        "started_at":     started_at,
        "web_categories": _update_web_categories(cfg),
        "target_lists":   _update_target_lists(cfg),
        "geoip":          _update_geoip(cfg),
        "app_signatures": _update_app_signatures(cfg),
        "finished_at":    datetime.utcnow().isoformat() + "Z",
    }

    # Roll up overall status
    errors = [
        feed
        for feed, result in summary.items()
        if isinstance(result, dict) and not result.get("skipped") and not result.get("updated")
        and result.get("error")
    ]
    summary["result"] = "error" if errors else "success"
    if errors:
        summary["failed_feeds"] = errors

    _output(summary)
    log.info("update_feeds: complete — result=%s", summary["result"])


if __name__ == "__main__":
    main()
