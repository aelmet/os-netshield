#!/usr/local/bin/python3
# SPDX-License-Identifier: BSD-2-Clause
#
# NetShield - get_alerts.py
# Called by configd to retrieve, flush, or summarise alerts.
# Usage:
#   get_alerts.py                  -> last 100 alerts as JSON array
#   get_alerts.py --limit N        -> last N alerts
#   get_alerts.py --type TYPE      -> filter by alert type
#   get_alerts.py --flush          -> delete alerts older than 30 days
#   get_alerts.py --stats          -> alert counts by type for today

import sys
import os
import json
import logging
import logging.handlers
import argparse
import traceback
from datetime import datetime, timedelta

_SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))
sys.path.insert(0, _SCRIPT_DIR)

from lib import db, alert_sender

LOG_DIR  = "/var/log/netshield"
LOG_FILE = os.path.join(LOG_DIR, "netshield.log")


def _setup_logging() -> logging.Logger:
    os.makedirs(LOG_DIR, exist_ok=True)
    logger = logging.getLogger("netshield.get_alerts")
    logger.setLevel(logging.WARNING)
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


def action_list(limit: int, alert_type: str | None) -> None:
    try:
        alerts = db.get_alerts(limit=limit, alert_type=alert_type)
        _output(alerts)
    except Exception as exc:
        log.error("get_alerts list error: %s\n%s", exc, traceback.format_exc())
        _output({"error": str(exc)})


def action_flush() -> None:
    try:
        cutoff = datetime.utcnow() - timedelta(days=30)
        deleted = db.flush_alerts_before(cutoff)
        _output({"result": "flushed", "deleted": deleted, "before": cutoff.isoformat()})
    except Exception as exc:
        log.error("get_alerts flush error: %s\n%s", exc, traceback.format_exc())
        _output({"error": str(exc)})


def action_stats() -> None:
    try:
        today = datetime.utcnow().date().isoformat()
        counts = db.alert_counts_by_type(date=today)
        total = sum(counts.values())
        _output({
            "date": today,
            "total": total,
            "by_type": counts,
        })
    except Exception as exc:
        log.error("get_alerts stats error: %s\n%s", exc, traceback.format_exc())
        _output({"error": str(exc)})


def main() -> None:
    parser = argparse.ArgumentParser(description="NetShield alert retrieval")
    parser.add_argument("--limit",  type=int, default=100,  help="Number of alerts to return")
    parser.add_argument("--type",   default=None,           help="Filter by alert type")
    parser.add_argument("--flush",  action="store_true",    help="Delete alerts older than 30 days")
    parser.add_argument("--stats",  action="store_true",    help="Alert counts by type for today")
    args = parser.parse_args()

    if args.flush:
        action_flush()
    elif args.stats:
        action_stats()
    else:
        action_list(limit=args.limit, alert_type=args.type)


if __name__ == "__main__":
    main()
