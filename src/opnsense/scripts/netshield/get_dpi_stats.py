#!/usr/local/bin/python3
# Copyright (c) 2025-2026, NetShield Contributors
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice,
#    this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright notice,
#    this list of conditions and the following disclaimer in the documentation
#    and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
# SPDX-License-Identifier: BSD-2-Clause

"""configd script — Returns DPI statistics as JSON."""

import argparse
import json
import logging
import os
import sys

# Ensure the lib/ directory is importable when called by configd
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from lib import db
from urllib.parse import unquote
from lib.bandwidth_tracker import (
    get_bandwidth_by_app,
    get_summary_stats,
    init_bandwidth_tables,
)

log = logging.getLogger("netshield.get_dpi_stats")


def _get_active_flows_count() -> int:
    """Count DPI flows seen in the last 5 minutes."""
    from lib.db import get_db, DB_PATH
    from datetime import datetime, timedelta
    cutoff = (datetime.utcnow() - timedelta(minutes=5)).strftime("%Y-%m-%dT%H:%M:%SZ")
    try:
        with get_db(DB_PATH) as conn:
            row = conn.execute(
                "SELECT COUNT(*) FROM dpi_flows WHERE last_seen >= ?", (cutoff,)
            ).fetchone()
            return row[0] if row else 0
    except Exception:  # pylint: disable=broad-except
        return 0


def _get_top_categories(hours: int = 1, limit: int = 10) -> list:
    """Aggregate bytes by category from dpi_flows."""
    from lib.db import get_db, DB_PATH
    from datetime import datetime, timedelta
    cutoff = (datetime.utcnow() - timedelta(hours=hours)).strftime("%Y-%m-%dT%H:%M:%SZ")
    try:
        with get_db(DB_PATH) as conn:
            rows = conn.execute(
                """
                SELECT category,
                       SUM(bytes_total) AS bytes_total,
                       COUNT(*)         AS flow_count
                FROM dpi_flows
                WHERE last_seen >= ?
                GROUP BY category
                ORDER BY bytes_total DESC
                LIMIT ?
                """,
                (cutoff, limit),
            ).fetchall()
        return [
            {
                "category":   r["category"],
                "bytes":      r["bytes_total"] or 0,
                "flow_count": r["flow_count"],
            }
            for r in rows
        ]
    except Exception:  # pylint: disable=broad-except
        return []


def _get_active_policies_count() -> int:
    """Count enabled policies in the database."""
    from lib.db import get_db, DB_PATH
    try:
        with get_db(DB_PATH) as conn:
            row = conn.execute(
                "SELECT COUNT(*) FROM policies WHERE enabled = 1"
            ).fetchone()
            return row[0] if row else 0
    except Exception:  # pylint: disable=broad-except
        return 0


def _get_device_apps(mac: str) -> dict:
    """Get application breakdown for a specific device MAC."""
    from lib.db import get_db, DB_PATH
    from datetime import datetime, timedelta
    cutoff = (datetime.utcnow() - timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
    try:
        with get_db(DB_PATH) as conn:
            rows = conn.execute(
                """
                SELECT app_name, SUM(bytes_total) AS bytes_total, COUNT(*) AS flow_count
                FROM dpi_flows
                WHERE last_seen >= ? AND device_mac = ?
                GROUP BY app_name ORDER BY bytes_total DESC LIMIT 20
                """,
                (cutoff, mac),
            ).fetchall()
        return {
            "apps": [
                {"name": r["app_name"], "bytes": r["bytes_total"] or 0, "flow_count": r["flow_count"]}
                for r in rows
            ]
        }
    except Exception:  # pylint: disable=broad-except
        return {"apps": []}


def _get_flows() -> dict:
    """Get recent DPI flow records."""
    from lib.db import get_db, DB_PATH
    from datetime import datetime, timedelta
    cutoff = (datetime.utcnow() - timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
    try:
        with get_db(DB_PATH) as conn:
            rows = conn.execute(
                "SELECT * FROM dpi_flows WHERE last_seen >= ? ORDER BY last_seen DESC LIMIT 200",
                (cutoff,),
            ).fetchall()
        return {"flows": [dict(r) for r in rows]}
    except Exception:  # pylint: disable=broad-except
        return {"flows": []}


def main() -> None:
    # configd passes all parameters as a single comma-delimited token
    if len(sys.argv) == 2:
        arg = sys.argv[1]
        parts = arg.replace(',', ' ').split()
        sys.argv = [sys.argv[0]] + [unquote(p.strip("'\"")) for p in parts]
    logging.basicConfig(
        level=logging.WARNING,
        format="%(levelname)s %(name)s: %(message)s",
        stream=sys.stderr,
    )

    parser = argparse.ArgumentParser(description="NetShield DPI statistics")
    sub = parser.add_subparsers(dest="cmd")

    # (no subcommand) = summary stats — also support explicit "summary"
    sub.add_parser("summary", help="Return summary DPI statistics (default)")

    # device <mac>
    p_device = sub.add_parser("device", help="Return app breakdown for a device")
    p_device.add_argument("mac", help="Device MAC address")

    # flows
    sub.add_parser("flows", help="Return recent DPI flow records")

    args = parser.parse_args()

    try:
        init_bandwidth_tables()
    except Exception as exc:  # pylint: disable=broad-except
        log.warning("Could not init bandwidth tables: %s", exc)

    if args.cmd == "device":
        result = _get_device_apps(args.mac)
        print(json.dumps(result, indent=2))
        return

    if args.cmd == "flows":
        result = _get_flows()
        print(json.dumps(result, indent=2))
        return

    # Default: summary stats
    active_flows     = _get_active_flows_count()
    top_apps         = get_bandwidth_by_app(hours=1, limit=10)
    top_categories   = _get_top_categories(hours=1, limit=10)
    active_policies  = _get_active_policies_count()
    summary          = get_summary_stats(hours=1)

    output = {
        "active_flows":     active_flows,
        "active_policies":  active_policies,
        "top_apps":         top_apps,
        "top_categories":   top_categories,
        "summary": {
            "bytes_in":       summary.get("bytes_in", 0),
            "bytes_out":      summary.get("bytes_out", 0),
            "bytes_total":    summary.get("bytes_total", 0),
            "packets":        summary.get("packets", 0),
            "active_devices": summary.get("active_devices", 0),
            "active_apps":    summary.get("active_apps", 0),
        },
    }

    print(json.dumps(output, indent=2))


if __name__ == "__main__":
    main()
