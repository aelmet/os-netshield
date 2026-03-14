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

"""
Bandwidth Tracker — Track per-device and per-app bandwidth usage.
Samples at regular intervals and stores in SQLite.
"""

import logging
import re
import subprocess
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

try:
    from .db import get_db, DB_PATH
except ImportError:
    from db import get_db, DB_PATH

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# DDL for Phase 2 tables
# ---------------------------------------------------------------------------

_BANDWIDTH_DDL = """
CREATE TABLE IF NOT EXISTS bandwidth_samples (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    device_mac TEXT NOT NULL,
    app_name TEXT NOT NULL DEFAULT 'Unknown',
    bytes_in INTEGER NOT NULL DEFAULT 0,
    bytes_out INTEGER NOT NULL DEFAULT 0,
    packets INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS dpi_flows (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    src_ip TEXT NOT NULL,
    dst_ip TEXT NOT NULL,
    src_port INTEGER NOT NULL,
    dst_port INTEGER NOT NULL,
    protocol TEXT NOT NULL,
    app_name TEXT NOT NULL DEFAULT 'Unknown',
    category TEXT NOT NULL DEFAULT 'Unknown',
    bytes_total INTEGER NOT NULL DEFAULT 0,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    device_mac TEXT NOT NULL DEFAULT ''
);
"""

_BANDWIDTH_INDEXES = """
CREATE INDEX IF NOT EXISTS idx_bw_timestamp  ON bandwidth_samples(timestamp);
CREATE INDEX IF NOT EXISTS idx_bw_device_mac ON bandwidth_samples(device_mac);
CREATE INDEX IF NOT EXISTS idx_bw_app_name   ON bandwidth_samples(app_name);
CREATE INDEX IF NOT EXISTS idx_dpi_src_ip    ON dpi_flows(src_ip);
CREATE INDEX IF NOT EXISTS idx_dpi_dst_ip    ON dpi_flows(dst_ip);
CREATE INDEX IF NOT EXISTS idx_dpi_app_name  ON dpi_flows(app_name);
CREATE INDEX IF NOT EXISTS idx_dpi_last_seen ON dpi_flows(last_seen);
CREATE INDEX IF NOT EXISTS idx_dpi_device    ON dpi_flows(device_mac);
"""


# ---------------------------------------------------------------------------
# Schema initialisation
# ---------------------------------------------------------------------------


def init_bandwidth_tables(db_path: str = DB_PATH) -> None:
    """Create bandwidth_samples and dpi_flows tables (safe to call multiple times)."""
    try:
        with get_db(db_path) as conn:
            conn.executescript(_BANDWIDTH_DDL)
            conn.executescript(_BANDWIDTH_INDEXES)
        log.debug("Bandwidth tables initialised")
    except Exception as exc:  # pylint: disable=broad-except
        log.error("Failed to initialise bandwidth tables: %s", exc)
        raise


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _now() -> str:
    return datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")


def _cutoff(hours: float) -> str:
    dt = datetime.utcnow() - timedelta(hours=hours)
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _days_cutoff(days: int) -> str:
    dt = datetime.utcnow() - timedelta(days=days)
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


# ---------------------------------------------------------------------------
# Sample recording
# ---------------------------------------------------------------------------


def record_sample(
    device_mac: str,
    app_name: str,
    bytes_in: int,
    bytes_out: int,
    packets: int,
    db_path: str = DB_PATH,
) -> int:
    """Insert a bandwidth sample. Returns the new row ID."""
    try:
        with get_db(db_path) as conn:
            cur = conn.execute(
                """
                INSERT INTO bandwidth_samples
                    (timestamp, device_mac, app_name, bytes_in, bytes_out, packets)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (_now(), device_mac, app_name or "Unknown",
                 max(0, bytes_in), max(0, bytes_out), max(0, packets)),
            )
            return cur.lastrowid
    except Exception as exc:  # pylint: disable=broad-except
        log.error("Failed to record bandwidth sample: %s", exc)
        return -1


def record_flow(
    flow: Dict[str, Any],
    device_mac: str = "",
    db_path: str = DB_PATH,
) -> int:
    """Upsert a DPI flow record. Returns the row ID (insert) or 0 (update)."""
    src_ip    = flow.get("src_ip", "")
    dst_ip    = flow.get("dst_ip", "")
    src_port  = int(flow.get("src_port", 0))
    dst_port  = int(flow.get("dst_port", 0))
    protocol  = flow.get("protocol", "TCP")
    app_name  = flow.get("app_name", "Unknown") or "Unknown"
    category  = flow.get("category", "Unknown") or "Unknown"
    bytes_total = int(flow.get("bytes_sent", 0)) + int(flow.get("bytes_recv", 0))
    first_seen = flow.get("first_seen", _now())
    last_seen  = flow.get("last_seen", _now())

    try:
        with get_db(db_path) as conn:
            # Check for existing flow record
            existing = conn.execute(
                """
                SELECT id FROM dpi_flows
                WHERE src_ip=? AND dst_ip=? AND src_port=? AND dst_port=? AND protocol=?
                ORDER BY first_seen DESC LIMIT 1
                """,
                (src_ip, dst_ip, src_port, dst_port, protocol),
            ).fetchone()

            if existing:
                conn.execute(
                    """
                    UPDATE dpi_flows
                    SET app_name=?, category=?, bytes_total=bytes_total + ?,
                        last_seen=?, device_mac=CASE WHEN ? != '' THEN ? ELSE device_mac END
                    WHERE id=?
                    """,
                    (app_name, category, bytes_total, last_seen,
                     device_mac, device_mac, existing["id"]),
                )
                return 0
            else:
                cur = conn.execute(
                    """
                    INSERT INTO dpi_flows
                        (src_ip, dst_ip, src_port, dst_port, protocol,
                         app_name, category, bytes_total, first_seen, last_seen, device_mac)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (src_ip, dst_ip, src_port, dst_port, protocol,
                     app_name, category, bytes_total, first_seen, last_seen, device_mac),
                )
                return cur.lastrowid
    except Exception as exc:  # pylint: disable=broad-except
        log.error("Failed to record DPI flow: %s", exc)
        return -1


# ---------------------------------------------------------------------------
# Interface stats sampling via netstat
# ---------------------------------------------------------------------------

# Stores previous byte counters for delta calculation
_prev_counters: Dict[str, Dict[str, int]] = {}


def record_samples_from_netstat(
    device_macs: Optional[Dict[str, str]] = None,
    db_path: str = DB_PATH,
) -> Dict[str, Any]:
    """Sample per-interface byte counters via ``netstat -ibn`` and record deltas.

    Args:
        device_macs: Optional dict mapping IP → MAC. If not provided, samples
                     are recorded with the interface name as device_mac.
        db_path: Database path.

    Returns:
        A dict with interface → {bytes_in, bytes_out} deltas recorded.
    """
    global _prev_counters

    try:
        output = subprocess.check_output(
            ["netstat", "-ibn"], stderr=subprocess.DEVNULL, timeout=10,
        ).decode("utf-8", errors="replace")
    except (subprocess.SubprocessError, FileNotFoundError, OSError) as exc:
        log.warning("netstat -ibn failed: %s", exc)
        return {"error": str(exc)}

    results: Dict[str, Dict[str, int]] = {}

    for line in output.splitlines()[1:]:
        parts = line.split()
        if len(parts) < 10:
            continue
        iface = parts[0].rstrip('*')
        # Skip loopback, non-physical, and inactive interfaces
        if (iface.startswith("lo") or iface.startswith("pflog") or
                iface.startswith("enc") or iface.startswith("pfsync") or
                parts[0].endswith('*')):
            continue
        try:
            # FreeBSD netstat -ibn columns:
            # Name Mtu Network Address Ipkts Ierrs Idrop Ibytes Opkts Oerrs Obytes Coll
            #  0    1    2       3       4     5     6     7      8     9     10     11
            bytes_in = int(parts[7])
            bytes_out = int(parts[10])
        except (ValueError, IndexError):
            continue

        prev = _prev_counters.get(iface, {})
        if prev:
            delta_in = max(0, bytes_in - prev.get("bytes_in", bytes_in))
            delta_out = max(0, bytes_out - prev.get("bytes_out", bytes_out))

            if delta_in > 0 or delta_out > 0:
                mac_label = iface  # Default: use interface name
                record_sample(
                    device_mac=mac_label,
                    app_name="Network",
                    bytes_in=delta_in,
                    bytes_out=delta_out,
                    packets=0,
                    db_path=db_path,
                )
                results[iface] = {"bytes_in": delta_in, "bytes_out": delta_out}

        _prev_counters[iface] = {"bytes_in": bytes_in, "bytes_out": bytes_out}

    return {"sampled": len(results), "interfaces": results}


# ---------------------------------------------------------------------------
# Current bandwidth (rates)
# ---------------------------------------------------------------------------


def get_current_bandwidth(
    window_minutes: int = 5,
    db_path: str = DB_PATH,
) -> Dict[str, Dict[str, Any]]:
    """Return per-device bandwidth rates over the last *window_minutes* minutes.

    Returns a dict keyed by device_mac with fields:
      bytes_in, bytes_out, bytes_total, packets, rate_in_kbps, rate_out_kbps
    """
    since = _cutoff(window_minutes / 60.0)
    window_seconds = window_minutes * 60

    try:
        with get_db(db_path) as conn:
            rows = conn.execute(
                """
                SELECT device_mac,
                       SUM(bytes_in)  AS bytes_in,
                       SUM(bytes_out) AS bytes_out,
                       SUM(packets)   AS packets
                FROM bandwidth_samples
                WHERE timestamp >= ?
                GROUP BY device_mac
                ORDER BY (SUM(bytes_in) + SUM(bytes_out)) DESC
                """,
                (since,),
            ).fetchall()

        result: Dict[str, Dict[str, Any]] = {}
        for row in rows:
            mac = row["device_mac"]
            b_in  = row["bytes_in"]  or 0
            b_out = row["bytes_out"] or 0
            pkts  = row["packets"]   or 0
            result[mac] = {
                "device_mac":     mac,
                "bytes_in":       b_in,
                "bytes_out":      b_out,
                "bytes_total":    b_in + b_out,
                "packets":        pkts,
                "rate_in_kbps":   round((b_in  * 8) / (window_seconds * 1000), 2),
                "rate_out_kbps":  round((b_out * 8) / (window_seconds * 1000), 2),
                "window_minutes": window_minutes,
            }
        return result
    except Exception as exc:  # pylint: disable=broad-except
        log.error("get_current_bandwidth failed: %s", exc)
        return {}


# ---------------------------------------------------------------------------
# Historical data
# ---------------------------------------------------------------------------


def get_bandwidth_history(
    device_mac: Optional[str] = None,
    hours: int = 24,
    bucket_minutes: int = 15,
    db_path: str = DB_PATH,
) -> List[Dict[str, Any]]:
    """Return time-bucketed bandwidth usage for the last *hours* hours.

    Each bucket is *bucket_minutes* wide (default 15 min).
    Returns a list of dicts: timestamp_bucket, bytes_in, bytes_out, packets.
    Optionally filtered to a single *device_mac*.
    """
    since = _cutoff(float(hours))

    # SQLite strftime trick to bucket timestamps into N-minute windows
    # We use integer division on the epoch seconds via (strftime('%s',...) / bucket_seconds)
    bucket_seconds = bucket_minutes * 60

    try:
        with get_db(db_path) as conn:
            if device_mac:
                rows = conn.execute(
                    f"""
                    SELECT
                        datetime(
                            (strftime('%s', timestamp) / {bucket_seconds}) * {bucket_seconds},
                            'unixepoch'
                        ) AS bucket,
                        SUM(bytes_in)  AS bytes_in,
                        SUM(bytes_out) AS bytes_out,
                        SUM(packets)   AS packets
                    FROM bandwidth_samples
                    WHERE timestamp >= ? AND device_mac = ?
                    GROUP BY bucket
                    ORDER BY bucket ASC
                    """,
                    (since, device_mac),
                ).fetchall()
            else:
                rows = conn.execute(
                    f"""
                    SELECT
                        datetime(
                            (strftime('%s', timestamp) / {bucket_seconds}) * {bucket_seconds},
                            'unixepoch'
                        ) AS bucket,
                        SUM(bytes_in)  AS bytes_in,
                        SUM(bytes_out) AS bytes_out,
                        SUM(packets)   AS packets
                    FROM bandwidth_samples
                    WHERE timestamp >= ?
                    GROUP BY bucket
                    ORDER BY bucket ASC
                    """,
                    (since,),
                ).fetchall()

        return [
            {
                "timestamp": row["bucket"],
                "bytes_in":  row["bytes_in"]  or 0,
                "bytes_out": row["bytes_out"] or 0,
                "bytes_total": (row["bytes_in"] or 0) + (row["bytes_out"] or 0),
                "packets":   row["packets"]   or 0,
            }
            for row in rows
        ]
    except Exception as exc:  # pylint: disable=broad-except
        log.error("get_bandwidth_history failed: %s", exc)
        return []


# ---------------------------------------------------------------------------
# Top devices / apps
# ---------------------------------------------------------------------------


def get_top_devices(
    hours: int = 1,
    limit: int = 10,
    db_path: str = DB_PATH,
) -> List[Dict[str, Any]]:
    """Return top devices by total bytes transferred in the last *hours* hours."""
    since = _cutoff(float(hours))
    try:
        with get_db(db_path) as conn:
            rows = conn.execute(
                """
                SELECT device_mac,
                       SUM(bytes_in)  AS bytes_in,
                       SUM(bytes_out) AS bytes_out,
                       SUM(bytes_in) + SUM(bytes_out) AS bytes_total,
                       SUM(packets)   AS packets,
                       COUNT(*)       AS sample_count
                FROM bandwidth_samples
                WHERE timestamp >= ?
                GROUP BY device_mac
                ORDER BY bytes_total DESC
                LIMIT ?
                """,
                (since, limit),
            ).fetchall()
        return [
            {
                "device_mac":   row["device_mac"],
                "bytes_in":     row["bytes_in"]    or 0,
                "bytes_out":    row["bytes_out"]   or 0,
                "bytes_total":  row["bytes_total"] or 0,
                "packets":      row["packets"]     or 0,
                "sample_count": row["sample_count"],
            }
            for row in rows
        ]
    except Exception as exc:  # pylint: disable=broad-except
        log.error("get_top_devices failed: %s", exc)
        return []


def get_bandwidth_by_app(
    hours: int = 24,
    limit: int = 20,
    db_path: str = DB_PATH,
) -> List[Dict[str, Any]]:
    """Return top applications by total bytes in the last *hours* hours."""
    since = _cutoff(float(hours))
    try:
        with get_db(db_path) as conn:
            rows = conn.execute(
                """
                SELECT app_name,
                       SUM(bytes_in)  AS bytes_in,
                       SUM(bytes_out) AS bytes_out,
                       SUM(bytes_in) + SUM(bytes_out) AS bytes_total,
                       SUM(packets)   AS packets,
                       COUNT(DISTINCT device_mac) AS device_count
                FROM bandwidth_samples
                WHERE timestamp >= ?
                GROUP BY app_name
                ORDER BY bytes_total DESC
                LIMIT ?
                """,
                (since, limit),
            ).fetchall()
        return [
            {
                "app_name":     row["app_name"],
                "bytes_in":     row["bytes_in"]    or 0,
                "bytes_out":    row["bytes_out"]   or 0,
                "bytes_total":  row["bytes_total"] or 0,
                "packets":      row["packets"]     or 0,
                "device_count": row["device_count"],
            }
            for row in rows
        ]
    except Exception as exc:  # pylint: disable=broad-except
        log.error("get_bandwidth_by_app failed: %s", exc)
        return []


def get_device_app_breakdown(
    device_mac: str,
    hours: int = 24,
    limit: int = 10,
    db_path: str = DB_PATH,
) -> List[Dict[str, Any]]:
    """Return per-app bandwidth breakdown for a specific device."""
    since = _cutoff(float(hours))
    try:
        with get_db(db_path) as conn:
            rows = conn.execute(
                """
                SELECT app_name,
                       SUM(bytes_in)  AS bytes_in,
                       SUM(bytes_out) AS bytes_out,
                       SUM(bytes_in) + SUM(bytes_out) AS bytes_total,
                       SUM(packets)   AS packets
                FROM bandwidth_samples
                WHERE timestamp >= ? AND device_mac = ?
                GROUP BY app_name
                ORDER BY bytes_total DESC
                LIMIT ?
                """,
                (since, device_mac, limit),
            ).fetchall()
        return [
            {
                "app_name":    row["app_name"],
                "bytes_in":    row["bytes_in"]   or 0,
                "bytes_out":   row["bytes_out"]  or 0,
                "bytes_total": row["bytes_total"] or 0,
                "packets":     row["packets"]    or 0,
            }
            for row in rows
        ]
    except Exception as exc:  # pylint: disable=broad-except
        log.error("get_device_app_breakdown failed: %s", exc)
        return []


# ---------------------------------------------------------------------------
# Maintenance
# ---------------------------------------------------------------------------


def cleanup_old_samples(days: int = 7, db_path: str = DB_PATH) -> Dict[str, int]:
    """Delete bandwidth_samples and dpi_flows older than *days* days.

    Returns a dict with 'deleted_samples' and 'deleted_flows' counts.
    """
    cutoff = _days_cutoff(days)
    try:
        with get_db(db_path) as conn:
            cur_s = conn.execute(
                "DELETE FROM bandwidth_samples WHERE timestamp < ?", (cutoff,)
            )
            deleted_samples = cur_s.rowcount

            cur_f = conn.execute(
                "DELETE FROM dpi_flows WHERE last_seen < ?", (cutoff,)
            )
            deleted_flows = cur_f.rowcount

        log.info(
            "Bandwidth cleanup: removed %d samples, %d flows (older than %d days)",
            deleted_samples, deleted_flows, days,
        )
        return {"deleted_samples": deleted_samples, "deleted_flows": deleted_flows}
    except Exception as exc:  # pylint: disable=broad-except
        log.error("cleanup_old_samples failed: %s", exc)
        return {"deleted_samples": 0, "deleted_flows": 0}


def get_summary_stats(
    hours: int = 24,
    db_path: str = DB_PATH,
) -> Dict[str, Any]:
    """Return a high-level bandwidth summary for the last *hours* hours."""
    since = _cutoff(float(hours))
    try:
        with get_db(db_path) as conn:
            totals = conn.execute(
                """
                SELECT SUM(bytes_in)  AS bytes_in,
                       SUM(bytes_out) AS bytes_out,
                       SUM(packets)   AS packets,
                       COUNT(DISTINCT device_mac) AS active_devices,
                       COUNT(DISTINCT app_name)   AS active_apps
                FROM bandwidth_samples
                WHERE timestamp >= ?
                """,
                (since,),
            ).fetchone()

            flow_count = conn.execute(
                "SELECT COUNT(*) FROM dpi_flows WHERE last_seen >= ?", (since,)
            ).fetchone()[0]

        b_in  = totals["bytes_in"]  or 0
        b_out = totals["bytes_out"] or 0
        return {
            "hours":          hours,
            "bytes_in":       b_in,
            "bytes_out":      b_out,
            "bytes_total":    b_in + b_out,
            "packets":        totals["packets"] or 0,
            "active_devices": totals["active_devices"] or 0,
            "active_apps":    totals["active_apps"] or 0,
            "active_flows":   flow_count or 0,
        }
    except Exception as exc:  # pylint: disable=broad-except
        log.error("get_summary_stats failed: %s", exc)
        return {}
