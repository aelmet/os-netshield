#!/usr/local/bin/python3

# Copyright (c) 2025-2026, NetShield Project
# All rights reserved.
# BSD 2-Clause License (see project LICENSE)

"""configd script: raw internet speed test bypassing VPN/firewall rules.

Uses curl --interface to bind directly to the WAN interface (pppoe0),
measuring actual ISP speed before any VPN tunneling or policy routing.
Results are stored persistently in the NetShield database.
"""

import json
import os
import re
import sqlite3
import subprocess
import sys
import time
from datetime import datetime, timezone


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

# Download test servers — large files on fast CDNs (HTTPS)
DOWNLOAD_TESTS = [
    ("cloudflare-25MB", "https://speed.cloudflare.com/__down?bytes=26214400"),
    ("cloudflare-10MB", "https://speed.cloudflare.com/__down?bytes=10485760"),
    ("hetzner-100MB",   "https://speed.hetzner.de/100MB.bin"),
    ("tele2-10MB",      "https://speedtest.tele2.net/10MB.zip"),
]

# Upload test — Cloudflare speed test accepts POST
UPLOAD_TESTS = [
    ("cloudflare-up", "https://speed.cloudflare.com/__up"),
]

# Ping targets
PING_HOSTS = ["8.8.8.8", "1.1.1.1", "9.9.9.9"]

# Timeouts
DL_TIMEOUT = 30
UL_TIMEOUT = 30
PING_COUNT = 5

# DB for persistent results
DB_PATH = "/var/db/netshield/netshield.db"


# ---------------------------------------------------------------------------
# WAN interface detection
# ---------------------------------------------------------------------------

def get_wan_interface():
    """Detect the WAN interface from the default route."""
    try:
        result = subprocess.run(
            ["route", "-n", "get", "default"],
            capture_output=True, text=True, timeout=5
        )
        for line in result.stdout.splitlines():
            if "interface:" in line:
                return line.split(":")[-1].strip()
    except Exception:
        pass

    # Fallback: check common WAN interfaces
    for iface in ["pppoe0", "igc0", "igb0", "em0", "vtnet0"]:
        result = subprocess.run(
            ["ifconfig", iface], capture_output=True, text=True
        )
        if "inet " in result.stdout and result.returncode == 0:
            return iface

    return None


# ---------------------------------------------------------------------------
# Download speed test (curl-based, WAN-bound)
# ---------------------------------------------------------------------------

def test_download(url, wan_iface, size_label=""):
    """Download via curl bound to WAN interface. Returns speed in Mbps."""
    cmd = [
        "curl", "-so", "/dev/null",
        "--interface", wan_iface,
        "--max-time", str(DL_TIMEOUT),
        "-w", "%{speed_download}|%{size_download}|%{time_total}|%{http_code}",
        url
    ]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=DL_TIMEOUT + 5)

    if result.returncode != 0:
        raise RuntimeError(f"curl failed: {result.stderr.strip()[:200]}")

    parts = result.stdout.strip().split("|")
    if len(parts) < 4:
        raise RuntimeError(f"Unexpected curl output: {result.stdout.strip()}")

    speed_bytes_sec = float(parts[0])
    size_bytes = float(parts[1])
    elapsed = float(parts[2])
    http_code = parts[3]

    if http_code != "200":
        raise RuntimeError(f"HTTP {http_code}")
    if size_bytes < 1024:
        raise RuntimeError("Too little data received")

    mbps = (speed_bytes_sec * 8) / 1_000_000
    return round(mbps, 2), round(size_bytes / 1_000_000, 1), round(elapsed, 2)


def run_download_test(wan_iface):
    """Multi-stream download test for accurate speed on fast connections.
    Uses 4 parallel streams to saturate the link, then reports aggregate speed.
    Falls back to single-stream if parallel fails.
    """
    from concurrent.futures import ThreadPoolExecutor, as_completed

    # Try multi-stream first (4 parallel downloads)
    url = DOWNLOAD_TESTS[0][1]  # Cloudflare 25MB
    name = DOWNLOAD_TESTS[0][0]
    streams = 4

    try:
        t_start = time.monotonic()
        total_bytes = 0
        results_ok = 0

        def _dl_stream(stream_id):
            outfile = f"/tmp/ns_speedtest_{stream_id}.bin"
            cmd = [
                "curl", "-so", outfile,
                "--interface", wan_iface,
                "--max-time", str(DL_TIMEOUT),
                "-w", "%{speed_download}|%{size_download}|%{time_total}|%{http_code}",
                url
            ]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=DL_TIMEOUT + 5)
            try:
                os.unlink(outfile)
            except OSError:
                pass
            parts = result.stdout.strip().split("|")
            if len(parts) >= 4 and parts[3] == "200":
                return float(parts[1])
            return 0

        with ThreadPoolExecutor(max_workers=streams) as executor:
            futures = [executor.submit(_dl_stream, i) for i in range(streams)]
            for f in as_completed(futures, timeout=DL_TIMEOUT + 10):
                size = f.result()
                if size > 0:
                    total_bytes += size
                    results_ok += 1

        total_elapsed = time.monotonic() - t_start

        if results_ok >= 2 and total_bytes > 1024 and total_elapsed > 0:
            mbps = (total_bytes * 8) / total_elapsed / 1_000_000
            return {
                "download_mbps": round(mbps, 2),
                "server": f"{name} x{results_ok}",
                "server_url": url,
                "dl_size_mb": round(total_bytes / 1_000_000, 1),
                "dl_elapsed_s": round(total_elapsed, 2),
            }
    except Exception:
        pass

    # Fallback: single-stream from each server
    errors = {}
    for sname, surl in DOWNLOAD_TESTS:
        try:
            mbps, size_mb, elapsed = test_download(surl, wan_iface)
            return {
                "download_mbps": mbps,
                "server": sname,
                "server_url": surl,
                "dl_size_mb": size_mb,
                "dl_elapsed_s": elapsed,
            }
        except Exception as exc:
            errors[sname] = str(exc)

    return {"error": "All download servers failed", "details": errors}


# ---------------------------------------------------------------------------
# Upload speed test (curl-based, WAN-bound)
# ---------------------------------------------------------------------------

def run_upload_test(wan_iface):
    """Upload test using curl POST to Cloudflare speed endpoint."""
    # Generate 5MB of data
    upload_size = 5 * 1024 * 1024
    data_file = "/tmp/netshield_speedtest_upload.bin"

    try:
        # Create upload payload
        with open(data_file, "wb") as f:
            f.write(os.urandom(upload_size))

        for name, url in UPLOAD_TESTS:
            try:
                cmd = [
                    "curl", "-so", "/dev/null",
                    "--interface", wan_iface,
                    "--max-time", str(UL_TIMEOUT),
                    "-X", "POST",
                    "-H", "Content-Type: application/octet-stream",
                    "--data-binary", f"@{data_file}",
                    "-w", "%{speed_upload}|%{size_upload}|%{time_total}|%{http_code}",
                    url
                ]
                result = subprocess.run(
                    cmd, capture_output=True, text=True, timeout=UL_TIMEOUT + 5
                )

                if result.returncode != 0:
                    continue

                parts = result.stdout.strip().split("|")
                if len(parts) < 4:
                    continue

                speed_bytes_sec = float(parts[0])
                http_code = parts[3]
                elapsed = float(parts[2])

                if http_code not in ("200", "201", "204"):
                    continue

                mbps = (speed_bytes_sec * 8) / 1_000_000
                return round(mbps, 2), round(elapsed, 2)
            except Exception:
                continue
    finally:
        try:
            os.unlink(data_file)
        except OSError:
            pass

    return None, None


# ---------------------------------------------------------------------------
# Ping / latency test (ICMP via ping command, WAN-bound)
# ---------------------------------------------------------------------------

def measure_ping(wan_iface):
    """Measure latency using ICMP ping bound to the WAN source address."""
    # Get WAN IP for source binding
    wan_ip = None
    try:
        result = subprocess.run(
            ["ifconfig", wan_iface], capture_output=True, text=True
        )
        for line in result.stdout.splitlines():
            m = re.search(r"inet (\d+\.\d+\.\d+\.\d+)", line)
            if m:
                wan_ip = m.group(1)
                break
    except Exception:
        pass

    best_avg = None
    best_host = None

    for host in PING_HOSTS:
        try:
            cmd = ["ping", "-c", str(PING_COUNT), "-W", "2000"]
            if wan_ip:
                cmd += ["-S", wan_ip]
            cmd.append(host)

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)

            # Parse "round-trip min/avg/max/stddev = 8.123/9.456/11.789/1.234 ms"
            m = re.search(
                r"min/avg/max/stddev\s*=\s*([\d.]+)/([\d.]+)/([\d.]+)/([\d.]+)",
                result.stdout
            )
            if m:
                avg_ms = float(m.group(2))
                if best_avg is None or avg_ms < best_avg:
                    best_avg = round(avg_ms, 2)
                    best_host = host
        except Exception:
            pass

    return {"ping_ms": best_avg, "ping_host": best_host}


# ---------------------------------------------------------------------------
# Persistent storage
# ---------------------------------------------------------------------------

def _ensure_table(db_path):
    """Create speedtest_results table if it doesn't exist."""
    conn = sqlite3.connect(db_path)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS speedtest_results (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp       TEXT    NOT NULL,
            download_mbps   REAL,
            upload_mbps     REAL,
            ping_ms         REAL,
            server          TEXT,
            wan_interface   TEXT,
            wan_ip          TEXT,
            dl_size_mb      REAL,
            dl_elapsed_s    REAL,
            ul_elapsed_s    REAL,
            ping_host       TEXT
        )
    """)
    conn.commit()
    conn.close()


def save_result(result, db_path=DB_PATH):
    """Save speed test result to the database."""
    try:
        _ensure_table(db_path)
        conn = sqlite3.connect(db_path)
        conn.execute(
            "INSERT INTO speedtest_results "
            "(timestamp, download_mbps, upload_mbps, ping_ms, server, "
            " wan_interface, wan_ip, dl_size_mb, dl_elapsed_s, ul_elapsed_s, ping_host) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                result.get("timestamp"),
                result.get("download_mbps"),
                result.get("upload_mbps"),
                result.get("ping_ms"),
                result.get("server"),
                result.get("wan_interface"),
                result.get("wan_ip"),
                result.get("dl_size_mb"),
                result.get("dl_elapsed_s"),
                result.get("ul_elapsed_s"),
                result.get("ping_host"),
            ),
        )
        conn.commit()
        conn.close()
    except Exception:
        pass  # Don't fail the test if DB write fails


def get_history(limit=20, db_path=DB_PATH):
    """Get recent speed test history."""
    try:
        _ensure_table(db_path)
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT * FROM speedtest_results ORDER BY timestamp DESC LIMIT ?",
            (limit,)
        ).fetchall()
        conn.close()
        return [dict(r) for r in rows]
    except Exception:
        return []


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    args = []
    for arg in sys.argv[1:]:
        args.extend(arg.replace(",", " ").split())

    # Sub-command: history
    if args and args[0] == "history":
        limit = int(args[1]) if len(args) > 1 else 20
        history = get_history(limit)
        print(json.dumps({"status": "ok", "results": history}, default=str))
        return

    # Default: run speed test
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    # Detect WAN interface
    wan_iface = get_wan_interface()
    if not wan_iface:
        print(json.dumps({
            "status": "error",
            "message": "Could not detect WAN interface",
            "timestamp": timestamp
        }))
        return

    # Get WAN IP
    wan_ip = None
    try:
        result = subprocess.run(
            ["ifconfig", wan_iface], capture_output=True, text=True
        )
        m = re.search(r"inet (\d+\.\d+\.\d+\.\d+)", result.stdout)
        if m:
            wan_ip = m.group(1)
    except Exception:
        pass

    # Run tests
    dl_result = run_download_test(wan_iface)

    if "error" in dl_result:
        print(json.dumps({
            "status": "error",
            "message": dl_result["error"],
            "details": dl_result.get("details"),
            "wan_interface": wan_iface,
            "timestamp": timestamp
        }))
        return

    ping_result = measure_ping(wan_iface)
    upload_mbps, ul_elapsed = run_upload_test(wan_iface)

    output = {
        "status": "ok",
        "download_mbps": dl_result["download_mbps"],
        "upload_mbps": upload_mbps,
        "ping_ms": ping_result["ping_ms"],
        "server": dl_result["server"],
        "server_url": dl_result["server_url"],
        "ping_host": ping_result["ping_host"],
        "wan_interface": wan_iface,
        "wan_ip": wan_ip,
        "dl_size_mb": dl_result.get("dl_size_mb"),
        "dl_elapsed_s": dl_result.get("dl_elapsed_s"),
        "ul_elapsed_s": ul_elapsed,
        "timestamp": timestamp,
    }

    # Save to DB for history
    save_result(output)

    print(json.dumps(output, indent=2))


if __name__ == "__main__":
    main()
