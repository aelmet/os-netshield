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

"""NetShield daemon — device tracking and alerting service.

Usage:
    netshield_daemon.py start   — daemonise and start
    netshield_daemon.py stop    — send SIGTERM to running daemon
    netshield_daemon.py restart — stop then start
    netshield_daemon.py status  — report running / stopped
"""

import asyncio
import logging
import logging.handlers
import os
import signal
import subprocess
import sys
import time

# ---------------------------------------------------------------------------
# sys.path: ensure lib/ is importable regardless of cwd
# ---------------------------------------------------------------------------
_SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))
if _SCRIPT_DIR not in sys.path:
    sys.path.insert(0, _SCRIPT_DIR)

from lib.config import load_config, PID_FILE, LOG_FILE
from lib import db as _db
from lib import device_tracker as _tracker
from lib import alert_sender as _sender
from lib import bandwidth_tracker as _bw

# ---------------------------------------------------------------------------
# Globals
# ---------------------------------------------------------------------------
_shutdown = False


# ---------------------------------------------------------------------------
# Logging setup
# ---------------------------------------------------------------------------

def _setup_logging(log_level: str = "INFO") -> logging.Logger:
    """Configure rotating file + stderr logging, return root logger."""
    numeric = getattr(logging, log_level.upper(), logging.INFO)
    formatter = logging.Formatter(
        "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
    )

    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)

    file_handler = logging.handlers.RotatingFileHandler(
        LOG_FILE, maxBytes=5 * 1024 * 1024, backupCount=3
    )
    file_handler.setFormatter(formatter)

    stderr_handler = logging.StreamHandler(sys.stderr)
    stderr_handler.setFormatter(formatter)

    root = logging.getLogger()
    root.setLevel(numeric)
    root.addHandler(file_handler)
    root.addHandler(stderr_handler)

    return root


# ---------------------------------------------------------------------------
# PID helpers
# ---------------------------------------------------------------------------

def _write_pid(pid: int) -> None:
    os.makedirs(os.path.dirname(PID_FILE), exist_ok=True)
    with open(PID_FILE, "w") as fh:
        fh.write(str(pid) + "\n")


def _read_pid() -> int:
    """Return PID from PID_FILE, or 0 if absent / invalid."""
    try:
        with open(PID_FILE, "r") as fh:
            return int(fh.read().strip())
    except (OSError, ValueError):
        return 0


def _remove_pid() -> None:
    try:
        os.unlink(PID_FILE)
    except OSError:
        pass


def _is_running(pid: int) -> bool:
    """Return True if *pid* is alive (kill(pid, 0) trick)."""
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
        return True
    except (ProcessLookupError, PermissionError):
        return False


# ---------------------------------------------------------------------------
# Double-fork daemonisation (POSIX only)
# ---------------------------------------------------------------------------

def _daemonise() -> None:
    """Detach from the controlling terminal using the double-fork technique."""
    # First fork
    try:
        pid = os.fork()
    except AttributeError:
        # Windows / platforms without fork — run in-process
        return

    if pid > 0:
        # Parent exits
        sys.exit(0)

    os.setsid()

    # Second fork
    pid = os.fork()
    if pid > 0:
        sys.exit(0)

    # Redirect standard file descriptors to /dev/null
    sys.stdout.flush()
    sys.stderr.flush()
    devnull = open(os.devnull, "r+")
    os.dup2(devnull.fileno(), sys.stdin.fileno())
    os.dup2(devnull.fileno(), sys.stdout.fileno())
    os.dup2(devnull.fileno(), sys.stderr.fileno())


# ---------------------------------------------------------------------------
# Signal handler
# ---------------------------------------------------------------------------

def _handle_sigterm(signum, frame) -> None:  # noqa: ARG001
    global _shutdown
    logging.getLogger(__name__).info("Received SIGTERM — shutting down")
    _shutdown = True


# ---------------------------------------------------------------------------
# CPU watchdog — kill runaway processes to prevent overheating
# ---------------------------------------------------------------------------

_CPU_THRESHOLD = 95.0       # per-process %CPU to consider "runaway"
_CPU_MAX_AGE_SECS = 120     # kill if running > 2 minutes at high CPU
_TEMP_CRITICAL = 85         # celsius — aggressive kill above this

def _get_cpu_temp() -> float:
    """Read CPU temperature (FreeBSD sysctl). Returns 0.0 on failure."""
    try:
        r = subprocess.run(
            ["sysctl", "-n", "dev.cpu.0.temperature"],
            capture_output=True, text=True, timeout=5,
        )
        # Output like "72.0C"
        return float(r.stdout.strip().rstrip("C"))
    except Exception:
        return 0.0


def _kill_runaway_processes(logger: logging.Logger) -> int:
    """Find and kill processes using >95% CPU for >2 min. Returns kill count."""
    killed = 0
    try:
        r = subprocess.run(
            ["ps", "-axo", "pid,pcpu,etime,command"],
            capture_output=True, text=True, timeout=10,
        )
        for line in r.stdout.strip().split("\n")[1:]:
            parts = line.split(None, 3)
            if len(parts) < 4:
                continue
            pid_s, cpu_s, etime, cmd = parts
            try:
                pid = int(pid_s)
                cpu = float(cpu_s)
            except ValueError:
                continue
            if cpu < _CPU_THRESHOLD or pid == os.getpid():
                continue
            # Parse etime (MM:SS or HH:MM:SS or D-HH:MM:SS)
            try:
                secs = 0
                if "-" in etime:
                    days, rest = etime.split("-", 1)
                    secs += int(days) * 86400
                    etime = rest
                parts_t = etime.split(":")
                if len(parts_t) == 3:
                    secs += int(parts_t[0]) * 3600 + int(parts_t[1]) * 60 + int(parts_t[2])
                elif len(parts_t) == 2:
                    secs += int(parts_t[0]) * 60 + int(parts_t[1])
            except ValueError:
                continue
            if secs < _CPU_MAX_AGE_SECS:
                continue
            # Skip critical system processes
            base = cmd.split("/")[-1].split()[0] if cmd else ""
            protected = {"kernel", "init", "syslogd", "devd", "configd", "python3", "php", "nginx", "unbound", "sshd", "pfctl"}
            if base in protected:
                continue
            logger.warning(
                "CPU watchdog: killing PID %d (%s) — %.1f%% CPU for %ds",
                pid, cmd[:80], cpu, secs,
            )
            try:
                os.kill(pid, signal.SIGKILL)
                killed += 1
            except ProcessLookupError:
                pass
    except Exception as exc:
        logger.debug("CPU watchdog error: %s", exc)
    return killed


# ---------------------------------------------------------------------------
# Main async loop
# ---------------------------------------------------------------------------

async def main_loop(cfg, logger: logging.Logger) -> None:
    """Continuously track devices and fire alerts until _shutdown is set."""
    global _shutdown

    check_interval = cfg.getint("general", "check_interval", fallback=60)
    new_device_alert = cfg.getboolean("alerts", "new_device_alert", fallback=True)
    flush_interval = cfg.getint("database", "flush_interval", fallback=86400)
    alert_retention_days = cfg.getint("general", "alert_retention_days", fallback=30)
    bw_sample_interval = cfg.getint("general", "bandwidth_sample_interval", fallback=30)

    last_flush = time.monotonic()
    last_bw_sample = time.monotonic()

    logger.info(
        "NetShield main_loop started (check_interval=%ds, new_device_alert=%s)",
        check_interval,
        new_device_alert,
    )

    while not _shutdown:
        loop_start = time.monotonic()

        # --- Device tracking ---
        try:
            new_alerts = _tracker.track_devices(_db)
        except Exception as exc:
            logger.error("track_devices error: %s", exc)
            new_alerts = []

        # --- Send alerts for new devices ---
        if new_device_alert and new_alerts:
            try:
                _sender.send_alerts(new_alerts, cfg)
            except Exception as exc:
                logger.error("send_alerts error: %s", exc)

        # --- Timestamp for periodic tasks ---
        now_mono = time.monotonic()

        # --- Bandwidth sampling ---
        if now_mono - last_bw_sample >= bw_sample_interval:
            try:
                _bw.record_samples_from_netstat()
            except Exception as exc:
                logger.error("bandwidth sampling error: %s", exc)
            last_bw_sample = now_mono

        # --- Periodic flush of old alerts ---
        if now_mono - last_flush >= flush_interval:
            try:
                result = _db.flush_old_alerts(days=alert_retention_days)
                logger.info("Flushed old alerts: %s", result)
            except Exception as exc:
                logger.warning("flush_old_alerts error: %s", exc)
            last_flush = now_mono

        # --- Sleep until next cycle (interruptible) ---
        elapsed = time.monotonic() - loop_start
        sleep_for = max(0.0, check_interval - elapsed)

        try:
            await asyncio.sleep(sleep_for)
        except asyncio.CancelledError:
            break

    logger.info("NetShield main_loop exiting")


# ---------------------------------------------------------------------------
# CLI commands
# ---------------------------------------------------------------------------

def cmd_start() -> None:
    """Start the daemon."""
    existing_pid = _read_pid()
    if _is_running(existing_pid):
        print(f"netshield is already running (pid {existing_pid})")
        sys.exit(1)

    _daemonise()

    # After daemonisation we are in the child process
    signal.signal(signal.SIGTERM, _handle_sigterm)
    signal.signal(signal.SIGINT, _handle_sigterm)

    cfg = load_config()
    log_level = cfg.get("general", "log_level", fallback="INFO")
    logger = _setup_logging(log_level)

    _write_pid(os.getpid())
    logger.info("NetShield daemon started (pid %d)", os.getpid())

    try:
        _db.init_db()
        _bw.init_bandwidth_tables()
        _db.audit("daemon_start", detail=f"pid={os.getpid()}")
    except Exception as exc:
        logger.error("Database initialisation failed: %s", exc)
        _remove_pid()
        sys.exit(1)

    try:
        asyncio.run(main_loop(cfg, logger))
    except Exception as exc:
        logger.critical("Unhandled exception in main_loop: %s", exc, exc_info=True)
    finally:
        _db.audit("daemon_stop", detail=f"pid={os.getpid()}")
        _remove_pid()
        logger.info("NetShield daemon stopped")


def cmd_stop() -> None:
    """Send SIGTERM to the running daemon."""
    pid = _read_pid()
    if not _is_running(pid):
        print("netshield is not running")
        sys.exit(1)

    print(f"Stopping netshield (pid {pid})...")
    os.kill(pid, signal.SIGTERM)

    # Wait up to 10 seconds for the process to exit
    for _ in range(20):
        time.sleep(0.5)
        if not _is_running(pid):
            _remove_pid()
            print("netshield stopped")
            return

    print(f"WARNING: netshield (pid {pid}) did not stop within 10 seconds")
    sys.exit(1)


def cmd_restart() -> None:
    """Stop (if running) then start."""
    pid = _read_pid()
    if _is_running(pid):
        cmd_stop()
    cmd_start()


def cmd_status() -> None:
    """Print running / stopped status."""
    pid = _read_pid()
    if _is_running(pid):
        print(f"netshield is running (pid {pid})")
    else:
        print("netshield is stopped")



# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

_COMMANDS = {
    "start":   cmd_start,
    "stop":    cmd_stop,
    "restart": cmd_restart,
    "status":  cmd_status,
}

if __name__ == "__main__":
    if len(sys.argv) != 2 or sys.argv[1] not in _COMMANDS:
        print(f"Usage: {os.path.basename(sys.argv[0])} {{start|stop|restart|status}}")
        sys.exit(1)

    _COMMANDS[sys.argv[1]]()
