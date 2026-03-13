#!/usr/local/bin/python3
# SPDX-License-Identifier: BSD-2-Clause
#
# NetShield Daemon - Main background daemon process.
# Called by configd: netshield daemon <start|stop|restart|status>
# Double-fork daemonizes on POSIX; loops drive device tracking,
# VPN detection, policy enforcement, alert delivery, and maintenance.

import sys
import os
import json
import time
import signal
import logging
import logging.handlers
import argparse
import traceback
import asyncio
from datetime import datetime, timedelta

# ---------------------------------------------------------------------------
# Path setup — lib/ lives next to this script
# ---------------------------------------------------------------------------
_SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))
sys.path.insert(0, _SCRIPT_DIR)

from lib import config, db, device_tracker, vpn_detector, policy_engine
from lib import alert_sender, enforcement, web_categories, dns_filter

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
PID_FILE    = "/var/run/netshield.pid"
LOG_DIR     = "/var/log/netshield"
LOG_FILE    = os.path.join(LOG_DIR, "netshield.log")
STATE_FILE  = "/var/db/netshield/daemon_state.json"

INTERVAL_DEVICE    = 60    # seconds
INTERVAL_VPN       = 30
INTERVAL_POLICY    = 60
INTERVAL_ALERT     = 10
INTERVAL_MAINT     = 3600  # 1 hour

# Alert deduplication cooldown (seconds)
ALERT_COOLDOWN_DEFAULT = 300  # 5 minutes

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

def _setup_logging() -> logging.Logger:
    os.makedirs(LOG_DIR, exist_ok=True)
    logger = logging.getLogger("netshield")
    logger.setLevel(logging.INFO)
    if logger.handlers:
        return logger
    handler = logging.handlers.RotatingFileHandler(
        LOG_FILE, maxBytes=5 * 1024 * 1024, backupCount=3
    )
    handler.setFormatter(
        logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s")
    )
    logger.addHandler(handler)
    return logger

log = _setup_logging()

# ---------------------------------------------------------------------------
# PID helpers
# ---------------------------------------------------------------------------

def _write_pid(pid: int) -> None:
    os.makedirs(os.path.dirname(PID_FILE), exist_ok=True)
    with open(PID_FILE, "w") as fh:
        fh.write(str(pid) + "\n")


def _read_pid() -> int | None:
    try:
        with open(PID_FILE) as fh:
            return int(fh.read().strip())
    except (FileNotFoundError, ValueError):
        return None


def _remove_pid() -> None:
    try:
        os.unlink(PID_FILE)
    except FileNotFoundError:
        pass


def _is_running(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except (OSError, ProcessLookupError):
        return False

# ---------------------------------------------------------------------------
# Double-fork daemonization
# ---------------------------------------------------------------------------

def _daemonize() -> None:
    """Standard POSIX double-fork daemonization."""
    # First fork
    try:
        pid = os.fork()
        if pid > 0:
            sys.exit(0)
    except OSError as exc:
        log.error("First fork failed: %s", exc)
        sys.exit(1)

    os.setsid()
    os.umask(0o022)

    # Second fork
    try:
        pid = os.fork()
        if pid > 0:
            sys.exit(0)
    except OSError as exc:
        log.error("Second fork failed: %s", exc)
        sys.exit(1)

    # Redirect standard file descriptors
    sys.stdout.flush()
    sys.stderr.flush()
    devnull = open(os.devnull, "r+b")
    os.dup2(devnull.fileno(), sys.stdin.fileno())
    os.dup2(devnull.fileno(), sys.stdout.fileno())
    os.dup2(devnull.fileno(), sys.stderr.fileno())
    devnull.close()

# ---------------------------------------------------------------------------
# Daemon state
# ---------------------------------------------------------------------------

class DaemonState:
    def __init__(self):
        self.start_time: float = time.time()
        self.alerts_today: int = 0
        self.devices_tracked: int = 0
        self.policies_active: int = 0
        self.last_device_check: float = 0.0
        self.last_vpn_check: float = 0.0
        self.last_policy_check: float = 0.0
        self.last_alert_delivery: float = 0.0
        self.last_maintenance: float = 0.0
        # Deduplication: key=(mac, alert_type) -> last sent epoch
        self._alert_sent: dict[tuple[str, str], float] = {}

    def should_send_alert(self, mac: str, alert_type: str, cooldown: int = ALERT_COOLDOWN_DEFAULT) -> bool:
        key = (mac, alert_type)
        last = self._alert_sent.get(key, 0.0)
        if time.time() - last >= cooldown:
            self._alert_sent[key] = time.time()
            return True
        return False

    def save(self) -> None:
        os.makedirs(os.path.dirname(STATE_FILE), exist_ok=True)
        data = {
            "start_time": self.start_time,
            "alerts_today": self.alerts_today,
            "devices_tracked": self.devices_tracked,
            "policies_active": self.policies_active,
            "last_device_check": self.last_device_check,
            "last_vpn_check": self.last_vpn_check,
            "last_policy_check": self.last_policy_check,
            "last_alert_delivery": self.last_alert_delivery,
            "last_maintenance": self.last_maintenance,
        }
        try:
            with open(STATE_FILE, "w") as fh:
                json.dump(data, fh)
        except OSError as exc:
            log.warning("Could not save daemon state: %s", exc)


_state = DaemonState()
_shutdown = False

# ---------------------------------------------------------------------------
# Signal handlers
# ---------------------------------------------------------------------------

def _handle_sigterm(signum, frame):
    global _shutdown
    log.info("Received SIGTERM — initiating graceful shutdown")
    _shutdown = True


def _handle_sigint(signum, frame):
    global _shutdown
    log.info("Received SIGINT — initiating graceful shutdown")
    _shutdown = True

# ---------------------------------------------------------------------------
# Loop helpers — each returns immediately if less than interval has passed
# ---------------------------------------------------------------------------

def _maybe_run(last: float, interval: int, fn, label: str) -> float:
    """Run fn() if interval has elapsed; return new last-run time."""
    if time.time() - last < interval:
        return last
    log.debug("Running loop: %s", label)
    try:
        fn()
    except Exception:
        log.error("Exception in loop %s:\n%s", label, traceback.format_exc())
    return time.time()


# ---------------------------------------------------------------------------
# Loop implementations
# ---------------------------------------------------------------------------

def _loop_device_tracking():
    cfg = config.load()
    interval = int(cfg.get("daemon", {}).get("interval_device", INTERVAL_DEVICE))
    devices = device_tracker.discover_devices()
    new_devices = device_tracker.update_db(devices)
    _state.devices_tracked = len(devices)
    for dev in new_devices:
        if _state.should_send_alert(dev.get("mac", ""), "new_device"):
            alert_sender.queue_alert(
                alert_type="new_device",
                device=dev,
                message=f"New device detected: {dev.get('hostname', dev.get('mac', 'unknown'))}",
            )
            _state.alerts_today += 1
    log.info("Device tracking: %d total, %d new", len(devices), len(new_devices))


def _loop_vpn_detection():
    results = vpn_detector.run_all_checks()
    for result in results:
        mac = result.get("mac", "")
        atype = result.get("alert_type", "vpn_detected")
        if result.get("detected") and _state.should_send_alert(mac, atype):
            alert_sender.queue_alert(
                alert_type=atype,
                device=result,
                message=result.get("message", "VPN/proxy usage detected"),
            )
            _state.alerts_today += 1
    log.info("VPN detection: %d results processed", len(results))


def _loop_policy_enforcement():
    policies = policy_engine.get_active_policies()
    _state.policies_active = len(policies)
    alerts = policy_engine.evaluate_all(policies)
    for alert in alerts:
        mac = alert.get("mac", "")
        atype = alert.get("alert_type", "policy_violation")
        cooldown = int(alert.get("cooldown", ALERT_COOLDOWN_DEFAULT))
        if _state.should_send_alert(mac, atype, cooldown):
            alert_sender.queue_alert(
                alert_type=atype,
                device=alert,
                message=alert.get("message", "Policy violation"),
            )
            _state.alerts_today += 1
    # Generate enforcement rules
    enforcement.apply_policies(policies)
    log.info("Policy enforcement: %d policies, %d new alerts", len(policies), len(alerts))


def _loop_alert_delivery():
    delivered = alert_sender.deliver_pending()
    if delivered:
        log.info("Alert delivery: delivered %d alerts", delivered)


def _loop_maintenance():
    log.info("Running maintenance tasks")
    try:
        alert_sender.flush_old_alerts(days=30)
    except Exception:
        log.error("Maintenance — flush_old_alerts failed:\n%s", traceback.format_exc())
    try:
        cfg = config.load()
        if cfg.get("web_categories", {}).get("auto_update"):
            web_categories.update_from_sources()
    except Exception:
        log.error("Maintenance — web_categories update failed:\n%s", traceback.format_exc())
    try:
        dns_filter.reload_if_changed()
    except Exception:
        log.error("Maintenance — dns_filter reload failed:\n%s", traceback.format_exc())

# ---------------------------------------------------------------------------
# Main run loop
# ---------------------------------------------------------------------------

def _run_daemon():
    global _shutdown

    log.info("NetShield daemon starting (pid=%d)", os.getpid())
    _write_pid(os.getpid())

    # Reset daily alert counter at midnight
    last_day = datetime.now().date()

    try:
        while not _shutdown:
            now_day = datetime.now().date()
            if now_day != last_day:
                _state.alerts_today = 0
                last_day = now_day

            cfg = config.load()
            intervals = cfg.get("daemon", {})

            _state.last_device_check = _maybe_run(
                _state.last_device_check,
                int(intervals.get("interval_device", INTERVAL_DEVICE)),
                _loop_device_tracking,
                "device_tracking",
            )
            _state.last_vpn_check = _maybe_run(
                _state.last_vpn_check,
                int(intervals.get("interval_vpn", INTERVAL_VPN)),
                _loop_vpn_detection,
                "vpn_detection",
            )
            _state.last_policy_check = _maybe_run(
                _state.last_policy_check,
                int(intervals.get("interval_policy", INTERVAL_POLICY)),
                _loop_policy_enforcement,
                "policy_enforcement",
            )
            _state.last_alert_delivery = _maybe_run(
                _state.last_alert_delivery,
                int(intervals.get("interval_alert", INTERVAL_ALERT)),
                _loop_alert_delivery,
                "alert_delivery",
            )
            _state.last_maintenance = _maybe_run(
                _state.last_maintenance,
                int(intervals.get("interval_maint", INTERVAL_MAINT)),
                _loop_maintenance,
                "maintenance",
            )

            _state.save()
            time.sleep(1)

    except Exception:
        log.critical("Unhandled exception in daemon main loop:\n%s", traceback.format_exc())
    finally:
        _remove_pid()
        log.info("NetShield daemon stopped")

# ---------------------------------------------------------------------------
# CLI commands
# ---------------------------------------------------------------------------

def cmd_start(args) -> dict:
    pid = _read_pid()
    if pid and _is_running(pid):
        return {"result": "already_running", "pid": pid}

    # Daemonize only if not in foreground mode
    if not getattr(args, "foreground", False):
        _daemonize()

    signal.signal(signal.SIGTERM, _handle_sigterm)
    signal.signal(signal.SIGINT, _handle_sigint)
    _run_daemon()
    return {"result": "started"}


def cmd_stop(args) -> dict:
    pid = _read_pid()
    if not pid:
        return {"result": "not_running"}
    if not _is_running(pid):
        _remove_pid()
        return {"result": "not_running"}
    try:
        os.kill(pid, signal.SIGTERM)
        # Wait up to 10 seconds
        for _ in range(100):
            time.sleep(0.1)
            if not _is_running(pid):
                return {"result": "stopped"}
        # Force kill
        os.kill(pid, signal.SIGKILL)
        _remove_pid()
        return {"result": "killed"}
    except OSError as exc:
        return {"result": "error", "message": str(exc)}


def cmd_restart(args) -> dict:
    stop_result = cmd_stop(args)
    time.sleep(1)
    start_result = cmd_start(args)
    return {"result": "restarted", "stop": stop_result, "start": start_result}


def cmd_status(args) -> dict:
    pid = _read_pid()
    running = bool(pid and _is_running(pid))

    # Load persisted state
    state_data: dict = {}
    try:
        with open(STATE_FILE) as fh:
            state_data = json.load(fh)
    except (FileNotFoundError, json.JSONDecodeError):
        pass

    uptime_secs: int | None = None
    if running and state_data.get("start_time"):
        uptime_secs = int(time.time() - state_data["start_time"])

    last_check: str | None = None
    ldc = state_data.get("last_device_check")
    if ldc:
        last_check = datetime.fromtimestamp(ldc).strftime("%Y-%m-%d %H:%M:%S")

    return {
        "status": "running" if running else "stopped",
        "pid": pid,
        "uptime": uptime_secs,
        "last_check": last_check,
        "alerts_today": state_data.get("alerts_today", 0),
        "devices_tracked": state_data.get("devices_tracked", 0),
        "policies_active": state_data.get("policies_active", 0),
    }


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="NetShield daemon controller")
    parser.add_argument(
        "command",
        choices=["start", "stop", "restart", "status"],
        help="Daemon command",
    )
    parser.add_argument(
        "--foreground", "-f",
        action="store_true",
        help="Run in foreground (no daemonize)",
    )
    args = parser.parse_args()

    dispatch = {
        "start":   cmd_start,
        "stop":    cmd_stop,
        "restart": cmd_restart,
        "status":  cmd_status,
    }

    try:
        result = dispatch[args.command](args)
    except Exception as exc:
        result = {"result": "error", "message": str(exc), "trace": traceback.format_exc()}

    print(json.dumps(result))


if __name__ == "__main__":
    main()
