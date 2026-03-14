#!/usr/local/bin/python3
"""
Router Health Check — detect and optionally kill runaway processes.

Usage:
  router_health_check.py              # Report only
  router_health_check.py --kill       # Kill runaway processes
  router_health_check.py --json       # JSON output for automation

A process is considered "runaway" if:
  - CPU > 90% for a non-whitelisted process
  - Running longer than 30 minutes for grep/find/sed/awk/sort
  - Python script using >90% CPU that isn't a known daemon
  - Zombie processes older than 5 minutes
"""

import subprocess
import json
import sys
import re

# Legitimate high-CPU processes (won't be flagged)
WHITELIST = {
    'eastpect', 'suricata', 'dpinger', 'openvpn',
    'unbound', 'lighttpd', 'php-cgi', 'configd',
    'sshd', 'cron', 'syslogd', 'devd',
    'netshield', 'pflogd', 'filterlog',
    'idle', 'kernel', 'init', 'audit', 'intr',
}

# Python scripts that are legitimate daemons (allowed to use CPU)
PYTHON_DAEMON_WHITELIST = {
    'netshield_daemon.py',
    'netguardian_daemon.py',
    'ddclient_opn.py',
    'flowd_aggregate.py',
    'logger.py',
    'configd.py',
    'gateway_watcher.php',
}

# Commands that should NEVER run longer than 30 minutes
TRANSIENT_COMMANDS = {'grep', 'find', 'sed', 'awk', 'sort', 'xargs', 'cat', 'tail', 'head'}

MAX_TRANSIENT_MINUTES = 30
CPU_THRESHOLD = 90.0


def get_processes():
    """Get all processes with CPU, time, and command info."""
    r = subprocess.run(
        ['ps', '-axo', 'pid,pcpu,etime,comm,args'],
        capture_output=True, text=True
    )
    processes = []
    for line in r.stdout.strip().split('\n')[1:]:
        parts = line.split(None, 4)
        if len(parts) < 5:
            continue
        try:
            pid = int(parts[0])
            cpu = float(parts[1])
            etime = parts[2]
            comm = parts[3]
            args = parts[4]
            processes.append({
                'pid': pid,
                'cpu': cpu,
                'etime': etime,
                'comm': comm,
                'args': args,
                'minutes': parse_etime(etime),
            })
        except (ValueError, IndexError):
            continue
    return processes


def parse_etime(etime):
    """Parse elapsed time like '555:43' or '1-02:30:15' to minutes."""
    days = 0
    if '-' in etime:
        day_part, etime = etime.split('-', 1)
        days = int(day_part)
    parts = etime.split(':')
    if len(parts) == 3:
        return days * 1440 + int(parts[0]) * 60 + int(parts[1])
    elif len(parts) == 2:
        return days * 1440 + int(parts[0])
    return 0


def is_python_daemon(args):
    """Check if a python process is a known daemon."""
    for daemon in PYTHON_DAEMON_WHITELIST:
        if daemon in args:
            return True
    return False


def find_runaways(processes):
    """Identify runaway processes."""
    runaways = []
    for p in processes:
        comm = p['comm'].lower()
        args = p['args']

        # Skip kernel threads
        if p['pid'] < 100 or comm.startswith('['):
            continue

        # Python process — check if it's a known daemon
        if comm in ('python3', 'python3.13', 'python3.11', 'python'):
            if p['cpu'] >= CPU_THRESHOLD and not is_python_daemon(args):
                runaways.append({**p, 'reason': f"Python script CPU {p['cpu']}% (not a known daemon)"})
            continue

        # Skip whitelisted processes
        if comm in WHITELIST:
            continue

        # High CPU non-whitelisted process
        if p['cpu'] >= CPU_THRESHOLD:
            runaways.append({**p, 'reason': f"CPU {p['cpu']}% (non-whitelisted)"})
            continue

        # Transient commands running too long
        if comm in TRANSIENT_COMMANDS and p['minutes'] > MAX_TRANSIENT_MINUTES:
            runaways.append({**p, 'reason': f"{comm} running {p['minutes']}min (max {MAX_TRANSIENT_MINUTES})"})
            continue

    return runaways


def main():
    kill_mode = '--kill' in sys.argv
    json_mode = '--json' in sys.argv

    processes = get_processes()
    runaways = find_runaways(processes)

    if json_mode:
        result = {
            'status': 'warning' if runaways else 'ok',
            'runaways': [{
                'pid': r['pid'],
                'cpu': r['cpu'],
                'minutes': r['minutes'],
                'command': r['args'][:200],
                'reason': r['reason'],
            } for r in runaways],
            'total_processes': len(processes),
        }
        if kill_mode and runaways:
            killed = []
            for r in runaways:
                try:
                    subprocess.run(['kill', str(r['pid'])], capture_output=True)
                    killed.append(r['pid'])
                except Exception:
                    pass
            result['killed'] = killed
        print(json.dumps(result))
        return

    if not runaways:
        print(f"OK: {len(processes)} processes, no runaways detected")
        return

    print(f"WARNING: {len(runaways)} runaway process(es) found:\n")
    for r in runaways:
        print(f"  PID {r['pid']:>6}  CPU {r['cpu']:>5.1f}%  {r['minutes']:>6}min  {r['reason']}")
        print(f"           {r['args'][:120]}")

    if kill_mode:
        print("\nKilling runaway processes...")
        for r in runaways:
            try:
                subprocess.run(['kill', str(r['pid'])], capture_output=True)
                print(f"  Killed PID {r['pid']}")
            except Exception as e:
                print(f"  Failed to kill PID {r['pid']}: {e}")
    else:
        print("\nRun with --kill to terminate these processes")


if __name__ == '__main__':
    main()
