#!/usr/local/bin/python3
"""
Tor Auto-Block Daemon: watches Suricata eve.json for Tor alerts,
automatically adds detected IPs to the TOR pf table.
Runs as a background daemon.
"""
import json
import os
import subprocess
import sys
import time
import signal

EVE_LOG = "/var/log/suricata/eve.json"
PF_TABLE = "TOR"
CHECK_INTERVAL = 5  # seconds
BLOCKED_IPS_FILE = "/var/db/netshield/tor_autoblock.txt"

# Tor-related alert signatures to act on
TOR_SIGNATURES = [
    "tor", "obfs4", "snowflake", "meek", "NETSHIELD", "NETGUARDIAN",
    "anonymizer", "Tor Exit", "Tor Relay",
]

running = True

def signal_handler(sig, frame):
    global running
    running = False

signal.signal(signal.SIGTERM, signal_handler)
signal.signal(signal.SIGINT, signal_handler)

def load_blocked():
    """Load already-blocked IPs."""
    if os.path.exists(BLOCKED_IPS_FILE):
        with open(BLOCKED_IPS_FILE) as f:
            return set(l.strip() for l in f if l.strip())
    return set()

def save_blocked(ips):
    """Save blocked IPs to file."""
    with open(BLOCKED_IPS_FILE, "w") as f:
        for ip in sorted(ips):
            f.write(ip + "\n")

def add_to_pf(ip):
    """Add IP to TOR pf table."""
    r = subprocess.run(
        ["pfctl", "-t", PF_TABLE, "-T", "add", ip],
        capture_output=True, text=True, timeout=5
    )
    return "1/1" in r.stderr  # "1/1 addresses added"

def is_tor_alert(alert_sig):
    """Check if an alert signature is Tor-related."""
    sig_lower = alert_sig.lower()
    return any(t.lower() in sig_lower for t in TOR_SIGNATURES)

def main():
    blocked = load_blocked()

    if not os.path.exists(EVE_LOG):
        print("Waiting for eve.json...")
        while not os.path.exists(EVE_LOG) and running:
            time.sleep(5)

    # Seek to end of file
    with open(EVE_LOG) as f:
        f.seek(0, 2)  # End of file
        file_pos = f.tell()

    print("Tor auto-block daemon started. Watching {}".format(EVE_LOG))

    while running:
        try:
            with open(EVE_LOG) as f:
                f.seek(file_pos)
                new_data = f.read()
                file_pos = f.tell()

            if new_data:
                for line in new_data.strip().split("\n"):
                    if not line.strip():
                        continue
                    try:
                        entry = json.loads(line)
                    except json.JSONDecodeError:
                        continue

                    if entry.get("event_type") != "alert":
                        continue

                    alert = entry.get("alert", {})
                    sig = alert.get("signature", "")

                    if is_tor_alert(sig):
                        dst_ip = entry.get("dest_ip", "")
                        src_ip = entry.get("src_ip", "")

                        # Block the external IP (not our LAN IP)
                        block_ip = dst_ip if dst_ip and not dst_ip.startswith("192.168.") else src_ip

                        if block_ip and block_ip not in blocked and not block_ip.startswith("192.168."):
                            if add_to_pf(block_ip):
                                blocked.add(block_ip)
                                save_blocked(blocked)
                                print("BLOCKED: {} (sig: {})".format(block_ip, sig[:60]))

            time.sleep(CHECK_INTERVAL)

        except Exception as exc:
            print("Error: {}".format(exc))
            time.sleep(10)

if __name__ == "__main__":
    main()
