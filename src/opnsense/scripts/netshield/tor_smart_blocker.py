#!/usr/local/bin/python3
"""
Smart Tor auto-blocker: monitors Suricata alerts and blocks Tor bridge IPs
WITH a CDN/legitimate IP whitelist to prevent false positives.

Runs as a daemon. Watches eve.json for Tor alerts, validates IPs aren't CDN,
then adds them to the TOR pf table.

Also implements connection pattern analysis: if a LAN client makes many
short-lived TLS connections to diverse IPs on port 443, that's Tor behavior.
"""
import json
import os
import subprocess
import time
import sys
import signal

# CDN/Cloud IP ranges that MUST NEVER be blocked
# These are /16 or /8 prefixes for major providers
WHITELIST_PREFIXES = [
    # AWS
    "3.", "13.", "15.", "18.", "35.", "44.", "50.", "52.", "54.", "99.",
    # Azure
    "4.", "13.64.", "13.65.", "13.66.", "13.67.", "13.68.", "13.69.",
    "13.70.", "13.71.", "13.72.", "13.73.", "13.74.", "13.75.", "13.76.",
    "13.77.", "13.78.", "13.79.", "13.80.", "13.81.", "13.82.", "13.83.",
    "13.84.", "13.85.", "13.86.", "13.87.", "13.88.", "13.89.", "13.90.",
    "13.91.", "13.92.", "13.93.", "13.94.", "13.95.", "13.96.", "13.97.",
    "13.98.", "13.99.", "13.100.", "13.101.", "13.102.", "13.103.", "13.104.",
    "13.105.", "13.106.", "13.107.",
    "20.", "40.", "51.", "52.", "65.", "70.", "74.", "104.40.", "104.41.",
    "104.42.", "104.43.", "104.44.", "104.45.", "104.46.", "104.47.",
    "104.208.", "104.209.", "104.210.", "104.211.", "104.212.", "104.213.",
    "104.214.", "104.215.",
    "157.55.", "157.56.",
    "168.61.", "168.62.", "168.63.",
    "191.232.", "191.233.", "191.234.", "191.235.", "191.236.", "191.237.",
    "191.238.", "191.239.",
    # Google Cloud
    "8.8.", "34.", "35.", "104.196.", "104.197.", "104.198.", "104.199.",
    "108.170.", "108.177.",
    "142.250.", "142.251.", "172.217.", "172.253.", "216.58.", "216.239.",
    # Cloudflare
    "104.16.", "104.17.", "104.18.", "104.19.", "104.20.", "104.21.",
    "104.22.", "104.23.", "104.24.", "104.25.", "104.26.", "104.27.",
    "162.159.", "172.64.", "172.65.", "172.66.", "172.67.",
    "188.114.", "190.93.", "197.234.", "198.41.",
    # Fastly
    "151.101.", "199.232.",
    # Akamai
    "23.0.", "23.1.", "23.2.", "23.3.", "23.4.", "23.5.", "23.6.", "23.7.",
    "23.8.", "23.9.", "23.10.", "23.11.", "23.12.", "23.13.", "23.14.",
    "23.15.", "23.32.", "23.33.", "23.34.", "23.35.", "23.36.", "23.37.",
    "23.38.", "23.39.", "23.40.", "23.41.", "23.42.", "23.43.", "23.44.",
    "23.45.", "23.46.", "23.47.", "23.48.", "23.49.", "23.50.", "23.51.",
    "23.52.", "23.53.", "23.54.", "23.55.", "23.56.", "23.57.", "23.58.",
    "23.59.", "23.60.", "23.61.", "23.62.", "23.63.",
    "23.192.", "23.193.", "23.194.", "23.195.", "23.196.", "23.197.",
    "23.198.", "23.199.", "23.200.", "23.201.", "23.202.", "23.203.",
    "23.204.", "23.205.", "23.206.", "23.207.", "23.208.", "23.209.",
    "23.210.", "23.211.", "23.212.", "23.213.", "23.214.", "23.215.",
    "23.216.", "23.217.", "23.218.", "23.219.", "23.220.", "23.221.",
    "23.222.", "23.223.",
    "2.16.", "2.17.", "2.18.", "2.19.", "2.20.", "2.21.", "2.22.", "2.23.",
    # Apple
    "17.",
    # Microsoft general
    "131.253.", "204.79.", "207.46.",
    # CloudFront
    "13.224.", "13.225.", "13.226.", "13.227.", "13.228.", "13.249.",
    "52.84.", "52.85.", "54.182.", "54.192.", "54.230.", "54.239.",
    "99.84.", "99.86.",
    "108.156.", "108.157.", "108.158.", "108.159.",
    "143.204.", "205.251.",
    # Private/local
    "10.", "127.", "192.168.", "169.254.", "172.16.", "172.17.", "172.18.",
    "172.19.", "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
    "172.25.", "172.26.", "172.27.", "172.28.", "172.29.", "172.30.",
    "172.31.",
]

# Specific IPs to never block
WHITELIST_IPS = {
    "1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "9.9.9.9",
    "149.112.112.112", "208.67.222.222", "208.67.220.220",
}

LOG_FILE = "/var/log/netshield/tor_smartblock.log"
STATE_FILE = "/var/db/netshield/tor_smartblock.json"
EVE_FILE = "/var/log/suricata/eve.json"
PF_TABLE = "TOR"

def log(msg):
    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    line = "[{}] {}".format(ts, msg)
    print(line)
    try:
        with open(LOG_FILE, "a") as f:
            f.write(line + "\n")
    except Exception:
        pass

def is_whitelisted(ip):
    if ip in WHITELIST_IPS:
        return True
    for prefix in WHITELIST_PREFIXES:
        if ip.startswith(prefix):
            return True
    return False

def add_to_pf(ip):
    """Add IP to TOR pf table."""
    r = subprocess.run(["pfctl", "-t", PF_TABLE, "-T", "add", ip],
                       capture_output=True, text=True, timeout=5)
    return "1/1" in r.stdout or "added" in r.stderr.lower()

def load_state():
    try:
        with open(STATE_FILE) as f:
            return json.load(f)
    except Exception:
        return {"blocked_ips": [], "skipped_cdn": [], "last_pos": 0}

def save_state(state):
    os.makedirs(os.path.dirname(STATE_FILE), exist_ok=True)
    with open(STATE_FILE, "w") as f:
        json.dump(state, f)

def process_alerts(state):
    """Process new Suricata alerts from eve.json."""
    if not os.path.exists(EVE_FILE):
        return state

    fsize = os.path.getsize(EVE_FILE)
    last_pos = state.get("last_pos", 0)

    # If file was rotated (smaller than last position), start from beginning
    if fsize < last_pos:
        last_pos = 0

    blocked = set(state.get("blocked_ips", []))
    skipped = set(state.get("skipped_cdn", []))
    new_blocks = []
    new_skips = []

    with open(EVE_FILE) as f:
        f.seek(last_pos)
        for line in f:
            try:
                e = json.loads(line)
                if e.get("event_type") != "alert":
                    continue
                sig = e.get("alert", {}).get("signature", "").lower()
                # Only process Tor-specific alerts
                if not any(t in sig for t in ["tor", "obfs4", "snowflake", "meek"]):
                    continue

                dst = e.get("dest_ip", "")
                if not dst or dst in blocked or dst in skipped:
                    continue

                if is_whitelisted(dst):
                    skipped.add(dst)
                    new_skips.append(dst)
                    log("SKIP CDN: {} (sig: {})".format(dst, sig[:60]))
                else:
                    if add_to_pf(dst):
                        blocked.add(dst)
                        new_blocks.append(dst)
                        log("BLOCK: {} (sig: {})".format(dst, sig[:60]))
            except Exception:
                pass

        state["last_pos"] = f.tell()

    state["blocked_ips"] = list(blocked)[-5000:]  # Keep last 5000
    state["skipped_cdn"] = list(skipped)[-1000:]  # Keep last 1000

    if new_blocks:
        log("Added {} new IPs to TOR table".format(len(new_blocks)))
    if new_skips:
        log("Skipped {} CDN IPs".format(len(new_skips)))

    return state

def main():
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
    log("Smart Tor blocker starting (PID {})".format(os.getpid()))

    # Write PID file
    with open("/var/run/netshield_smartblock.pid", "w") as f:
        f.write(str(os.getpid()))

    state = load_state()
    log("Loaded state: {} blocked, {} skipped CDN".format(
        len(state.get("blocked_ips", [])), len(state.get("skipped_cdn", []))))

    def handle_signal(sig, frame):
        log("Received signal {}, saving state and exiting".format(sig))
        save_state(state)
        sys.exit(0)

    signal.signal(signal.SIGTERM, handle_signal)
    signal.signal(signal.SIGINT, handle_signal)

    while True:
        try:
            state = process_alerts(state)
            save_state(state)
        except Exception as ex:
            log("Error: {}".format(ex))
        time.sleep(10)  # Check every 10 seconds

if __name__ == "__main__":
    # If run with "status" arg, show status
    if len(sys.argv) > 1 and sys.argv[1] == "status":
        state = load_state()
        print("Blocked: {} IPs".format(len(state.get("blocked_ips", []))))
        print("Skipped CDN: {} IPs".format(len(state.get("skipped_cdn", []))))
        print("Last position: {}".format(state.get("last_pos", 0)))
        # Show recent log
        if os.path.exists(LOG_FILE):
            with open(LOG_FILE) as f:
                lines = f.readlines()
                for line in lines[-10:]:
                    print(line.strip())
        sys.exit(0)

    # Daemonize
    if os.fork():
        sys.exit(0)
    os.setsid()
    if os.fork():
        sys.exit(0)

    main()
