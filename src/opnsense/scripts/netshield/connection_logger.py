#!/usr/local/bin/python3
"""NetShield Phase 6 - Connection Logger

Parses Unbound DNS query logs and DNSBL block data to build a connection
history in SQLite.  Designed to run as a periodic cron job or configd action.

Log format expected (Unbound verbosity 2+):
  [timestamp] unbound[pid]: info: IP PORT domain TYPE CLASS
Example:
  [1709654400] unbound[1234]: info: 192.168.1.50 12345 www.google.com. A IN
"""

import json
import os
import re
import sqlite3
import sys
import time
from datetime import datetime, timedelta, timezone
from urllib.parse import unquote

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
CONN_DB_PATH = "/var/db/netshield/connections.db"
NETSHIELD_DB_PATH = "/var/db/netshield/netshield.db"
UNBOUND_LOG = "/var/log/resolver/latest.log"
DNSBL_JSON = "/var/unbound/data/dnsbl.json"
STATE_FILE = "/var/db/netshield/logger_state.json"
CACHE_STATE_FILE = "/var/db/netshield/logger_cache_state.json"
DNSBL_CACHE_DB = "/var/db/netshield/dnsbl_cache.db"
APP_SIG_PATH = "/usr/local/opnsense/scripts/netshield/lib"

# Default retention in days (overridden by settings table or env)
DEFAULT_RETENTION_DAYS = 7

# OPNsense RFC5424 syslog format:
# <30>1 2026-03-05T23:18:19+00:00 router.local unbound 29296 - [...] query: 192.168.1.39 domain.com. A IN
QUERY_RE = re.compile(
    r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}).*?query:\s+'
    r'(\d+\.\d+\.\d+\.\d+)\s+'
    r'(\S+)\.\s+(\w+)\s+(\w+)'
)

# Fallback: traditional syslog format
QUERY_RE_ALT = re.compile(
    r'(\w+\s+\d+\s+\d+:\d+:\d+)\s+\S+\s+unbound\[\d+\]:\s+'
    r'(?:\[\S+\]\s+)?query:\s+'
    r'(\d+\.\d+\.\d+\.\d+)\s+'
    r'(\S+)\.\s+(\w+)\s+(\w+)'
)


# ---------------------------------------------------------------------------
# Database setup
# ---------------------------------------------------------------------------
def init_connections_db():
    """Create the connections database and table if needed."""
    os.makedirs(os.path.dirname(CONN_DB_PATH), exist_ok=True)
    conn = sqlite3.connect(CONN_DB_PATH)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("""
        CREATE TABLE IF NOT EXISTS connections (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            device_mac TEXT,
            device_ip TEXT,
            device_name TEXT,
            dst_hostname TEXT,
            dst_ip TEXT,
            protocol TEXT DEFAULT 'DNS',
            app_category TEXT,
            application TEXT,
            blocked INTEGER DEFAULT 0,
            block_reason TEXT,
            block_policy TEXT,
            block_type TEXT,
            security_category TEXT,
            bytes_in INTEGER DEFAULT 0,
            bytes_out INTEGER DEFAULT 0
        )
    """)
    # Add new columns to existing tables (safe to run multiple times)
    for col, default in [('block_type', "''"), ('security_category', "''")]:
        try:
            conn.execute(f"ALTER TABLE connections ADD COLUMN {col} TEXT DEFAULT {default}")
        except sqlite3.OperationalError:
            pass  # Column already exists
    conn.execute("CREATE INDEX IF NOT EXISTS idx_conn_ts ON connections(timestamp)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_conn_device ON connections(device_ip)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_conn_blocked ON connections(blocked)")
    conn.commit()
    conn.close()


# ---------------------------------------------------------------------------
# Helper loaders
# ---------------------------------------------------------------------------

# Map bl field values to human-readable block types and categories
_BL_TYPE_MAP = {
    "netshield-doh": ("DoH Block", "Security"),
    "netshield-nointernet": ("No Internet", "Policy"),
    "netshield-policy": ("Policy Block", "Policy"),
    "netshield-category": ("Web Category", "Content Filter"),
    "netshield-device": ("Device Block", "Device Policy"),
    "netshield-targetlist": ("Target List", "Content Filter"),
    "netshield-session": ("Manual Block", "User Action"),
}

# Cache for policy name lookup (idx -> policy name)
_policy_name_cache = None


def _load_policy_names():
    """Load policy names from netshield.db to map config idx to policy names."""
    global _policy_name_cache
    if _policy_name_cache is not None:
        return _policy_name_cache
    _policy_name_cache = {}
    if not os.path.isfile(NETSHIELD_DB_PATH):
        return _policy_name_cache
    try:
        conn = sqlite3.connect(NETSHIELD_DB_PATH)
        cursor = conn.execute(
            "SELECT id, name, action FROM policies WHERE enabled = 1 ORDER BY priority"
        )
        # idx 1 is always DoH, then policies follow in priority order starting from idx 2
        idx = 2
        for row in cursor:
            _policy_name_cache[str(idx)] = row[1]  # name
            idx += 1
        conn.close()
    except (sqlite3.OperationalError, sqlite3.DatabaseError):
        pass
    return _policy_name_cache


def _parse_bl_entries(entries):
    """Parse a list of blocklist entries from dnsbl.json into meaningful fields.

    Returns: (block_type, security_category, reason, policy)
    """
    if not entries:
        return ("DNSBL", "", "dnsbl", "")

    block_types = []
    categories = []
    reasons = []
    policy_names = []

    policy_map = _load_policy_names()

    for entry in entries:
        bl = entry.get("bl", "")
        idx = entry.get("idx", "")

        if bl in _BL_TYPE_MAP:
            btype, cat = _BL_TYPE_MAP[bl]
            block_types.append(btype)
            categories.append(cat)
            # Look up actual policy name for policy/category blocks
            pname = policy_map.get(idx, "")
            if pname:
                reasons.append(pname)
                policy_names.append(pname)
            else:
                reasons.append(btype)
        elif bl:
            # External DNSBL lists
            block_types.append("DNSBL")
            bl_lower = bl.lower()
            if any(k in bl_lower for k in ("malware", "threat", "abuse", "phish")):
                categories.append("Malware/Threat")
            elif any(k in bl_lower for k in ("ad", "track", "analytic")):
                categories.append("Ad/Tracker")
            elif any(k in bl_lower for k in ("porn", "adult", "nsfw")):
                categories.append("Adult Content")
            elif any(k in bl_lower for k in ("gambling", "casino")):
                categories.append("Gambling")
            else:
                categories.append("DNSBL: " + bl)
            reasons.append(bl)

    # Pick the most specific type/category (prefer non-DoH)
    non_doh_types = [t for t in block_types if t != "DoH Block"]
    block_type = non_doh_types[0] if non_doh_types else (block_types[0] if block_types else "DNSBL")
    non_security_cats = [c for c in categories if c != "Security"]
    security_cat = non_security_cats[0] if non_security_cats else (categories[0] if categories else "")
    reason = ", ".join(dict.fromkeys(reasons))  # unique, ordered
    policy = ", ".join(dict.fromkeys(policy_names)) if policy_names else ""

    return (block_type, security_cat, reason, policy)


# ---------------------------------------------------------------------------
# DNSBL SQLite Cache (replaces loading 310MB JSON into memory every run)
# ---------------------------------------------------------------------------
def _get_file_mtime(path):
    """Get file mtime, return 0 if file doesn't exist."""
    try:
        return os.path.getmtime(path)
    except OSError:
        return 0


def _load_cache_state():
    """Load cache state (mtimes of data files)."""
    if os.path.isfile(CACHE_STATE_FILE):
        try:
            with open(CACHE_STATE_FILE, 'r') as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError):
            pass
    return {}


def _save_cache_state(state):
    """Save cache state."""
    with open(CACHE_STATE_FILE, 'w') as f:
        json.dump(state, f)


def _rebuild_dnsbl_cache():
    """Rebuild SQLite DNSBL cache from dnsbl.json.

    Only called when dnsbl.json mtime changes (typically once per day at midnight).
    This is the expensive operation (~25s) but only runs when data actually changes.
    """
    if not os.path.isfile(DNSBL_JSON):
        return 0

    conn = sqlite3.connect(DNSBL_CACHE_DB)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("DROP TABLE IF EXISTS dnsbl_lookup")
    conn.execute("""
        CREATE TABLE dnsbl_lookup (
            domain TEXT PRIMARY KEY,
            block_type TEXT,
            security_category TEXT,
            reason TEXT,
            policy TEXT
        )
    """)

    count = 0
    try:
        with open(DNSBL_JSON, 'r') as f:
            data = json.load(f)

        if isinstance(data, dict):
            domain_data = data.get('data', data)
            if not isinstance(domain_data, dict):
                domain_data = data

            batch = []
            for domain, info in domain_data.items():
                d = domain.rstrip('.').lower()
                if isinstance(info, list):
                    block_type, security_cat, reason, policy = _parse_bl_entries(info)
                elif isinstance(info, dict):
                    block_type = info.get('block_type', 'DNSBL')
                    security_cat = info.get('security_category', '')
                    reason = info.get('reason', 'dnsbl')
                    policy = info.get('policy', '')
                else:
                    block_type = 'DNSBL'
                    security_cat = ''
                    reason = str(info)
                    policy = ''

                batch.append((d, block_type, security_cat, reason, policy))

                if len(batch) >= 5000:
                    conn.executemany(
                        "INSERT OR REPLACE INTO dnsbl_lookup VALUES (?,?,?,?,?)", batch
                    )
                    count += len(batch)
                    batch = []

            if batch:
                conn.executemany(
                    "INSERT OR REPLACE INTO dnsbl_lookup VALUES (?,?,?,?,?)", batch
                )
                count += len(batch)
    except (json.JSONDecodeError, IOError):
        pass

    conn.commit()
    conn.close()
    return count


def _ensure_dnsbl_cache():
    """Ensure SQLite DNSBL cache is up to date. Rebuilds only if dnsbl.json changed."""
    cache_state = _load_cache_state()
    current_mtime = _get_file_mtime(DNSBL_JSON)
    last_mtime = cache_state.get("dnsbl_mtime", 0)

    if current_mtime != last_mtime or not os.path.isfile(DNSBL_CACHE_DB):
        _rebuild_dnsbl_cache()
        cache_state["dnsbl_mtime"] = current_mtime
        _save_cache_state(cache_state)


def lookup_dnsbl_domains(domains):
    """Look up a batch of domains against the DNSBL SQLite cache.

    Returns dict of {domain: {block_type, security_category, reason, policy}}
    Only returns domains that ARE blocked.
    """
    if not domains or not os.path.isfile(DNSBL_CACHE_DB):
        return {}

    results = {}
    conn = sqlite3.connect(DNSBL_CACHE_DB)
    conn.row_factory = sqlite3.Row
    domain_list = list(domains)
    for i in range(0, len(domain_list), 500):
        batch = domain_list[i:i + 500]
        placeholders = ','.join('?' * len(batch))
        cursor = conn.execute(
            f"SELECT * FROM dnsbl_lookup WHERE domain IN ({placeholders})",
            batch
        )
        for row in cursor:
            results[row['domain']] = {
                'block_type': row['block_type'],
                'security_category': row['security_category'],
                'reason': row['reason'],
                'policy': row['policy'],
            }
    conn.close()
    return results


def load_device_map():
    """Build IP -> {mac, hostname} map from netshield.db devices table."""
    device_map = {}
    if not os.path.isfile(NETSHIELD_DB_PATH):
        return device_map
    try:
        conn = sqlite3.connect(NETSHIELD_DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.execute("SELECT ip, mac, hostname FROM devices")
        for row in cursor:
            ip = row['ip']
            if ip:
                device_map[ip] = {
                    'mac': row['mac'] or '',
                    'hostname': row['hostname'] or ''
                }
        conn.close()
    except (sqlite3.OperationalError, sqlite3.DatabaseError):
        pass
    return device_map


def load_app_signatures():
    """Build domain -> {app_key, category, name} lookup from app_signatures."""
    domain_map = {}
    try:
        sys.path.insert(0, APP_SIG_PATH)
        from app_signatures import APPLICATION_SIGNATURES
        for app_key, info in APPLICATION_SIGNATURES.items():
            category = info.get('category', '')
            name = info.get('name', app_key)
            for domain in info.get('domains', []):
                domain_map[domain.lower()] = {
                    'app_key': app_key,
                    'category': category,
                    'name': name
                }
    except ImportError:
        pass
    return domain_map


def match_app(domain, app_domain_map):
    """Match a domain against app signatures, trying progressively shorter suffixes."""
    domain = domain.lower().rstrip('.')
    # Exact match
    if domain in app_domain_map:
        return app_domain_map[domain]
    # Try removing subdomains progressively
    parts = domain.split('.')
    for i in range(1, len(parts) - 1):
        candidate = '.'.join(parts[i:])
        if candidate in app_domain_map:
            return app_domain_map[candidate]
    return None


# ---------------------------------------------------------------------------
# State management
# ---------------------------------------------------------------------------
def load_state():
    """Load logger state (last processed position)."""
    if os.path.isfile(STATE_FILE):
        try:
            with open(STATE_FILE, 'r') as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError):
            pass
    return {"last_position": 0, "last_inode": 0}


def save_state(state):
    """Save logger state."""
    os.makedirs(os.path.dirname(STATE_FILE), exist_ok=True)
    with open(STATE_FILE, 'w') as f:
        json.dump(state, f)


# ---------------------------------------------------------------------------
# Retention
# ---------------------------------------------------------------------------
def get_retention_days():
    """Get retention days from settings table, env, or default."""
    # Check environment variable first
    env_val = os.environ.get('NETSHIELD_RETENTION_DAYS')
    if env_val:
        try:
            return int(env_val)
        except ValueError:
            pass
    # Check netshield.db settings table
    if os.path.isfile(NETSHIELD_DB_PATH):
        try:
            conn = sqlite3.connect(NETSHIELD_DB_PATH)
            cursor = conn.execute(
                "SELECT value FROM settings WHERE key = 'connection_retention_days'"
            )
            row = cursor.fetchone()
            conn.close()
            if row:
                return int(row[0])
        except (sqlite3.OperationalError, sqlite3.DatabaseError, ValueError):
            pass
    return DEFAULT_RETENTION_DAYS


def purge_old_entries(conn, retention_days):
    """Delete entries older than retention_days. Returns count purged."""
    cutoff = (datetime.now(timezone.utc) - timedelta(days=retention_days)).isoformat()
    cursor = conn.execute("DELETE FROM connections WHERE timestamp < ?", (cutoff,))
    return cursor.rowcount


# ---------------------------------------------------------------------------
# Log parsing
# ---------------------------------------------------------------------------
def parse_timestamp_iso(iso_str):
    """Parse ISO timestamp from syslog (e.g., '2026-03-05T23:18:19')."""
    try:
        return iso_str.replace('T', ' ')[:19]  # '2026-03-05 23:18:19'
    except Exception:
        return datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')


def parse_timestamp_syslog(ts_str):
    """Convert syslog timestamp (e.g. 'Jan  1 00:00:00') to ISO format."""
    try:
        # Add current year since syslog doesn't include it
        year = datetime.now(timezone.utc).year
        dt = datetime.strptime(f"{year} {ts_str}", "%Y %b %d %H:%M:%S")
        return dt.isoformat()
    except ValueError:
        return datetime.now(timezone.utc).isoformat()


def process_log():
    """Main log processing routine."""
    init_connections_db()

    # Ensure DNSBL SQLite cache is current (only rebuilds when dnsbl.json changes)
    _ensure_dnsbl_cache()
    device_map = load_device_map()
    app_domain_map = load_app_signatures()

    # Load state
    state = load_state()
    last_pos = state.get("last_position", 0)
    last_inode = state.get("last_inode", 0)

    if not os.path.isfile(UNBOUND_LOG):
        result = {"status": "ok", "new_entries": 0, "purged": 0, "message": "No log file found"}
        print(json.dumps(result))
        return

    # Check if log file was rotated (inode changed)
    try:
        stat = os.stat(UNBOUND_LOG)
        current_inode = stat.st_ino
        if current_inode != last_inode:
            last_pos = 0  # File rotated, start from beginning
    except OSError:
        current_inode = 0

    # Read new log entries
    new_entries = 0
    batch = []

    try:
        with open(UNBOUND_LOG, 'r', errors='replace') as f:
            # If file is smaller than our position, it was truncated
            f.seek(0, 2)  # Seek to end
            file_size = f.tell()
            if file_size < last_pos:
                last_pos = 0
            f.seek(last_pos)

            for line in f:
                line = line.strip()
                if not line:
                    continue

                # Try RFC5424 format first
                m = QUERY_RE.search(line)
                if m:
                    ts = parse_timestamp_iso(m.group(1))
                    device_ip = m.group(2)
                    domain = m.group(3).rstrip('.').lower()
                    qtype = m.group(4)
                else:
                    # Try traditional syslog format
                    m = QUERY_RE_ALT.search(line)
                    if m:
                        ts = parse_timestamp_syslog(m.group(1))
                        device_ip = m.group(2)
                        domain = m.group(3).rstrip('.').lower()
                        qtype = m.group(4)
                    else:
                        continue

                # Skip non-interesting query types
                if qtype not in ('A', 'AAAA', 'CNAME', 'HTTPS', 'SRV'):
                    continue

                # Resolve device info
                dev_info = device_map.get(device_ip, {})
                device_mac = dev_info.get('mac', '')
                device_name = dev_info.get('hostname', '')

                # Match application
                app_info = match_app(domain, app_domain_map)
                app_category = app_info['category'] if app_info else ''
                application = app_info['name'] if app_info else ''

                # Store parsed entry (DNSBL lookup done in batch later)
                batch.append({
                    'ts': ts, 'mac': device_mac, 'ip': device_ip,
                    'name': device_name, 'domain': domain,
                    'app_category': app_category, 'application': application,
                })

                # Process in batches of 500
                if len(batch) >= 500:
                    new_entries += _insert_batch_with_dnsbl(batch)
                    batch = []

            # Record final position
            new_pos = f.tell()
    except IOError as e:
        result = {"status": "error", "message": str(e)}
        print(json.dumps(result))
        return

    # Insert remaining batch
    if batch:
        new_entries += _insert_batch_with_dnsbl(batch)

    # Purge old entries
    retention = get_retention_days()
    conn = sqlite3.connect(CONN_DB_PATH)
    purged = purge_old_entries(conn, retention)
    conn.commit()
    conn.close()

    # Save state
    save_state({"last_position": new_pos, "last_inode": current_inode})

    result = {"status": "ok", "new_entries": new_entries, "purged": purged}
    print(json.dumps(result))


def _insert_batch_with_dnsbl(entries):
    """Insert entries with batch DNSBL lookup via SQLite cache."""
    if not entries:
        return 0
    # Batch lookup all unique domains against SQLite DNSBL cache
    domains = set(e['domain'] for e in entries)
    blocked_map = lookup_dnsbl_domains(domains)

    rows = []
    for e in entries:
        dnsbl_entry = blocked_map.get(e['domain'])
        if dnsbl_entry:
            blocked = 1
            block_reason = dnsbl_entry.get('reason', 'dnsbl')
            block_policy = dnsbl_entry.get('policy', '')
            block_type = dnsbl_entry.get('block_type', 'DNSBL')
            security_category = dnsbl_entry.get('security_category', '')
        else:
            blocked = 0
            block_reason = ''
            block_policy = ''
            block_type = ''
            security_category = ''

        rows.append((
            e['ts'], e['mac'], e['ip'], e['name'],
            e['domain'], None, 'DNS',
            e['app_category'], e['application'],
            blocked, block_reason, block_policy,
            block_type, security_category,
            0, 0
        ))

    return _insert_batch(rows)


def _insert_batch(batch):
    """Insert a batch of connection records. Returns count inserted."""
    conn = sqlite3.connect(CONN_DB_PATH)
    conn.executemany("""
        INSERT INTO connections
            (timestamp, device_mac, device_ip, device_name,
             dst_hostname, dst_ip, protocol,
             app_category, application,
             blocked, block_reason, block_policy,
             block_type, security_category,
             bytes_in, bytes_out)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, batch)
    conn.commit()
    count = len(batch)
    conn.close()
    return count


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
def main():
    # configd may pass comma-delimited args
    if len(sys.argv) == 2:
        arg = sys.argv[1]
        parts = arg.replace(',', ' ').split()
        sys.argv = [sys.argv[0]] + [unquote(p.strip("'\"")) for p in parts]

    try:
        process_log()
    except Exception as e:
        print(json.dumps({"status": "error", "message": str(e)}))
        sys.exit(0)  # Exit 0 for configd script_output compatibility


if __name__ == "__main__":
    main()
