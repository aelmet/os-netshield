#!/usr/local/bin/python3
"""NetShield Policy Management Script - Phase 1 (Tabbed UI support)"""

import argparse
import json
import os
import sqlite3
import sys
from datetime import datetime
from urllib.parse import unquote

DB_PATH = "/var/db/netshield/netshield.db"

# Sentinel value used by PHP controller to clear a field
CLEAR_SENTINEL = "__CLEAR__"


def _clean(val):
    """Return empty string if val is the clear sentinel, else return as-is."""
    if val == CLEAR_SENTINEL:
        return ''
    return val or ''


def init_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS policies (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            action TEXT DEFAULT 'block',
            targets TEXT DEFAULT '{}',
            schedule TEXT DEFAULT 'always',
            priority INTEGER DEFAULT 100,
            enabled INTEGER DEFAULT 1,
            bandwidth_kbps INTEGER DEFAULT 0,
            created TEXT DEFAULT CURRENT_TIMESTAMP,
            updated TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)
    # Original columns
    for col, default in [
        ('description', "''"), ('scope', "'network'"), ('apps', "''"),
        ('web_categories', "''"), ('devices', "''"), ('vlans', "''"),
        ('schedule_type', "'always'"), ('start_time', "''"), ('end_time', "''"),
        ('blocked_count', '0')
    ]:
        try:
            conn.execute(f"ALTER TABLE policies ADD COLUMN {col} TEXT DEFAULT {default}")
        except sqlite3.OperationalError:
            pass

    # Phase 1 new columns
    for col, default in [
        ('no_internet', '0'),
        ('security_preset', "'custom'"),
        ('security_categories', "'{}'"),
        ('exclusions_json', "'[]'"),
        ('schedules_json', "'[]'"),
        ('block_tor', '0'),
        ('block_vpn', '0'),
        ('block_doh', '0'),
        ('block_ech', '0'),
        ('safe_search', '0'),
    ]:
        try:
            conn.execute(f"ALTER TABLE policies ADD COLUMN {col} TEXT DEFAULT {default}")
        except sqlite3.OperationalError:
            pass

    # Named schedules table
    conn.execute("""
        CREATE TABLE IF NOT EXISTS schedules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            policy_id INTEGER REFERENCES policies(id) ON DELETE CASCADE,
            name TEXT NOT NULL,
            start_time TEXT NOT NULL,
            end_time TEXT NOT NULL,
            days TEXT NOT NULL DEFAULT 'mon,tue,wed,thu,fri,sat,sun',
            created TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # Exclusions table
    conn.execute("""
        CREATE TABLE IF NOT EXISTS policy_exclusions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            policy_id INTEGER REFERENCES policies(id) ON DELETE CASCADE,
            entry TEXT NOT NULL,
            list_type TEXT NOT NULL DEFAULT 'blacklist',
            description TEXT DEFAULT '',
            is_global INTEGER DEFAULT 0,
            created TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)

    conn.commit()
    conn.close()


def list_policies():
    init_db()
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.execute("SELECT * FROM policies ORDER BY priority ASC, id DESC")
    policies = [dict(row) for row in cursor.fetchall()]

    # Attach schedules and exclusions as JSON for each policy
    for p in policies:
        pid = p['id']
        # Schedules
        cur = conn.execute(
            "SELECT name, start_time, end_time, days FROM schedules WHERE policy_id = ? ORDER BY id",
            (pid,)
        )
        scheds = [dict(r) for r in cur.fetchall()]
        p['schedules_json'] = json.dumps(scheds) if scheds else (p.get('schedules_json') or '[]')

        # Exclusions
        cur = conn.execute(
            "SELECT entry, list_type, description FROM policy_exclusions WHERE policy_id = ? ORDER BY id",
            (pid,)
        )
        excls = [dict(r) for r in cur.fetchall()]
        p['exclusions_json'] = json.dumps(excls) if excls else (p.get('exclusions_json') or '[]')

    conn.close()
    return {"status": "ok", "data": {"policies": policies}}


def add_policy(args):
    init_db()
    conn = sqlite3.connect(DB_PATH)
    apps_str = _clean(args.get('apps', ''))
    cats_str = _clean(args.get('web_categories', ''))
    devs_str = _clean(args.get('devices', ''))
    apps_list = [a.strip() for a in apps_str.split(',') if a.strip()]
    cats_list = [c.strip() for c in cats_str.split(',') if c.strip()]
    devs_list = [d.strip() for d in devs_str.split(',') if d.strip()]
    targets = json.dumps({"apps": apps_list, "categories": cats_list, "devices": devs_list})

    cursor = conn.execute("""
        INSERT INTO policies (name, action, targets, schedule, priority, enabled,
                              description, scope, apps, web_categories, devices, vlans,
                              schedule_type, start_time, end_time,
                              no_internet, security_preset, security_categories,
                              exclusions_json, schedules_json,
                              block_tor, block_vpn, block_doh, block_ech, safe_search,
                              bandwidth_kbps)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        args.get('name', ''),
        args.get('action', 'block'),
        targets,
        args.get('schedule', 'always'),
        int(args.get('priority', 100) or 100),
        1 if args.get('enabled', '1') in ('1', 'true', True) else 0,
        _clean(args.get('description', '')),
        args.get('scope', 'network'),
        apps_str,
        cats_str,
        devs_str,
        _clean(args.get('vlans', '')),
        args.get('schedule_type', 'always'),
        _clean(args.get('start_time', '')),
        _clean(args.get('end_time', '')),
        1 if args.get('no_internet', '0') in ('1', 'true', True) else 0,
        args.get('security_preset', 'custom'),
        args.get('security_categories', '{}'),
        args.get('exclusions_json', '[]'),
        args.get('schedules_json', '[]'),
        1 if args.get('block_tor', '0') in ('1', 'true', True) else 0,
        1 if args.get('block_vpn', '0') in ('1', 'true', True) else 0,
        1 if args.get('block_doh', '0') in ('1', 'true', True) else 0,
        1 if args.get('block_ech', '0') in ('1', 'true', True) else 0,
        1 if args.get('safe_search', '0') in ('1', 'true', True) else 0,
        int(args.get('bandwidth_kbps', 0) or 0),
    ))
    policy_id = cursor.lastrowid

    # Save schedules to table
    _save_schedules(conn, policy_id, args.get('schedules_json', '[]'))
    # Save exclusions to table
    _save_exclusions(conn, policy_id, args.get('exclusions_json', '[]'))

    conn.commit()
    conn.close()
    return {"status": "ok", "id": policy_id}


def _save_schedules(conn, policy_id, schedules_json):
    """Save schedule rows from JSON into schedules table."""
    conn.execute("DELETE FROM schedules WHERE policy_id = ?", (policy_id,))
    try:
        scheds = json.loads(schedules_json) if isinstance(schedules_json, str) else schedules_json
        if not isinstance(scheds, list):
            return
        for s in scheds:
            if not s.get('start_time') or not s.get('end_time'):
                continue
            conn.execute(
                "INSERT INTO schedules (policy_id, name, start_time, end_time, days) VALUES (?, ?, ?, ?, ?)",
                (policy_id, s.get('name', 'Schedule'), s['start_time'], s['end_time'],
                 s.get('days', 'mon,tue,wed,thu,fri,sat,sun'))
            )
    except (json.JSONDecodeError, TypeError):
        pass


def _save_exclusions(conn, policy_id, exclusions_json):
    """Save exclusion rows from JSON into policy_exclusions table."""
    conn.execute("DELETE FROM policy_exclusions WHERE policy_id = ?", (policy_id,))
    try:
        excls = json.loads(exclusions_json) if isinstance(exclusions_json, str) else exclusions_json
        if not isinstance(excls, list):
            return
        for e in excls:
            if not e.get('entry'):
                continue
            conn.execute(
                "INSERT INTO policy_exclusions (policy_id, entry, list_type, description) VALUES (?, ?, ?, ?)",
                (policy_id, e['entry'], e.get('list_type', 'blacklist'), e.get('description', ''))
            )
    except (json.JSONDecodeError, TypeError):
        pass


def update_policy(policy_id, args):
    init_db()
    conn = sqlite3.connect(DB_PATH)
    updates = []
    values = []

    # All updatable text fields
    fields = ['name', 'description', 'action', 'scope', 'apps', 'web_categories',
              'devices', 'vlans', 'schedule', 'schedule_type', 'start_time', 'end_time',
              'priority', 'security_preset', 'security_categories',
              'exclusions_json', 'schedules_json', 'bandwidth_kbps']
    for field in fields:
        if field in args and args[field] is not None:
            val = _clean(args[field])
            updates.append(f"{field} = ?")
            values.append(val)

    # Boolean/integer fields
    bool_fields = ['enabled', 'no_internet', 'block_tor', 'block_vpn', 'block_doh', 'block_ech', 'safe_search']
    for field in bool_fields:
        if field in args and args[field] is not None:
            updates.append(f"{field} = ?")
            values.append(1 if args[field] in ('1', 'true', True) else 0)

    # Rebuild targets JSON from current values (use updated or fetch existing)
    clearable = ('apps', 'web_categories', 'devices')
    if any(f in args and args[f] is not None for f in clearable):
        apps_str = _clean(args.get('apps')) if args.get('apps') is not None else None
        cats_str = _clean(args.get('web_categories')) if args.get('web_categories') is not None else None
        devs_str = _clean(args.get('devices')) if args.get('devices') is not None else None

        if any(v is None for v in (apps_str, cats_str, devs_str)):
            cursor = conn.execute("SELECT apps, web_categories, devices FROM policies WHERE id = ?", (policy_id,))
            row = cursor.fetchone()
            if row:
                if apps_str is None: apps_str = row[0] or ''
                if cats_str is None: cats_str = row[1] or ''
                if devs_str is None: devs_str = row[2] or ''

        apps_str = apps_str or ''
        cats_str = cats_str or ''
        devs_str = devs_str or ''

        targets = json.dumps({
            "apps": [a.strip() for a in apps_str.split(',') if a.strip()],
            "categories": [c.strip() for c in cats_str.split(',') if c.strip()],
            "devices": [d.strip() for d in devs_str.split(',') if d.strip()]
        })
        updates.append("targets = ?")
        values.append(targets)

    if updates:
        updates.append("updated = CURRENT_TIMESTAMP")
        values.append(policy_id)
        sql = f"UPDATE policies SET {', '.join(updates)} WHERE id = ?"
        conn.execute(sql, values)

    # Update schedules table
    if 'schedules_json' in args and args['schedules_json'] is not None:
        _save_schedules(conn, policy_id, args['schedules_json'])

    # Update exclusions table
    if 'exclusions_json' in args and args['exclusions_json'] is not None:
        _save_exclusions(conn, policy_id, args['exclusions_json'])

    conn.commit()
    conn.close()
    return {"status": "ok"}


def delete_policy(policy_id):
    init_db()
    conn = sqlite3.connect(DB_PATH)
    conn.execute("DELETE FROM schedules WHERE policy_id = ?", (policy_id,))
    conn.execute("DELETE FROM policy_exclusions WHERE policy_id = ?", (policy_id,))
    conn.execute("DELETE FROM policies WHERE id = ?", (policy_id,))
    conn.commit()
    conn.close()
    return {"status": "ok"}


def toggle_policy(policy_id):
    init_db()
    conn = sqlite3.connect(DB_PATH)
    conn.execute("UPDATE policies SET enabled = CASE WHEN enabled = 1 THEN 0 ELSE 1 END WHERE id = ?", (policy_id,))
    conn.commit()
    conn.close()
    return {"status": "ok"}


def reorder_policy(policy_id, priority):
    init_db()
    conn = sqlite3.connect(DB_PATH)
    conn.execute("UPDATE policies SET priority = ? WHERE id = ?", (priority, policy_id))
    conn.commit()
    conn.close()
    return {"status": "ok"}


def get_stats():
    init_db()
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.execute("SELECT COUNT(*) FROM policies")
    total = cursor.fetchone()[0]
    cursor = conn.execute("SELECT COUNT(*) FROM policies WHERE enabled = 1")
    active = cursor.fetchone()[0]
    try:
        cursor = conn.execute("SELECT COALESCE(SUM(blocked_count), 0) FROM policies")
        blocked = cursor.fetchone()[0]
    except sqlite3.OperationalError:
        blocked = 0
    conn.close()
    return {"total_policies": total, "active_policies": active, "blocked_today": blocked}


def main():
    # configd passes all parameters as a single comma-delimited token
    # PHP controller URL-encodes values, so we URL-decode after splitting
    if len(sys.argv) == 2:
        arg = sys.argv[1]
        parts = arg.replace(',', ' ').split()
        sys.argv = [sys.argv[0]] + [unquote(p.strip("'\"")) for p in parts]

    parser = argparse.ArgumentParser()
    parser.add_argument('command', nargs='?', default='list')
    parser.add_argument('--update', action='store_true')
    parser.add_argument('--delete', action='store_true')
    parser.add_argument('--toggle', action='store_true')
    parser.add_argument('--reorder', action='store_true')
    parser.add_argument('--id', type=int)
    parser.add_argument('--name')
    parser.add_argument('--description')
    parser.add_argument('--action')
    parser.add_argument('--scope')
    parser.add_argument('--apps')
    parser.add_argument('--web_categories')
    parser.add_argument('--devices')
    parser.add_argument('--vlans')
    parser.add_argument('--targets')
    parser.add_argument('--schedule')
    parser.add_argument('--schedule_type')
    parser.add_argument('--start_time')
    parser.add_argument('--end_time')
    parser.add_argument('--priority', type=int)
    parser.add_argument('--enabled')
    # Phase 1 new args
    parser.add_argument('--no_internet')
    parser.add_argument('--security_preset')
    parser.add_argument('--security_categories')
    parser.add_argument('--exclusions_json')
    parser.add_argument('--schedules_json')
    parser.add_argument('--block_tor')
    parser.add_argument('--block_vpn')
    parser.add_argument('--block_doh')
    parser.add_argument('--block_ech')
    parser.add_argument('--safe_search')
    parser.add_argument('--bandwidth_kbps')
    parser.add_argument('--excluded_devices')
    parser.add_argument('--device_categories')
    args, _ = parser.parse_known_args()  # Ignore unknown args from newer controller

    try:
        if args.delete and args.id:
            result = delete_policy(args.id)
        elif args.toggle and args.id:
            result = toggle_policy(args.id)
        elif args.reorder and args.id:
            result = reorder_policy(args.id, args.priority or 100)
        elif args.update and args.id:
            result = update_policy(args.id, vars(args))
        elif args.command == 'add' or args.name:
            result = add_policy(vars(args))
        elif args.command == 'stats':
            result = get_stats()
        else:
            result = list_policies()
        print(json.dumps(result))
    except Exception as e:
        print(json.dumps({"status": "error", "message": str(e)}))

if __name__ == "__main__":
    main()
