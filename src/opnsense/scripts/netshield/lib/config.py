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

"""NetShield configuration loader."""

import os
import configparser

CONFIG_FILE = "/usr/local/etc/netshield.conf"
PID_FILE = "/var/run/netshield.pid"
LOG_FILE = "/var/log/netshield.log"
DB_DIR = "/var/db/netshield"
DB_PATH = os.path.join(DB_DIR, "netshield.db")

# Default configuration values
_DEFAULTS = {
    "general": {
        "enabled": "1",
        "check_interval": "60",
        "log_level": "INFO",
        "alert_retention_days": "30",
    },
    "telegram": {
        "enabled": "0",
        "bot_token": "",
        "chat_id": "",
        "batch_delay": "2",
        "max_retries": "3",
    },
    "alerts": {
        "new_device_alert": "1",
        "quarantine_alert": "1",
        "port_scan_alert": "1",
        "threat_alert": "1",
        "vpn_alert": "1",
        "adult_content_alert": "0",
        "dns_bypass_alert": "1",
        "data_exfil_alert": "1",
        "beaconing_alert": "1",
        "severity_filter": "low",
    },
    "detection": {
        "port_scan_threshold": "20",
        "port_scan_window": "60",
        "beaconing_interval": "300",
        "beaconing_tolerance": "10",
        "exfil_threshold_mb": "100",
    },
    "database": {
        "db_path": DB_PATH,
        "flush_interval": "86400",
    },
    "syslog": {
        "enabled": "0",
        "host": "",
        "port": "514",
        "protocol": "udp",
    },
}


def load_config(config_file: str = CONFIG_FILE) -> configparser.ConfigParser:
    """Read the INI config file and return a ConfigParser with all defaults applied.

    Falls back gracefully if the file does not exist — default values are
    always present so callers never need to handle missing keys.
    """
    cfg = configparser.ConfigParser()

    # Populate defaults for every section before reading the file so that
    # missing keys always resolve to sensible values.
    for section, values in _DEFAULTS.items():
        if not cfg.has_section(section):
            cfg.add_section(section)
        for key, value in values.items():
            cfg.set(section, key, value)

    # Read file — silently ignored if absent (configparser contract).
    cfg.read(config_file)

    return cfg


def get_section(cfg: configparser.ConfigParser, section: str = "general") -> dict:
    """Return all key/value pairs from *section* as a plain dict.

    Always returns a dict even when the section is absent (empty dict).
    """
    if not cfg.has_section(section):
        return {}
    return dict(cfg.items(section))
