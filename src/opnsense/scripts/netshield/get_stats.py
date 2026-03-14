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

"""configd script: return aggregated NetShield statistics as JSON.

Called by OPNsense configd via netshield.conf action definitions.

Usage:
    get_stats.py

Outputs a JSON object with device totals, alert totals, top devices by
alert count, and recent unacknowledged alerts.

The output format matches what the frontend expects:
- total_alerts_today: number of alerts today
- threat_alerts: number of threat-type alerts today
- new_devices: number of new devices today
- quarantined_devices: number of quarantined devices
"""

import json
import os
import sys
from datetime import datetime

# ---------------------------------------------------------------------------
# Ensure lib/ is on the path regardless of cwd
# ---------------------------------------------------------------------------
_SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))
if _SCRIPT_DIR not in sys.path:
    sys.path.insert(0, _SCRIPT_DIR)

from lib import db as _db


def main() -> None:
    try:
        _db.init_db()
        
        # Get today's date prefix for filtering
        today = datetime.utcnow().strftime("%Y-%m-%d")
        
        # Get raw stats from db module
        raw_stats = _db.get_stats()
        
        # Transform to frontend-expected format
        # The frontend expects flat fields like:
        # - total_alerts_today
        # - threat_alerts
        # - new_devices
        # - quarantined_devices
        
        stats = {
            "total_alerts_today": raw_stats.get("alerts", {}).get("today", 0),
            "threat_alerts": raw_stats.get("alerts", {}).get("by_type", {}).get("threat", 0),
            "new_devices": raw_stats.get("devices", {}).get("new_today", 0),
            "quarantined_devices": raw_stats.get("devices", {}).get("quarantined", 0),
            # Severity breakdown for alerts page
            "severity_counts": raw_stats.get("alerts", {}).get("by_severity", {}),
            # Also include the full nested data for other consumers
            "devices": raw_stats.get("devices", {}),
            "alerts": raw_stats.get("alerts", {}),
            "top_devices": raw_stats.get("top_devices", []),
            "recent_alerts": raw_stats.get("recent_alerts", []),
        }
        
        print(json.dumps(stats, indent=2))
    except Exception as exc:
        # Return error in a format the frontend can handle
        error = {
            "total_alerts_today": 0,
            "threat_alerts": 0,
            "new_devices": 0,
            "quarantined_devices": 0,
            "error": str(exc)
        }
        print(json.dumps(error))
        sys.exit(1)


if __name__ == "__main__":
    main()
