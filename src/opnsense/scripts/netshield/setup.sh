#!/bin/sh
# NetShield dependency installer — idempotent, safe to run multiple times
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2024-2026 NetShield Contributors

set -e

NETSHIELD_SCRIPTS="$(cd "$(dirname "$0")" && pwd)"
NETSHIELD_DB_DIR="/var/db/netshield"
NETSHIELD_LOG_DIR="/var/log/netshield"

echo "==> NetShield setup: Starting dependency check..."

# ---------------------------------------------------------------------------
# Helper: check whether a pkg is installed
# ---------------------------------------------------------------------------
pkg_installed() {
    pkg info -e "$1" 2>/dev/null
}

# ---------------------------------------------------------------------------
# Required system packages
# ---------------------------------------------------------------------------
echo "==> NetShield setup: Checking system packages..."

# python3 — should already be present on OPNsense, but ensure it
if ! command -v python3 >/dev/null 2>&1; then
    echo "    Installing python3..."
    pkg install -y python3 || echo "    WARNING: Could not install python3"
fi

# sqlite3 — used for the alert/device/policy database
if ! command -v sqlite3 >/dev/null 2>&1; then
    echo "    Installing sqlite3..."
    pkg install -y sqlite3 || echo "    WARNING: Could not install sqlite3"
fi

# suricata — optional, used for DPI if dpi_enabled=1
if ! pkg_installed suricata; then
    echo "    NOTE: Suricata is not installed."
    echo "          DPI features will be unavailable until Suricata is installed."
    echo "          To enable DPI: pkg install suricata"
    # Do NOT force-install suricata here — it is a large dependency and the
    # administrator may not want it.  The daemon will detect its absence at
    # runtime and disable DPI gracefully.
fi

# ---------------------------------------------------------------------------
# Python pip dependencies (minimal — prefer stdlib)
# ---------------------------------------------------------------------------
REQUIREMENTS="${NETSHIELD_SCRIPTS}/requirements.txt"
if [ -f "${REQUIREMENTS}" ]; then
    echo "==> NetShield setup: Checking Python requirements..."
    if command -v pip3 >/dev/null 2>&1; then
        # Install into the system site-packages (OPNsense convention).
        # --quiet suppresses noise; errors are still printed.
        pip3 install --quiet --no-deps -r "${REQUIREMENTS}" \
            2>&1 | grep -v "^$" || echo "    WARNING: pip install had warnings (check above)"
    elif command -v python3 >/dev/null 2>&1; then
        python3 -m pip install --quiet --no-deps -r "${REQUIREMENTS}" \
            2>&1 | grep -v "^$" || echo "    WARNING: pip install had warnings (check above)"
    else
        echo "    WARNING: pip3 not available — skipping Python requirements"
    fi
fi

# ---------------------------------------------------------------------------
# Directory structure
# ---------------------------------------------------------------------------
echo "==> NetShield setup: Ensuring data directories exist..."

for dir in \
    "${NETSHIELD_DB_DIR}" \
    "${NETSHIELD_DB_DIR}/geoip" \
    "${NETSHIELD_DB_DIR}/targetlists" \
    "${NETSHIELD_DB_DIR}/appsigs" \
    "${NETSHIELD_DB_DIR}/dns_blocklists" \
    "${NETSHIELD_DB_DIR}/webcategories" \
    "${NETSHIELD_LOG_DIR}"; do
    if [ ! -d "${dir}" ]; then
        mkdir -p "${dir}"
        echo "    Created: ${dir}"
    fi
done

# ---------------------------------------------------------------------------
# Permissions
# ---------------------------------------------------------------------------
echo "==> NetShield setup: Setting permissions..."
chown -R root:wheel "${NETSHIELD_DB_DIR}" "${NETSHIELD_LOG_DIR}"
chmod -R 0750 "${NETSHIELD_DB_DIR}" "${NETSHIELD_LOG_DIR}"

# Make all scripts executable
find "${NETSHIELD_SCRIPTS}" -name "*.py" -exec chmod 0755 {} \;
find "${NETSHIELD_SCRIPTS}" -name "*.sh" -exec chmod 0755 {} \;

echo "==> NetShield setup: Done."
