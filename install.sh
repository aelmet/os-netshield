#!/bin/sh
# NetShield OPNsense Plugin - Direct Install Script
# Usage: fetch -o - https://raw.githubusercontent.com/REPO/main/install.sh | sh
# Or:    sh install.sh (from cloned repo)

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SRC_DIR="$SCRIPT_DIR/src"

# Verify we're on OPNsense/FreeBSD
if ! command -v opnsense-version >/dev/null 2>&1; then
    echo "Error: This script must be run on an OPNsense system."
    exit 1
fi

OPNSENSE_VER=$(opnsense-version -v 2>/dev/null || echo "unknown")
echo "NetShield: Installing on OPNsense $OPNSENSE_VER"

# Verify source directory exists
if [ ! -d "$SRC_DIR" ]; then
    echo "Error: src/ directory not found. Run from the repository root."
    exit 1
fi

# Stop existing daemon if running
if pgrep -f netshield_daemon >/dev/null 2>&1; then
    echo "Stopping existing NetShield daemon..."
    configctl netshield stop 2>/dev/null || true
    sleep 2
fi

# Copy plugin registration
echo "Installing plugin registration..."
cp "$SRC_DIR/etc/inc/plugins.inc.d/netshield.inc" /usr/local/etc/inc/plugins.inc.d/

# Copy MVC layer
echo "Installing MVC controllers..."
mkdir -p /usr/local/opnsense/mvc/app/controllers/OPNsense/NetShield/Api
cp "$SRC_DIR/opnsense/mvc/app/controllers/OPNsense/NetShield/IndexController.php" \
   /usr/local/opnsense/mvc/app/controllers/OPNsense/NetShield/
cp "$SRC_DIR/opnsense/mvc/app/controllers/OPNsense/NetShield/Api/"*.php \
   /usr/local/opnsense/mvc/app/controllers/OPNsense/NetShield/Api/

echo "Installing MVC models..."
mkdir -p /usr/local/opnsense/mvc/app/models/OPNsense/NetShield/ACL
mkdir -p /usr/local/opnsense/mvc/app/models/OPNsense/NetShield/Menu
cp "$SRC_DIR/opnsense/mvc/app/models/OPNsense/NetShield/NetShield.php" \
   /usr/local/opnsense/mvc/app/models/OPNsense/NetShield/
cp "$SRC_DIR/opnsense/mvc/app/models/OPNsense/NetShield/NetShield.xml" \
   /usr/local/opnsense/mvc/app/models/OPNsense/NetShield/
cp "$SRC_DIR/opnsense/mvc/app/models/OPNsense/NetShield/ACL/ACL.xml" \
   /usr/local/opnsense/mvc/app/models/OPNsense/NetShield/ACL/
cp "$SRC_DIR/opnsense/mvc/app/models/OPNsense/NetShield/Menu/Menu.xml" \
   /usr/local/opnsense/mvc/app/models/OPNsense/NetShield/Menu/

echo "Installing views..."
mkdir -p /usr/local/opnsense/mvc/app/views/OPNsense/NetShield
cp "$SRC_DIR/opnsense/mvc/app/views/OPNsense/NetShield/"*.volt \
   /usr/local/opnsense/mvc/app/views/OPNsense/NetShield/

# Copy backend scripts
echo "Installing backend scripts..."
mkdir -p /usr/local/opnsense/scripts/netshield/lib
cp "$SRC_DIR/opnsense/scripts/netshield/"*.py /usr/local/opnsense/scripts/netshield/
cp "$SRC_DIR/opnsense/scripts/netshield/"*.sh /usr/local/opnsense/scripts/netshield/ 2>/dev/null || true
cp "$SRC_DIR/opnsense/scripts/netshield/lib/"*.py /usr/local/opnsense/scripts/netshield/lib/

# Make scripts executable
chmod +x /usr/local/opnsense/scripts/netshield/*.py
chmod +x /usr/local/opnsense/scripts/netshield/*.sh 2>/dev/null || true

# Copy service configuration
echo "Installing configd actions..."
cp "$SRC_DIR/opnsense/service/conf/actions.d/actions_netshield"*.conf \
   /usr/local/opnsense/service/conf/actions.d/

echo "Installing templates..."
mkdir -p /usr/local/opnsense/service/templates/OPNsense/NetShield
cp "$SRC_DIR/opnsense/service/templates/OPNsense/NetShield/"* \
   /usr/local/opnsense/service/templates/OPNsense/NetShield/

# Initialize database directory
mkdir -p /var/db/netshield
chmod 750 /var/db/netshield

# Clear caches
echo "Clearing caches..."
rm -rf /tmp/opnsense_*cache* 2>/dev/null || true

# Flush Volt template cache
if [ -d "/usr/local/opnsense/mvc/app/cache" ]; then
    find /usr/local/opnsense/mvc/app/cache -name "*.php" -delete 2>/dev/null || true
fi

# Clear PHP opcache
if command -v php >/dev/null 2>&1; then
    php -r 'if (function_exists("opcache_reset")) opcache_reset();' 2>/dev/null || true
fi

# Restart configd to pick up new actions
echo "Restarting configd..."
service configd restart

# Generate config from templates
configctl template reload OPNsense/NetShield 2>/dev/null || true

echo ""
echo "========================================="
echo " NetShield installed successfully!"
echo " Navigate to Services > NetShield in the"
echo " OPNsense web interface to get started."
echo "========================================="
exit 0
