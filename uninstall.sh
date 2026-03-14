#!/bin/sh
# NetShield OPNsense Plugin - Uninstall Script
# Usage: sh uninstall.sh

set -e

echo "NetShield: Uninstalling..."

# Stop daemon
if pgrep -f netshield_daemon >/dev/null 2>&1; then
    echo "Stopping NetShield daemon..."
    configctl netshield stop 2>/dev/null || true
    sleep 2
    pkill -f netshield_daemon 2>/dev/null || true
fi

# Remove plugin files
echo "Removing plugin files..."
rm -rf /usr/local/opnsense/mvc/app/controllers/OPNsense/NetShield
rm -rf /usr/local/opnsense/mvc/app/models/OPNsense/NetShield
rm -rf /usr/local/opnsense/mvc/app/views/OPNsense/NetShield
rm -rf /usr/local/opnsense/scripts/netshield
rm -rf /usr/local/opnsense/service/templates/OPNsense/NetShield
rm -f /usr/local/opnsense/service/conf/actions.d/actions_netshield*.conf
rm -f /usr/local/etc/inc/plugins.inc.d/netshield.inc

# Clear caches
rm -rf /tmp/opnsense_*cache* 2>/dev/null || true
find /usr/local/opnsense/mvc/app/cache -name "*.php" -delete 2>/dev/null || true

# Restart configd
service configd restart

echo ""
echo "NetShield uninstalled. Database at /var/db/netshield/ preserved."
echo "To remove data: rm -rf /var/db/netshield"
exit 0
