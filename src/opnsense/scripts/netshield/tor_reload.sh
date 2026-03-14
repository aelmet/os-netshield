#!/bin/sh
# NetShield Tor Blocking — reload pf rules
# Called after filter reloads to re-inject Tor blocking anchor
sleep 2
pfctl -t ns_block_tor -T replace -f /var/db/netshield/pf_tables/block_tor.txt 2>/dev/null
pfctl -a netshield_tor -f /tmp/netshield_tor_merge.conf 2>/dev/null
