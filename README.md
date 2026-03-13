# NetShield — Network Security Suite for OPNsense

NetShield is a comprehensive network security and parental-control plugin for OPNsense. It combines DNS-based filtering, application identification, VPN/proxy detection, device management, policy enforcement, GeoIP blocking, and real-time alerting into a single unified dashboard — all running locally on your router with no cloud dependency.

---

## Features

- **DNS Filtering** — Block domains via Unbound with support for category lists, custom target lists, and safe search enforcement (Google, YouTube, Bing)
- **Application Identification** — Detect 50+ applications by SNI and DNS query patterns (TikTok, Netflix, WhatsApp, gaming platforms, etc.)
- **Policy Engine** — Flexible rule system with scope targeting (network CIDR, VLAN, single device, device category), scheduling (days + time windows), and actions (block, allow, throttle, log)
- **VPN / Proxy Detection** — Five-method detection: port-based, SNI, DNS query, DPI via Suricata, and behavioral heuristics
- **Device Management** — Automatic discovery with MAC/IP/hostname/vendor tracking, per-device categorization, approve/quarantine workflow
- **Web Categories** — Subscription-style blocklists (adult, gambling, malware, ads, social media, etc.) with configurable sync schedules
- **GeoIP Blocking** — Country-level traffic blocking via MaxMind GeoLite2 database
- **Custom Target Lists** — Import and maintain domain, IP, or CIDR blocklists from URLs or manual entry
- **Real-time Alerts** — Per-event alerting stored in SQLite with syslog forwarding and webhook delivery (Slack, Teams, Discord, N8n, etc.)
- **Safe Search Enforcement** — Forces Google, YouTube, and Bing into restricted/safe mode via DNS CNAME overrides
- **DoH / DoT Blocking** — Prevents DNS-over-HTTPS and DNS-over-TLS bypass
- **Force DNS** — Redirects all DNS queries to Unbound regardless of destination
- **Suricata Integration** — Reads EVE JSON for deep packet inspection data
- **Dashboard** — Live summary cards, service control, top offending devices, and recent alerts
- **No Telemetry** — All data stays on your router; no external calls except optional list syncs

---

## Requirements

### Minimum Hardware

| Resource | Minimum | Recommended |
|----------|---------|-------------|
| CPU | 2 cores | 4+ cores (for DPI) |
| RAM | 2 GB | 4 GB (8 GB+ for large networks) |
| Storage | 500 MB | 1 GB+ (for category lists and logs) |

### Software Requirements

- **OPNsense** 23.1 or later (tested up to 25.x)
- **Python** 3.8+ (included with OPNsense)
- **Unbound DNS** — must be the active DNS resolver (OPNsense default)
- **Suricata** — optional, required for DPI and VPN detection via EVE JSON
  - Install via: Firmware > Plugins > os-suricata

### Network Requirements

- Unbound must be configured as the active DNS resolver
- For full VPN detection: Suricata with EVE JSON logging enabled at `/var/log/suricata/eve.json`
- For GeoIP blocking: MaxMind GeoLite2-Country.mmdb (free account at maxmind.com)

---

## Installation

### Method 1: From Package (Recommended)

```sh
pkg install os-netshield
```

Navigate to **Services > NetShield** after installation.

---

### Method 2: Manual Installation

```bash
# Download the latest release tarball
fetch https://github.com/netshield-community/os-netshield/releases/latest/download/os-netshield.tar.gz

# Extract to OPNsense file tree
tar xzf os-netshield.tar.gz -C /usr/local

# Restart configd to register new actions
service configd restart

# Navigate to Services > NetShield in the web UI
```

---

### Method 3: Development Install

```bash
# Clone the repository
git clone https://github.com/netshield-community/os-netshield.git
cd os-netshield/src

# Package the source tree
tar czf ../netshield-dev.tar.gz .

# Copy to your OPNsense router and install
scp ../netshield-dev.tar.gz root@<your-opnsense-ip>:/tmp/
ssh root@<your-opnsense-ip> "tar xzf /tmp/netshield-dev.tar.gz -C /usr/local && service configd restart"

# Verify configd registered the new actions
ssh root@<your-opnsense-ip> "configctl netshield status"
```

---

## Post-Installation Setup

1. Navigate to **Services > NetShield > Settings**
2. Set **Enable NetShield** to `Enabled`
3. Enable the detection modules you want (DNS Filtering, Device Tracking, VPN Detection)
4. Configure notifications (syslog or webhook) if desired
5. Click **Save**, then **Save & Apply**
6. Go to **Web Categories** and click **Sync All** to download the default category lists
7. Go to **Policies** and create your first policy
8. Click **Apply Policies** in the Policies tab to enforce them

---

## Configuration

### General
Controls the master enable switch, log verbosity, how often the daemon runs its checks, and alert deduplication cooldown.

### DNS Filtering
Enables Unbound-based blocking. Configure safe search enforcement and DoH/DoT blocking here. Requires Unbound to be the active resolver.

### Detection
Toggle individual detection modules. Suricata integration path must match your EVE log location. SNI detection works without Suricata but provides less detail.

### Enforcement
Configures firewall-level actions: force DNS redirection, VPN port blocking, proxy port blocking, and automatic quarantine thresholds.

### Alerts & Notifications
Configure where alerts are forwarded. Syslog supports UDP/TCP with configurable facility. Webhooks POST a JSON payload compatible with Slack incoming webhooks, Teams connectors, Discord webhooks, and N8n HTTP triggers.

### GeoIP
Enable country-level blocking and set the path to your MaxMind .mmdb file. Country toggles are managed from the GeoIP tab in the dashboard.

---

## Feature Details

### Application Identification

NetShield identifies applications using Server Name Indication (SNI) extracted from TLS ClientHello packets and DNS query correlation. The built-in library covers 50+ common applications across categories:

- **Streaming**: Netflix, YouTube, Twitch, Disney+, Spotify, Apple TV+
- **Social**: TikTok, Instagram, Snapchat, Twitter/X, Facebook, Reddit
- **Gaming**: Steam, Xbox Live, PlayStation Network, Epic Games, Roblox
- **Communication**: WhatsApp, Telegram, Signal, Discord, Zoom, Teams
- **VPN/Proxy**: WireGuard, OpenVPN, NordVPN, ExpressVPN, Tor, Shadowsocks

Custom applications can be added via the Applications tab by specifying a name, category, and domain list.

### Policy Engine

Policies are processed in priority order (lower number = higher priority). Each policy defines:

- **Scope** — Who is affected: a CIDR network range, a specific VLAN, a single device by MAC, or all devices in a named category
- **Action** — What happens: block traffic, allow traffic (overrides lower-priority blocks), throttle to a bandwidth limit, or log only
- **Target** — What traffic is matched: specific applications, web categories, target lists, or all traffic
- **Schedule** — When the policy is active: configurable per day-of-week with start/end time windows

After making changes in the Policies tab, click **Apply Policies** to push the new ruleset to the firewall and DNS resolver.

### DNS Filtering

NetShield injects blocklists into Unbound's `local-zone` and `local-data` configuration. Blocked domains return NXDOMAIN (configurable to REFUSED or a sinkhole IP). Safe search enforcement works by overriding the CNAME for search engine domains to their restricted-mode equivalents:

- `google.com` → `forcesafesearch.google.com`
- `youtube.com` → `restrictmoderate.youtube.com`
- `bing.com` → `strict.bing.com`

### VPN / Proxy Detection

Five complementary detection methods are combined to catch evasion attempts:

1. **Port-based** — Flags traffic on known VPN ports (UDP 1194, TCP 1723, UDP 4500, TCP 8388)
2. **SNI matching** — Matches TLS server names against a list of known VPN provider domains
3. **DNS query analysis** — Detects lookups for VPN provider domains before the connection is made
4. **DPI via Suricata** — Protocol detection from EVE JSON `app_proto` field (tls, wireguard, etc.)
5. **Behavioral heuristics** — Flags unusual traffic patterns such as high-entropy payloads and non-standard port usage

Detections generate alerts in the alert log and optionally trigger policy enforcement or quarantine.

### Device Management

Devices are discovered automatically from ARP table and DHCP lease data. For each device, NetShield tracks:

- MAC address and vendor (via OUI database)
- Current and historical IP addresses
- Hostname (from DHCP, mDNS, and reverse DNS)
- User-assigned category (computer, mobile, IoT, smart TV, gaming, etc.)
- Alert history and status (approved / unknown / quarantined)

Quarantined devices are blocked according to the configured quarantine action (full block, internet-only block, or captive portal redirect).

### Web Categories

Categories are domain lists grouped by content type. Each category has a source URL that is fetched and parsed on a configurable schedule. Supported list formats:

- Plain text (one domain per line)
- Hosts file format
- AdBlock/AdGuard filter syntax (domain rules only)

Built-in category sources cover: adult content, gambling, malware, phishing, ads/trackers, social media, gaming, streaming, and more.

### GeoIP Blocking

Country-level blocking uses MaxMind GeoLite2-Country database to resolve IP addresses to countries. Blocked country traffic is dropped at the firewall level using pf tables. The country list is managed from the GeoIP tab with checkboxes per country, a search filter, and live statistics for blocked countries and connection counts.

The database can be updated automatically on a weekly or monthly schedule once the mmdb file path is configured.

### Target Lists

Custom blocklists can be added by URL or manual entry. Supported types:

- **Domain** — Plain domain names, one per line
- **IP** — Individual IP addresses
- **CIDR** — IP ranges in CIDR notation

Lists are fetched from their source URLs on a configurable interval (hourly, daily, weekly) and compiled into Unbound configuration and pf tables.

---

## Troubleshooting

### Service won't start

1. Check the log: `cat /var/log/netshield/netshield.log`
2. Verify Python 3.8+: `python3 --version`
3. Check configd action is registered: `configctl netshield status`
4. Ensure Unbound is the active resolver under Services > Unbound DNS

### DNS blocking not working

1. Confirm DNS Filtering is enabled in Settings
2. Confirm Unbound is the active resolver (not Dnsmasq)
3. After any list change, click **Save & Apply** so Unbound reloads
4. Test with: `nslookup blocked-domain.example.com 127.0.0.1`
5. Check Unbound config for injected zones: `grep netshield /var/unbound/unbound.conf`

### VPN detection not firing

1. Confirm Detection > VPN Detection is enabled
2. For DPI-based detection: confirm Suricata is installed and EVE JSON logging is enabled
3. Verify the EVE log path in Settings matches the actual Suricata log location
4. Check the Suricata interface is monitoring the right interface (LAN, not WAN)
5. Test by generating some traffic and checking `/var/log/suricata/eve.json`

### Policies not enforcing

1. Click **Apply Policies** in the Policies tab after any policy change
2. Verify the policy is Enabled and the priority is correct
3. Check scope values: CIDR must be valid notation, MAC must match exactly
4. Check the API response in the browser developer console for apply errors
5. Review the system log: System > Log Files > General

### Dashboard shows no data

1. Confirm the service is running (green indicator on Dashboard tab)
2. Check API connectivity: open browser dev tools, look for failed `/api/netshield/` calls
3. Verify configd is running: `service configd status`
4. Restart configd: `service configd restart`
5. Check for Python errors: `cat /var/log/netshield/netshield.log | grep ERROR`

---

## Uninstallation

```sh
pkg remove os-netshield
```

Optionally remove all data and logs:

```sh
rm -rf /var/db/netshield /var/log/netshield
```

The plugin does not modify any core OPNsense configuration files. All changes made during operation (Unbound zones, pf tables, firewall rules) are removed when the service is stopped or the package is uninstalled.

---

## Contributing

Contributions are welcome. Please follow these steps:

1. Fork the repository on GitHub
2. Create a feature branch: `git checkout -b feature/my-feature`
3. Write code following the existing module structure
4. Add or update tests where applicable
5. Run syntax validation: `python3 -m py_compile` on all modified Python files
6. Submit a pull request with a clear description of the change and why it is needed

### Reporting Bugs

Open an issue on GitHub with:
- OPNsense version
- NetShield version
- Steps to reproduce
- Relevant log output from `/var/log/netshield/netshield.log`

### Feature Requests

Open a GitHub issue with the `enhancement` label. Describe the use case and expected behavior.

---

## License

BSD 2-Clause License

Copyright (c) NetShield Contributors

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

---

## Security

- **No telemetry** — NetShield never contacts external servers except when explicitly syncing category lists or target lists from URLs you configure
- **No hardcoded credentials** — All authentication uses OPNsense's native API key system
- **All data local** — The SQLite database, logs, and all detection state live on your router only
- **No frontend secrets** — The web UI contains no API keys, tokens, or sensitive values; all privileged operations go through the configd/API layer
- **Responsible disclosure** — If you find a security vulnerability, please open a GitHub issue marked `security` or contact the maintainers privately before public disclosure. Allow a reasonable time for a fix before publishing details.
