# NetShield - OPNsense Network Security Plugin

Real-time network security monitoring, DNS filtering, device management, traffic inspection, and threat intelligence for OPNsense firewalls.

## Features

- **Deep Packet Inspection** - Application identification and traffic classification
- **DNS Filtering** - Category-based content filtering with Unbound integration
- **Device Management** - Auto-discovery, tracking, quarantine, and Wake-on-LAN
- **Policy Engine** - Per-device/VLAN/network access policies with app blocking
- **Behavioral IDS** - Anomaly detection with threat feed integration
- **GeoIP Blocking** - Country-level traffic filtering with MaxMind integration
- **Tor Protection** - Exit node detection and auto-blocking
- **Web Categories** - Domain categorization and filtering
- **Bandwidth Monitoring** - Per-device real-time bandwidth tracking
- **Session Viewer** - Live connection monitoring with app classification
- **Fusion VPN** - Multi-VPN profile management with per-device routing
- **Target Lists** - Custom domain/IP block and allow lists
- **Vulnerability Scanner** - Network device scanning
- **Threat Intelligence** - Multi-source threat feed aggregation
- **Mobile API** - JWT-authenticated REST API for remote monitoring
- **Telegram Alerts** - Real-time security notifications via Telegram bot

## Requirements

- OPNsense 23.x or later
- Python 3.9+
- Unbound DNS (default OPNsense DNS resolver)

## Installation

### Quick Install (SSH into your OPNsense box)

```sh
fetch -o /tmp/netshield.tar.gz https://github.com/OWNER/os-netshield/archive/refs/heads/main.tar.gz
tar xzf /tmp/netshield.tar.gz -C /tmp
sh /tmp/os-netshield-main/install.sh
rm -rf /tmp/netshield.tar.gz /tmp/os-netshield-main
```

### Manual Install (from cloned repo)

```sh
git clone https://github.com/OWNER/os-netshield.git
cd os-netshield
sh install.sh
```

### Update

Re-run the install script. It handles stopping the daemon, copying files, clearing caches, and restarting services.

### Uninstall

```sh
sh uninstall.sh
```

## Usage

After installation, navigate to **Services > NetShield** in the OPNsense web interface.

### Initial Setup

1. Go to **Settings** tab to configure general options
2. (Optional) Add your Telegram Bot token and Chat ID for alert notifications
3. Go to **Dashboard** for an overview of your network
4. Create **Policies** to enforce per-device or per-VLAN access rules
5. Configure **DNS Filtering** and **Web Categories** for content filtering

### Mobile App

NetShield includes a JWT-authenticated REST API for remote monitoring. Generate a one-time password from the Settings page and use it with the NetShield mobile app.

## Architecture

```
src/
├── etc/inc/plugins.inc.d/        Plugin registration
├── opnsense/
│   ├── mvc/app/
│   │   ├── controllers/          PHP API controllers (MVC)
│   │   ├── models/               Data model + ACL + Menu
│   │   └── views/                Volt templates (UI)
│   ├── scripts/netshield/        Python backend (called via configd)
│   │   └── lib/                  Shared Python modules
│   └── service/
│       ├── conf/actions.d/       configd action definitions
│       └── templates/            Config file templates
```

All backend operations run through OPNsense's `configd` service for sandboxed execution. No direct PHP-to-script calls.

## License

BSD 2-Clause License. See [LICENSE](LICENSE) for details.
