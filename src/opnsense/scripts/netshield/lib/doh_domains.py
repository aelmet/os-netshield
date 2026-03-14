#!/usr/local/bin/python3
"""Comprehensive DoH, Tor, VPN, and ECH domain lists for NetShield enforcement."""

# DNS-over-HTTPS providers - comprehensive list from curl DOH-SERVERS.md + manual research
DOH_DOMAINS = [
    # Major providers
    "cloudflare-dns.com", "1dot1dot1dot1.cloudflare-dns.com",
    "one.one.one.one", "family.cloudflare-dns.com",
    "security.cloudflare-dns.com", "mozilla.cloudflare-dns.com",
    "dns.google", "dns.google.com", "dns64.dns.google",
    "dns.quad9.net", "dns9.quad9.net", "dns10.quad9.net", "dns11.quad9.net",
    "doh.opendns.com", "dns.umbrella.com",
    "dns.nextdns.io", "anycast.dns.nextdns.io",
    "doh.cleanbrowsing.org", "doh.cleanbrowsing.org",
    "dns.adguard.com", "dns.adguard-dns.com",
    "dns-unfiltered.adguard.com", "dns-family.adguard.com",
    # Regional / smaller
    "doh.dns.sb", "doh.sb",
    "doh.applied-privacy.net", "doh.li",
    "doh.dns.apple.com", "mask.icloud.com", "mask-h2.icloud.com",
    "dns.alidns.com", "doh.360.cn",
    "dns.twnic.tw",
    "doh.centraleu.pi-dns.com", "doh.eastus.pi-dns.com",
    "doh.northeu.pi-dns.com", "doh.westus.pi-dns.com",
    "jp.tiar.app", "doh.tiar.app", "doh.tiarap.org",
    "dns.rubyfish.cn", "dns.containerpi.com",
    "dns.digitale-gesellschaft.ch",
    "dns.flatuslifir.is",
    "doh.ffmuc.net",
    "dns.hostux.net",
    "dns.oszx.co",
    "doh.powerdns.org",
    "doh.seby.io",
    "resolver-eu.lelux.fi",
    "doh.libredns.gr",
    "dns.switch.ch",
    "doh.xfinity.com", "doh.cox.net",
    "ordns.he.net",
    "dns.mullvad.net", "adblock.dns.mullvad.net",
    "dns.controld.com",
    "freedns.controld.com",
    "private.canadianshield.cira.ca",
    "protected.canadianshield.cira.ca",
    "family.canadianshield.cira.ca",
    "odvr.nic.cz",
    "dns.aa.net.uk",
    "dns.restena.lu",
    "doh.crypto.sx",
    "dns.njal.la",
    "doh.post-factum.tk",
    "dns.dnshome.de",
    "dns.telekom.de",
    "doh.dns.snopyta.org",
    "dns.pumplex.com",
    # Use-application-dns.net canary domain (Firefox checks this)
    "use-application-dns.net",
]

# Tor infrastructure domains
TOR_DOMAINS = [
    # Official Tor Project
    "torproject.org", "www.torproject.org",
    "bridges.torproject.org", "snowflake.torproject.org",
    "tb-manual.torproject.org", "check.torproject.org",
    "dist.torproject.org", "blog.torproject.org",
    "support.torproject.org", "community.torproject.org",
    "metrics.torproject.org", "collector.torproject.org",
    "onionoo.torproject.org", "stem.torproject.org",
    "gitweb.torproject.org", "gitlab.torproject.org",
    "trac.torproject.org", "people.torproject.org",
    "spec.torproject.org", "deb.torproject.org",
    "rpm.torproject.org", "archive.torproject.org",
    # Tor2Web gateways (allow accessing .onion via clearnet)
    "onion.cab", "onion.link", "onion.ly",
    "onion.pet", "onion.ws", "onion.to",
    "onion.dog", "onion.sh", "onion.city",
    "onion.direct", "onion.top", "onion.plus",
    "onion.rip", "onion.guide",
    "tor2web.org", "tor2web.io", "tor2web.fi",
    # Tor browser mirrors/downloads
    "torbrowser.cc", "torservers.net",
    "tor.eff.org", "tor.blingblongbling.de",
    "tor.hermetix.org", "tor.ccc.de",
    # Snowflake / pluggable transports
    "snowflake-broker.torproject.net",
    "cdn.sstatic.net",  # Used for domain fronting by Tor
    # Orbot (Android Tor)
    "orbot.app", "guardianproject.info",
]

# Commercial VPN provider domains
VPN_DOMAINS = [
    # Top VPNs
    "nordvpn.com", "nordvpn.net", "nordcdn.com",
    "expressvpn.com", "expressvpn.net", "xvtest.net",
    "surfshark.com",
    "protonvpn.com", "protonvpn.net", "proton.me",
    "mullvad.net",
    "windscribe.com", "windscribe.net",
    "privateinternetaccess.com", "piavpn.com",
    "cyberghostvpn.com", "cyberghost.com",
    "ipvanish.com",
    "purevpn.com",
    "tunnelbear.com",
    "hide.me", "hideipvpn.com",
    "hotspotshield.com",
    "vyprvpn.com", "goldenfrog.com",
    "strongvpn.com",
    "zenmate.com",
    "torguard.net",
    "privatevpn.com",
    "astrill.com",
    "atlasvpn.com",
    "mozillavpn.com",
    # Cloudflare WARP
    "warp.cloudflare.com", "cloudflarewarp.com",
    # Other VPNs
    "betternet.co",
    "psiphon.ca", "psiphon3.com",
    "lantern.io", "getlantern.org",
    "hola.org", "holabetterinternet.com",
    "ultrasurf.us",
    "freegate.me",
    "vpnbook.com",
    "vpngate.net",
    "proxysh.com",
    "bolehvpn.net",
    "azirevpn.com",
    "oeck.com",
    "cryptostorm.is", "cryptostorm.nu",
    "airvpn.org",
    "ivpn.net",
    "trustzone.net",
    "safervpn.com",
    "speedify.com",
    "getoutline.org", "s3.amazonaws.com",  # Outline VPN
    # VPN review/comparison sites (users looking for VPNs)
    "vpnmentor.com", "comparitech.com",
    "thebestvpn.com", "vpnpro.com",
    "restoreprivacy.com",
]

# ECH (Encrypted Client Hello) related domains
# These serve HTTPS DNS records with ECH keys
ECH_DOMAINS = [
    # Cloudflare hosts most ECH-enabled domains
    "cloudflare.com", "cloudflare-dns.com",
    "cloudflareinsights.com", "cloudflarestream.com",
    # Firefox canary
    "use-application-dns.net",
    # Cloudflare-proxied major domains that support ECH
    "crypto.cloudflare.com",
    "encryptedsni.com",  # Cloudflare's ECH test domain
    "defo.ie",  # ECH testing
    "tls-ech.dev",  # ECH testing
    "hidden.hoba.de",  # ECH testing
]
