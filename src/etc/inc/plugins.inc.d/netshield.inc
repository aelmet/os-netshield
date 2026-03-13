<?php
/*
 * netshield.inc — OPNsense plugin registration for NetShield
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2024-2026 NetShield Contributors
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

/**
 * Return the NetShield service descriptor for the OPNsense service framework.
 *
 * This makes NetShield appear under System -> Services -> Status and allows
 * start/stop/restart from the UI and via configd.
 *
 * @return array
 */
function netshield_services(): array
{
    $services = [];

    // Only register the service when the plugin is enabled.
    $model = \OPNsense\NetShield\General::getInstance();
    if (empty((string)$model->enabled) || (string)$model->enabled !== '1') {
        return $services;
    }

    $services[] = [
        'description' => gettext('NetShield Network Security'),
        'configd'     => [
            'restart' => ['netshield restart'],
            'start'   => ['netshield start'],
            'stop'    => ['netshield stop'],
        ],
        'name'        => 'netshield',
        'pidfile'     => '/var/run/netshield.pid',
    ];

    return $services;
}

/**
 * Return the NetShield configure hooks invoked during bootup and reconfigure.
 *
 * Returning a callable here causes OPNsense to call netshield_configure_do()
 * at the appropriate point in the boot sequence and after any configuration
 * change that triggers a configd reconfigure sweep.
 *
 * @return array  Keys are hook names, values are [callable, priority].
 */
function netshield_configure(): array
{
    return [
        'netshield' => ['netshield_configure_do', 20],
    ];
}

/**
 * Apply the current NetShield configuration.
 *
 * Called automatically on boot and whenever configd runs a reconfigure sweep.
 * Renders the Jinja2 template to /usr/local/etc/netshield.conf, then signals
 * the daemon to reload without a full restart when possible.
 *
 * @param bool $verbose  Whether to print progress messages (used during boot).
 * @return void
 */
function netshield_configure_do(bool $verbose = false): void
{
    $model = \OPNsense\NetShield\General::getInstance();
    if (empty((string)$model->enabled) || (string)$model->enabled !== '1') {
        // Plugin disabled — ensure service is not running.
        configd_run('netshield stop', true);
        return;
    }

    if ($verbose) {
        echo gettext('Applying NetShield configuration') . '... ';
        flush();
    }

    // Re-render the config template.
    configd_run('template reload OPNsense/NetShield', true);

    // Reconfigure (reload daemon config / enforce rules).
    configd_run('netshield reconfigure', true);

    if ($verbose) {
        echo gettext('done') . ".\n";
    }
}

/**
 * Register NetShield pf anchor rules with the OPNsense firewall framework.
 *
 * Each rule set is conditionally included based on the corresponding model
 * setting so that administrators can independently enable/disable each
 * enforcement category without editing pf rules manually.
 *
 * Anchors registered here:
 *   netshield/dns_redirect  — Redirect LAN DNS to the local resolver
 *   netshield/block_doh     — Block DoH (port 443 to known DoH providers)
 *   netshield/block_dot     — Block DoT (port 853)
 *   netshield/block_vpn     — Block outbound VPN ports (OpenVPN, WireGuard, etc.)
 *   netshield/block_proxy   — Block proxy ports (SOCKS, HTTP CONNECT, etc.)
 *   netshield/apps          — Per-application blocking rules
 *   netshield/geoip         — GeoIP country blocks
 *   netshield/targetlists   — Custom target list blocks
 *
 * @param object $fw  The OPNsense firewall rule collector object.
 * @return void
 */
function netshield_firewall($fw): void
{
    $model = \OPNsense\NetShield\General::getInstance();

    // Nothing to do when the plugin is disabled.
    if (empty((string)$model->enabled) || (string)$model->enabled !== '1') {
        return;
    }

    // Load the enforcement sub-model.
    $enforcement = \OPNsense\NetShield\Enforcement::getInstance();

    // --- DNS Redirection / Enforcement ---
    if (!empty((string)$enforcement->force_dns) && (string)$enforcement->force_dns === '1') {
        $fw->registerAnchor('netshield/dns_redirect', 'nat', 100, gettext('NetShield: Force DNS to local resolver'));
        $fw->registerAnchor('netshield/dns_redirect', 'filter', 100, gettext('NetShield: DNS redirect filter'));
    }

    // --- DoH / DoT Blocking ---
    if (!empty((string)$enforcement->block_doh) && (string)$enforcement->block_doh === '1') {
        $fw->registerAnchor('netshield/block_doh', 'filter', 110, gettext('NetShield: Block DNS-over-HTTPS'));
        $fw->registerAnchor('netshield/block_dot', 'filter', 111, gettext('NetShield: Block DNS-over-TLS (port 853)'));
    }

    // --- VPN Port Blocking ---
    if (!empty((string)$enforcement->block_vpn_ports) && (string)$enforcement->block_vpn_ports === '1') {
        $fw->registerAnchor('netshield/block_vpn', 'filter', 120, gettext('NetShield: Block unauthorized VPN ports'));
    }

    // --- Proxy Port Blocking ---
    if (!empty((string)$enforcement->block_proxy_ports) && (string)$enforcement->block_proxy_ports === '1') {
        $fw->registerAnchor('netshield/block_proxy', 'filter', 130, gettext('NetShield: Block proxy ports'));
    }

    // --- Application Policy Rules ---
    $fw->registerAnchor('netshield/apps', 'filter', 200, gettext('NetShield: Application policy rules'));

    // --- GeoIP Blocking ---
    if (!empty((string)$model->geoip_enabled) && (string)$model->geoip_enabled === '1') {
        $fw->registerAnchor('netshield/geoip', 'filter', 210, gettext('NetShield: GeoIP country blocks'));
    }

    // --- Custom Target Lists ---
    $fw->registerAnchor('netshield/targetlists', 'filter', 220, gettext('NetShield: Custom target list blocks'));
}
