<?php

/*
 * Copyright (C) 2025 NetShield
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
 * OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

function netshield_enabled()
{
    $config = \OPNsense\Core\Config::getInstance()->object();
    return isset($config->OPNsense->netshield->general->enabled)
        && (string)$config->OPNsense->netshield->general->enabled === '1';
}

function netshield_services()
{
    $services = [];

    $services[] = [
        'description' => gettext('NetShield'),
        'configd'     => [
            'restart' => ['netshield restart'],
            'start'   => ['netshield start'],
            'stop'    => ['netshield stop'],
        ],
        'name'    => 'netshield',
        'pidfile' => '/var/run/netshield.pid',
    ];

    return $services;
}

function netshield_firewall($fw)
{
    // Register Tor blocking anchor (rules loaded by tor_blocker.py)
    $fw->registerAnchor('netshield_tor', 'fw');
    // Get quarantined device IPs from helper script (safe, no user input)
    $output = array();
    $rc = 0;
    exec('/usr/local/opnsense/scripts/netshield/get_quarantined_ips.py', $output, $rc);
    if ($rc !== 0 || empty($output)) {
        return;
    }

    $ips = array();
    foreach ($output as $line) {
        $ip = trim($line);
        if (!empty($ip) && filter_var($ip, FILTER_VALIDATE_IP)) {
            $ips[] = $ip;
        }
    }

    if (empty($ips)) {
        return;
    }

    foreach ($ips as $ip) {
        $fw->registerFilterRule(
            1,
            array(
                'ipprotocol' => 'inet',
                'descr'      => 'NetShield quarantine: block ' . $ip,
                'from'       => $ip,
                'direction'  => 'in',
                'type'       => 'block',
                'log'        => true,
                'quick'      => true
            )
        );
        $fw->registerFilterRule(
            1,
            array(
                'ipprotocol' => 'inet',
                'descr'      => 'NetShield quarantine: block ' . $ip,
                'to'         => $ip,
                'direction'  => 'out',
                'type'       => 'block',
                'log'        => true,
                'quick'      => true
            )
        );
    }
}

