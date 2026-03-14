<?php

/*
 * Copyright (C) 2025-2026 NetShield Contributors
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
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

namespace OPNsense\NetShield\Api;

use OPNsense\Base\ApiControllerBase;
use OPNsense\Core\Backend;

class NetworkController extends JwtAwareController
{
    /**
     * GET — return network topology graph for D3.js rendering.
     */
    public function topologyAction()
    {
        $backend = new Backend();
        $raw = $backend->configdRun('netshield get_topology');
        $data = json_decode($raw, true);
        if ($data === null) {
            return ['error' => 'Failed to retrieve topology data', 'nodes' => [], 'edges' => []];
        }
        return $data;
    }

    /**
     * POST — run an internet speed test and return results.
     */
    public function speedtestAction()
    {
        if (!$this->request->isPost()) {
            return ['result' => 'failed', 'message' => 'POST required'];
        }

        $backend = new Backend();
        $raw = $backend->configdRun('netshield run_speedtest');
        $data = json_decode($raw, true);
        if ($data === null) {
            return ['error' => 'Failed to run speed test'];
        }
        return $data;
    }

    /**
     * GET — speed test history.
     */
    public function speedtestHistoryAction()
    {
        $backend = new Backend();
        $raw = $backend->configdRun('netshield run_speedtest history');
        $data = json_decode($raw, true);
        if ($data === null) {
            return ['status' => 'error', 'results' => []];
        }
        return $data;
    }

    /**
     * POST — send Wake-on-LAN magic packet to a device.
     *
     * Required POST param: mac
     * Optional POST param: broadcast
     */
    public function wakeAction()
    {
        if (!$this->request->isPost()) {
            return ['result' => 'failed', 'message' => 'POST required'];
        }

        $mac = trim($this->request->getPost('mac') ?? '');
        if (empty($mac)) {
            return ['result' => 'failed', 'message' => 'mac parameter required'];
        }

        // Validate MAC format to prevent injection
        if (!preg_match('/^[0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5}$/', $mac)) {
            return ['result' => 'failed', 'message' => 'Invalid MAC address format'];
        }

        $broadcast = trim($this->request->getPost('broadcast') ?? '255.255.255.255');
        // Validate broadcast IP
        if (!filter_var($broadcast, FILTER_VALIDATE_IP)) {
            $broadcast = '255.255.255.255';
        }

        $backend = new Backend();
        $cmd = sprintf('netshield wake_device %s,%s',
            escapeshellarg($mac),
            escapeshellarg($broadcast)
        );
        $raw = $backend->configdRun($cmd);
        $data = json_decode($raw, true);
        if ($data === null) {
            return ['result' => 'failed', 'message' => 'No response from wake_device'];
        }
        return $data;
    }

    /**
     * GET — return list of currently quarantined devices.
     */
    public function quarantineStatusAction()
    {
        $backend = new Backend();
        $raw = $backend->configdRun('netshield get_devices quarantined');
        $data = json_decode($raw, true);
        if ($data === null) {
            return ['devices' => []];
        }
        return ['devices' => $data];
    }

    /**
     * GET — return list of VLANs/interfaces configured on the system.
     */
    public function vlansAction()
    {
        $backend = new Backend();
        $raw = $backend->configdRun('netshield get_vlans');
        $data = json_decode($raw, true);

        if ($data && isset($data['vlans'])) {
            return $data;
        }

        // Fallback: try to get interfaces from OPNsense config
        $configPath = '/conf/config.xml';
        if (file_exists($configPath)) {
            $config = simplexml_load_file($configPath);
            $vlans = [];

            // Get VLANs from config
            if (isset($config->vlans->vlan)) {
                foreach ($config->vlans->vlan as $vlan) {
                    $vlans[] = [
                        'id' => (string)$vlan->tag,
                        'name' => (string)$vlan->descr ?: 'VLAN ' . (string)$vlan->tag,
                        'interface' => (string)$vlan->if,
                        'subnet' => ''
                    ];
                }
            }

            // Add interfaces as fallback
            if (isset($config->interfaces)) {
                foreach ($config->interfaces->children() as $ifname => $iface) {
                    if ($ifname === 'wan' || $ifname === 'lan' || strpos($ifname, 'opt') === 0) {
                        $descr = (string)$iface->descr ?: strtoupper($ifname);
                        $subnet = '';
                        if (isset($iface->ipaddr) && isset($iface->subnet)) {
                            $subnet = (string)$iface->ipaddr . '/' . (string)$iface->subnet;
                        }
                        $vlans[] = [
                            'id' => $ifname,
                            'name' => $descr,
                            'interface' => (string)$iface->if,
                            'subnet' => $subnet
                        ];
                    }
                }
            }

            return ['vlans' => $vlans];
        }

        // Absolute fallback — no hardcoded subnets; return empty so UI adapts
        return ['vlans' => []];
    }
}
