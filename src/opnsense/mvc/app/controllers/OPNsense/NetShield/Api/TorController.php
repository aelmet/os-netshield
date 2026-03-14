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

/**
 * Tor/Anonymizer blocking controller.
 * Manages multi-layer Tor blocking: IP blocklists, port blocking, DNS blocking.
 */
class TorController extends ApiControllerBase
{
    /**
     * Helper: encode a parameter for safe configd transport.
     * Uses rawurlencode to avoid escapeshellarg quoting issues with configd %s.
     */
    private function encParam($val)
    {
        return rawurlencode(trim($val));
    }

    /**
     * GET /api/netshield/tor/status
     * Returns current Tor blocker status, layer states, and statistics.
     */
    public function statusAction()
    {
        $backend = new Backend();
        $raw = $backend->configdRun('netshield manage_tor status');
        return json_decode($raw, true) ?: [];
    }

    /**
     * POST /api/netshield/tor/enable
     * Enable all Tor blocking layers (IP, ports, DNS).
     */
    public function enableAction()
    {
        if (!$this->request->isPost()) {
            return ['result' => 'failed', 'message' => 'POST required'];
        }

        $backend = new Backend();
        $raw = $backend->configdRun('netshield manage_tor enable');
        return json_decode($raw, true) ?: ['result' => trim($raw) ?: 'ok'];
    }

    /**
     * POST /api/netshield/tor/disable
     * Disable all Tor blocking layers.
     */
    public function disableAction()
    {
        if (!$this->request->isPost()) {
            return ['result' => 'failed', 'message' => 'POST required'];
        }

        $backend = new Backend();
        $raw = $backend->configdRun('netshield manage_tor disable');
        return json_decode($raw, true) ?: ['result' => trim($raw) ?: 'ok'];
    }

    /**
     * POST /api/netshield/tor/update
     * Trigger immediate update of Tor node IP lists.
     */
    public function updateAction()
    {
        if (!$this->request->isPost()) {
            return ['result' => 'failed', 'message' => 'POST required'];
        }

        $backend = new Backend();
        $raw = $backend->configdRun('netshield manage_tor update');
        return json_decode($raw, true) ?: ['result' => trim($raw) ?: 'ok'];
    }

    /**
     * POST /api/netshield/tor/toggleLayer
     * Toggle a specific blocking layer.
     *
     * POST params: layer (block_ips|block_ports|block_dns|alert_on_attempt), enabled (1|0)
     */
    public function toggleLayerAction()
    {
        if (!$this->request->isPost()) {
            return ['result' => 'failed', 'message' => 'POST required'];
        }

        $layer   = $this->request->getPost('layer');
        $enabled = $this->request->getPost('enabled', 'string', '1');

        $allowed = ['block_ips', 'block_ports', 'block_dns', 'alert_on_attempt'];
        if (empty($layer) || !in_array($layer, $allowed, true)) {
            return ['result' => 'failed', 'message' => 'layer must be one of: ' . implode(', ', $allowed)];
        }

        $enabledVal = ($enabled === '0' || $enabled === 'false') ? '0' : '1';

        $backend = new Backend();
        $cmd = 'netshield manage_tor toggle-layer ' . $layer . ' ' . $enabledVal;
        $raw = $backend->configdRun($cmd);
        return json_decode($raw, true) ?: ['result' => trim($raw) ?: 'ok'];
    }

    /**
     * GET /api/netshield/tor/checkIp
     * Check if an IP address is a known Tor node.
     *
     * GET param: ip
     */
    public function checkIpAction()
    {
        $ip = $this->request->get('ip');
        if (empty($ip) || !filter_var($ip, FILTER_VALIDATE_IP)) {
            return ['result' => 'failed', 'message' => 'Valid IP address required'];
        }

        $backend = new Backend();
        $raw = $backend->configdRun('netshield manage_tor check-ip ' . $ip);
        return json_decode($raw, true) ?: [];
    }

    /**
     * GET /api/netshield/tor/listIps
     * Paginated list of blocked Tor IPs (bootgrid compatible).
     */
    public function listIpsAction()
    {
        $current  = max(1, (int)$this->request->get('current', 'int', 1));
        $rowCount = max(1, min(500, (int)$this->request->get('rowCount', 'int', 25)));
        $offset   = ($current - 1) * $rowCount;

        $backend = new Backend();
        $cmd = 'netshield manage_tor list-ips ' . $rowCount . ' ' . $offset;
        $raw = $backend->configdRun($cmd);
        $data = json_decode($raw, true) ?: ['ips' => [], 'total' => 0];

        return [
            'rows'     => $data['ips'] ?? [],
            'rowCount' => $rowCount,
            'total'    => $data['total'] ?? 0,
            'current'  => $current,
        ];
    }

    /**
     * POST /api/netshield/tor/purgeStale
     * Remove Tor IPs not seen in recent days.
     *
     * POST param: days (default 7)
     */
    public function purgeStaleAction()
    {
        if (!$this->request->isPost()) {
            return ['result' => 'failed', 'message' => 'POST required'];
        }

        $days = max(1, (int)$this->request->getPost('days', 'int', 7));

        $backend = new Backend();
        $raw = $backend->configdRun('netshield manage_tor purge-stale ' . $days);
        return json_decode($raw, true) ?: ['result' => trim($raw) ?: 'ok'];
    }
}
