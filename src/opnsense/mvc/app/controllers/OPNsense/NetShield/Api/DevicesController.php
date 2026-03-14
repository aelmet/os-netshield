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

namespace OPNsense\Netshield\Api;

use OPNsense\Base\ApiControllerBase;
use OPNsense\Core\Backend;

class DevicesController extends ApiControllerBase
{
    /**
     * Helper: fetch all devices from backend and normalize fields.
     */
    private function fetchDevices(): array
    {
        $backend = new Backend();
        $raw = $backend->configdRun('netshield get_devices');
        $devices = json_decode($raw, true) ?: [];

        foreach ($devices as &$device) {
            // Add status field
            if (!empty($device['is_quarantined'])) {
                $device['status'] = 'quarantined';
            } elseif (!empty($device['is_approved'])) {
                $device['status'] = 'approved';
            } else {
                $device['status'] = 'new';
            }
            // Normalize field names for volt views
            if (!isset($device['name'])) {
                $device['name'] = $device['hostname'] ?? $device['device_name'] ?? '';
            }
        }
        unset($device);

        return $devices;
    }

    /**
     * POST /api/netshield/devices/search
     * Bootgrid-compatible search with pagination and filtering.
     */
    public function searchAction()
    {
        $devices = $this->fetchDevices();

        // Filter by status if provided
        $statusFilter = $this->request->get('status') ?? $this->request->getPost('status');
        if ($statusFilter && $statusFilter !== 'all') {
            $devices = array_values(array_filter($devices, function ($d) use ($statusFilter) {
                return ($d['status'] ?? '') === $statusFilter;
            }));
        }

        // Search filter
        $search = $this->request->get('searchPhrase') ?? $this->request->getPost('searchPhrase') ?? '';
        if (!empty($search)) {
            $search = strtolower($search);
            $devices = array_values(array_filter($devices, function ($d) use ($search) {
                return stripos($d['mac'] ?? '', $search) !== false
                    || stripos($d['ip'] ?? '', $search) !== false
                    || stripos($d['hostname'] ?? '', $search) !== false
                    || stripos($d['vendor'] ?? '', $search) !== false
                    || stripos($d['name'] ?? '', $search) !== false;
            }));
        }

        $current  = (int)($this->request->get('current') ?? $this->request->getPost('current') ?? 1);
        $rowCount = (int)($this->request->get('rowCount') ?? $this->request->getPost('rowCount') ?? 25);
        $total    = count($devices);
        $offset   = ($current - 1) * $rowCount;
        $rows     = array_slice($devices, $offset, $rowCount);

        return [
            'rows'     => $rows,
            'rowCount' => $rowCount,
            'total'    => $total,
            'current'  => $current,
        ];
    }

    /**
     * GET /api/netshield/devices/list
     * Returns device list for dashboard (non-bootgrid format).
     * Dashboard expects: {devices: [{mac, name, hostname, ip, type, online, quarantined, bytes_up, bytes_down}]}
     */
    public function listAction()
    {
        $devices = $this->fetchDevices();

        // Enrich with bandwidth data if available
        $backend = new Backend();
        $bwRaw = $backend->configdRun('netshield get_bandwidth current');
        $bwData = json_decode($bwRaw, true) ?: [];
        $bwByMac = [];
        foreach (($bwData['devices'] ?? []) as $d) {
            $mac = $d['device_mac'] ?? '';
            if ($mac) {
                $bwByMac[$mac] = $d;
            }
        }

        $result = [];
        foreach ($devices as $d) {
            $mac = $d['mac'] ?? '';
            $bw = $bwByMac[$mac] ?? [];
            $result[] = [
                'mac' => $mac,
                'name' => $d['name'] ?? $d['hostname'] ?? '',
                'hostname' => $d['hostname'] ?? '',
                'ip' => $d['ip'] ?? '',
                'type' => $d['device_type'] ?? $d['type'] ?? 'unknown',
                'device_type' => $d['device_type'] ?? $d['type'] ?? 'unknown',
                'online' => !empty($bw),
                'quarantined' => !empty($d['is_quarantined']),
                'status' => $d['status'] ?? 'new',
                'bytes_up' => (int)($bw['bytes_out'] ?? 0),
                'bytes_down' => (int)($bw['bytes_in'] ?? 0),
            ];
        }

        return ['devices' => $result];
    }

    public function quarantineAction()
    {
        if ($this->request->isPost()) {
            $uuid = $this->request->getPost('uuid') ?? $this->request->getPost('mac');
            if (empty($uuid)) {
                return ['result' => 'failed', 'message' => 'uuid/mac required'];
            }
            $backend = new Backend();
            $result = trim($backend->configdRun('netshield quarantine_device ' . escapeshellarg($uuid)));
            return ['result' => $result ?: 'ok'];
        }
        return ['result' => 'failed'];
    }

    public function unquarantineAction()
    {
        if ($this->request->isPost()) {
            $uuid = $this->request->getPost('uuid') ?? $this->request->getPost('mac');
            if (empty($uuid)) {
                return ['result' => 'failed', 'message' => 'uuid/mac required'];
            }
            $backend = new Backend();
            $result = trim($backend->configdRun('netshield unquarantine_device ' . escapeshellarg($uuid)));
            return ['result' => $result ?: 'ok'];
        }
        return ['result' => 'failed'];
    }

    public function approveNewAction()
    {
        if ($this->request->isPost()) {
            $uuid = $this->request->getPost('uuid') ?? $this->request->getPost('mac');
            if (empty($uuid)) {
                return ['result' => 'failed', 'message' => 'uuid/mac required'];
            }
            $backend = new Backend();
            $result = trim($backend->configdRun('netshield approve_device ' . escapeshellarg($uuid)));
            return ['result' => $result ?: 'ok'];
        }
        return ['result' => 'failed'];
    }
}
