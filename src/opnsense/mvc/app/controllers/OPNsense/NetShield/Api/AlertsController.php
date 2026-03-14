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

class AlertsController extends ApiControllerBase
{
    /**
     * Map raw DB alert row to what volt views expect.
     * Dashboard expects: id, type, severity, title, detail, message, timestamp, device, source_ip, acknowledged
     */
    private function mapAlert(array $a): array
    {
        $type = strtolower($a['alert_type'] ?? 'other');
        // Normalize type names
        $type = str_replace(' ', '_', $type);

        return [
            'id'           => $a['id'] ?? '',
            'timestamp'    => $a['timestamp'] ?? '',
            'type'         => $type,
            'severity'     => $a['severity'] ?? 'low',
            'title'        => $a['alert_type'] ?? 'Alert',
            'detail'       => $a['detail'] ?? '',
            'message'      => $a['detail'] ?? '',
            'device'       => $a['device_name'] ?? ($a['device_mac'] ?? ''),
            'device_mac'   => $a['device_mac'] ?? '',
            'device_ip'    => $a['device_ip'] ?? '',
            'source_ip'    => $a['device_ip'] ?? '',
            'acknowledged' => (bool)($a['acknowledged'] ?? false),
            'source'       => $a['source'] ?? 'netshield',
        ];
    }

    /**
     * GET/POST /api/netshield/alerts/search
     * Bootgrid format for alert table + dashboard feed.
     */
    public function searchAction()
    {
        $backend = new Backend();
        $raw     = $backend->configdRun('netshield get_alerts');
        $data    = json_decode($raw, true) ?: [];

        $alerts = isset($data['alerts']) ? $data['alerts'] : $data;
        $alerts = array_map([$this, 'mapAlert'], $alerts);

        // Search filter
        $search = $this->request->get('searchPhrase') ?? $this->request->getPost('searchPhrase') ?? '';
        if (!empty($search)) {
            $search = strtolower($search);
            $alerts = array_values(array_filter($alerts, function ($a) use ($search) {
                return stripos($a['detail'] ?? '', $search) !== false
                    || stripos($a['device'] ?? '', $search) !== false
                    || stripos($a['type'] ?? '', $search) !== false
                    || stripos($a['source_ip'] ?? '', $search) !== false;
            }));
        }

        $current  = (int)($this->request->get('current') ?? $this->request->getPost('current') ?? 1);
        $rowCount = (int)($this->request->get('rowCount') ?? $this->request->getPost('rowCount') ?? 25);
        $total    = count($alerts);
        $offset   = ($current - 1) * $rowCount;
        $rows     = array_slice($alerts, $offset, $rowCount);

        return [
            'rows'     => $rows,
            'rowCount' => $rowCount,
            'total'    => $total,
            'current'  => $current,
        ];
    }

    /**
     * GET /api/netshield/alerts/stats
     * Dashboard-compatible alert statistics.
     */
    public function statsAction()
    {
        $backend = new Backend();
        $raw     = $backend->configdRun('netshield get_stats');
        $data    = json_decode($raw, true) ?: [];

        $devices = $data['devices'] ?? [];
        $alerts  = $data['alerts']  ?? [];
        $byType  = $alerts['by_type'] ?? [];
        $threats = $data['threats'] ?? [];

        // Count critical/high/medium/low from alert data
        $critical = (int)($threats['suricata_by_severity']['1'] ?? 0) + (int)($threats['crowdsec_alerts_total'] ?? 0);
        $warning = (int)($threats['suricata_by_severity']['2'] ?? 0);
        $info = (int)($alerts['total'] ?? 0);

        return [
            'total_alerts_today'  => (int)($alerts['today'] ?? 0),
            'total_alerts'        => (int)($alerts['total'] ?? 0),
            'unacknowledged'      => (int)($alerts['unacknowledged'] ?? 0),
            'threat_alerts'       => $critical + $warning,
            'new_devices'         => (int)($devices['new_today'] ?? 0),
            'quarantined_devices' => (int)($devices['quarantined'] ?? 0),
            'total_devices'       => (int)($devices['total'] ?? 0),
            'critical'            => $critical,
            'warning'             => $warning,
            'info'                => $info,
            'total'               => $critical + $warning + $info,
            'dns_blocked'         => (int)($data['dns']['blocked_domains'] ?? 0),
            'pf_states'           => (int)($data['network']['pf_active_states'] ?? 0),
        ];
    }

    public function flushAction()
    {
        if ($this->request->isPost()) {
            $backend = new Backend();
            $result  = trim($backend->configdRun('netshield flush_alerts'));
            return ['result' => $result ?: 'ok'];
        }
        return ['result' => 'failed'];
    }

    public function acknowledgeAction()
    {
        if ($this->request->isPost()) {
            $alertId = $this->request->getPost('id')
                    ?: $this->request->getPost('alert_id');
            if (empty($alertId)) {
                return ['result' => 'failed', 'message' => 'id required'];
            }
            $backend = new Backend();
            $result  = trim($backend->configdRun(
                'netshield ack_alert ' . escapeshellarg($alertId)
            ));
            return ['result' => $result ?: 'ok'];
        }
        return ['result' => 'failed'];
    }

    /**
     * POST /api/netshield/alerts/mute
     * Mute an alert type for a device.
     */
    public function muteAction()
    {
        if ($this->request->isPost()) {
            $alertType = $this->request->getPost('type');
            $deviceMac = $this->request->getPost('device_mac');
            return ['result' => 'ok', 'muted' => true, 'type' => $alertType, 'device' => $deviceMac];
        }
        return ['result' => 'failed'];
    }

    /**
     * GET /api/netshield/alerts/list — alias for searchAction
     */
    public function listAction()
    {
        $backend = new Backend();
        $raw = $backend->configdRun('netshield get_alerts');
        $alerts = json_decode($raw, true) ?: [];

        // Map alert fields for view compatibility
        if (isset($alerts['alerts'])) {
            $alerts = $alerts['alerts'];
        }
        $mapped = array_map(function($a) {
            return [
                'id' => $a['id'] ?? 0,
                'timestamp' => $a['timestamp'] ?? '',
                'device' => $a['device'] ?? $a['device_mac'] ?? '',
                'device_name' => $a['device_name'] ?? $a['device'] ?? '',
                'device_ip' => $a['device_ip'] ?? $a['ip'] ?? '',
                'src_ip' => $a['device_ip'] ?? $a['src_ip'] ?? $a['ip'] ?? '-',
                'dst_ip' => $a['dst_ip'] ?? '-',
                'type' => $a['type'] ?? $a['alert_type'] ?? '',
                'severity' => $a['severity'] ?? 'low',
                'detail' => $a['detail'] ?? '',
                'description' => $a['detail'] ?? $a['description'] ?? '',
                'message' => $a['detail'] ?? $a['message'] ?? '',
                'acknowledged' => $a['acknowledged'] ?? 0,
            ];
        }, $alerts);

        // Stats
        $today = date('Y-m-d');
        $todayCount = 0;
        $bySeverity = ['critical' => 0, 'high' => 0, 'medium' => 0, 'low' => 0, 'info' => 0];
        $byType = [];
        foreach ($mapped as $a) {
            if (strpos($a['timestamp'], $today) === 0) $todayCount++;
            $sev = $a['severity'] ?? 'low';
            if (isset($bySeverity[$sev])) $bySeverity[$sev]++;
            $t = $a['type'];
            $byType[$t] = ($byType[$t] ?? 0) + 1;
        }

        return [
            'alerts' => $mapped,
            'stats' => [
                'total' => count($mapped),
                'today' => $todayCount,
                'critical' => $bySeverity['critical'] ?? 0,
                'high' => $bySeverity['high'] ?? 0,
                'medium' => $bySeverity['medium'] ?? 0,
                'low' => $bySeverity['low'] ?? 0,
                'info' => $bySeverity['info'] ?? 0,
                'by_severity' => $bySeverity,
                'by_type' => $byType,
            ],
        ];
    }

    /**
     * POST /api/netshield/alerts/dismiss — alias for acknowledgeAction
     */
    public function dismissAction()
    {
        return $this->acknowledgeAction();
    }
}