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

class BandwidthController extends ApiControllerBase
{
    /**
     * Helper: fetch and parse current bandwidth data from backend.
     */
    private function fetchCurrent(): array
    {
        $backend = new Backend();
        $raw = $backend->configdRun('netshield get_bandwidth current');
        return json_decode($raw, true) ?: [];
    }

    /**
     * Helper: aggregate device-level data into totals.
     */
    private function aggregateDevices(array $data): array
    {
        $devices = $data['devices'] ?? [];
        $totalIn = 0;
        $totalOut = 0;
        $totalRateIn = 0.0;
        $totalRateOut = 0.0;

        foreach ($devices as $d) {
            $totalIn += (int)($d['bytes_in'] ?? 0);
            $totalOut += (int)($d['bytes_out'] ?? 0);
            $totalRateIn += (float)($d['rate_in_kbps'] ?? 0);
            $totalRateOut += (float)($d['rate_out_kbps'] ?? 0);
        }

        return [
            'bytes_in' => $totalIn,
            'bytes_out' => $totalOut,
            'total_in' => $totalIn,
            'total_out' => $totalOut,
            'active_devices' => count($devices),
            'devices' => count($devices),
            'download_bps' => (int)($totalRateIn * 1024 / 8),
            'upload_bps' => (int)($totalRateOut * 1024 / 8),
            'download_rate_kbps' => round($totalRateIn, 2),
            'upload_rate_kbps' => round($totalRateOut, 2),
        ];
    }

    /**
     * GET /api/netshield/bandwidth/current
     * Returns aggregated current bandwidth summary.
     */
    public function currentAction()
    {
        $data = $this->fetchCurrent();
        $agg = $this->aggregateDevices($data);

        // Find top app across all devices
        $appBytes = [];
        foreach (($data['devices'] ?? []) as $d) {
            foreach (($d['top_apps'] ?? []) as $app) {
                $name = $app['app'] ?? $app['name'] ?? 'Unknown';
                $appBytes[$name] = ($appBytes[$name] ?? 0) + (int)($app['bytes'] ?? 0);
            }
        }
        arsort($appBytes);
        $topApp = $appBytes ? array_key_first($appBytes) : '';

        $agg['top_app'] = $topApp;
        return $agg;
    }

    /**
     * GET /api/netshield/bandwidth/realtime
     * Returns real-time bandwidth for live charts (download_bps, upload_bps).
     */
    public function realtimeAction()
    {
        $data = $this->fetchCurrent();
        $agg = $this->aggregateDevices($data);

        return [
            'download_bps' => $agg['download_bps'],
            'upload_bps' => $agg['upload_bps'],
            'download_rate_kbps' => $agg['download_rate_kbps'],
            'upload_rate_kbps' => $agg['upload_rate_kbps'],
            'timestamp' => date('Y-m-d H:i:s'),
        ];
    }

    /**
     * GET /api/netshield/bandwidth/history
     * Returns bandwidth history for the past N hours.
     */
    public function historyAction()
    {
        $hours = (int)($this->request->get('hours') ?? 24);
        if ($hours < 1 || $hours > 168) {
            $hours = 24;
        }

        $backend = new Backend();
        $raw = $backend->configdRun('netshield get_bandwidth history ' . (int)$hours);
        $data = json_decode($raw, true) ?: [];

        $history = $data['history'] ?? $data['data'] ?? [];
        return [
            'hours' => $hours,
            'history' => $history,
            'data' => $history,
        ];
    }

    /**
     * GET /api/netshield/bandwidth/topDevices
     * Returns devices sorted by total bandwidth.
     */
    public function topDevicesAction()
    {
        $hours = (int)($this->request->get('hours') ?? 24);
        $limit = (int)($this->request->get('limit') ?? 10);
        if ($hours < 1 || $hours > 168) {
            $hours = 24;
        }
        if ($limit < 1 || $limit > 100) {
            $limit = 10;
        }

        // Try dedicated backend command first
        $backend = new Backend();
        $cmd = 'netshield get_bandwidth top-devices ' . (int)$hours . ' ' . (int)$limit;
        $raw = $backend->configdRun($cmd);
        $data = json_decode($raw, true) ?: [];

        $devices = $data['devices'] ?? $data['rows'] ?? [];

        // If empty, fall back to current data sorted by bytes
        if (empty($devices)) {
            $current = $this->fetchCurrent();
            $rawDevices = $current['devices'] ?? [];
            usort($rawDevices, function ($a, $b) {
                return (($b['bytes_total'] ?? 0) <=> ($a['bytes_total'] ?? 0));
            });
            $devices = [];
            foreach (array_slice($rawDevices, 0, $limit) as $d) {
                $devices[] = [
                    'device' => $d['device_ip'] ?? '',
                    'hostname' => $d['hostname'] ?? $d['device_name'] ?? '',
                    'ip' => $d['device_ip'] ?? '',
                    'mac' => $d['device_mac'] ?? '',
                    'bytes_in' => (int)($d['bytes_in'] ?? 0),
                    'bytes_out' => (int)($d['bytes_out'] ?? 0),
                    'bytes_total' => (int)($d['bytes_total'] ?? 0),
                    'last_updated' => date('Y-m-d H:i:s'),
                ];
            }
        }

        return [
            'devices' => $devices,
            'rows' => $devices,
            'hours' => $hours,
            'limit' => $limit,
        ];
    }

    /**
     * GET /api/netshield/bandwidth/byApp
     * Returns bandwidth breakdown by application.
     */
    public function byAppAction()
    {
        $hours = (int)($this->request->get('hours') ?? 24);
        $limit = (int)($this->request->get('limit') ?? 10);
        if ($hours < 1 || $hours > 168) {
            $hours = 24;
        }
        if ($limit < 1 || $limit > 100) {
            $limit = 10;
        }

        $backend = new Backend();
        $cmd = 'netshield get_bandwidth by-app ' . (int)$hours . ' ' . (int)$limit;
        $raw = $backend->configdRun($cmd);
        $data = json_decode($raw, true) ?: [];

        $apps = $data['apps'] ?? $data['rows'] ?? [];
        if (empty($apps)) {
            // Fallback: aggregate from current device stats
            $current = $this->fetchCurrent();
            $appBytes = [];
            foreach (($current['devices'] ?? []) as $d) {
                foreach (($d['top_apps'] ?? []) as $app) {
                    $name = $app['app'] ?? $app['name'] ?? 'Unknown';
                    $appBytes[$name] = ($appBytes[$name] ?? 0) + (int)($app['bytes'] ?? 0);
                }
            }
            arsort($appBytes);
            $apps = [];
            $i = 0;
            foreach ($appBytes as $name => $bytes) {
                if ($i >= $limit) {
                    break;
                }
                $apps[] = ['name' => $name, 'bytes' => $bytes, 'connections' => 0];
                $i++;
            }
        }

        return [
            'apps' => $apps,
            'rows' => $apps,
            'hours' => $hours,
            'limit' => $limit,
        ];
    }

    /**
     * GET /api/netshield/bandwidth/summary
     * Quick summary for dashboard widget.
     */
    public function summaryAction()
    {
        return $this->currentAction();
    }

    /**
     * GET /api/netshield/bandwidth/device
     * Returns bandwidth data for a specific device.
     */
    public function deviceAction()
    {
        $mac = $this->request->get('mac');
        if (empty($mac)) {
            return ['error' => 'mac parameter required'];
        }

        $backend = new Backend();
        $raw = $backend->configdRun('netshield get_bandwidth device ' . escapeshellarg($mac));
        $data = json_decode($raw, true);

        if ($data && !empty($data)) {
            return array_merge(['mac' => $mac], $data);
        }

        // Fallback: extract from current data
        $current = $this->fetchCurrent();
        foreach (($current['devices'] ?? []) as $d) {
            if (($d['device_mac'] ?? '') === $mac) {
                return [
                    'mac' => $mac,
                    'bytes_down' => (int)($d['bytes_in'] ?? 0),
                    'bytes_up' => (int)($d['bytes_out'] ?? 0),
                    'download_today' => (int)($d['bytes_in'] ?? 0),
                    'upload_today' => (int)($d['bytes_out'] ?? 0),
                ];
            }
        }

        return ['mac' => $mac, 'bytes_down' => 0, 'bytes_up' => 0, 'download_today' => 0, 'upload_today' => 0];
    }
}
