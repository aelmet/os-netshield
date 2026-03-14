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

class ThreatintelController extends JwtAwareController
{
    private function encParam(string $val): string
    {
        return rawurlencode($val);
    }

    /**
     * GET /api/netshield/threatintel/feeds
     * List all configured threat feeds with their status.
     */
    public function feedsAction()
    {
        $backend = new Backend();
        $raw = $backend->configdRun('netshield update_feeds list');
        $data = json_decode($raw, true) ?: [];
        return $data;
    }

    /**
     * POST /api/netshield/threatintel/updateFeeds
     * Trigger an immediate download of all enabled feeds.
     */
    public function updateFeedsAction()
    {
        if ($this->request->isPost()) {
            $backend = new Backend();
            $raw = $backend->configdRun('netshield update_feeds update-all');
            $data = json_decode($raw, true) ?: [];
            return $data;
        }
        return ['status' => 'error', 'message' => 'POST required'];
    }

    /**
     * POST /api/netshield/threatintel/toggleFeed
     * Enable or disable a named feed.
     * POST params: name (string), enabled (1|0)
     */
    public function toggleFeedAction()
    {
        if ($this->request->isPost()) {
            $name    = $this->request->getPost('name');
            $enabled = $this->request->getPost('enabled');

            if (empty($name)) {
                return ['status' => 'error', 'message' => 'Feed name required'];
            }

            $flag    = ($enabled == '1' || $enabled === 'true') ? 'enable' : 'disable';
            $backend = new Backend();
            $raw     = $backend->configdRun(
                'netshield update_feeds ' . $flag . ',' . $this->encParam($name)
            );
            return json_decode($raw, true) ?: ['status' => 'error'];
        }
        return ['status' => 'error', 'message' => 'POST required'];
    }

    /**
     * GET /api/netshield/threatintel/checkIp?ip=x.x.x.x
     * Check a single IP against loaded IoCs.
     */
    public function checkIpAction()
    {
        $ip = $this->request->get('ip');
        if (empty($ip)) {
            return ['status' => 'error', 'message' => 'ip parameter required'];
        }
        $backend = new Backend();
        $raw = $backend->configdRun(
            'netshield update_feeds check-ip,' . $this->encParam($ip)
        );
        return json_decode($raw, true) ?: ['status' => 'error'];
    }

    /**
     * GET /api/netshield/threatintel/stats
     * Aggregate threat intelligence statistics.
     */
    public function statsAction()
    {
        $backend = new Backend();
        $raw = $backend->configdRun('netshield update_feeds stats');
        return json_decode($raw, true) ?: [];
    }

    /**
     * GET /api/netshield/threatintel/detections
     * Paginated list of behavioral IDS detections (bootgrid compatible).
     */
    public function detectionsAction()
    {
        $backend  = new Backend();
        $raw      = $backend->configdRun('netshield get_alerts');
        $all      = json_decode($raw, true) ?: [];

        // Filter to behavioral IDS detections only
        $detections = array_values(array_filter($all, function ($a) {
            return isset($a['detection_type']);
        }));

        $current  = (int)($this->request->get('current') ?? 1);
        $rowCount = (int)($this->request->get('rowCount') ?? 20);
        $total    = count($detections);
        $offset   = ($current - 1) * $rowCount;
        $rows     = array_slice($detections, $offset, $rowCount);

        return [
            'rows'     => $rows,
            'rowCount' => $rowCount,
            'total'    => $total,
            'current'  => $current,
        ];
    }

    /**
     * GET /api/netshield/threatintel/list
     * List all threat intelligence feeds.
     */
    public function listAction()
    {
        $backend = new Backend();
        $raw = $backend->configdRun('netshield update_feeds list');
        return json_decode($raw, true) ?: ['feeds' => []];
    }

}
