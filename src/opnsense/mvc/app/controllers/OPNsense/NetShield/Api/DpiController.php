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

class DpiController extends JwtAwareController
{
    /**
     * GET /api/netshield/dpi/topApps
     * Returns top applications by traffic from DPI statistics.
     */
    public function topAppsAction()
    {
        $backend = new Backend();
        $raw = $backend->configdRun('netshield get_dpi_stats summary');
        $data = json_decode($raw, true) ?: [];

        $apps = $data['top_apps'] ?? $data['apps'] ?? [];

        usort($apps, function ($a, $b) {
            return ($b['bytes'] ?? 0) <=> ($a['bytes'] ?? 0);
        });

        return ['apps' => $apps, 'total' => count($apps)];
    }

    /**
     * GET /api/netshield/dpi/appList
     * Returns a deduplicated list of all recognised application names.
     */
    public function appListAction()
    {
        $backend = new Backend();
        $raw = $backend->configdRun('netshield get_dpi_stats summary');
        $data = json_decode($raw, true) ?: [];

        $apps = $data['apps'] ?? $data['top_apps'] ?? [];
        $list = array_values(array_unique(array_column($apps, 'name')));
        sort($list);

        return ['apps' => $list, 'total' => count($list)];
    }

    /**
     * GET /api/netshield/dpi/deviceApps
     * Returns application breakdown for a specific device MAC address.
     *
     * Query param: device_mac
     */
    public function deviceAppsAction()
    {
        $mac = $this->request->get('device_mac');
        if (empty($mac)) {
            return ['result' => 'failed', 'message' => 'device_mac parameter required'];
        }

        $backend = new Backend();
        $raw = $backend->configdRun('netshield get_dpi_stats device,' . escapeshellarg($mac));
        $data = json_decode($raw, true) ?: [];

        return [
            'device_mac' => $mac,
            'apps'       => $data['apps'] ?? [],
            'total'      => count($data['apps'] ?? []),
        ];
    }

    /**
     * GET /api/netshield/dpi/flowHistory
     * Returns paginated flow history records.
     *
     * Query params: current (page), rowCount
     */
    public function flowHistoryAction()
    {
        $backend = new Backend();
        $raw = $backend->configdRun('netshield get_dpi_stats flows');
        $data = json_decode($raw, true) ?: [];

        $flows    = $data['flows'] ?? $data ?? [];
        $current  = (int)($this->request->get('current') ?? 1);
        $rowCount = (int)($this->request->get('rowCount') ?? 25);

        if ($current < 1) {
            $current = 1;
        }
        if ($rowCount < 1 || $rowCount > 500) {
            $rowCount = 25;
        }

        $total  = count($flows);
        $offset = ($current - 1) * $rowCount;
        $rows   = array_slice($flows, $offset, $rowCount);

        return [
            'rows'     => $rows,
            'rowCount' => $rowCount,
            'total'    => $total,
            'current'  => $current,
        ];
    }
}
