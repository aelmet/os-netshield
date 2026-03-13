<?php

/**
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (C) 2024-2026 NetShield Contributors
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

namespace OPNsense\NetShield\Api;

use OPNsense\Base\ApiControllerBase;
use OPNsense\Core\Backend;

/**
 * Class AlertsController
 *
 * Read-only and maintenance endpoints for NetShield alert data.
 * All data is retrieved from the running daemon via configd commands.
 *
 * Endpoints:
 *   GET  api/netshield/alerts/search    — paginated alert list
 *   GET  api/netshield/alerts/stats     — aggregate statistics
 *   GET  api/netshield/alerts/dashboard — dashboard summary data
 *   POST api/netshield/alerts/flush     — remove old / acknowledged alerts
 *
 * @package OPNsense\NetShield\Api
 */
class AlertsController extends ApiControllerBase
{
    /**
     * Search and retrieve alerts from the NetShield daemon.
     *
     * Query parameters (all optional):
     *   - rowCount   (int)    Rows per page, default 25, -1 for all
     *   - current    (int)    Page number, default 1
     *   - searchPhrase (str) Filter string applied to alert fields
     *   - sort       (array) Column sort order
     *
     * @return array JSON-serialisable alert result set
     */
    public function searchAction()
    {
        if ($this->request->isGet()) {
            $backend = new Backend();
            $rawResponse = trim($backend->configdRun('netshield get_alerts'));

            if (empty($rawResponse)) {
                return ['rows' => [], 'rowCount' => 0, 'total' => 0, 'current' => 1];
            }

            $data = json_decode($rawResponse, true);
            if (json_last_error() !== JSON_ERROR_NONE || !isset($data['rows'])) {
                return ['rows' => [], 'rowCount' => 0, 'total' => 0, 'current' => 1, 'error' => 'Invalid daemon response'];
            }

            return $data;
        }

        return $this->returnErrorStatus(405, 'Method Not Allowed');
    }

    /**
     * Retrieve aggregate alert statistics.
     *
     * Returns counts by severity, type, and time window suitable
     * for rendering charts and summary widgets on the dashboard.
     *
     * @return array JSON-serialisable statistics
     */
    public function statsAction()
    {
        if ($this->request->isGet()) {
            $backend = new Backend();
            $rawResponse = trim($backend->configdRun('netshield get_stats'));

            if (empty($rawResponse)) {
                return ['status' => 'error', 'message' => 'No response from daemon'];
            }

            $data = json_decode($rawResponse, true);
            if (json_last_error() !== JSON_ERROR_NONE) {
                return ['status' => 'error', 'message' => 'Invalid daemon response'];
            }

            return $data;
        }

        return $this->returnErrorStatus(405, 'Method Not Allowed');
    }

    /**
     * Retrieve dashboard summary data.
     *
     * Returns combined service status, recent alert counts, active device
     * counts, and policy enforcement summary for the main dashboard view.
     *
     * @return array JSON-serialisable dashboard payload
     */
    public function dashboardAction()
    {
        if ($this->request->isGet()) {
            $backend = new Backend();
            $rawResponse = trim($backend->configdRun('netshield get_dashboard'));

            if (empty($rawResponse)) {
                return ['status' => 'error', 'message' => 'No response from daemon'];
            }

            $data = json_decode($rawResponse, true);
            if (json_last_error() !== JSON_ERROR_NONE) {
                return ['status' => 'error', 'message' => 'Invalid daemon response'];
            }

            return $data;
        }

        return $this->returnErrorStatus(405, 'Method Not Allowed');
    }

    /**
     * Flush (delete) old or acknowledged alerts from the daemon store.
     *
     * POST body parameters (all optional):
     *   - older_than_days  (int) Purge alerts older than N days (default: 30)
     *   - severity         (str) Purge only alerts of this severity level
     *
     * @return array Result status
     */
    public function flushAction()
    {
        if ($this->request->isPost()) {
            $olderThanDays = (int)$this->request->getPost('older_than_days', 'int', 30);
            $severity      = $this->request->getPost('severity', 'string', '');

            $params = escapeshellarg((string)$olderThanDays);
            if (!empty($severity)) {
                $params .= ' ' . escapeshellarg($severity);
            }

            $backend = new Backend();
            $rawResponse = trim($backend->configdRun("netshield flush_alerts {$params}"));

            if (empty($rawResponse)) {
                return ['status' => 'error', 'message' => 'No response from daemon'];
            }

            $data = json_decode($rawResponse, true);
            if (json_last_error() !== JSON_ERROR_NONE) {
                return ['status' => 'error', 'message' => 'Invalid daemon response'];
            }

            return $data;
        }

        return $this->returnErrorStatus(405, 'Method Not Allowed');
    }

    /**
     * Helper: return a minimal error structure with HTTP status code.
     *
     * @param int    $statusCode HTTP status code
     * @param string $message    Human-readable message
     * @return array
     */
    private function returnErrorStatus(int $statusCode, string $message): array
    {
        $this->response->setStatusCode($statusCode);
        return ['status' => 'error', 'message' => $message];
    }
}
