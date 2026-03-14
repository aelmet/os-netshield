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

class GeoipController extends JwtAwareController
{
    /**
     * GET /api/netshield/geoip/lookup?ip=x.x.x.x
     * Return country information for the given IP.
     */
    public function lookupAction()
    {
        $ip = $this->request->get('ip');
        if (empty($ip)) {
            return ['status' => 'error', 'message' => 'ip parameter required'];
        }
        $backend = new Backend();
        $raw = $backend->configdRun(
            'netshield manage_geoip lookup,' . escapeshellarg($ip)
        );
        return json_decode($raw, true) ?: ['status' => 'error'];
    }

    /**
     * GET /api/netshield/geoip/rules
     * Paginated list of country rules (bootgrid compatible).
     */
    public function rulesAction()
    {
        $backend = new Backend();
        $raw     = $backend->configdRun('netshield manage_geoip list-rules');
        $data    = json_decode($raw, true) ?: [];
        $rules   = $data['rules'] ?? [];

        $current  = (int)($this->request->get('current') ?? 1);
        $rowCount = (int)($this->request->get('rowCount') ?? 20);
        $total    = count($rules);
        $offset   = ($current - 1) * $rowCount;
        $rows     = array_slice($rules, $offset, $rowCount);

        return [
            'rows'     => $rows,
            'rowCount' => $rowCount,
            'total'    => $total,
            'current'  => $current,
        ];
    }

    /**
     * POST /api/netshield/geoip/addRule
     * Add or update a country rule.
     * POST params: country (ISO 3166-1 alpha-2), action (allow|block|log)
     */
    public function addRuleAction()
    {
        if ($this->request->isPost()) {
            $country = strtoupper(trim($this->request->getPost('country') ?? ''));
            $action  = $this->request->getPost('action');

            if (empty($country) || strlen($country) !== 2) {
                return ['status' => 'error', 'message' => 'Valid 2-letter country code required'];
            }
            if (!in_array($action, ['allow', 'block', 'log'])) {
                return ['status' => 'error', 'message' => 'action must be allow, block, or log'];
            }

            $backend = new Backend();
            $raw = $backend->configdRun(
                'netshield manage_geoip add-rule,' . escapeshellarg($country)
                . ',' . escapeshellarg($action)
            );
            return json_decode($raw, true) ?: ['status' => 'error'];
        }
        return ['status' => 'error', 'message' => 'POST required'];
    }

    /**
     * POST /api/netshield/geoip/removeRule
     * Remove a country rule.
     * POST params: country (ISO 3166-1 alpha-2)
     */
    public function removeRuleAction()
    {
        if ($this->request->isPost()) {
            $country = strtoupper(trim($this->request->getPost('country') ?? ''));
            if (empty($country)) {
                return ['status' => 'error', 'message' => 'country required'];
            }
            $backend = new Backend();
            $raw = $backend->configdRun(
                'netshield manage_geoip remove-rule,' . escapeshellarg($country)
            );
            return json_decode($raw, true) ?: ['status' => 'error'];
        }
        return ['status' => 'error', 'message' => 'POST required'];
    }

    /**
     * GET /api/netshield/geoip/stats
     * GeoIP connection statistics.
     */
    public function statsAction()
    {
        $backend = new Backend();
        $raw = $backend->configdRun('netshield manage_geoip stats');
        return json_decode($raw, true) ?: [];
    }

    /**
     * POST /api/netshield/geoip/apply
     * Generate and apply pf country block rules.
     */
    public function applyAction()
    {
        if ($this->request->isPost()) {
            $backend = new Backend();
            $raw = $backend->configdRun('netshield manage_geoip apply');
            return json_decode($raw, true) ?: ['status' => 'error'];
        }
        return ['status' => 'error', 'message' => 'POST required'];
    }
}
