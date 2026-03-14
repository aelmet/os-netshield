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

class ParentalController extends JwtAwareController
{
    /**
     * GET /api/netshield/parental/search
     * Returns a paginated bootgrid-compatible list of parental profiles.
     */
    public function searchAction()
    {
        $backend = new Backend();
        $raw     = $backend->configdRun('netshield manage_parental list');
        $data    = json_decode($raw, true) ?: [];

        $profiles = $data['profiles'] ?? $data ?? [];
        $current  = (int)($this->request->get('current') ?? 1);
        $rowCount = (int)($this->request->get('rowCount') ?? 20);

        if ($current < 1) {
            $current = 1;
        }
        if ($rowCount < 1 || $rowCount > 500) {
            $rowCount = 20;
        }

        $total  = count($profiles);
        $offset = ($current - 1) * $rowCount;
        $rows   = array_slice($profiles, $offset, $rowCount);

        return [
            'rows'     => $rows,
            'rowCount' => $rowCount,
            'total'    => $total,
            'current'  => $current,
        ];
    }

    /**
     * POST /api/netshield/parental/add
     * Create a new parental profile.
     *
     * POST params: name, time_limit, bedtime_start, bedtime_end,
     *              blocked_categories, allowed_categories, enabled
     */
    public function addAction()
    {
        if (!$this->request->isPost()) {
            return ['result' => 'failed', 'message' => 'POST required'];
        }

        $name       = $this->request->getPost('name');
        $timeLimit  = $this->request->getPost('time_limit', 'int', 0);
        $btStart    = $this->request->getPost('bedtime_start', 'string', '');
        $btEnd      = $this->request->getPost('bedtime_end', 'string', '');
        $blockedCat = $this->request->getPost('blocked_categories', 'string', '');
        $allowedCat = $this->request->getPost('allowed_categories', 'string', '');
        $enabled    = $this->request->getPost('enabled', 'string', '1');

        if (empty($name)) {
            return ['result' => 'failed', 'message' => 'name is required'];
        }

        $backend = new Backend();
        // Positional: add <name> [time_limit] [bedtime_start] [bedtime_end] [blocked_cat] [allowed_cat] [enabled]
        $cmd = 'netshield manage_parental add,'
            . escapeshellarg($name)
            . ',' . (int)$timeLimit
            . ',' . escapeshellarg($btStart ?: '')
            . ',' . escapeshellarg($btEnd ?: '')
            . ',' . escapeshellarg($blockedCat ?: '')
            . ',' . escapeshellarg($allowedCat ?: '')
            . ',' . escapeshellarg($enabled);

        $raw    = $backend->configdRun($cmd);
        $result = json_decode($raw, true) ?: ['result' => trim($raw) ?: 'ok'];
        return $result;
    }

    /**
     * POST /api/netshield/parental/update
     * Update an existing parental profile.
     *
     * POST params: id, [name, time_limit, bedtime_start, bedtime_end,
     *              blocked_categories, allowed_categories, enabled]
     */
    public function updateAction()
    {
        if (!$this->request->isPost()) {
            return ['result' => 'failed', 'message' => 'POST required'];
        }

        $id = $this->request->getPost('id');
        if (empty($id)) {
            return ['result' => 'failed', 'message' => 'id is required'];
        }

        $name       = $this->request->getPost('name', 'string', '');
        $timeLimit  = $this->request->getPost('time_limit', 'string', null);
        $btStart    = $this->request->getPost('bedtime_start', 'string', null);
        $btEnd      = $this->request->getPost('bedtime_end', 'string', null);
        $blockedCat = $this->request->getPost('blocked_categories', 'string', null);
        $allowedCat = $this->request->getPost('allowed_categories', 'string', null);
        $enabled    = $this->request->getPost('enabled', 'string', null);

        $backend = new Backend();
        // Positional: update <id> [name] [time_limit] [bedtime_start] [bedtime_end] [blocked_cat] [allowed_cat] [enabled]
        $cmd = 'netshield manage_parental update,'
            . (int)$id
            . ',' . escapeshellarg($name ?: '')
            . ',' . escapeshellarg($timeLimit !== null ? (string)(int)$timeLimit : '')
            . ',' . escapeshellarg($btStart ?: '')
            . ',' . escapeshellarg($btEnd ?: '')
            . ',' . escapeshellarg($blockedCat ?: '')
            . ',' . escapeshellarg($allowedCat ?: '')
            . ',' . escapeshellarg($enabled ?: '');

        $raw    = $backend->configdRun($cmd);
        $result = json_decode($raw, true) ?: ['result' => trim($raw) ?: 'ok'];
        return $result;
    }

    /**
     * POST /api/netshield/parental/delete
     * Delete a parental profile by ID.
     *
     * POST param: id
     */
    public function deleteAction()
    {
        if (!$this->request->isPost()) {
            return ['result' => 'failed', 'message' => 'POST required'];
        }

        $id = $this->request->getPost('id');
        if (empty($id)) {
            return ['result' => 'failed', 'message' => 'id is required'];
        }

        $backend = new Backend();
        $raw     = $backend->configdRun('netshield manage_parental delete,' . (int)$id);
        $result  = json_decode($raw, true) ?: ['result' => trim($raw) ?: 'ok'];
        return $result;
    }

    /**
     * POST /api/netshield/parental/assignDevice
     * Assign a device MAC to a profile.
     *
     * POST params: id (profile_id), mac
     */
    public function assignDeviceAction()
    {
        if (!$this->request->isPost()) {
            return ['result' => 'failed', 'message' => 'POST required'];
        }

        $id  = $this->request->getPost('id');
        $mac = $this->request->getPost('mac');

        if (empty($id) || empty($mac)) {
            return ['result' => 'failed', 'message' => 'id and mac are required'];
        }

        $backend = new Backend();
        $cmd     = 'netshield manage_parental assign-device,'
            . (int)$id
            . ',' . escapeshellarg($mac);

        $raw    = $backend->configdRun($cmd);
        $result = json_decode($raw, true) ?: ['result' => trim($raw) ?: 'ok'];
        return $result;
    }

    /**
     * POST /api/netshield/parental/unassignDevice
     * Remove a device from its assigned profile.
     *
     * POST param: mac
     */
    public function unassignDeviceAction()
    {
        if (!$this->request->isPost()) {
            return ['result' => 'failed', 'message' => 'POST required'];
        }

        $mac = $this->request->getPost('mac');
        if (empty($mac)) {
            return ['result' => 'failed', 'message' => 'mac is required'];
        }

        $backend = new Backend();
        $cmd     = 'netshield manage_parental unassign-device,' . escapeshellarg($mac);
        $raw     = $backend->configdRun($cmd);
        $result  = json_decode($raw, true) ?: ['result' => trim($raw) ?: 'ok'];
        return $result;
    }

    /**
     * GET /api/netshield/parental/usage
     * Returns daily usage data for a profile.
     *
     * GET params: id, days (default 7)
     */
    public function usageAction()
    {
        $id   = (int)$this->request->get('id', 'int', 0);
        $days = (int)$this->request->get('days', 'int', 7);

        if ($id < 1) {
            return ['result' => 'failed', 'message' => 'id is required'];
        }
        if ($days < 1 || $days > 365) {
            $days = 7;
        }

        $backend = new Backend();
        $cmd     = 'netshield manage_parental usage,' . $id . ',' . $days;
        $raw     = $backend->configdRun($cmd);
        $data    = json_decode($raw, true) ?: ['usage' => []];
        return $data;
    }
}
