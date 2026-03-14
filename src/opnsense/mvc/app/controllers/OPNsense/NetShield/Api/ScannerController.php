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

use OPNsense\Core\Backend;

class ScannerController extends JwtAwareController
{
    private function encParam($v)
    {
        return rawurlencode((string)$v);
    }

    /**
     * POST — scan a single device by IP address.
     */
    public function scanDeviceAction()
    {
        if (!$this->request->isPost()) {
            return ['result' => 'failed', 'message' => 'POST required'];
        }

        $ip = trim($this->request->getPost('ip') ?? '');
        if (empty($ip) || !filter_var($ip, FILTER_VALIDATE_IP)) {
            return ['result' => 'failed', 'message' => 'Valid IP address required'];
        }

        $ports = trim($this->request->getPost('ports') ?? '');
        if (!empty($ports) && !preg_match('/^[0-9,\-]+$/', $ports)) {
            return ['result' => 'failed', 'message' => 'Invalid ports format'];
        }

        $portsArg = !empty($ports) ? $this->encParam($ports) : '1-1024';
        $backend = new Backend();
        $cmd = 'netshield run_scan target,' . $this->encParam($ip) . ',' . $portsArg;

        $raw = $backend->configdRun($cmd);
        $data = json_decode($raw, true);
        if (!is_array($data)) {
            return ['result' => 'failed', 'message' => 'Scanner service unavailable: ' . trim($raw ?: 'no response')];
        }
        return $data;
    }

    /**
     * POST — scan an entire subnet.
     */
    public function scanNetworkAction()
    {
        if (!$this->request->isPost()) {
            return ['result' => 'failed', 'message' => 'POST required'];
        }

        $subnet = trim($this->request->getPost('subnet') ?? '');
        if (empty($subnet) || !preg_match('/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d{1,2}$/', $subnet)) {
            return ['result' => 'failed', 'message' => 'Valid CIDR subnet required (e.g. 192.168.1.0/24)'];
        }

        $backend = new Backend();
        $cmd = 'netshield run_scan network,' . $this->encParam($subnet);
        $raw = $backend->configdRun($cmd);
        $data = json_decode($raw, true);
        if (!is_array($data)) {
            return ['result' => 'failed', 'message' => 'Scanner service unavailable'];
        }
        return $data;
    }

    /**
     * GET — return recent scan results, paginated for bootgrid.
     *
     * Query params: current (page), rowCount (per page), limit
     */
    public function resultsAction()
    {
        $limit  = (int)($this->request->get('limit') ?? 100);
        $current  = (int)($this->request->get('current') ?? 1);
        $rowCount = (int)($this->request->get('rowCount') ?? 20);

        $backend = new Backend();
        $cmd = 'netshield run_scan results,' . (int)$limit;
        $raw = $backend->configdRun($cmd);
        $all = json_decode($raw, true) ?: [];

        $total  = count($all);
        $offset = ($current - 1) * $rowCount;
        $rows   = array_slice($all, $offset, $rowCount);

        return [
            'rows'     => $rows,
            'rowCount' => $rowCount,
            'total'    => $total,
            'current'  => $current,
        ];
    }
}
