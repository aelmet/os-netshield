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

class ServiceController extends JwtAwareController
{
    public function startAction()
    {
        if ($this->request->isPost()) {
            $backend = new Backend();
            $result = trim($backend->configdRun('netshield start'));
            return ['result' => $result ?: 'ok'];
        }
        return ['result' => 'failed'];
    }

    public function stopAction()
    {
        if ($this->request->isPost()) {
            $backend = new Backend();
            $result = trim($backend->configdRun('netshield stop'));
            return ['result' => $result ?: 'ok'];
        }
        return ['result' => 'failed'];
    }

    public function restartAction()
    {
        if ($this->request->isPost()) {
            $backend = new Backend();
            $result = trim($backend->configdRun('netshield restart'));
            return ['result' => $result ?: 'ok'];
        }
        return ['result' => 'failed'];
    }

    /**
     * GET /api/netshield/service/status
     * Returns { "status": "running"|"stopped" }
     */
    public function statusAction()
    {
        $backend = new Backend();
        $result = trim($backend->configdRun('netshield status'));
        // Normalise to "running" or "stopped"
        $status = (stripos($result, 'running') !== false) ? 'running' : 'stopped';
        return ['status' => $status, 'result' => $result ?: 'stopped'];
    }

    /**
     * POST /api/netshield/service/reconfigure
     * Reloads the config template and restarts the daemon.
     */
    public function reconfigureAction()
    {
        if ($this->request->isPost()) {
            $backend = new Backend();
            $backend->configdRun('template reload OPNsense/NetShield');
            $result = trim($backend->configdRun('netshield restart'));
            return ['result' => $result ?: 'ok'];
        }
        return ['result' => 'failed'];
    }
}
