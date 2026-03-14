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

class SyslogController extends JwtAwareController
{
    /**
     * POST /api/netshield/syslog/test
     * Sends a test syslog message to the configured remote syslog/SIEM server.
     * Returns the result of the send attempt including target host/port/protocol.
     */
    public function testAction()
    {
        if (!$this->request->isPost()) {
            return ['result' => 'failed', 'message' => 'POST required'];
        }

        $backend = new Backend();
        $raw     = $backend->configdRun('netshield syslog_test test');
        $result  = json_decode($raw, true);

        if ($result === null) {
            return ['result' => 'error', 'message' => 'Invalid response from backend', 'raw' => trim($raw)];
        }

        return $result;
    }

    /**
     * GET /api/netshield/syslog/stats
     * Returns syslog export statistics: per-event-type counts, error count,
     * and timestamp of the last successful export.
     */
    public function statsAction()
    {
        $backend = new Backend();
        $raw     = $backend->configdRun('netshield syslog_test stats');
        $result  = json_decode($raw, true);

        if ($result === null) {
            return ['result' => 'error', 'message' => 'Invalid response from backend', 'raw' => trim($raw)];
        }

        return $result;
    }
}
