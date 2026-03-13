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
 * Class PoliciesController
 *
 * Runtime policy enforcement endpoints.
 * Policy CRUD is handled by SettingsController; this controller handles
 * the operational actions: applying policies to the live firewall and
 * querying current enforcement status.
 *
 * Endpoints:
 *   POST api/netshield/policies/apply   — compile and push all policies
 *   GET  api/netshield/policies/status  — current enforcement status
 *
 * @package OPNsense\NetShield\Api
 */
class PoliciesController extends ApiControllerBase
{
    /**
     * Apply / enforce all enabled policies.
     *
     * Instructs the NetShield daemon (via configd) to re-read the current
     * policy configuration, compile the ruleset, and push it to pf/ipfw.
     * This is separate from a full service reconfigure — it only reloads
     * the policy enforcement layer without restarting other subsystems.
     *
     * @return array Result with 'status' key: 'ok' or 'error'
     */
    public function applyAction()
    {
        if ($this->request->isPost()) {
            $backend     = new Backend();
            $rawResponse = trim($backend->configdRun('netshield activate_enforcement'));

            if (empty($rawResponse)) {
                return ['status' => 'error', 'message' => 'No response from daemon'];
            }

            $data = json_decode($rawResponse, true);
            if (json_last_error() !== JSON_ERROR_NONE) {
                return ['status' => 'error', 'message' => 'Invalid daemon response'];
            }

            return $data;
        }

        $this->response->setStatusCode(405);
        return ['status' => 'error', 'message' => 'Method Not Allowed'];
    }

    /**
     * Retrieve current policy enforcement status.
     *
     * Returns the number of active rules, last-applied timestamp, any
     * policies that failed to compile, and a per-policy summary so the
     * UI can display which policies are currently in effect.
     *
     * @return array JSON-serialisable enforcement status
     */
    public function statusAction()
    {
        if ($this->request->isGet()) {
            $backend     = new Backend();
            $rawResponse = trim($backend->configdRun('netshield enforcement_status'));

            if (empty($rawResponse)) {
                return ['status' => 'error', 'message' => 'No response from daemon'];
            }

            $data = json_decode($rawResponse, true);
            if (json_last_error() !== JSON_ERROR_NONE) {
                return ['status' => 'error', 'message' => 'Invalid daemon response'];
            }

            return $data;
        }

        $this->response->setStatusCode(405);
        return ['status' => 'error', 'message' => 'Method Not Allowed'];
    }
}
