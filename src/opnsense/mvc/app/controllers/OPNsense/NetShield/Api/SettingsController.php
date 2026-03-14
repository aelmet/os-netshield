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
use OPNsense\Core\Config;
use OPNsense\NetShield\NetShield;

class SettingsController extends ApiControllerBase
{
    /**
     * GET /api/netshield/settings/getSettings
     * Returns settings in format compatible with mapDataToFormUI.
     */
    public function getSettingsAction()
    {
        try {
            $mdl = new NetShield();
            $nodes = $mdl->general->getNodes();
            return ['netshield' => ['general' => $nodes]];
        } catch (\Exception $e) {
            // Fallback: read from config.xml directly
            $config = Config::getInstance()->object();
            $ns = $config->OPNsense->netshield ?? null;
            if ($ns && $ns->general) {
                $result = [];
                foreach ($ns->general->children() as $key => $val) {
                    $result[(string)$key] = (string)$val;
                }
                return ['netshield' => ['general' => $result]];
            }
            return ['netshield' => ['general' => []]];
        }
    }

    /**
     * POST /api/netshield/settings/setSettings
     * Saves settings from saveFormToEndpoint POST.
     */
    public function setSettingsAction()
    {
        if (!$this->request->isPost()) {
            return ['result' => 'failed', 'message' => 'POST required'];
        }

        $post = $this->request->getPost('netshield');
        if (!is_array($post)) {
            return ['result' => 'failed', 'message' => 'invalid payload'];
        }

        try {
            $mdl = new NetShield();
            $general = $post['general'] ?? $post;
            $mdl->general->setNodes($general);
            $validations = $mdl->validate();
            if (count($validations) > 0) {
                return ['result' => 'failed', 'validations' => $validations];
            }
            $mdl->serializeToConfig();
            Config::getInstance()->save();
            return ['result' => 'saved'];
        } catch (\Exception $e) {
            return ['result' => 'failed', 'message' => $e->getMessage()];
        }
    }

    /**
     * POST /api/netshield/settings/sendMobileSetup
     * Generate OTP and send mobile app setup info to Telegram.
     */
    public function sendMobileSetupAction()
    {
        if (!$this->request->isPost()) {
            return ['status' => 'error', 'message' => 'POST required'];
        }

        $backend = new Backend();
        $raw = trim($backend->configdRun('netshield mobile_send_setup_telegram'));
        $result = json_decode($raw, true);

        if ($result && ($result['status'] ?? '') === 'ok') {
            return [
                'status' => 'ok',
                'message' => $result['message'] ?? 'Setup info sent to Telegram'
            ];
        }

        return [
            'status' => 'error',
            'message' => $result['message'] ?? 'Failed to send setup info'
        ];
    }
}
