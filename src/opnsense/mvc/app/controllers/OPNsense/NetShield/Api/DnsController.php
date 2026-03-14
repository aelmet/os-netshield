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

class DnsController extends ApiControllerBase
{
    public function blocklistsAction()
    {
        $backend = new Backend();
        $raw = $backend->configdRun('netshield manage_dns list-blocklists');
        $data = json_decode($raw, true) ?: [];

        // Ensure blocklists key exists
        if (!isset($data['blocklists'])) {
            $data = ['blocklists' => $data['blocklist_counts'] ?? []];
        }
        return $data;
    }

    public function updateBlocklistsAction()
    {
        if (!$this->request->isPost()) {
            return ['result' => 'failed', 'message' => 'POST required'];
        }
        $backend = new Backend();
        $raw = $backend->configdRun('netshield manage_dns update-blocklists');
        return json_decode($raw, true) ?: ['result' => 'ok'];
    }

    public function toggleBlocklistAction()
    {
        if (!$this->request->isPost()) {
            return ['result' => 'failed', 'message' => 'POST required'];
        }

        $name = $this->request->getPost('name');
        $enabled = $this->request->getPost('enabled', 'string', '1');

        if (empty($name)) {
            return ['result' => 'failed', 'message' => 'name is required'];
        }

        $flag = ($enabled === '0' || $enabled === 'false') ? 'disable-blocklist' : 'enable-blocklist';
        $backend = new Backend();
        $raw = $backend->configdRun('netshield manage_dns ' . $flag . ' ' . escapeshellarg($name));
        return json_decode($raw, true) ?: ['result' => 'ok'];
    }

    public function rulesAction()
    {
        $search = $this->request->get('search', 'string', '');
        $cmd = 'netshield manage_dns list-rules';
        if (!empty($search)) {
            $cmd .= ' ' . escapeshellarg($search);
        }

        $backend = new Backend();
        $raw = $backend->configdRun($cmd);
        $data = json_decode($raw, true) ?: [];

        if (!isset($data['rules'])) {
            $data = ['rules' => is_array($data) ? $data : []];
        }
        return $data;
    }

    public function addRuleAction()
    {
        if (!$this->request->isPost()) {
            return ['result' => 'failed', 'message' => 'POST required'];
        }

        $domain = $this->request->getPost('domain');
        $action = $this->request->getPost('action', 'string', 'block');

        if (empty($domain)) {
            return ['result' => 'failed', 'message' => 'domain is required'];
        }

        $allowedActions = ['block', 'allow', 'redirect'];
        if (!in_array($action, $allowedActions, true)) {
            return ['result' => 'failed', 'message' => 'action must be block, allow, or redirect'];
        }

        $backend = new Backend();
        $raw = $backend->configdRun(
            'netshield manage_dns add-rule ' . escapeshellarg($domain) . ' ' . escapeshellarg($action)
        );
        return json_decode($raw, true) ?: ['result' => 'ok'];
    }

    public function removeRuleAction()
    {
        if (!$this->request->isPost()) {
            return ['result' => 'failed', 'message' => 'POST required'];
        }

        $domain = $this->request->getPost('domain');
        if (empty($domain)) {
            return ['result' => 'failed', 'message' => 'domain is required'];
        }

        $backend = new Backend();
        $raw = $backend->configdRun('netshield manage_dns remove-rule ' . escapeshellarg($domain));
        return json_decode($raw, true) ?: ['result' => 'ok'];
    }

    /**
     * GET /api/netshield/dns/stats
     * Returns DNS stats in format the volt expects:
     * total_blocked, safe_search_enabled, blocklist_counts[]
     */
    public function statsAction()
    {
        $backend = new Backend();
        $raw = $backend->configdRun('netshield manage_dns stats');
        $data = json_decode($raw, true) ?: [];

        // Transform to volt-expected format
        $blocklists = $data['blocklist_counts'] ?? [];

        return [
            'total_blocked' => (int)($data['blocked_domains_total'] ?? $data['total_blocked'] ?? 0),
            'total_blocked_today' => (int)($data['total_blocked_today'] ?? 0),
            'total_allowed_today' => (int)($data['total_allowed_today'] ?? 0),
            'safe_search_enabled' => (bool)($data['safe_search_enabled'] ?? false),
            'blocklist_counts' => $blocklists,
            'categories' => $data['categories'] ?? [],
            'top_blocked_domains' => $data['top_blocked_domains'] ?? [],
            'unbound' => $data['unbound'] ?? [],
        ];
    }

    public function queryLogAction()
    {
        $limit = (int)$this->request->get('limit', 'int', 100);
        if ($limit < 1 || $limit > 1000) {
            $limit = 100;
        }

        $backend = new Backend();
        $raw = $backend->configdRun('netshield manage_dns query-log ' . $limit);
        $data = json_decode($raw, true) ?: [];

        if (!isset($data['log'])) {
            $data = ['log' => is_array($data) ? $data : []];
        }
        return $data;
    }

    public function safeSearchAction()
    {
        if (!$this->request->isPost()) {
            return ['result' => 'failed', 'message' => 'POST required'];
        }

        $enabled = $this->request->getPost('enabled', 'string', '1');
        $flag = ($enabled === '0' || $enabled === 'false') ? 'safe-search-off' : 'safe-search-on';

        $backend = new Backend();
        $raw = $backend->configdRun('netshield manage_dns ' . $flag);
        return json_decode($raw, true) ?: ['result' => 'ok'];
    }

    public function categoriesAction()
    {
        $backend = new Backend();
        $raw = $backend->configdRun('netshield manage_dns list-categories');
        $data = json_decode($raw, true) ?: [];

        if (!isset($data['categories'])) {
            $data = ['categories' => is_array($data) ? $data : []];
        }
        return $data;
    }

    public function toggleCategoryAction()
    {
        if (!$this->request->isPost()) {
            return ['result' => 'failed', 'message' => 'POST required'];
        }

        $name = $this->request->getPost('name');
        $enabled = $this->request->getPost('enabled', 'string', '1');

        if (empty($name)) {
            return ['result' => 'failed', 'message' => 'name is required'];
        }

        $enabledVal = ($enabled === '0' || $enabled === 'false') ? '0' : '1';
        $backend = new Backend();
        $raw = $backend->configdRun(
            'netshield manage_dns toggle-category ' . escapeshellarg($name) . ' ' . escapeshellarg($enabledVal)
        );
        return json_decode($raw, true) ?: ['result' => 'ok'];
    }
}
