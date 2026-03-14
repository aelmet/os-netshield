<?php

/*
 * Copyright (C) 2025-2026 NetShield
 * All rights reserved.
 *
 * Target Lists Controller - Firewalla-style grouped domains/IPs
 */

namespace OPNsense\NetShield\Api;

use OPNsense\Base\ApiControllerBase;
use OPNsense\Core\Backend;

class TargetlistsController extends JwtAwareController
{
    private function enc($v)
    {
        return rawurlencode((string)$v);
    }

    /**
     * GET /api/netshield/targetlists/list
     */
    public function listAction()
    {
        $backend = new Backend();
        $raw = $backend->configdRun('netshield targetlists list');
        $data = json_decode($raw, true) ?: [];
        // Read blocked state
        $stateFile = '/var/db/netshield/targetlists_blocked.json';
        $blockedIds = [];
        if (file_exists($stateFile)) {
            $blockedIds = json_decode(file_get_contents($stateFile), true) ?: [];
        }
        // Map fields for view compatibility
        foreach ($data as &$item) {
            $item['domain_count'] = $item['entry_count'] ?? 0;
            $item['ip_count'] = 0;
            $item['hits'] = 0;
            $item['blocked'] = in_array((string)($item['id'] ?? 0), $blockedIds);
        }
        unset($item);
        return ['lists' => $data, 'total' => count($data)];
    }

    /**
     * GET /api/netshield/targetlists/get
     */
    public function getAction()
    {
        $id = (int)$this->request->get('id');
        if (!$id) {
            return ['status' => 'error', 'message' => 'id required'];
        }
        $backend = new Backend();
        $raw = $backend->configdRun('netshield targetlists get,' . $id);
        return json_decode($raw, true) ?: ['status' => 'error'];
    }

    /**
     * POST /api/netshield/targetlists/create
     */
    public function createAction()
    {
        if (!$this->request->isPost()) {
            return ['status' => 'error', 'message' => 'POST required'];
        }
        $name = $this->request->getPost('name');
        $description = $this->request->getPost('description', '');
        $type = $this->request->getPost('type', 'domain');

        if (!$name) {
            return ['status' => 'error', 'message' => 'name required'];
        }

        $backend = new Backend();
        $raw = $backend->configdRun(
            'netshield targetlists create,name=' . $this->enc($name)
            . ',description=' . $this->enc($description)
            . ',type=' . $this->enc($type)
        );
        return json_decode($raw, true) ?: ['status' => 'error'];
    }

    /**
     * POST /api/netshield/targetlists/delete
     */
    public function deleteAction()
    {
        if (!$this->request->isPost()) {
            return ['status' => 'error', 'message' => 'POST required'];
        }
        $id = (int)($this->request->getPost('id') ?: $this->request->getPost('list_id'));
        if (!$id) {
            return ['status' => 'error', 'message' => 'id required'];
        }
        $backend = new Backend();
        $raw = $backend->configdRun('netshield targetlists delete,' . $id);
        return json_decode($raw, true) ?: ['status' => 'error'];
    }

    /**
     * POST /api/netshield/targetlists/update
     */
    public function updateAction()
    {
        if (!$this->request->isPost()) {
            return ['status' => 'error', 'message' => 'POST required'];
        }
        $id = (int)$this->request->getPost('id');
        $name = $this->request->getPost('name');
        $description = $this->request->getPost('description');

        if (!$id) {
            return ['status' => 'error', 'message' => 'id required'];
        }

        $params = "id=$id";
        if ($name) {
            $params .= ',name=' . $this->enc($name);
        }
        if ($description !== null) {
            $params .= ',description=' . $this->enc($description);
        }

        $backend = new Backend();
        $raw = $backend->configdRun('netshield targetlists update,' . $params);
        return json_decode($raw, true) ?: ['status' => 'error'];
    }

    /**
     * GET /api/netshield/targetlists/entries
     */
    public function entriesAction()
    {
        $listId = (int)$this->request->get('list_id');
        $current = (int)($this->request->get('current') ?? 1);
        $rowCount = (int)($this->request->get('rowCount') ?? 100);
        $search = $this->request->get('search');

        if (!$listId) {
            return ['status' => 'error', 'message' => 'list_id required'];
        }

        $params = sprintf('list_id=%d,limit=%d,offset=%d', $listId, $rowCount, ($current - 1) * $rowCount);
        if ($search) {
            $params .= ',search=' . $this->enc($search);
        }

        $backend = new Backend();
        $raw = $backend->configdRun('netshield targetlists entries,' . $params);
        $data = json_decode($raw, true) ?: [];

        $entries = $data['entries'] ?? [];
        // Get list name
        $listName = '';
        $listRaw = $backend->configdRun('netshield targetlists get,' . $listId);
        $listInfo = json_decode($listRaw, true);
        if ($listInfo && isset($listInfo['name'])) {
            $listName = $listInfo['name'];
        }

        return [
            'entries' => $entries,
            'rows' => $entries,
            'list_name' => $listName,
            'rowCount' => $rowCount,
            'total' => $data['total'] ?? count($entries),
            'current' => $current,
        ];
    }

    /**
     * POST /api/netshield/targetlists/addEntry
     */
    public function addEntryAction()
    {
        if (!$this->request->isPost()) {
            return ['status' => 'error', 'message' => 'POST required'];
        }
        $listId = (int)$this->request->getPost('list_id');
        $value = $this->request->getPost('value');
        $comment = $this->request->getPost('comment', '');

        if (!$listId || !$value) {
            return ['status' => 'error', 'message' => 'list_id and value required'];
        }

        $backend = new Backend();
        $raw = $backend->configdRun(
            'netshield targetlists add-entry,list_id=' . $listId
            . ',value=' . $this->enc($value)
            . ',comment=' . $this->enc($comment)
        );
        return json_decode($raw, true) ?: ['status' => 'error'];
    }

    /**
     * POST /api/netshield/targetlists/removeEntry
     */
    public function removeEntryAction()
    {
        if (!$this->request->isPost()) {
            return ['status' => 'error', 'message' => 'POST required'];
        }
        $entryId = (int)$this->request->getPost('entry_id');
        $value = $this->request->getPost('value');
        $listId = (int)$this->request->getPost('list_id');

        if ($entryId) {
            $backend = new Backend();
            $raw = $backend->configdRun('netshield targetlists remove-entry,' . $entryId);
            return json_decode($raw, true) ?: ['status' => 'error'];
        } elseif ($value && $listId) {
            $backend = new Backend();
            $raw = $backend->configdRun(
                'netshield targetlists remove-entry-by-value,list_id=' . $listId
                . ',value=' . $this->enc($value)
            );
            return json_decode($raw, true) ?: ['status' => 'error'];
        }
        return ['status' => 'error', 'message' => 'entry_id or (list_id + value) required'];
    }

    /**
     * POST /api/netshield/targetlists/bulkAddEntries
     */
    public function bulkAddEntriesAction()
    {
        if (!$this->request->isPost()) {
            return ['status' => 'error', 'message' => 'POST required'];
        }
        $listId = (int)$this->request->getPost('list_id');
        $entries = $this->request->getPost('entries');

        if (!$listId || !$entries) {
            return ['status' => 'error', 'message' => 'list_id and entries required'];
        }

        $entriesArray = preg_split('/[\n,]+/', $entries);
        $entriesArray = array_map('trim', $entriesArray);
        $entriesArray = array_filter($entriesArray);

        $backend = new Backend();
        $count = 0;
        foreach ($entriesArray as $entry) {
            $raw = $backend->configdRun(
                'netshield targetlists add-entry,list_id=' . $listId
                . ',value=' . $this->enc($entry)
            );
            $result = json_decode($raw, true);
            if ($result && isset($result['id'])) {
                $count++;
            }
        }

        return ['status' => 'ok', 'added' => $count, 'total' => count($entriesArray)];
    }

    /**
     * GET /api/netshield/targetlists/checkDomain
     */
    public function checkDomainAction()
    {
        $domain = $this->request->get('domain');
        if (!$domain) {
            return ['status' => 'error', 'message' => 'domain required'];
        }
        $backend = new Backend();
        $raw = $backend->configdRun('netshield targetlists check-domain,' . $this->enc($domain));
        return json_decode($raw, true) ?: [];
    }

    /**
     * GET /api/netshield/targetlists/checkIp
     */
    public function checkIpAction()
    {
        $ip = $this->request->get('ip');
        if (!$ip) {
            return ['status' => 'error', 'message' => 'ip required'];
        }
        $backend = new Backend();
        $raw = $backend->configdRun('netshield targetlists check-ip,' . $this->enc($ip));
        return json_decode($raw, true) ?: [];
    }

    /**
     * POST /api/netshield/targetlists/addPolicy
     */
    public function addPolicyAction()
    {
        if (!$this->request->isPost()) {
            return ['status' => 'error', 'message' => 'POST required'];
        }
        $listId = (int)$this->request->getPost('list_id');
        $action = $this->request->getPost('action', 'block');
        $direction = $this->request->getPost('direction', 'both');
        $priority = (int)($this->request->getPost('priority') ?? 100);

        if (!$listId) {
            return ['status' => 'error', 'message' => 'list_id required'];
        }

        $backend = new Backend();
        $raw = $backend->configdRun(
            'netshield targetlists add-policy,list_id=' . $listId
            . ',action=' . $this->enc($action)
            . ',direction=' . $this->enc($direction)
            . ',priority=' . $priority
        );
        return json_decode($raw, true) ?: ['status' => 'error'];
    }

    /**
     * GET /api/netshield/targetlists/policies
     */
    public function policiesAction()
    {
        $listId = (int)$this->request->get('list_id');
        if (!$listId) {
            return ['status' => 'error', 'message' => 'list_id required'];
        }
        $backend = new Backend();
        $raw = $backend->configdRun('netshield targetlists policies,' . $listId);
        return json_decode($raw, true) ?: [];
    }

    /**
     * POST /api/netshield/targetlists/muteAlarms
     */
    public function muteAlarmsAction()
    {
        if (!$this->request->isPost()) {
            return ['status' => 'error', 'message' => 'POST required'];
        }
        $listId = (int)$this->request->getPost('list_id');
        $alarmType = $this->request->getPost('alarm_type');
        if (!$listId) {
            return ['status' => 'error', 'message' => 'list_id required'];
        }
        $params = "list_id=$listId";
        if ($alarmType) {
            $params .= ',alarm_type=' . $this->enc($alarmType);
        }
        $backend = new Backend();
        $raw = $backend->configdRun('netshield targetlists mute-alarms,' . $params);
        return json_decode($raw, true) ?: ['status' => 'error'];
    }

    /**
     * POST /api/netshield/targetlists/unmuteAlarms
     */
    public function unmuteAlarmsAction()
    {
        if (!$this->request->isPost()) {
            return ['status' => 'error', 'message' => 'POST required'];
        }
        $listId = (int)$this->request->getPost('list_id');
        $alarmType = $this->request->getPost('alarm_type');
        if (!$listId) {
            return ['status' => 'error', 'message' => 'list_id required'];
        }
        $params = "list_id=$listId";
        if ($alarmType) {
            $params .= ',alarm_type=' . $this->enc($alarmType);
        }
        $backend = new Backend();
        $raw = $backend->configdRun('netshield targetlists unmute-alarms,' . $params);
        return json_decode($raw, true) ?: ['status' => 'error'];
    }

    /**
     * GET /api/netshield/targetlists/stats
     */
    public function statsAction()
    {
        $backend = new Backend();
        $raw = $backend->configdRun('netshield targetlists stats');
        return json_decode($raw, true) ?: [];
    }

    /**
     * POST /api/netshield/targetlists/toggleBlock
     * Toggle blocking enforcement for a target list.
     * Stores blocked state in a JSON file and triggers Unbound enforcement.
     */
    public function toggleBlockAction()
    {
        if (!$this->request->isPost()) {
            return ['status' => 'error', 'message' => 'POST required'];
        }
        $listId = (int)$this->request->getPost('list_id');
        if (!$listId) {
            return ['status' => 'error', 'message' => 'list_id required'];
        }

        // Read current blocked state from JSON file
        $stateFile = '/var/db/netshield/targetlists_blocked.json';
        $blocked = [];
        if (file_exists($stateFile)) {
            $blocked = json_decode(file_get_contents($stateFile), true) ?: [];
        }

        // Toggle
        $listIdStr = (string)$listId;
        if (in_array($listIdStr, $blocked)) {
            $blocked = array_values(array_diff($blocked, [$listIdStr]));
            $newState = false;
        } else {
            $blocked[] = $listIdStr;
            $newState = true;
        }

        // Save state
        file_put_contents($stateFile, json_encode($blocked));

        // Trigger FULL enforcement (rebuild all Unbound rules)
        $backend = new Backend();
        $enforceRaw = $backend->configdRun('netshield enforce');
        $enforceResult = json_decode($enforceRaw, true) ?: [];

        return [
            'status' => 'ok',
            'list_id' => $listId,
            'blocked' => $newState,
            'message' => $newState ? 'List is now blocked via DNS' : 'List unblocked - DNS rules removed',
            'total_blocked' => $enforceResult['total_domains'] ?? 0,
        ];
    }

}