<?php

/*
 * Copyright (C) 2025-2026 NetShield
 * All rights reserved.
 *
 * Web Categories Controller - Domain categorization and filtering
 */

namespace OPNsense\Netshield\Api;

use OPNsense\Base\ApiControllerBase;
use OPNsense\Core\Backend;

class WebcategoriesController extends ApiControllerBase
{
    public function listAction()
    {
        $backend = new Backend();
        $raw = $backend->configdRun('netshield webcategories list');
        $data = json_decode($raw, true) ?: [];

        // Ensure categories key exists
        if (!isset($data['categories']) && is_array($data) && !empty($data)) {
            return ['categories' => $data];
        }
        return $data;
    }

    public function groupsAction()
    {
        $backend = new Backend();
        $raw = $backend->configdRun('netshield webcategories groups');
        $data = json_decode($raw, true) ?: [];

        if (!isset($data['groups']) && is_array($data) && !empty($data)) {
            return ['groups' => $data];
        }
        return $data;
    }

    public function enableAction()
    {
        if ($this->request->isPost()) {
            $category = $this->request->getPost('category');
            if (!$category) {
                return ['status' => 'error', 'message' => 'category required'];
            }
            $backend = new Backend();
            $raw = $backend->configdRun('netshield webcategories enable ' . escapeshellarg($category));
            return json_decode($raw, true) ?: ['status' => 'ok'];
        }
        return ['status' => 'error', 'message' => 'POST required'];
    }

    public function disableAction()
    {
        if ($this->request->isPost()) {
            $category = $this->request->getPost('category');
            if (!$category) {
                return ['status' => 'error', 'message' => 'category required'];
            }
            $backend = new Backend();
            $raw = $backend->configdRun('netshield webcategories disable ' . escapeshellarg($category));
            return json_decode($raw, true) ?: ['status' => 'ok'];
        }
        return ['status' => 'error', 'message' => 'POST required'];
    }

    public function classifyAction()
    {
        $domain = $this->request->get('domain');
        if (!$domain) {
            return ['status' => 'error', 'message' => 'domain required'];
        }
        $backend = new Backend();
        $raw = $backend->configdRun('netshield webcategories classify ' . escapeshellarg($domain));
        return json_decode($raw, true) ?: ['categories' => []];
    }

    public function addOverrideAction()
    {
        if ($this->request->isPost()) {
            $domain = $this->request->getPost('domain');
            $category = $this->request->getPost('category');
            if (!$domain || !$category) {
                return ['status' => 'error', 'message' => 'domain and category required'];
            }
            $backend = new Backend();
            $raw = $backend->configdRun(sprintf(
                'netshield webcategories add-override domain=%s category=%s',
                escapeshellarg($domain),
                escapeshellarg($category)
            ));
            return json_decode($raw, true) ?: ['status' => 'ok'];
        }
        return ['status' => 'error', 'message' => 'POST required'];
    }

    public function removeOverrideAction()
    {
        if ($this->request->isPost()) {
            $domain = $this->request->getPost('domain');
            if (!$domain) {
                return ['status' => 'error', 'message' => 'domain required'];
            }
            $backend = new Backend();
            $raw = $backend->configdRun('netshield webcategories remove-override ' . escapeshellarg($domain));
            return json_decode($raw, true) ?: ['status' => 'ok'];
        }
        return ['status' => 'error', 'message' => 'POST required'];
    }

    public function overridesAction()
    {
        $backend = new Backend();
        $raw = $backend->configdRun('netshield webcategories overrides');
        return json_decode($raw, true) ?: ['overrides' => []];
    }

    public function setDevicePolicyAction()
    {
        if ($this->request->isPost()) {
            $mac = $this->request->getPost('mac');
            $category = $this->request->getPost('category');
            $action = $this->request->getPost('action') ?? 'block';

            if (!$mac || !$category) {
                return ['status' => 'error', 'message' => 'mac and category required'];
            }

            $backend = new Backend();
            $raw = $backend->configdRun(sprintf(
                'netshield webcategories set-device-policy mac=%s category=%s action=%s',
                escapeshellarg($mac),
                escapeshellarg($category),
                escapeshellarg($action)
            ));
            return json_decode($raw, true) ?: ['status' => 'ok'];
        }
        return ['status' => 'error', 'message' => 'POST required'];
    }

    public function devicePoliciesAction()
    {
        $mac = $this->request->get('mac');
        if (!$mac) {
            return ['status' => 'error', 'message' => 'mac required'];
        }
        $backend = new Backend();
        $raw = $backend->configdRun('netshield webcategories device-policies ' . escapeshellarg($mac));
        return json_decode($raw, true) ?: ['policies' => []];
    }

    public function updateDatabaseAction()
    {
        if ($this->request->isPost()) {
            $source = $this->request->getPost('source') ?? 'shalla';
            $backend = new Backend();
            $backend->configdRun('netshield webcategories update-db ' . escapeshellarg($source), true);
            return ['status' => 'ok', 'message' => 'Database update started'];
        }
        return ['status' => 'error', 'message' => 'POST required'];
    }

    /**
     * GET /api/netshield/webcategories/stats
     * Returns stats in format volt expects: total_categories, blocked_categories, queries_blocked.
     * Also includes top_blocked for dashboard.
     */
    public function statsAction()
    {
        $backend = new Backend();
        $raw = $backend->configdRun('netshield webcategories stats');
        $data = json_decode($raw, true) ?: [];

        // Transform backend fields → volt expected fields
        return [
            'total_categories' => (int)($data['categories_defined'] ?? $data['total_categories'] ?? 0),
            'blocked_categories' => (int)($data['categories_used'] ?? $data['blocked_categories'] ?? 0),
            'queries_blocked' => (int)($data['queries_blocked'] ?? 0),
            'total_domains' => (int)($data['total_domains'] ?? 0),
            'custom_overrides' => (int)($data['custom_overrides'] ?? 0),
            'groups_defined' => (int)($data['groups_defined'] ?? 0),
            // For dashboard top blocked categories
            'top_blocked' => $data['top_blocked'] ?? [],
        ];
    }

    public function searchAction()
    {
        $query = $this->request->get('query');
        $category = $this->request->get('category');
        $limit = (int)($this->request->get('limit') ?? 100);

        if (!$query) {
            return ['status' => 'error', 'message' => 'query required'];
        }

        $params = sprintf('query=%s limit=%d', escapeshellarg($query), $limit);
        if ($category) {
            $params .= ' category=' . escapeshellarg($category);
        }

        $backend = new Backend();
        $raw = $backend->configdRun('netshield webcategories search ' . $params);
        return json_decode($raw, true) ?: ['results' => []];
    }

    public function blockGroupAction()
    {
        if ($this->request->isPost()) {
            $group = $this->request->getPost('group');
            if (!$group) {
                return ['status' => 'error', 'message' => 'group required'];
            }
            $backend = new Backend();
            $raw = $backend->configdRun('netshield webcategories block-group ' . escapeshellarg($group));
            return json_decode($raw, true) ?: ['status' => 'ok'];
        }
        return ['status' => 'error', 'message' => 'POST required'];
    }

    public function unblockGroupAction()
    {
        if ($this->request->isPost()) {
            $group = $this->request->getPost('group');
            if (!$group) {
                return ['status' => 'error', 'message' => 'group required'];
            }
            $backend = new Backend();
            $raw = $backend->configdRun('netshield webcategories unblock-group ' . escapeshellarg($group));
            return json_decode($raw, true) ?: ['status' => 'ok'];
        }
        return ['status' => 'error', 'message' => 'POST required'];
    }
}
