<?php

/*
 * Copyright (C) 2025-2026 NetShield
 * All rights reserved.
 *
 * IDS/IPS Controller - Suricata integration with signature management
 */

namespace OPNsense\NetShield\Api;

use OPNsense\Base\ApiControllerBase;
use OPNsense\Core\Backend;

class IdsController extends JwtAwareController
{
    /**
     * GET /api/netshield/ids/status
     * Get IDS engine status
     */
    public function statusAction()
    {
        $backend = new Backend();
        $raw = $backend->configdRun('netshield ids status');
        return json_decode($raw, true) ?: ['status' => 'error'];
    }

    /**
     * POST /api/netshield/ids/start
     * Start IDS engine
     */
    public function startAction()
    {
        if ($this->request->isPost()) {
            $backend = new Backend();
            $raw = $backend->configdRun('netshield ids start');
            return json_decode($raw, true) ?: ['status' => 'error'];
        }
        return ['status' => 'error', 'message' => 'POST required'];
    }

    /**
     * POST /api/netshield/ids/stop
     * Stop IDS engine
     */
    public function stopAction()
    {
        if ($this->request->isPost()) {
            $backend = new Backend();
            $raw = $backend->configdRun('netshield ids stop');
            return json_decode($raw, true) ?: ['status' => 'error'];
        }
        return ['status' => 'error', 'message' => 'POST required'];
    }

    /**
     * POST /api/netshield/ids/reloadRules
     * Reload Suricata rules
     */
    public function reloadRulesAction()
    {
        if ($this->request->isPost()) {
            $backend = new Backend();
            $raw = $backend->configdRun('netshield ids reload-rules');
            return json_decode($raw, true) ?: ['status' => 'error'];
        }
        return ['status' => 'error', 'message' => 'POST required'];
    }

    /**
     * GET /api/netshield/ids/alerts
     * Get IDS alerts with pagination
     */
    public function alertsAction()
    {
        $current = (int)($this->request->get('current') ?? 1);
        $rowCount = (int)($this->request->get('rowCount') ?? 20);
        $severity = $this->request->get('severity');
        $srcIp = $this->request->get('src_ip');

        $params = "limit=$rowCount,offset=" . (($current - 1) * $rowCount);
        if ($severity) {
            $params .= ",severity=$severity";
        }
        if ($srcIp) {
            $params .= ",src_ip=" . escapeshellarg($srcIp);
        }

        $backend = new Backend();
        $raw = $backend->configdRun('netshield ids alerts,' . $params);
        $data = json_decode($raw, true) ?: [];

        return [
            'rows' => $data['rows'] ?? [],
            'rowCount' => $rowCount,
            'total' => $data['total'] ?? 0,
            'current' => $current,
        ];
    }

    /**
     * GET /api/netshield/ids/alertStats
     * Get alert statistics
     */
    public function alertStatsAction()
    {
        $backend = new Backend();
        $raw = $backend->configdRun('netshield ids alert-stats');
        return json_decode($raw, true) ?: [];
    }

    /**
     * POST /api/netshield/ids/acknowledgeAlert
     * Acknowledge an alert
     */
    public function acknowledgeAlertAction()
    {
        if ($this->request->isPost()) {
            $alertId = $this->request->getPost('alert_id');
            if (!$alertId) {
                return ['status' => 'error', 'message' => 'alert_id required'];
            }
            $backend = new Backend();
            $raw = $backend->configdRun('netshield ids acknowledge,' . (int)$alertId);
            return json_decode($raw, true) ?: ['status' => 'error'];
        }
        return ['status' => 'error', 'message' => 'POST required'];
    }

    /**
     * GET /api/netshield/ids/signatures
     * List signatures with filtering
     */
    public function signaturesAction()
    {
        $current = (int)($this->request->get('current') ?? 1);
        $rowCount = (int)($this->request->get('rowCount') ?? 50);
        $category = $this->request->get('category');
        $search = $this->request->get('search');
        $enabledOnly = $this->request->get('enabled_only') === '1';

        $params = "limit=$rowCount,offset=" . (($current - 1) * $rowCount);
        if ($category) {
            $params .= ",category=" . escapeshellarg($category);
        }
        if ($search) {
            $params .= ",search=" . escapeshellarg($search);
        }
        if ($enabledOnly) {
            $params .= ",enabled_only=1";
        }

        $backend = new Backend();
        $raw = $backend->configdRun('netshield ids signatures,' . $params);
        $data = json_decode($raw, true) ?: [];

        return [
            'rows' => $data['rows'] ?? [],
            'rowCount' => $rowCount,
            'total' => $data['total'] ?? 0,
            'current' => $current,
        ];
    }

    /**
     * POST /api/netshield/ids/enableSignature
     * Enable a signature
     */
    public function enableSignatureAction()
    {
        if ($this->request->isPost()) {
            $sid = $this->request->getPost('sid');
            if (!$sid) {
                return ['status' => 'error', 'message' => 'sid required'];
            }
            $backend = new Backend();
            $raw = $backend->configdRun('netshield ids enable-sig,' . (int)$sid);
            return json_decode($raw, true) ?: ['status' => 'error'];
        }
        return ['status' => 'error', 'message' => 'POST required'];
    }

    /**
     * POST /api/netshield/ids/disableSignature
     * Disable a signature
     */
    public function disableSignatureAction()
    {
        if ($this->request->isPost()) {
            $sid = $this->request->getPost('sid');
            if (!$sid) {
                return ['status' => 'error', 'message' => 'sid required'];
            }
            $backend = new Backend();
            $raw = $backend->configdRun('netshield ids disable-sig,' . (int)$sid);
            return json_decode($raw, true) ?: ['status' => 'error'];
        }
        return ['status' => 'error', 'message' => 'POST required'];
    }

    /**
     * POST /api/netshield/ids/addCustomRule
     * Add a custom IDS rule
     */
    public function addCustomRuleAction()
    {
        if ($this->request->isPost()) {
            $action = $this->request->getPost('action', 'alert');
            $protocol = $this->request->getPost('protocol', 'tcp');
            $src = $this->request->getPost('src', 'any any');
            $dst = $this->request->getPost('dst', 'any any');
            $msg = $this->request->getPost('msg');
            $classtype = $this->request->getPost('classtype', 'misc-activity');
            $priority = (int)($this->request->getPost('priority') ?? 3);

            if (!$msg) {
                return ['status' => 'error', 'message' => 'msg required'];
            }

            $params = sprintf(
                'action=%s,protocol=%s,src=%s,dst=%s,msg=%s,classtype=%s,priority=%d',
                escapeshellarg($action),
                escapeshellarg($protocol),
                escapeshellarg($src),
                escapeshellarg($dst),
                escapeshellarg($msg),
                escapeshellarg($classtype),
                $priority
            );

            $backend = new Backend();
            $raw = $backend->configdRun('netshield ids add-rule,' . $params);
            return json_decode($raw, true) ?: ['status' => 'error'];
        }
        return ['status' => 'error', 'message' => 'POST required'];
    }

    /**
     * POST /api/netshield/ids/deleteCustomRule
     * Delete a custom IDS rule
     */
    public function deleteCustomRuleAction()
    {
        if ($this->request->isPost()) {
            $sid = $this->request->getPost('sid');
            if (!$sid) {
                return ['status' => 'error', 'message' => 'sid required'];
            }
            $backend = new Backend();
            $raw = $backend->configdRun('netshield ids delete-rule,' . (int)$sid);
            return json_decode($raw, true) ?: ['status' => 'error'];
        }
        return ['status' => 'error', 'message' => 'POST required'];
    }

    /**
     * POST /api/netshield/ids/enableCategory
     * Enable a signature category
     */
    public function enableCategoryAction()
    {
        if ($this->request->isPost()) {
            $category = $this->request->getPost('category');
            if (!$category) {
                return ['status' => 'error', 'message' => 'category required'];
            }
            $backend = new Backend();
            $raw = $backend->configdRun('netshield ids enable-category,' . escapeshellarg($category));
            return json_decode($raw, true) ?: ['status' => 'error'];
        }
        return ['status' => 'error', 'message' => 'POST required'];
    }

    /**
     * POST /api/netshield/ids/disableCategory
     * Disable a signature category
     */
    public function disableCategoryAction()
    {
        if ($this->request->isPost()) {
            $category = $this->request->getPost('category');
            if (!$category) {
                return ['status' => 'error', 'message' => 'category required'];
            }
            $backend = new Backend();
            $raw = $backend->configdRun('netshield ids disable-category,' . escapeshellarg($category));
            return json_decode($raw, true) ?: ['status' => 'error'];
        }
        return ['status' => 'error', 'message' => 'POST required'];
    }

    /**
     * GET /api/netshield/ids/categories
     * Get signature categories
     */
    public function categoriesAction()
    {
        $backend = new Backend();
        $raw = $backend->configdRun('netshield ids categories');
        return json_decode($raw, true) ?: [];
    }

    /**
     * GET /api/netshield/ids/topSignatures
     * Get most triggered signatures
     */
    public function topSignaturesAction()
    {
        $limit = (int)($this->request->get('limit') ?? 10);
        $backend = new Backend();
        $raw = $backend->configdRun('netshield ids top-signatures,limit=' . $limit);
        return json_decode($raw, true) ?: [];
    }

    /**
     * GET /api/netshield/ids/topAttackers
     * Get top attacking IPs
     */
    public function topAttackersAction()
    {
        $limit = (int)($this->request->get('limit') ?? 10);
        $backend = new Backend();
        $raw = $backend->configdRun('netshield ids top-attackers,limit=' . $limit);
        return json_decode($raw, true) ?: [];
    }
}
