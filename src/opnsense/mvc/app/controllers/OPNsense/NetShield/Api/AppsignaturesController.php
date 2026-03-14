<?php

/*
 * Copyright (C) 2025-2026 NetShield
 * All rights reserved.
 *
 * Application Signatures Controller - 3000+ app signatures for DPI
 */

namespace OPNsense\NetShield\Api;

use OPNsense\Base\ApiControllerBase;
use OPNsense\Core\Backend;

class AppsignaturesController extends ApiControllerBase
{
    /**
     * GET /api/netshield/appsignatures/list
     * Get all application signatures
     */
    public function listAction()
    {
        $category = $this->request->get('category');
        $params = $category ? 'category=' . escapeshellarg($category) : '';

        $backend = new Backend();
        $raw = $backend->configdRun('netshield appsignatures list ' . $params);
        return json_decode($raw, true) ?: [];
    }

    /**
     * GET /api/netshield/appsignatures/categories
     * Get all application categories
     */
    public function categoriesAction()
    {
        $backend = new Backend();
        $raw = $backend->configdRun('netshield appsignatures categories');
        return json_decode($raw, true) ?: [];
    }

    /**
     * GET /api/netshield/appsignatures/matchDomain
     * Match a domain to an application
     */
    public function matchDomainAction()
    {
        $domain = $this->request->get('domain');
        if (!$domain) {
            return ['status' => 'error', 'message' => 'domain required'];
        }
        $backend = new Backend();
        $raw = $backend->configdRun('netshield appsignatures match-domain ' . escapeshellarg($domain));
        return json_decode($raw, true) ?: [];
    }

    /**
     * GET /api/netshield/appsignatures/matchPort
     * Match a port to possible applications
     */
    public function matchPortAction()
    {
        $port = (int)$this->request->get('port');
        $protocol = $this->request->get('protocol', 'tcp');

        if (!$port) {
            return ['status' => 'error', 'message' => 'port required'];
        }

        $backend = new Backend();
        $raw = $backend->configdRun(sprintf(
            'netshield appsignatures match-port %d protocol=%s',
            $port,
            escapeshellarg($protocol)
        ));
        return json_decode($raw, true) ?: [];
    }

    /**
     * GET /api/netshield/appsignatures/search
     * Search for applications
     */
    public function searchAction()
    {
        $query = $this->request->get('query');
        if (!$query) {
            return ['status' => 'error', 'message' => 'query required'];
        }
        $backend = new Backend();
        $raw = $backend->configdRun('netshield appsignatures search query=' . escapeshellarg($query));
        return json_decode($raw, true) ?: [];
    }

    /**
     * GET /api/netshield/appsignatures/byCategory
     * Get applications by category
     */
    public function byCategoryAction()
    {
        $category = $this->request->get('category');
        if (!$category) {
            return ['status' => 'error', 'message' => 'category required'];
        }
        $backend = new Backend();
        $raw = $backend->configdRun('netshield appsignatures apps-by-category ' . escapeshellarg($category));
        return json_decode($raw, true) ?: [];
    }

    /**
     * POST /api/netshield/appsignatures/addCustom
     * Add a custom application signature
     */
    public function addCustomAction()
    {
        if ($this->request->isPost()) {
            $appId = $this->request->getPost('id');
            $name = $this->request->getPost('name');
            $category = $this->request->getPost('category');
            $domains = $this->request->getPost('domains');
            $ports = $this->request->getPost('ports', '');
            $risk = $this->request->getPost('risk', 'low');

            if (!$appId || !$name || !$category || !$domains) {
                return ['status' => 'error', 'message' => 'id, name, category, and domains required'];
            }

            $backend = new Backend();
            $raw = $backend->configdRun(sprintf(
                'netshield appsignatures add-custom id=%s name=%s category=%s domains=%s ports=%s risk=%s',
                escapeshellarg($appId),
                escapeshellarg($name),
                escapeshellarg($category),
                escapeshellarg($domains),
                escapeshellarg($ports),
                escapeshellarg($risk)
            ));
            return json_decode($raw, true) ?: ['status' => 'error'];
        }
        return ['status' => 'error', 'message' => 'POST required'];
    }

    /**
     * POST /api/netshield/appsignatures/removeCustom
     * Remove a custom application signature
     */
    public function removeCustomAction()
    {
        if ($this->request->isPost()) {
            $appId = $this->request->getPost('id');
            if (!$appId) {
                return ['status' => 'error', 'message' => 'id required'];
            }
            $backend = new Backend();
            $raw = $backend->configdRun('netshield appsignatures remove-custom ' . escapeshellarg($appId));
            return json_decode($raw, true) ?: ['status' => 'error'];
        }
        return ['status' => 'error', 'message' => 'POST required'];
    }

    /**
     * GET /api/netshield/appsignatures/stats
     * Get application signatures statistics
     */
    public function statsAction()
    {
        $backend = new Backend();
        $raw = $backend->configdRun('netshield appsignatures stats');
        return json_decode($raw, true) ?: [];
    }
}
