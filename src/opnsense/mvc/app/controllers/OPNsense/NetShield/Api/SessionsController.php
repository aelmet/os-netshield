<?php

namespace OPNsense\NetShield\Api;

use OPNsense\Base\ApiControllerBase;
use OPNsense\Core\Backend;

class SessionsController extends JwtAwareController
{
    private function encParam(string $val): string
    {
        return rawurlencode($val);
    }

    private function addParam(string &$cmd, string $flag, string $val): void
    {
        if ($val !== '') {
            $cmd .= ',' . $flag . ',' . $this->encParam($val);
        }
    }

    /**
     * Search/list connection sessions with filters and pagination.
     * GET /api/netshield/sessions/search
     */
    public function searchAction()
    {
        // Read params from JSON body (JS sends contentType: application/json)
        // or fall back to form params
        $jsonBody = json_decode($this->request->getRawBody(), true) ?: [];
        $getParam = function($key, $default = '') use ($jsonBody) {
            if (isset($jsonBody[$key]) && $jsonBody[$key] !== '') {
                return trim((string)$jsonBody[$key]);
            }
            return trim($this->request->get($key) ?? $default);
        };

        $cmd = 'netshield get_sessions list';

        $device = $getParam('device');
        $this->addParam($cmd, '--device', $device);

        $blocked = $getParam('blocked');

        $appCategory = $getParam('app_category', $getParam('category'));
        $this->addParam($cmd, '--app_category', $appCategory);

        $search = $getParam('searchPhrase', $getParam('search'));
        $this->addParam($cmd, '--search', $search);

        // Map status filter to blocked param
        $status = $getParam('status');
        if ($blocked === '' && $status !== '') {
            if ($status === 'blocked' || $status === 'threats') {
                $blocked = '1';
            } elseif ($status === 'allowed') {
                $blocked = '0';
            }
        }
        if ($blocked === '0' || $blocked === '1') {
            $this->addParam($cmd, '--blocked', $blocked);
        }

        // Map from/to date filters
        $startDate = $getParam('start_date');
        if ($startDate === '') {
            $startDate = $getParam('from');
        }
        $this->addParam($cmd, '--start_date', $startDate);

        $endDate = $getParam('end_date');
        if ($endDate === '') {
            $endDate = $getParam('to');
        }
        $this->addParam($cmd, '--end_date', $endDate);

        // Pagination
        $limit  = (int)($getParam('limit') ?: $getParam('rowCount') ?: 50);
        $offset = (int)($getParam('offset') ?: 0);
        $current = (int)($getParam('current') ?: 1);
        if ($limit < 1) $limit = 50;
        if ($offset < 0) $offset = 0;
        if ($current > 1 && $offset === 0) {
            $offset = ($current - 1) * $limit;
        }

        $this->addParam($cmd, '--limit', (string)$limit);
        $this->addParam($cmd, '--offset', (string)$offset);

        $backend = new Backend();
        $raw  = $backend->configdRun($cmd);
        $data = json_decode($raw, true);

        if (!$data || ($data['status'] ?? '') === 'error') {
            return [
                'status'   => 'error',
                'rows'     => [],
                'total'    => 0,
                'message'  => $data['message'] ?? (trim($raw) ?: 'Backend error'),
            ];
        }

        $sessions = $data['data']['sessions'] ?? [];
        $total    = $data['data']['total']    ?? 0;

        // Fetch active policies for block reason enrichment
        $policyRaw = $backend->configdRun('netshield manage_policy list');
        $policyData = json_decode($policyRaw, true) ?: [];
        $policies = $policyData['data']['policies'] ?? [];

        // Map field names to what the JS expects
        foreach ($sessions as &$s) {
            $s['destination'] = $s['dst_hostname'] ?? $s['dst_ip'] ?? '';
            $s['status'] = !empty($s['blocked']) ? 'blocked' : 'allowed';

            // Enrich blocked sessions with block reason
            if (!empty($s['blocked'])) {
                $domain = $s['dst_hostname'] ?? '';
                $app = $s['application'] ?? $s['app_name'] ?? '';
                $cat = $s['app_category'] ?? $s['category'] ?? '';

                // Determine security category and block reason from policies
                $secCat = '';
                $blockType = 'dns';
                $blockReason = '';

                foreach ($policies as $p) {
                    if (empty($p['enabled']) || $p['enabled'] === '0' || $p['enabled'] === 'false') continue;
                    $policyApps = !empty($p['apps']) ? explode(',', $p['apps']) : [];
                    $policyCats = !empty($p['web_categories']) ? explode(',', $p['web_categories']) : [];

                    // Check if this policy matches the blocked session
                    $matched = false;
                    if (!empty($p['no_internet']) && $p['no_internet'] === '1') {
                        $matched = true;
                        $secCat = 'Internet Block';
                        $blockReason = 'Policy: ' . ($p['name'] ?? 'Unknown') . ' (No Internet)';
                    } elseif ($app && in_array(strtolower($app), array_map('strtolower', $policyApps))) {
                        $matched = true;
                        $secCat = 'App Block';
                        $blockReason = 'Policy: ' . ($p['name'] ?? 'Unknown') . ' (App: ' . $app . ')';
                    } elseif ($cat && in_array(strtolower($cat), array_map('strtolower', $policyCats))) {
                        $matched = true;
                        $secCat = 'Category Block';
                        $blockReason = 'Policy: ' . ($p['name'] ?? 'Unknown') . ' (Category: ' . $cat . ')';
                    }

                    if ($matched) {
                        $blockType = ($p['action'] ?? 'block');
                        break;
                    }
                }

                // If no policy matched, it's a DNS/targetlist block
                if (empty($blockReason)) {
                    if ($domain) {
                        $secCat = 'DNS Block';
                        $blockReason = 'Blocked domain: ' . $domain;
                    } else {
                        $secCat = 'Firewall';
                        $blockReason = 'Blocked by firewall rule';
                    }
                }

                $s['security_category'] = $secCat;
                $s['block_type'] = $blockType;
                $s['block_reason'] = $blockReason;
            } else {
                $s['security_category'] = '';
                $s['block_type'] = '';
                $s['block_reason'] = '';
            }
        }
        unset($s);

        return [
            'status'   => 'ok',
            'rows'     => $sessions,
            'total'    => $total,
            'rowCount' => $limit,
            'current'  => $current,
        ];
    }

    /**
     * Connection statistics.
     * GET /api/netshield/sessions/stats
     */
    public function statsAction()
    {
        $backend = new Backend();
        $raw  = $backend->configdRun('netshield get_sessions stats');
        $data = json_decode($raw, true);

        if (!$data || ($data['status'] ?? '') === 'error') {
            return ['status' => 'error', 'message' => trim($raw) ?: 'Backend error'];
        }

        // Pass through backend data structure directly.
        // Backend: {status, data: {total_connections, blocked_count,
        //   today: {total, blocked, top_devices, top_domains, top_categories},
        //   all_time: {...}}}
        // Dashboard JS expects data.data.today.* which matches this.
        return $data;
    }

    /**
     * Purge old connection entries.
     * POST /api/netshield/sessions/purge
     */
    public function purgeAction()
    {
        if (!$this->request->isPost()) {
            return ['status' => 'error', 'message' => 'POST required'];
        }

        $days = (int)($this->request->getPost('days') ?? 7);
        if ($days < 1) $days = 1;

        $cmd = 'netshield get_sessions purge,--days,' . $days;

        $backend = new Backend();
        $raw  = $backend->configdRun($cmd);
        $data = json_decode($raw, true);

        if ($data) {
            return $data;
        }
        return ['status' => 'error', 'message' => trim($raw) ?: 'Backend error'];
    }

    /**
     * Trigger the connection logger immediately.
     * POST /api/netshield/sessions/logNow
     */
    public function logNowAction()
    {
        if (!$this->request->isPost()) {
            return ['status' => 'error', 'message' => 'POST required'];
        }

        $backend = new Backend();
        $raw  = $backend->configdRun('netshield log_connections');
        $data = json_decode($raw, true);

        if ($data) {
            return $data;
        }
        return ['status' => 'error', 'message' => trim($raw) ?: 'Backend error'];
    }

    /**
     * Block a connection by adding a DNS rule for the destination.
     * POST /api/netshield/sessions/blockConnection
     */
    public function blockConnectionAction()
    {
        if (!$this->request->isPost()) {
            return ['status' => 'error', 'message' => 'POST required'];
        }

        $body = json_decode($this->request->getRawBody(), true) ?: [];
        $dstIp = trim($body['dst_ip'] ?? '');
        $dstPort = trim($body['dst_port'] ?? '');
        $protocol = trim($body['protocol'] ?? '');

        if (empty($dstIp)) {
            return ['status' => 'error', 'message' => 'dst_ip required'];
        }

        // Add a DNS block rule for this IP via manage_dns
        $backend = new Backend();
        $cmd = 'netshield manage_dns add-rule,'
             . $this->encParam($dstIp) . ','
             . $this->encParam('block') . ','
             . $this->encParam('session_block');
        $raw = $backend->configdRun($cmd);
        $data = json_decode($raw, true);

        if ($data && ($data['status'] ?? '') !== 'error') {
            // Also kill existing pf state for this IP
            $backend->configdRun('netshield manage_dns enforce');
            return ['status' => 'ok', 'message' => "Blocked $dstIp"];
        }

        return $data ?: ['status' => 'error', 'message' => trim($raw) ?: 'Block failed'];
    }

    /**
     * Allow (unblock) a connection by removing its DNS block rule.
     * POST /api/netshield/sessions/allowConnection
     */
    public function allowConnectionAction()
    {
        if (!$this->request->isPost()) {
            return ['status' => 'error', 'message' => 'POST required'];
        }

        $body = json_decode($this->request->getRawBody(), true) ?: [];
        $dstIp = trim($body['dst_ip'] ?? '');

        if (empty($dstIp)) {
            return ['status' => 'error', 'message' => 'dst_ip required'];
        }

        $backend = new Backend();
        $cmd = 'netshield manage_dns remove-rule,'
             . $this->encParam($dstIp);
        $raw = $backend->configdRun($cmd);
        $data = json_decode($raw, true);

        if ($data && ($data['status'] ?? '') !== 'error') {
            $backend->configdRun('netshield manage_dns enforce');
            return ['status' => 'ok', 'message' => "Allowed $dstIp"];
        }

        return $data ?: ['status' => 'error', 'message' => trim($raw) ?: 'Allow failed'];
    }

    /**
     * Block a domain by adding it to DNS blocklist.
     * POST /api/netshield/sessions/blockDomain
     */
    public function blockDomainAction()
    {
        if (!$this->request->isPost()) {
            return ['status' => 'error', 'message' => 'POST required'];
        }

        $body = json_decode($this->request->getRawBody(), true) ?: [];
        $domain = trim($body['domain'] ?? '');

        if (empty($domain)) {
            return ['status' => 'error', 'message' => 'domain required'];
        }

        $backend = new Backend();
        $cmd = 'netshield manage_dns add-rule,'
             . $this->encParam($domain) . ','
             . $this->encParam('block');
        $raw = $backend->configdRun($cmd);
        $data = json_decode($raw, true);

        if ($data && ($data['status'] ?? '') !== 'error') {
            $backend->configdRun('netshield manage_dns enforce');
            return ['status' => 'ok', 'message' => "Blocked $domain"];
        }

        return $data ?: ['status' => 'error', 'message' => trim($raw) ?: 'Block failed'];
    }

    /**
     * Unblock a domain by removing it from DNS blocklist.
     * POST /api/netshield/sessions/unblockDomain
     */
    public function unblockDomainAction()
    {
        if (!$this->request->isPost()) {
            return ['status' => 'error', 'message' => 'POST required'];
        }

        $body = json_decode($this->request->getRawBody(), true) ?: [];
        $domain = trim($body['domain'] ?? '');

        if (empty($domain)) {
            return ['status' => 'error', 'message' => 'domain required'];
        }

        $backend = new Backend();
        $cmd = 'netshield manage_dns remove-rule,'
             . $this->encParam($domain);
        $raw = $backend->configdRun($cmd);
        $data = json_decode($raw, true);

        if ($data && ($data['status'] ?? '') !== 'error') {
            $backend->configdRun('netshield manage_dns enforce');
            return ['status' => 'ok', 'message' => "Unblocked $domain"];
        }

        return $data ?: ['status' => 'error', 'message' => trim($raw) ?: 'Unblock failed'];
    }
}
