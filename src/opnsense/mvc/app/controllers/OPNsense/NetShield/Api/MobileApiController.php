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
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
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
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

namespace OPNsense\NetShield\Api;

use OPNsense\Base\ApiControllerBase;
use OPNsense\Core\Backend;

/**
 * Mobile API Controller — JWT-authenticated REST API for mobile clients.
 *
 * Endpoints (all under /api/netshield/mobile/):
 *   POST login           — issue access + refresh tokens
 *   POST refresh         — exchange refresh token for new access token
 *   POST logout          — revoke refresh token
 *   GET  dashboard       — combined stats summary  [JWT]
 *   GET  devices         — device list             [JWT]
 *   GET  alerts          — recent alerts           [JWT]
 *   GET  websocket_info  — WS connection info      [JWT]
 */
class MobileApiController extends ApiControllerBase
{
    /** Configd backend instance */
    private Backend $backend;

    /**
     * Allow unauthenticated access to login/refresh endpoints.
     * These use JWT auth, not OPNsense session auth.
     */
    public function beforeExecuteRoute($dispatcher)
    {
        // All actions in this controller use JWT auth (not OPNsense session auth).
        // Each protected action calls _validateJwt() internally.
        return true;
    }

    public function initialize(): void
    {
        parent::initialize();
        $this->backend = new Backend();
    }

    // ------------------------------------------------------------------
    // Auth endpoints (no JWT required)
    // ------------------------------------------------------------------

    /**
     * POST /api/netshield/mobile/login
     * Body: { "username": "...", "password": "...", "device_name": "...", "device_id": "..." }
     * Returns: { "access_token": "...", "refresh_token": "...", "expires_in": 900 }
     */
    public function loginAction(): array
    {
        if ($this->request->getMethod() !== 'POST') {
            $this->response->setStatusCode(405, 'Method Not Allowed');
            return ['error' => 'POST required'];
        }

        $body        = $this->request->getJsonRawBody(true) ?? [];
        $username    = trim($body['username'] ?? '');
        $password    = $body['password'] ?? '';
        $deviceName  = trim($body['device_name'] ?? '');
        $deviceId    = trim($body['device_id'] ?? '');

        if ($username === '' || $password === '') {
            $this->response->setStatusCode(400, 'Bad Request');
            return ['error' => 'username and password are required'];
        }

        // Validate credentials against OPNsense system auth
        if (!$this->_validateCredentials($username, $password)) {
            $this->response->setStatusCode(401, 'Unauthorized');
            return ['error' => 'Invalid credentials'];
        }

        // Generate token pair via configd → jwt_helper_cli.py
        $args   = escapeshellarg($username) . ' ' . escapeshellarg($deviceName) . ' ' . escapeshellarg($deviceId);
        $raw    = trim($this->backend->configdpRun('netshield mobile_generate_jwt', [$username, $deviceName, $deviceId]));
        $result = json_decode($raw, true);

        if (!$result || ($result['status'] ?? '') !== 'ok') {
            $this->response->setStatusCode(500, 'Internal Server Error');
            return ['error' => 'Token generation failed'];
        }

        return [
            'access_token'  => $result['access_token'],
            'refresh_token' => $result['refresh_token'],
            'expires_in'    => $result['expires_in'] ?? 900,
            'token_type'    => 'Bearer',
        ];
    }

    /**
     * POST /api/netshield/mobile/refresh
     * Body: { "refresh_token": "..." }
     * Returns: { "access_token": "...", "expires_in": 900 }
     */
    public function refreshAction(): array
    {
        if ($this->request->getMethod() !== 'POST') {
            $this->response->setStatusCode(405, 'Method Not Allowed');
            return ['error' => 'POST required'];
        }

        $body         = $this->request->getJsonRawBody(true) ?? [];
        $refreshToken = trim($body['refresh_token'] ?? '');

        if ($refreshToken === '') {
            $this->response->setStatusCode(400, 'Bad Request');
            return ['error' => 'refresh_token is required'];
        }

        $raw    = trim($this->backend->configdpRun('netshield mobile_refresh_jwt', [$refreshToken]));
        $result = json_decode($raw, true);

        if (!$result || ($result['status'] ?? '') !== 'ok') {
            $this->response->setStatusCode(401, 'Unauthorized');
            return ['error' => 'Invalid or expired refresh token'];
        }

        return [
            'access_token' => $result['access_token'],
            'expires_in'   => 900,
            'token_type'   => 'Bearer',
        ];
    }

    /**
     * POST /api/netshield/mobile/logout
     * Body: { "refresh_token": "..." }
     */
    public function logoutAction(): array
    {
        if ($this->request->getMethod() !== 'POST') {
            $this->response->setStatusCode(405, 'Method Not Allowed');
            return ['error' => 'POST required'];
        }

        $username = $this->_validateJwt();
        if ($username === null) {
            $this->response->setStatusCode(401, 'Unauthorized');
            return ['error' => 'Invalid or missing token'];
        }

        $body         = $this->request->getJsonRawBody(true) ?? [];
        $refreshToken = trim($body['refresh_token'] ?? '');

        if ($refreshToken !== '') {
            // Validate the refresh token to extract its JTI, then revoke
            $raw    = trim($this->backend->configdpRun('netshield mobile_validate_jwt', [$refreshToken]));
            $result = json_decode($raw, true);
            if ($result && ($result['status'] ?? '') === 'ok') {
                $jti = $result['payload']['jti'] ?? '';
                if ($jti !== '') {
                    $this->backend->configdpRun('netshield mobile_revoke_jwt', [$jti]);
                }
            }
        }

        return ['status' => 'ok', 'message' => 'Logged out'];
    }

    // ------------------------------------------------------------------
    // JWT-protected endpoints
    // ------------------------------------------------------------------

    /**
     * GET /api/netshield/mobile/dashboard
     * Returns combined stats: alert counts, device counts, bandwidth, threats.
     */
    public function dashboardAction(): array
    {
        $username = $this->_validateJwt();
        if ($username === null) {
            $this->response->setStatusCode(401, 'Unauthorized');
            return ['error' => 'Invalid or missing token'];
        }

        $alertsRaw    = trim($this->backend->configdRun('netshield get_alerts'));
        $devicesRaw   = trim($this->backend->configdRun('netshield get_devices'));
        $bandwidthRaw = trim($this->backend->configdRun('netshield get_bandwidth'));
        $statsRaw     = trim($this->backend->configdRun('netshield get_stats'));

        $alertsData    = json_decode($alertsRaw,    true) ?? [];
        $devicesData   = json_decode($devicesRaw,   true) ?? [];
        $bandwidth     = json_decode($bandwidthRaw, true) ?? [];
        $stats         = json_decode($statsRaw,     true) ?? [];

        // Scripts return flat lists or wrapped objects — normalize
        $alertsList  = isset($alertsData['alerts'])  ? $alertsData['alerts']  : (is_array($alertsData)  ? $alertsData  : []);
        $devicesList = isset($devicesData['devices']) ? $devicesData['devices'] : (is_array($devicesData) ? $devicesData : []);

        $criticalCount = 0;
        foreach ($alertsList as $a) {
            if (in_array(strtolower($a['severity'] ?? ''), ['critical', 'high'], true)) {
                $criticalCount++;
            }
        }

        return [
            'alerts' => [
                'total'    => count($alertsList),
                'critical' => $criticalCount,
                'recent'   => array_slice($alertsList, 0, 5),
            ],
            'devices' => [
                'total'       => count($devicesList),
                'quarantined' => count(array_filter(
                    $devicesList,
                    fn($d) => ($d['is_quarantined'] ?? 0) == 1
                )),
                'unknown'     => count(array_filter(
                    $devicesList,
                    fn($d) => ($d['is_approved'] ?? 0) == 0
                )),
            ],
            'bandwidth' => $bandwidth,
            'threats'   => is_array($stats) ? ($stats['threats'] ?? $stats) : [],
        ];
    }

    /**
     * GET /api/netshield/mobile/devices
     */
    public function devicesAction(): array
    {
        $username = $this->_validateJwt();
        if ($username === null) {
            $this->response->setStatusCode(401, 'Unauthorized');
            return ['error' => 'Invalid or missing token'];
        }

        $raw    = trim($this->backend->configdRun('netshield get_devices'));
        $result = json_decode($raw, true);

        return $result ?? ['devices' => []];
    }

    /**
     * GET /api/netshield/mobile/alerts
     */
    public function alertsAction(): array
    {
        $username = $this->_validateJwt();
        if ($username === null) {
            $this->response->setStatusCode(401, 'Unauthorized');
            return ['error' => 'Invalid or missing token'];
        }

        $limit  = (int) ($this->request->getQuery('limit', null, 50));
        $limit  = max(1, min(500, $limit));

        $raw    = trim($this->backend->configdRun('netshield get_alerts'));
        $result = json_decode($raw, true);

        if (isset($result['alerts'])) {
            $result['alerts'] = array_slice($result['alerts'], 0, $limit);
        }

        return $result ?? ['alerts' => []];
    }

    /**
     * GET /api/netshield/mobile/websocket_info
     * Returns WebSocket connection parameters for mobile clients.
     */
    public function websocketInfoAction(): array
    {
        $username = $this->_validateJwt();
        if ($username === null) {
            $this->response->setStatusCode(401, 'Unauthorized');
            return ['error' => 'Invalid or missing token'];
        }

        return [
            'host'               => $this->request->getHttpHost(),
            'port'               => 9443,
            'tls'                => true,
            'path'               => '/ws',
            'channels_available' => ['alerts', 'bandwidth', 'devices', 'threats', 'dpi'],
        ];
    }

    // ------------------------------------------------------------------
    // Private helpers
    // ------------------------------------------------------------------

    /**
     * Extract and validate the Bearer JWT from the Authorization header.
     * Returns the username (sub claim) on success, or null on failure.
     */
    private function _validateJwt(): ?string
    {
        $authHeader = $this->request->getHeader('Authorization');
        if (empty($authHeader)) {
            return null;
        }

        if (!str_starts_with($authHeader, 'Bearer ')) {
            return null;
        }

        $token = substr($authHeader, 7);
        if (empty($token)) {
            return null;
        }

        $raw    = trim($this->backend->configdpRun('netshield mobile_validate_jwt', [$token]));
        $result = json_decode($raw, true);

        if (!$result || ($result['status'] ?? '') !== 'ok') {
            return null;
        }

        if (($result['payload']['type'] ?? '') !== 'access') {
            return null;
        }

        return $result['username'] ?? null;
    }

    /**
     * Validate username + password against OPNsense system authentication.
     * Uses password_verify against the system user database if available,
     * otherwise falls back to PAM via the configd helper.
     */
    private function _validateCredentials(string $username, string $password): bool
    {
        // Sanitise username to prevent injection
        if (!preg_match('/^[a-zA-Z0-9._@-]{1,64}$/', $username)) {
            return false;
        }

        // Try OPNsense local auth via configd
        $raw    = trim($this->backend->configdpRun('netshield mobile_auth_user', [$username, $password]));
        $result = json_decode($raw, true);

        if ($result && ($result['status'] ?? '') === 'ok') {
            return true;
        }

        return false;
    }
}
