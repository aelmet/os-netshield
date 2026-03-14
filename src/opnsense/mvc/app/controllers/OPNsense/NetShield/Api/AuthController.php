<?php
/*
 * Copyright (C) 2025 NetShield
 * BSD 2-Clause License
 */

namespace OPNsense\NetShield\Api;

use OPNsense\Base\ApiControllerBase;
use OPNsense\Core\Backend;

/**
 * Mobile Auth API Controller - public endpoints for mobile app authentication.
 */
class AuthController extends ApiControllerBase
{
    private Backend $backend;

    /**
     * Allow unauthenticated access to all actions in this controller.
     */
    public function beforeExecuteRoute($dispatcher)
    {
        // All endpoints in this controller are public (JWT-based auth)
        return true;
    }

    public function initialize(): void
    {
        parent::initialize();
        $this->backend = new Backend();
    }

    private function encParam(string $val): string
    {
        return rawurlencode($val);
    }

    /**
     * POST /api/netshield/auth/token
     * Authenticate and get JWT tokens
     */
    public function tokenAction(): array
    {
        if ($this->request->getMethod() !== 'POST') {
            $this->response->setStatusCode(405, 'Method Not Allowed');
            return ['error' => 'POST required'];
        }

        $body = $this->request->getJsonRawBody(true) ?? [];
        $username = trim($body['username'] ?? '');
        $password = $body['password'] ?? '';
        $deviceName = trim($body['device_name'] ?? '');
        $deviceId = trim($body['device_id'] ?? '');

        if ($username === '' || $password === '') {
            $this->response->setStatusCode(400, 'Bad Request');
            return ['error' => 'username and password are required'];
        }

        // Validate credentials
        if (!$this->_validateCredentials($username, $password)) {
            $this->response->setStatusCode(401, 'Unauthorized');
            return ['error' => 'Invalid credentials'];
        }

        // Generate JWT tokens
        $raw = trim($this->backend->configdRun(
            'netshield mobile_generate_jwt ' . $this->encParam($username)
            . ',' . $this->encParam($deviceName)
            . ',' . $this->encParam($deviceId)
        ));
        $result = json_decode($raw, true);

        if (!$result || ($result['status'] ?? '') !== 'ok') {
            $this->response->setStatusCode(500, 'Internal Server Error');
            return ['error' => 'Token generation failed'];
        }

        return [
            'access_token' => $result['access_token'],
            'refresh_token' => $result['refresh_token'],
            'expires_in' => $result['expires_in'] ?? 900,
            'token_type' => 'Bearer',
        ];
    }

    /**
     * POST /api/netshield/auth/refresh
     * Refresh access token
     */
    public function refreshAction(): array
    {
        if ($this->request->getMethod() !== 'POST') {
            $this->response->setStatusCode(405, 'Method Not Allowed');
            return ['error' => 'POST required'];
        }

        $body = $this->request->getJsonRawBody(true) ?? [];
        $refreshToken = trim($body['refresh_token'] ?? '');

        if ($refreshToken === '') {
            $this->response->setStatusCode(400, 'Bad Request');
            return ['error' => 'refresh_token is required'];
        }

        $raw = trim($this->backend->configdRun('netshield mobile_refresh_jwt ' . $this->encParam($refreshToken)));
        $result = json_decode($raw, true);

        if (!$result || ($result['status'] ?? '') !== 'ok') {
            $this->response->setStatusCode(401, 'Unauthorized');
            return ['error' => 'Invalid or expired refresh token'];
        }

        return [
            'access_token' => $result['access_token'],
            'expires_in' => 900,
            'token_type' => 'Bearer',
        ];
    }

    /**
     * POST /api/netshield/auth/sendcredentials
     * Generate OTP and send mobile app setup credentials to Telegram (public endpoint).
     */
    public function sendcredentialsAction(): array
    {
        if ($this->request->getMethod() !== 'POST') {
            $this->response->setStatusCode(405, 'Method Not Allowed');
            return ['error' => 'POST required'];
        }

        $raw = trim($this->backend->configdRun('netshield mobile_send_setup_telegram'));
        $result = json_decode($raw, true);

        if ($result && ($result['status'] ?? '') === 'ok') {
            return [
                'status' => 'ok',
                'message' => $result['message'] ?? 'Setup info sent to Telegram',
            ];
        }

        $this->response->setStatusCode(500, 'Internal Server Error');
        return [
            'status' => 'error',
            'message' => $result['message'] ?? 'Failed to send credentials to Telegram',
        ];
    }

    private function _validateCredentials(string $username, string $password): bool
    {
        if (!preg_match('/^[a-zA-Z0-9._@-]{1,64}$/', $username)) {
            return false;
        }

        $raw = trim($this->backend->configdRun(
            'netshield mobile_auth_user ' . $this->encParam($username)
            . ',' . $this->encParam($password)
        ));
        $result = json_decode($raw, true);

        return $result && ($result['status'] ?? '') === 'ok';
    }
}
