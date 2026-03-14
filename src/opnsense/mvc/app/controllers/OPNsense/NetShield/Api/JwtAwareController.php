<?php
/*
 * Copyright (C) 2025 NetShield
 * BSD 2-Clause License
 *
 * Base controller that accepts both JWT Bearer tokens (mobile app)
 * and OPNsense session/API-key auth (web GUI).
 */

namespace OPNsense\NetShield\Api;

use OPNsense\Base\ApiControllerBase;
use OPNsense\Core\Backend;

class JwtAwareController extends ApiControllerBase
{
    /**
     * Accept JWT Bearer OR OPNsense session auth.
     * If a Bearer token is present and valid, allow access.
     * Otherwise fall back to normal OPNsense session auth.
     */
    public function beforeExecuteRoute($dispatcher)
    {
        $authHeader = $this->request->getHeader('Authorization');
        if (!empty($authHeader) && str_starts_with($authHeader, 'Bearer ')) {
            $token = substr($authHeader, 7);
            if (!empty($token) && $this->_jwtIsValid($token)) {
                return true;
            }
            $this->response->setStatusCode(401, 'Unauthorized');
            $this->response->setJsonContent(['error' => 'Invalid or expired token']);
            $this->response->send();
            return false;
        }
        // No Bearer token — fall back to OPNsense session auth (web GUI)
        return parent::beforeExecuteRoute($dispatcher);
    }

    /**
     * Validate a JWT token via configd.
     */
    private function _jwtIsValid(string $token): bool
    {
        $backend = new Backend();
        $raw = trim($backend->configdpRun('netshield mobile_validate_jwt', [$token]));
        $result = json_decode($raw, true);
        return $result && ($result['status'] ?? '') === 'ok';
    }
}
