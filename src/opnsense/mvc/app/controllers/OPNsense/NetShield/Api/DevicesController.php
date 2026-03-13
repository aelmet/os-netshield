<?php

/**
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (C) 2024-2026 NetShield Contributors
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
 */

namespace OPNsense\NetShield\Api;

use OPNsense\Base\ApiControllerBase;
use OPNsense\Core\Backend;
use OPNsense\NetShield\NetShield;

/**
 * Class DevicesController
 *
 * Manages runtime device discovery data and quarantine operations.
 * Device configuration (approved list) interacts with the NetShield model.
 * Live discovery data comes from the running daemon via configd.
 *
 * Endpoints:
 *   GET  api/netshield/devices/list              — discovered devices
 *   POST api/netshield/devices/quarantine        — quarantine by MAC
 *   POST api/netshield/devices/unquarantine      — lift quarantine by MAC
 *
 * @package OPNsense\NetShield\Api
 */
class DevicesController extends ApiControllerBase
{
    /**
     * Retrieve the list of all currently discovered network devices.
     *
     * Combines live ARP/DHCP data from the daemon with the approved-device
     * configuration stored in the NetShield model so the UI can show both
     * known and unknown devices in a single merged view.
     *
     * @return array JSON-serialisable device list
     */
    public function listAction()
    {
        if ($this->request->isGet()) {
            $backend = new Backend();
            $rawResponse = trim($backend->configdRun('netshield list_devices'));

            $discovered = [];
            if (!empty($rawResponse)) {
                $decoded = json_decode($rawResponse, true);
                if (json_last_error() === JSON_ERROR_NONE && isset($decoded['devices'])) {
                    $discovered = $decoded['devices'];
                }
            }

            // Enrich with approved/configured status from model
            $model    = new NetShield();
            $approved = [];
            foreach ($model->devices->device->iterateItems() as $uuid => $device) {
                $mac = strtolower((string)$device->mac);
                $approved[$mac] = [
                    'uuid'        => $uuid,
                    'name'        => (string)$device->name,
                    'category'    => (string)$device->category,
                    'approved'    => (string)$device->approved === '1',
                    'description' => (string)$device->description,
                ];
            }

            foreach ($discovered as &$dev) {
                $mac = strtolower($dev['mac'] ?? '');
                if (isset($approved[$mac])) {
                    $dev = array_merge($dev, $approved[$mac]);
                } else {
                    $dev['approved']  = false;
                    $dev['name']      = $dev['name'] ?? '';
                    $dev['category']  = 'other';
                }
            }
            unset($dev);

            return ['devices' => array_values($discovered), 'total' => count($discovered)];
        }

        return $this->returnErrorStatus(405, 'Method Not Allowed');
    }

    /**
     * Quarantine a device by MAC address.
     *
     * Quarantining isolates the device by instructing the daemon to apply
     * blocking firewall rules for all traffic from that MAC address.
     * The device remains visible in the UI with a quarantine status flag.
     *
     * POST body:
     *   - mac  (string, required) MAC address of the device to quarantine
     *
     * @return array Result status
     */
    public function quarantineAction()
    {
        if ($this->request->isPost()) {
            $mac = trim($this->request->getPost('mac', 'string', ''));

            if (empty($mac) || !preg_match('/^([0-9A-Fa-f]{2}[:\-]){5}([0-9A-Fa-f]{2})$/', $mac)) {
                $this->response->setStatusCode(400);
                return ['status' => 'error', 'message' => 'Invalid or missing MAC address'];
            }

            $backend     = new Backend();
            $rawResponse = trim($backend->configdRun('netshield quarantine_device ' . escapeshellarg($mac)));

            if (empty($rawResponse)) {
                return ['status' => 'error', 'message' => 'No response from daemon'];
            }

            $data = json_decode($rawResponse, true);
            if (json_last_error() !== JSON_ERROR_NONE) {
                return ['status' => 'error', 'message' => 'Invalid daemon response'];
            }

            return $data;
        }

        return $this->returnErrorStatus(405, 'Method Not Allowed');
    }

    /**
     * Lift quarantine from a device by MAC address.
     *
     * Removes the isolation firewall rules applied by quarantineAction,
     * restoring normal policy-based network access for the device.
     *
     * POST body:
     *   - mac  (string, required) MAC address of the device to unquarantine
     *
     * @return array Result status
     */
    public function unquarantineAction()
    {
        if ($this->request->isPost()) {
            $mac = trim($this->request->getPost('mac', 'string', ''));

            if (empty($mac) || !preg_match('/^([0-9A-Fa-f]{2}[:\-]){5}([0-9A-Fa-f]{2})$/', $mac)) {
                $this->response->setStatusCode(400);
                return ['status' => 'error', 'message' => 'Invalid or missing MAC address'];
            }

            $backend     = new Backend();
            $rawResponse = trim($backend->configdRun('netshield unquarantine_device ' . escapeshellarg($mac)));

            if (empty($rawResponse)) {
                return ['status' => 'error', 'message' => 'No response from daemon'];
            }

            $data = json_decode($rawResponse, true);
            if (json_last_error() !== JSON_ERROR_NONE) {
                return ['status' => 'error', 'message' => 'Invalid daemon response'];
            }

            return $data;
        }

        return $this->returnErrorStatus(405, 'Method Not Allowed');
    }

    /**
     * Helper: return a minimal error structure with HTTP status code.
     *
     * @param int    $statusCode HTTP status code
     * @param string $message    Human-readable message
     * @return array
     */
    private function returnErrorStatus(int $statusCode, string $message): array
    {
        $this->response->setStatusCode($statusCode);
        return ['status' => 'error', 'message' => $message];
    }
}
