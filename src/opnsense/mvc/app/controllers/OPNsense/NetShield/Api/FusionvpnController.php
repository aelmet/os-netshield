<?php

/*
 * Copyright (C) 2025-2026 NetShield Contributors
 * All rights reserved.
 *
 * Fusion VPN Controller - multi-VPN profile management
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

namespace OPNsense\NetShield\Api;

use OPNsense\Base\ApiControllerBase;
use OPNsense\Core\Backend;

class FusionvpnController extends JwtAwareController
{
    /**
     * GET /api/netshield/fusionvpn/status
     * Get overall Fusion VPN status
     */
    public function statusAction()
    {
        $backend = new Backend();
        $raw = $backend->configdRun('netshield fusion_vpn status');
        $data = json_decode($raw, true);
        return $data ?: ['status' => 'error', 'message' => 'Failed to get status'];
    }

    /**
     * GET /api/netshield/fusionvpn/profiles
     * List all VPN profiles
     */
    public function profilesAction()
    {
        $backend = new Backend();
        $raw = $backend->configdRun('netshield fusion_vpn profiles');
        $data = json_decode($raw, true);
        return ['profiles' => $data ?: []];
    }

    /**
     * GET /api/netshield/fusionvpn/profile
     * Get a single profile by ID
     */
    public function profileAction()
    {
        $id = (int)$this->request->get('id');
        if (!$id) {
            return ['status' => 'error', 'message' => 'id required'];
        }

        $backend = new Backend();
        $raw = $backend->configdRun('netshield fusion_vpn profile,' . escapeshellarg($id));
        return json_decode($raw, true) ?: ['status' => 'error', 'message' => 'Profile not found'];
    }

    /**
     * POST /api/netshield/fusionvpn/createProfile
     * Create a new VPN profile
     */
    public function createProfileAction()
    {
        if (!$this->request->isPost()) {
            return ['status' => 'error', 'message' => 'POST required'];
        }

        $name = trim($this->request->getPost('name') ?? '');
        $protocol = trim($this->request->getPost('protocol') ?? 'openvpn');
        $configContent = trim($this->request->getPost('config_content') ?? '');
        $username = trim($this->request->getPost('username') ?? '');
        $password = trim($this->request->getPost('password') ?? '');
        $applyToAll = $this->request->getPost('apply_to_all') ?? '1';
        $killSwitch = $this->request->getPost('kill_switch') ?? '0';

        if (empty($name)) {
            return ['status' => 'error', 'message' => 'name required'];
        }

        if (empty($configContent)) {
            return ['status' => 'error', 'message' => 'config_content required'];
        }

        // Base64 encode the config content to safely pass it
        $configBase64 = base64_encode($configContent);

        $backend = new Backend();
        $cmd = sprintf(
            'netshield fusion_vpn create,name=%s,protocol=%s,config_base64=%s,apply_to_all=%s,kill_switch=%s',
            escapeshellarg($name),
            escapeshellarg($protocol),
            escapeshellarg($configBase64),
            escapeshellarg($applyToAll),
            escapeshellarg($killSwitch)
        );

        if (!empty($username)) {
            $cmd .= ',username=' . escapeshellarg($username);
        }
        if (!empty($password)) {
            $cmd .= ',password=' . escapeshellarg($password);
        }

        $raw = $backend->configdRun($cmd);
        return json_decode($raw, true) ?: ['status' => 'error', 'message' => 'Failed to create profile'];
    }

    /**
     * POST /api/netshield/fusionvpn/updateProfile
     * Update a VPN profile
     */
    public function updateProfileAction()
    {
        if (!$this->request->isPost()) {
            return ['status' => 'error', 'message' => 'POST required'];
        }

        $id = (int)$this->request->getPost('id');
        if (!$id) {
            return ['status' => 'error', 'message' => 'id required'];
        }

        $params = ['id=' . $id];

        $fields = ['name', 'username', 'password', 'apply_to_all', 'kill_switch', 'enabled'];
        foreach ($fields as $field) {
            $value = $this->request->getPost($field);
            if ($value !== null && $value !== '') {
                $params[] = $field . '=' . escapeshellarg($value);
            }
        }

        $backend = new Backend();
        $raw = $backend->configdRun('netshield fusion_vpn update,' . implode(',', $params));
        return json_decode($raw, true) ?: ['status' => 'error', 'message' => 'Failed to update profile'];
    }

    /**
     * POST /api/netshield/fusionvpn/deleteProfile
     * Delete a VPN profile
     */
    public function deleteProfileAction()
    {
        if (!$this->request->isPost()) {
            return ['status' => 'error', 'message' => 'POST required'];
        }

        $id = (int)$this->request->getPost('id');
        if (!$id) {
            return ['status' => 'error', 'message' => 'id required'];
        }

        $backend = new Backend();
        $raw = $backend->configdRun('netshield fusion_vpn delete,' . escapeshellarg($id));
        return json_decode($raw, true) ?: ['status' => 'error', 'message' => 'Failed to delete profile'];
    }

    /**
     * POST /api/netshield/fusionvpn/connect
     * Connect a VPN profile
     */
    public function connectAction()
    {
        if (!$this->request->isPost()) {
            return ['status' => 'error', 'message' => 'POST required'];
        }

        $id = (int)$this->request->getPost('id');
        if (!$id) {
            return ['status' => 'error', 'message' => 'id required'];
        }

        $backend = new Backend();
        $raw = $backend->configdRun('netshield fusion_vpn connect,' . escapeshellarg($id));
        return json_decode($raw, true) ?: ['status' => 'error', 'message' => 'Failed to connect'];
    }

    /**
     * POST /api/netshield/fusionvpn/disconnect
     * Disconnect a VPN profile
     */
    public function disconnectAction()
    {
        if (!$this->request->isPost()) {
            return ['status' => 'error', 'message' => 'POST required'];
        }

        $id = (int)$this->request->getPost('id');
        if (!$id) {
            return ['status' => 'error', 'message' => 'id required'];
        }

        $backend = new Backend();
        $raw = $backend->configdRun('netshield fusion_vpn disconnect,' . escapeshellarg($id));
        return json_decode($raw, true) ?: ['status' => 'error', 'message' => 'Failed to disconnect'];
    }

    /**
     * GET /api/netshield/fusionvpn/assignments
     * Get device assignments
     */
    public function assignmentsAction()
    {
        $profileId = (int)$this->request->get('profile_id');

        $backend = new Backend();
        $cmd = 'netshield fusion_vpn assignments';
        if ($profileId) {
            $cmd .= ',profile_id=' . escapeshellarg($profileId);
        }

        $raw = $backend->configdRun($cmd);
        $data = json_decode($raw, true);
        return ['assignments' => $data ?: []];
    }

    /**
     * POST /api/netshield/fusionvpn/assignDevice
     * Assign a device to a VPN profile
     */
    public function assignDeviceAction()
    {
        if (!$this->request->isPost()) {
            return ['status' => 'error', 'message' => 'POST required'];
        }

        $profileId = (int)$this->request->getPost('profile_id');
        $deviceMac = trim($this->request->getPost('device_mac') ?? '');
        $deviceName = trim($this->request->getPost('device_name') ?? '');

        if (!$profileId || empty($deviceMac)) {
            return ['status' => 'error', 'message' => 'profile_id and device_mac required'];
        }

        $backend = new Backend();
        $cmd = sprintf(
            'netshield fusion_vpn assign,profile_id=%s,device_mac=%s',
            escapeshellarg($profileId),
            escapeshellarg($deviceMac)
        );
        if (!empty($deviceName)) {
            $cmd .= ',device_name=' . escapeshellarg($deviceName);
        }

        $raw = $backend->configdRun($cmd);
        return json_decode($raw, true) ?: ['status' => 'error', 'message' => 'Failed to assign device'];
    }

    /**
     * POST /api/netshield/fusionvpn/unassignDevice
     * Remove a device assignment
     */
    public function unassignDeviceAction()
    {
        if (!$this->request->isPost()) {
            return ['status' => 'error', 'message' => 'POST required'];
        }

        $id = (int)$this->request->getPost('id');
        if (!$id) {
            return ['status' => 'error', 'message' => 'id required'];
        }

        $backend = new Backend();
        $raw = $backend->configdRun('netshield fusion_vpn unassign,' . escapeshellarg($id));
        return json_decode($raw, true) ?: ['status' => 'error', 'message' => 'Failed to unassign device'];
    }

    /**
     * GET /api/netshield/fusionvpn/exceptions
     * Get exception devices (bypass VPN)
     */
    public function exceptionsAction()
    {
        $backend = new Backend();
        $raw = $backend->configdRun('netshield fusion_vpn exceptions');
        $data = json_decode($raw, true);
        return ['exceptions' => $data ?: []];
    }

    /**
     * POST /api/netshield/fusionvpn/addException
     * Add a device to exception list
     */
    public function addExceptionAction()
    {
        if (!$this->request->isPost()) {
            return ['status' => 'error', 'message' => 'POST required'];
        }

        $deviceMac = trim($this->request->getPost('device_mac') ?? '');
        $deviceName = trim($this->request->getPost('device_name') ?? '');
        $reason = trim($this->request->getPost('reason') ?? '');

        if (empty($deviceMac)) {
            return ['status' => 'error', 'message' => 'device_mac required'];
        }

        $backend = new Backend();
        $cmd = 'netshield fusion_vpn add-exception,device_mac=' . escapeshellarg($deviceMac);
        if (!empty($deviceName)) {
            $cmd .= ',device_name=' . escapeshellarg($deviceName);
        }
        if (!empty($reason)) {
            $cmd .= ',reason=' . escapeshellarg($reason);
        }

        $raw = $backend->configdRun($cmd);
        return json_decode($raw, true) ?: ['status' => 'error', 'message' => 'Failed to add exception'];
    }

    /**
     * POST /api/netshield/fusionvpn/removeException
     * Remove a device from exception list
     */
    public function removeExceptionAction()
    {
        if (!$this->request->isPost()) {
            return ['status' => 'error', 'message' => 'POST required'];
        }

        $id = (int)$this->request->getPost('id');
        if (!$id) {
            return ['status' => 'error', 'message' => 'id required'];
        }

        $backend = new Backend();
        $raw = $backend->configdRun('netshield fusion_vpn remove-exception,' . escapeshellarg($id));
        return json_decode($raw, true) ?: ['status' => 'error', 'message' => 'Failed to remove exception'];
    }
}
