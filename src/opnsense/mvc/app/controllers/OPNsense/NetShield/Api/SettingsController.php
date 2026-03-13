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

use OPNsense\Base\ApiMutableModelControllerBase;
use OPNsense\Base\UserException;
use OPNsense\Core\Config;

/**
 * Class SettingsController
 *
 * Provides CRUD REST API for all NetShield configuration sections.
 * Scalar sections (general, dns, detection, enforcement, alerts, geoip) are
 * accessed via the inherited getAction / setAction pair from the base class.
 *
 * ArrayField sections each expose:
 *   GET  api/netshield/settings/search{Entity}
 *   GET  api/netshield/settings/get{Entity}/<uuid>
 *   POST api/netshield/settings/add{Entity}
 *   POST api/netshield/settings/set{Entity}/<uuid>
 *   POST api/netshield/settings/del{Entity}/<uuid>
 *
 * @package OPNsense\NetShield\Api
 */
class SettingsController extends ApiMutableModelControllerBase
{
    /**
     * Short model name used for JSON key wrapping in request/response bodies.
     *
     * @var string
     */
    protected static $internalModelName = 'netshield';

    /**
     * Fully-qualified model class.
     *
     * @var string
     */
    protected static $internalModelClass = '\OPNsense\NetShield\NetShield';

    // ----------------------------------------------------------------
    // Devices
    // ----------------------------------------------------------------

    /**
     * Search/list all configured devices with pagination.
     * GET api/netshield/settings/searchDevice
     */
    public function searchDeviceAction()
    {
        return $this->searchBase('devices.device', ['name', 'mac', 'ip', 'category', 'approved', 'description']);
    }

    /**
     * Retrieve a single device record by UUID.
     * GET api/netshield/settings/getDevice/<uuid>
     *
     * @param string|null $uuid
     */
    public function getDeviceAction($uuid = null)
    {
        return $this->getBase('device', 'devices.device', $uuid);
    }

    /**
     * Create a new device record.
     * POST api/netshield/settings/addDevice
     */
    public function addDeviceAction()
    {
        return $this->addBase('device', 'devices.device');
    }

    /**
     * Update an existing device record.
     * POST api/netshield/settings/setDevice/<uuid>
     *
     * @param string $uuid
     */
    public function setDeviceAction($uuid)
    {
        return $this->setBase('device', 'devices.device', $uuid);
    }

    /**
     * Delete a device record.
     * POST api/netshield/settings/delDevice/<uuid>
     *
     * @param string $uuid
     */
    public function delDeviceAction($uuid)
    {
        return $this->delBase('devices.device', $uuid);
    }

    // ----------------------------------------------------------------
    // Policies
    // ----------------------------------------------------------------

    /**
     * Search/list all configured policies.
     * GET api/netshield/settings/searchPolicy
     */
    public function searchPolicyAction()
    {
        return $this->searchBase(
            'policies.policy',
            ['name', 'enabled', 'scope', 'scope_value', 'action', 'target_type', 'target_value', 'priority', 'description']
        );
    }

    /**
     * Retrieve a single policy by UUID.
     * GET api/netshield/settings/getPolicy/<uuid>
     *
     * @param string|null $uuid
     */
    public function getPolicyAction($uuid = null)
    {
        return $this->getBase('policy', 'policies.policy', $uuid);
    }

    /**
     * Create a new policy.
     * POST api/netshield/settings/addPolicy
     */
    public function addPolicyAction()
    {
        return $this->addBase('policy', 'policies.policy');
    }

    /**
     * Update an existing policy.
     * POST api/netshield/settings/setPolicy/<uuid>
     *
     * @param string $uuid
     */
    public function setPolicyAction($uuid)
    {
        return $this->setBase('policy', 'policies.policy', $uuid);
    }

    /**
     * Delete a policy.
     * POST api/netshield/settings/delPolicy/<uuid>
     *
     * @param string $uuid
     */
    public function delPolicyAction($uuid)
    {
        return $this->delBase('policies.policy', $uuid);
    }

    // ----------------------------------------------------------------
    // Applications
    // ----------------------------------------------------------------

    /**
     * Search/list all application signatures.
     * GET api/netshield/settings/searchApplication
     */
    public function searchApplicationAction()
    {
        return $this->searchBase('applications.app', ['name', 'category', 'domains', 'sni_patterns', 'enabled']);
    }

    /**
     * Retrieve a single application signature by UUID.
     * GET api/netshield/settings/getApplication/<uuid>
     *
     * @param string|null $uuid
     */
    public function getApplicationAction($uuid = null)
    {
        return $this->getBase('app', 'applications.app', $uuid);
    }

    /**
     * Create a new application signature.
     * POST api/netshield/settings/addApplication
     */
    public function addApplicationAction()
    {
        return $this->addBase('app', 'applications.app');
    }

    /**
     * Update an existing application signature.
     * POST api/netshield/settings/setApplication/<uuid>
     *
     * @param string $uuid
     */
    public function setApplicationAction($uuid)
    {
        return $this->setBase('app', 'applications.app', $uuid);
    }

    /**
     * Delete an application signature.
     * POST api/netshield/settings/delApplication/<uuid>
     *
     * @param string $uuid
     */
    public function delApplicationAction($uuid)
    {
        return $this->delBase('applications.app', $uuid);
    }

    // ----------------------------------------------------------------
    // Web Categories
    // ----------------------------------------------------------------

    /**
     * Search/list all web categories.
     * GET api/netshield/settings/searchWebcategory
     */
    public function searchWebcategoryAction()
    {
        return $this->searchBase('webcategories.category', ['name', 'enabled', 'source_url', 'description']);
    }

    /**
     * Retrieve a single web category by UUID.
     * GET api/netshield/settings/getWebcategory/<uuid>
     *
     * @param string|null $uuid
     */
    public function getWebcategoryAction($uuid = null)
    {
        return $this->getBase('category', 'webcategories.category', $uuid);
    }

    /**
     * Create a new web category.
     * POST api/netshield/settings/addWebcategory
     */
    public function addWebcategoryAction()
    {
        return $this->addBase('category', 'webcategories.category');
    }

    /**
     * Update an existing web category.
     * POST api/netshield/settings/setWebcategory/<uuid>
     *
     * @param string $uuid
     */
    public function setWebcategoryAction($uuid)
    {
        return $this->setBase('category', 'webcategories.category', $uuid);
    }

    /**
     * Delete a web category.
     * POST api/netshield/settings/delWebcategory/<uuid>
     *
     * @param string $uuid
     */
    public function delWebcategoryAction($uuid)
    {
        return $this->delBase('webcategories.category', $uuid);
    }

    // ----------------------------------------------------------------
    // Target Lists
    // ----------------------------------------------------------------

    /**
     * Search/list all target lists.
     * GET api/netshield/settings/searchTargetlist
     */
    public function searchTargetlistAction()
    {
        return $this->searchBase(
            'targetlists.targetlist',
            ['name', 'enabled', 'list_type', 'source_url', 'update_interval', 'description']
        );
    }

    /**
     * Retrieve a single target list by UUID.
     * GET api/netshield/settings/getTargetlist/<uuid>
     *
     * @param string|null $uuid
     */
    public function getTargetlistAction($uuid = null)
    {
        return $this->getBase('targetlist', 'targetlists.targetlist', $uuid);
    }

    /**
     * Create a new target list.
     * POST api/netshield/settings/addTargetlist
     */
    public function addTargetlistAction()
    {
        return $this->addBase('targetlist', 'targetlists.targetlist');
    }

    /**
     * Update an existing target list.
     * POST api/netshield/settings/setTargetlist/<uuid>
     *
     * @param string $uuid
     */
    public function setTargetlistAction($uuid)
    {
        return $this->setBase('targetlist', 'targetlists.targetlist', $uuid);
    }

    /**
     * Delete a target list.
     * POST api/netshield/settings/delTargetlist/<uuid>
     *
     * @param string $uuid
     */
    public function delTargetlistAction($uuid)
    {
        return $this->delBase('targetlists.targetlist', $uuid);
    }
}
