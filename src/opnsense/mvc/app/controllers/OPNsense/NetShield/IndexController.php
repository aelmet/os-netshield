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

namespace OPNsense\NetShield;

use OPNsense\Base\UIModelGrid;

/**
 * Class IndexController
 *
 * Handles all UI page rendering for the NetShield plugin.
 * Each action maps to a Volt template under views/OPNsense/NetShield/.
 *
 * @package OPNsense\NetShield
 */
class IndexController extends \OPNsense\Base\IndexController
{
    /**
     * Dashboard — overview of service status, active alerts, and detected devices.
     */
    public function indexAction()
    {
        $this->view->pick('OPNsense/NetShield/index');
    }

    /**
     * Devices — list and manage discovered network devices.
     */
    public function devicesAction()
    {
        $this->view->pick('OPNsense/NetShield/devices');
    }

    /**
     * Policies — create and manage traffic enforcement policies.
     */
    public function policiesAction()
    {
        $this->view->pick('OPNsense/NetShield/policies');
    }

    /**
     * Applications — manage application identification signatures.
     */
    public function applicationsAction()
    {
        $this->view->pick('OPNsense/NetShield/applications');
    }

    /**
     * Web Categories — manage URL/domain content category lists.
     */
    public function webcategoriesAction()
    {
        $this->view->pick('OPNsense/NetShield/webcategories');
    }

    /**
     * DNS Filtering — configure DNS-based content filtering and enforcement.
     */
    public function dnsAction()
    {
        $this->view->pick('OPNsense/NetShield/dns');
    }

    /**
     * Target Lists — manage domain and IP block/allow lists with auto-update.
     */
    public function targetlistsAction()
    {
        $this->view->pick('OPNsense/NetShield/targetlists');
    }

    /**
     * GeoIP — configure country-based blocking rules.
     */
    public function geoipAction()
    {
        $this->view->pick('OPNsense/NetShield/geoip');
    }

    /**
     * Alerts — view, filter, and manage security alert history.
     */
    public function alertsAction()
    {
        $this->view->pick('OPNsense/NetShield/alerts');
    }

    /**
     * Settings — configure general, detection, enforcement, and notification settings.
     */
    public function settingsAction()
    {
        $this->view->pick('OPNsense/NetShield/settings');
    }
}
