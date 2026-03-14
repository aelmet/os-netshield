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
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
 * OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

namespace OPNsense\NetShield;

class IndexController extends \OPNsense\Base\IndexController
{
    public function indexAction()
    {
        $this->view->pick('OPNsense/NetShield/index');
    }

    public function devicesAction()
    {
        $this->view->pick('OPNsense/NetShield/devices');
    }

    public function settingsAction()
    {
        $this->view->pick('OPNsense/NetShield/settings');
    }

    public function policiesAction()
    {
        $this->view->title = gettext('NetShield - Policies');
        $this->view->pick('OPNsense/NetShield/policies');
    }

    public function bandwidthAction()
    {
        $this->view->title = gettext('NetShield - Bandwidth');
        $this->view->pick('OPNsense/NetShield/bandwidth');
    }

    public function threatsAction()
    {
        $this->view->title = gettext('NetShield - Threat Intelligence');
        $this->view->pick('OPNsense/NetShield/threats');
    }

    public function geoipAction()
    {
        $this->view->title = gettext('NetShield - GeoIP');
        $this->view->pick('OPNsense/NetShield/geoip');
    }

    public function dnsAction()
    {
        $this->view->title = gettext('NetShield - DNS Filter');
        $this->view->pick('OPNsense/NetShield/dns');
    }

    public function parentalAction()
    {
        $this->view->title = gettext('NetShield - Parental Controls');
        $this->view->pick('OPNsense/NetShield/parental');
    }

    public function networkAction()
    {
        $this->view->title = gettext('NetShield - Network');
        $this->view->pick('OPNsense/NetShield/network');
    }

    public function scannerAction()
    {
        $this->view->title = gettext('NetShield - Scanner');
        $this->view->pick('OPNsense/NetShield/scanner');
    }

    public function fusionvpnAction()
    {
        $this->view->title = gettext('NetShield - Fusion VPN');
        $this->view->pick('OPNsense/NetShield/fusionvpn');
    }

    public function dashboardAction()
    {
        $this->view->title = gettext('NetShield - Dashboard');
        $this->view->pick('OPNsense/NetShield/dashboard');
    }

    public function idsAction()
    {
        $this->view->title = gettext('NetShield - IDS/IPS');
        $this->view->pick('OPNsense/NetShield/ids');
    }

    public function webcategoriesAction()
    {
        $this->view->title = gettext('NetShield - Web Categories');
        $this->view->pick('OPNsense/NetShield/webcategories');
    }

    public function targetlistsAction()
    {
        $this->view->title = gettext('NetShield - Target Lists');
        $this->view->pick('OPNsense/NetShield/targetlists');
    }

    public function appsignaturesAction()
    {
        $this->view->title = gettext('NetShield - Application Signatures');
        $this->view->pick('OPNsense/NetShield/appsignatures');
    }

    public function alertsAction()
    {
        $this->view->title = gettext('NetShield - Alerts');
        $this->view->pick('OPNsense/NetShield/alerts');
    }

    public function sessionsAction()
    {
        $this->view->title = gettext('NetShield - Sessions');
        $this->view->pick('OPNsense/NetShield/sessions');
    }

    public function torAction()
    {
        $this->view->title = gettext('NetShield - Tor Blocking');
        $this->view->pick('OPNsense/NetShield/tor');
    }
}
