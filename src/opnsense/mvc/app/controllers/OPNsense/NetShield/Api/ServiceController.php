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

use OPNsense\Base\ApiMutableServiceControllerBase;
use OPNsense\Core\Backend;

/**
 * Class ServiceController
 *
 * Provides service lifecycle endpoints for the NetShield daemon.
 * Inherits start/stop/restart/reconfigure actions from the base class.
 *
 * Endpoints (via ApiMutableServiceControllerBase):
 *   GET  api/netshield/service/start
 *   GET  api/netshield/service/stop
 *   GET  api/netshield/service/restart
 *   POST api/netshield/service/reconfigure
 *   GET  api/netshield/service/status
 *
 * @package OPNsense\NetShield\Api
 */
class ServiceController extends ApiMutableServiceControllerBase
{
    /**
     * Model class used by the base controller to read configuration
     * and determine whether the service should be running.
     *
     * @var string
     */
    protected static $internalServiceClass = '\OPNsense\NetShield\NetShield';

    /**
     * Configuration field (dot-notation) whose value determines whether
     * the service is enabled.  Maps to //OPNsense/netshield/general/enabled.
     *
     * @var string
     */
    protected static $internalServiceEnabled = 'general.enabled';

    /**
     * Name of the configd template to render when reconfiguring.
     * The template lives at:
     *   /usr/local/opnsense/service/templates/OPNsense/NetShield/
     *
     * @var string
     */
    protected static $internalServiceTemplate = 'OPNsense/NetShield';

    /**
     * RC service name as registered with configd / rc.d.
     *
     * @var string
     */
    protected static $internalServiceName = 'netshield';
}
