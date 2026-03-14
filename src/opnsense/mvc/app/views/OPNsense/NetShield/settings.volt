{#
# Copyright (c) 2024 Your Name
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice,
# this list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright notice,
# this list of conditions and the following disclaimer in the documentation
# and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
#}

<script>
    $(document).ready(function () {

        /*
         * Service control helpers
         */
        function updateServiceStatus() {
            ajaxCall('/api/netshield/service/status', {}, function (data) {
                if (data && (data.status || data.result)) {
                    var running = (data.status === 'running' || data.result === 'running');
                    $('#service-status-badge')
                        .removeClass('label-success label-danger label-default')
                        .addClass(running ? 'label-success' : 'label-danger')
                        .text(running ? lang._('Running') : lang._('Stopped'));
                    $('#btn-service-stop').prop('disabled', !running);
                    $('#btn-service-start').prop('disabled', running);
                    $('#btn-service-restart').prop('disabled', !running);
                } else {
                    $('#service-status-badge')
                        .removeClass('label-success label-danger')
                        .addClass('label-default')
                        .text(lang._('Unknown'));
                }
            });
        }

        function serviceAction(action) {
            $('#btn-service-start, #btn-service-stop, #btn-service-restart').prop('disabled', true);
            ajaxCall('/api/netshield/service/' + action, {}, function (data) {
                setTimeout(updateServiceStatus, 1500);
            });
        }

        $('#btn-service-start').on('click', function () {
            serviceAction('start');
        });

        $('#btn-service-stop').on('click', function () {
            BootstrapDialog.confirm({
                title: lang._('Stop NetShield'),
                message: lang._('Stop the NetShield service? Monitoring will be disabled.'),
                type: BootstrapDialog.TYPE_WARNING,
                btnOKLabel: lang._('Stop'),
                callback: function (result) {
                    if (result) { serviceAction('stop'); }
                }
            });
        });

        $('#btn-service-restart').on('click', function () {
            serviceAction('restart');
        });

        /*
         * Load settings form
         */
        mapDataToFormUI({ 'frm_netshield_settings': '/api/netshield/settings/getSettings' }).done(function () {
            formatTokenizersUI();
            $('.selectpicker').selectpicker('refresh');
        });

        /*
         * Save settings
         */
        $('#btn-save-settings').on('click', function () {
            var $btn = $(this);
            $btn.prop('disabled', true);
            saveFormToEndpoint(
                '/api/netshield/settings/setSettings',
                'frm_netshield_settings',
                function (data) {
                    $btn.prop('disabled', false);
                    if (data.result === 'saved') {
                        /* Reconfigure backend */
                        ajaxCall('/api/netshield/service/reconfigure', {}, function () {
                            updateServiceStatus();
                        });
                        BootstrapDialog.alert({
                            title: lang._('Settings Saved'),
                            message: lang._('Settings have been saved successfully.'),
                            type: BootstrapDialog.TYPE_SUCCESS
                        });
                    }
                },
                true
            );
        });

        /*
         * Initial service status
         */
        updateServiceStatus();

        /*
         * Syslog test button
         */
        $('#btn-syslog-test').on('click', function () {
            var $btn = $(this);
            var $result = $('#syslog-test-result');
            $btn.prop('disabled', true);
            $result.text(lang._('Sending...')).removeClass('text-success text-danger');
            ajaxCall('/api/netshield/syslog/test', {}, function (data) {
                $btn.prop('disabled', false);
                if (data && data.result === 'ok') {
                    $result
                        .addClass('text-success')
                        .text(data.message || lang._('Test message sent successfully.'));
                } else {
                    $result
                        .addClass('text-danger')
                        .text((data && data.message) ? data.message : lang._('Test failed. Check host and port settings.'));
                }
            });
        });

        /*
         * Send mobile setup to Telegram
         */
        $('#btn-send-mobile-setup').on('click', function () {
            var $btn = $(this);
            var $result = $('#mobile-setup-result');
            $btn.prop('disabled', true);
            $result.text(lang._('Sending...')).removeClass('text-success text-danger');
            ajaxCall('/api/netshield/settings/sendMobileSetup', {}, function (data) {
                $btn.prop('disabled', false);
                if (data && data.status === 'ok') {
                    $result
                        .addClass('text-success')
                        .text(data.message || lang._('Setup info sent to Telegram!'));
                } else {
                    $result
                        .addClass('text-danger')
                        .text((data && data.message) ? data.message : lang._('Failed. Check Telegram settings.'));
                }
            });
        });

    });
</script>

<!-- ======================================================================== -->
<!-- SERVICE CONTROL PANEL                                                      -->
<!-- ======================================================================== -->
<div class="content-box" style="padding: 15px; margin-bottom: 15px;">
    <div style="display: flex; align-items: center; gap: 12px; flex-wrap: wrap;">
        <h4 style="margin: 0;">{{ lang._('NetShield Service') }}</h4>
        <span id="service-status-badge" class="label label-default">{{ lang._('Unknown') }}</span>
        <div class="btn-group" style="margin-left: auto;">
            <button id="btn-service-start" class="btn btn-sm btn-success" disabled>
                <span class="fa fa-play"></span>
                {{ lang._('Start') }}
            </button>
            <button id="btn-service-stop" class="btn btn-sm btn-danger" disabled>
                <span class="fa fa-stop"></span>
                {{ lang._('Stop') }}
            </button>
            <button id="btn-service-restart" class="btn btn-sm btn-warning" disabled>
                <span class="fa fa-refresh"></span>
                {{ lang._('Restart') }}
            </button>
        </div>
    </div>
</div>

<!-- ======================================================================== -->
<!-- SETTINGS FORM                                                              -->
<!-- ======================================================================== -->
<form id="frm_netshield_settings">
    <div class="content-box" style="padding: 15px;">

        <!-- General Settings -->
        <div class="table-responsive">
            <table class="table table-striped table-condensed">
                <colgroup>
                    <col style="width: 35%;">
                    <col style="width: 65%;">
                </colgroup>
                <thead>
                    <tr>
                        <th colspan="2">{{ lang._('General Settings') }}</th>
                    </tr>
                </thead>
                <tbody>
                    <tr>
                        <td><a id="help_netshield_enabled" href="#" class="showhelp">
                                <span class="fa fa-info-circle"></span></a>
                            {{ lang._('Enable NetShield') }}
                            <div class="hidden" data-for="help_netshield_enabled">
                                {{ lang._('Enable or disable the NetShield monitoring service.') }}
                            </div>
                        </td>
                        <td>
                            <input type="checkbox" id="netshield.general.enabled" name="netshield.general.enabled">
                        </td>
                    </tr>
                    <tr>
                        <td><a id="help_netshield_check_interval" href="#" class="showhelp">
                                <span class="fa fa-info-circle"></span></a>
                            {{ lang._('Check Interval (seconds)') }}
                            <div class="hidden" data-for="help_netshield_check_interval">
                                {{ lang._('How often NetShield polls for new events, in seconds.') }}
                            </div>
                        </td>
                        <td>
                            <input type="text" class="form-control" id="netshield.general.check_interval"
                                name="netshield.general.check_interval">
                        </td>
                    </tr>
                    <tr>
                        <td><a id="help_netshield_alert_cooldown" href="#" class="showhelp">
                                <span class="fa fa-info-circle"></span></a>
                            {{ lang._('Alert Cooldown (seconds)') }}
                            <div class="hidden" data-for="help_netshield_alert_cooldown">
                                {{ lang._('Minimum seconds between repeated alerts for the same event.') }}
                            </div>
                        </td>
                        <td>
                            <input type="text" class="form-control" id="netshield.general.alert_cooldown"
                                name="netshield.general.alert_cooldown">
                        </td>
                    </tr>
                    <tr>
                        <td><a id="help_netshield_excluded_devices" href="#" class="showhelp">
                                <span class="fa fa-info-circle"></span></a>
                            {{ lang._('Excluded Devices') }}
                            <div class="hidden" data-for="help_netshield_excluded_devices">
                                {{ lang._('Comma-separated list of MAC addresses to exclude from monitoring.') }}
                            </div>
                        </td>
                        <td>
                            <input type="text" class="form-control" id="netshield.general.excluded_devices"
                                name="netshield.general.excluded_devices" placeholder="aa:bb:cc:dd:ee:ff, ...">
                        </td>
                    </tr>
                    <tr>
                        <td><a id="help_netshield_log_level" href="#" class="showhelp">
                                <span class="fa fa-info-circle"></span></a>
                            {{ lang._('Log Level') }}
                            <div class="hidden" data-for="help_netshield_log_level">
                                {{ lang._('Verbosity of the NetShield log output.') }}
                            </div>
                        </td>
                        <td>
                            <select class="selectpicker" id="netshield.general.log_level"
                                name="netshield.general.log_level">
                                <option value="DEBUG">{{ lang._('Debug') }}</option>
                                <option value="INFO">{{ lang._('Info') }}</option>
                                <option value="WARNING">{{ lang._('Warning') }}</option>
                                <option value="ERROR">{{ lang._('Error') }}</option>
                            </select>
                        </td>
                    </tr>
                </tbody>
            </table>
        </div>

        <!-- Telegram Settings -->
        <div class="table-responsive" style="margin-top: 20px;">
            <table class="table table-striped table-condensed">
                <colgroup>
                    <col style="width: 35%;">
                    <col style="width: 65%;">
                </colgroup>
                <thead>
                    <tr>
                        <th colspan="2">{{ lang._('Telegram Notifications') }}</th>
                    </tr>
                </thead>
                <tbody>
                    <tr>
                        <td><a id="help_netshield_telegram_bot_token" href="#" class="showhelp">
                                <span class="fa fa-info-circle"></span></a>
                            {{ lang._('Bot Token') }}
                            <div class="hidden" data-for="help_netshield_telegram_bot_token">
                                {{ lang._('Telegram Bot API token from @BotFather.') }}
                            </div>
                        </td>
                        <td>
                            <input type="text" class="form-control" id="netshield.general.telegram_bot_token"
                                name="netshield.general.telegram_bot_token" autocomplete="off"
                                placeholder="123456:ABC-DEF...">
                        </td>
                    </tr>
                    <tr>
                        <td><a id="help_netshield_telegram_chat_id" href="#" class="showhelp">
                                <span class="fa fa-info-circle"></span></a>
                            {{ lang._('Chat ID') }}
                            <div class="hidden" data-for="help_netshield_telegram_chat_id">
                                {{ lang._('Telegram chat or group ID to send alerts to.') }}
                            </div>
                        </td>
                        <td>
                            <input type="text" class="form-control" id="netshield.general.telegram_chat_id"
                                name="netshield.general.telegram_chat_id" placeholder="-100123456789">
                        </td>
                    </tr>
                </tbody>
            </table>
        </div>

        <!-- Mobile App Setup -->
        <div class="table-responsive" style="margin-top: 20px;">
            <table class="table table-striped table-condensed">
                <colgroup>
                    <col style="width: 35%;">
                    <col style="width: 65%;">
                </colgroup>
                <thead>
                    <tr>
                        <th colspan="2">{{ lang._('Mobile App Setup') }}</th>
                    </tr>
                </thead>
                <tbody>
                    <tr>
                        <td><a id="help_netshield_mobile_setup" href="#" class="showhelp">
                                <span class="fa fa-info-circle"></span></a>
                            {{ lang._('Send Setup to Telegram') }}
                            <div class="hidden" data-for="help_netshield_mobile_setup">
                                {{ lang._('Generate a one-time password and send mobile app setup instructions to your Telegram. The password expires in 1 hour.') }}
                            </div>
                        </td>
                        <td>
                            <button id="btn-send-mobile-setup" type="button" class="btn btn-sm btn-primary">
                                <span class="fa fa-mobile"></span>
                                {{ lang._('Send Setup Info') }}
                            </button>
                            <span id="mobile-setup-result" style="margin-left: 10px;"></span>
                        </td>
                    </tr>
                </tbody>
            </table>
        </div>

        <!-- Feature Toggles -->
        <div class="table-responsive" style="margin-top: 20px;">
            <table class="table table-striped table-condensed">
                <colgroup>
                    <col style="width: 35%;">
                    <col style="width: 65%;">
                </colgroup>
                <thead>
                    <tr>
                        <th colspan="2">{{ lang._('Features') }}</th>
                    </tr>
                </thead>
                <tbody>
                    <tr>
                        <td><a id="help_netshield_dpi_enabled" href="#" class="showhelp">
                                <span class="fa fa-info-circle"></span></a>
                            {{ lang._('Deep Packet Inspection') }}
                            <div class="hidden" data-for="help_netshield_dpi_enabled">
                                {{ lang._('Enable DPI-based traffic analysis.') }}
                            </div>
                        </td>
                        <td>
                            <input type="checkbox" id="netshield.general.dpi_enabled"
                                name="netshield.general.dpi_enabled">
                        </td>
                    </tr>
                    <tr>
                        <td><a id="help_netshield_dns_filtering_enabled" href="#" class="showhelp">
                                <span class="fa fa-info-circle"></span></a>
                            {{ lang._('DNS Filtering') }}
                            <div class="hidden" data-for="help_netshield_dns_filtering_enabled">
                                {{ lang._('Enable DNS-based content filtering.') }}
                            </div>
                        </td>
                        <td>
                            <input type="checkbox" id="netshield.general.dns_filtering_enabled"
                                name="netshield.general.dns_filtering_enabled">
                        </td>
                    </tr>
                    <tr>
                        <td><a id="help_netshield_device_tracking_enabled" href="#" class="showhelp">
                                <span class="fa fa-info-circle"></span></a>
                            {{ lang._('Device Tracking') }}
                            <div class="hidden" data-for="help_netshield_device_tracking_enabled">
                                {{ lang._('Track devices by MAC address and hostname.') }}
                            </div>
                        </td>
                        <td>
                            <input type="checkbox" id="netshield.general.device_tracking_enabled"
                                name="netshield.general.device_tracking_enabled">
                        </td>
                    </tr>
                    <tr>
                        <td><a id="help_netshield_threat_intel_enabled" href="#" class="showhelp">
                                <span class="fa fa-info-circle"></span></a>
                            {{ lang._('Threat Intelligence') }}
                            <div class="hidden" data-for="help_netshield_threat_intel_enabled">
                                {{ lang._('Check IPs and domains against threat intelligence feeds.') }}
                            </div>
                        </td>
                        <td>
                            <input type="checkbox" id="netshield.general.threat_intel_enabled"
                                name="netshield.general.threat_intel_enabled">
                        </td>
                    </tr>
                </tbody>
            </table>
        </div>

        <!-- Device Policy -->
        <div class="table-responsive" style="margin-top: 20px;">
            <table class="table table-striped table-condensed">
                <colgroup>
                    <col style="width: 35%;">
                    <col style="width: 65%;">
                </colgroup>
                <thead>
                    <tr>
                        <th colspan="2">{{ lang._('Device Policy') }}</th>
                    </tr>
                </thead>
                <tbody>
                    <tr>
                        <td><a id="help_netshield_new_device_alert" href="#" class="showhelp">
                                <span class="fa fa-info-circle"></span></a>
                            {{ lang._('Alert on New Device') }}
                            <div class="hidden" data-for="help_netshield_new_device_alert">
                                {{ lang._('Send a Telegram alert when a previously unseen device connects.') }}
                            </div>
                        </td>
                        <td>
                            <input type="checkbox" id="netshield.general.new_device_alert"
                                name="netshield.general.new_device_alert">
                        </td>
                    </tr>
                    <tr>
                        <td><a id="help_netshield_auto_quarantine_unknown" href="#" class="showhelp">
                                <span class="fa fa-info-circle"></span></a>
                            {{ lang._('Auto-Quarantine Unknown Devices') }}
                            <div class="hidden" data-for="help_netshield_auto_quarantine_unknown">
                                {{ lang._('Automatically quarantine devices that have not been approved.') }}
                            </div>
                        </td>
                        <td>
                            <input type="checkbox" id="netshield.general.auto_quarantine_unknown"
                                name="netshield.general.auto_quarantine_unknown">
                        </td>
                    </tr>
                </tbody>
            </table>
        </div>

        <!-- Syslog / SIEM Export -->
        <div class="table-responsive" style="margin-top: 20px;">
            <table class="table table-striped table-condensed">
                <colgroup>
                    <col style="width: 35%;">
                    <col style="width: 65%;">
                </colgroup>
                <thead>
                    <tr>
                        <th colspan="2">{{ lang._('Syslog / SIEM Export') }}</th>
                    </tr>
                </thead>
                <tbody>
                    <tr>
                        <td><a id="help_netshield_syslog_enabled" href="#" class="showhelp">
                                <span class="fa fa-info-circle"></span></a>
                            {{ lang._('Enable Syslog Export') }}
                            <div class="hidden" data-for="help_netshield_syslog_enabled">
                                {{ lang._('Forward NetShield alerts, flows, and threat events to a remote syslog or SIEM
                                server.') }}
                            </div>
                        </td>
                        <td>
                            <input type="checkbox" id="netshield.general.syslog_enabled"
                                name="netshield.general.syslog_enabled">
                        </td>
                    </tr>
                    <tr>
                        <td><a id="help_netshield_syslog_host" href="#" class="showhelp">
                                <span class="fa fa-info-circle"></span></a>
                            {{ lang._('Syslog Host') }}
                            <div class="hidden" data-for="help_netshield_syslog_host">
                                {{ lang._('IP address or hostname of the remote syslog/SIEM server.') }}
                            </div>
                        </td>
                        <td>
                            <input type="text" class="form-control" id="netshield.general.syslog_host"
                                name="netshield.general.syslog_host" placeholder="192.168.1.100">
                        </td>
                    </tr>
                    <tr>
                        <td><a id="help_netshield_syslog_port" href="#" class="showhelp">
                                <span class="fa fa-info-circle"></span></a>
                            {{ lang._('Syslog Port') }}
                            <div class="hidden" data-for="help_netshield_syslog_port">
                                {{ lang._('UDP or TCP port of the remote syslog server (default: 514).') }}
                            </div>
                        </td>
                        <td>
                            <input type="text" class="form-control" id="netshield.general.syslog_port"
                                name="netshield.general.syslog_port" placeholder="514">
                        </td>
                    </tr>
                    <tr>
                        <td><a id="help_netshield_syslog_protocol" href="#" class="showhelp">
                                <span class="fa fa-info-circle"></span></a>
                            {{ lang._('Transport Protocol') }}
                            <div class="hidden" data-for="help_netshield_syslog_protocol">
                                {{ lang._('UDP is the standard syslog transport. Use TCP for reliable delivery to SIEM
                                systems that support it.') }}
                            </div>
                        </td>
                        <td>
                            <select class="selectpicker" id="netshield.general.syslog_protocol"
                                name="netshield.general.syslog_protocol">
                                <option value="udp">{{ lang._('UDP') }}</option>
                                <option value="tcp">{{ lang._('TCP') }}</option>
                            </select>
                        </td>
                    </tr>
                    <tr>
                        <td>{{ lang._('Test Connection') }}</td>
                        <td>
                            <button id="btn-syslog-test" type="button" class="btn btn-sm btn-default">
                                <span class="fa fa-paper-plane"></span>
                                {{ lang._('Send Test') }}
                            </button>
                            <span id="syslog-test-result" style="margin-left: 10px;"></span>
                        </td>
                    </tr>
                </tbody>
            </table>
        </div>

        <!-- Save button -->
        <div style="margin-top: 20px; text-align: right;">
            <button id="btn-save-settings" type="button" class="btn btn-primary">
                <span class="fa fa-save"></span>
                {{ lang._('Save Settings') }}
            </button>
        </div>

    </div>
</form>