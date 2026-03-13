{#
 # NetShield — Network Security Suite for OPNsense
 # Settings View — full configuration form
 #
 # SPDX-License-Identifier: BSD-2-Clause
 #}
<script>
$( document ).ready(function () {

    /*
     * =========================================================
     * LOAD SETTINGS
     * =========================================================
     */
    function loadSettings() {
        ajaxCall('/api/netshield/settings/get', {}, function(data) {
            if (data && data.netshield) {
                mapDataToFormUI({'frm_settings': data.netshield});
            }
        });
    }

    /*
     * =========================================================
     * SAVE SETTINGS (no restart)
     * =========================================================
     */
    $('#btn-save').click(function() {
        var btn = $(this).prop('disabled', true).html('<i class="fa fa-spinner fa-spin"></i> Saving…');
        saveFormToEndpoint('/api/netshield/settings/set', 'frm_settings', function(data) {
            btn.prop('disabled', false).html('<i class="fa fa-save"></i> Save');
            if (data && data.result === 'saved') {
                $('#save-feedback').fadeIn(200).delay(2500).fadeOut(400);
            }
        });
    });

    /*
     * =========================================================
     * SAVE + APPLY (save + reconfigure service)
     * =========================================================
     */
    $('#btn-apply').click(function() {
        var btn = $(this).prop('disabled', true).html('<i class="fa fa-spinner fa-spin"></i> Applying…');
        saveFormToEndpoint('/api/netshield/settings/set', 'frm_settings', function(data) {
            if (!data || data.result !== 'saved') {
                btn.prop('disabled', false).html('<i class="fa fa-check"></i> Save &amp; Apply');
                return;
            }
            ajaxCall('/api/netshield/service/reconfigure', {}, function(svcData) {
                btn.prop('disabled', false).html('<i class="fa fa-check"></i> Save &amp; Apply');
                var ok = svcData && svcData.status === 'ok';
                BootstrapDialog.show({
                    type: ok ? BootstrapDialog.TYPE_SUCCESS : BootstrapDialog.TYPE_DANGER,
                    title: ok ? 'Settings Applied' : 'Apply Error',
                    message: ok
                        ? 'Configuration saved and NetShield service reconfigured successfully.'
                        : 'Settings were saved but the service failed to reconfigure. Check the system log.',
                    buttons: [{ label: 'OK', action: function(d){ d.close(); } }]
                });
            });
        });
    });

    /*
     * =========================================================
     * TEST WEBHOOK
     * =========================================================
     */
    $('#btn-test-webhook').click(function() {
        var url = $('[name="alerts.webhook_url"]').val();
        if (!url) {
            BootstrapDialog.alert({ type: BootstrapDialog.TYPE_WARNING, message: 'Enter a webhook URL first.' });
            return;
        }
        ajaxCall('/api/netshield/settings/testWebhook', {url: url}, function(data) {
            var ok = data && data.status === 'ok';
            BootstrapDialog.show({
                type: ok ? BootstrapDialog.TYPE_SUCCESS : BootstrapDialog.TYPE_DANGER,
                title: ok ? 'Webhook OK' : 'Webhook Failed',
                message: ok ? 'Test event delivered successfully.' : ('Error: ' + (data && data.message ? data.message : 'Unknown error')),
                buttons: [{ label: 'OK', action: function(d){ d.close(); } }]
            });
        });
    });

    /*
     * =========================================================
     * TEST SYSLOG
     * =========================================================
     */
    $('#btn-test-syslog').click(function() {
        ajaxCall('/api/netshield/settings/testSyslog', {}, function(data) {
            var ok = data && data.status === 'ok';
            BootstrapDialog.show({
                type: ok ? BootstrapDialog.TYPE_SUCCESS : BootstrapDialog.TYPE_DANGER,
                title: ok ? 'Syslog Test Sent' : 'Syslog Test Failed',
                message: ok ? 'Test message sent to syslog target.' : ('Error: ' + (data && data.message ? data.message : 'Unknown error')),
                buttons: [{ label: 'OK', action: function(d){ d.close(); } }]
            });
        });
    });

    // Initial load
    loadSettings();
});
</script>

<!-- Page Header -->
<div class="content-box" style="padding:10px 15px; margin-bottom:5px;">
    <h2 style="margin:0 0 5px 0;"><i class="fa fa-cog"></i> NetShield Settings</h2>
    <p class="text-muted" style="margin:0;">All configuration is saved immediately. Click <strong>Save &amp; Apply</strong> to restart the service with new settings.</p>
</div>

<!-- Save Feedback (hidden, fades in/out) -->
<div id="save-feedback" class="alert alert-success" style="display:none; margin:0 15px 10px 15px;">
    <i class="fa fa-check"></i> Settings saved. Click <strong>Save &amp; Apply</strong> to activate.
</div>

<form id="frm_settings">

    <!-- ===================================================
         SECTION: GENERAL
         =================================================== -->
    <div class="content-box" style="padding:0;">
        <div class="content-box-main" style="padding:10px 15px;">
            <h3 style="margin-top:5px; border-bottom:1px solid #eee; padding-bottom:8px;">
                <i class="fa fa-cogs text-muted"></i> General
            </h3>
            <div class="row">
                <div class="col-md-4">
                    <div class="form-group">
                        <label class="control-label">Enable NetShield</label>
                        <select class="form-control" name="general.enabled">
                            <option value="1">Enabled</option>
                            <option value="0">Disabled</option>
                        </select>
                        <span class="help-block">Master switch. Disabling stops all detection and enforcement.</span>
                    </div>
                </div>
                <div class="col-md-4">
                    <div class="form-group">
                        <label class="control-label">Log Level</label>
                        <select class="form-control" name="general.log_level">
                            <option value="error">Error — critical failures only</option>
                            <option value="warning">Warning — errors + warnings</option>
                            <option value="info" selected>Info — normal operation</option>
                            <option value="debug">Debug — verbose (high volume)</option>
                        </select>
                    </div>
                </div>
                <div class="col-md-4">
                    <div class="form-group">
                        <label class="control-label">Check Interval (seconds)</label>
                        <input type="number" class="form-control" name="general.check_interval"
                               value="60" min="10" max="3600">
                        <span class="help-block">How often the daemon checks for policy violations</span>
                    </div>
                </div>
            </div>
            <div class="row">
                <div class="col-md-4">
                    <div class="form-group">
                        <label class="control-label">Alert Cooldown (seconds)</label>
                        <input type="number" class="form-control" name="general.alert_cooldown"
                               value="300" min="0" max="86400">
                        <span class="help-block">Minimum time before the same alert fires again for the same device</span>
                    </div>
                </div>
                <div class="col-md-4">
                    <div class="form-group">
                        <label class="control-label">Alert Retention (days)</label>
                        <input type="number" class="form-control" name="general.alert_retention"
                               value="30" min="1" max="365">
                        <span class="help-block">Alerts older than this are removed during periodic flush</span>
                    </div>
                </div>
                <div class="col-md-4">
                    <div class="form-group">
                        <label class="control-label">Database Path</label>
                        <input type="text" class="form-control" name="general.db_path"
                               placeholder="/var/db/netshield/netshield.db">
                        <span class="help-block">SQLite database location. Leave blank for default.</span>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <!-- ===================================================
         SECTION: DNS FILTERING
         =================================================== -->
    <div class="content-box" style="padding:0; margin-top:10px;">
        <div class="content-box-main" style="padding:10px 15px;">
            <h3 style="margin-top:5px; border-bottom:1px solid #eee; padding-bottom:8px;">
                <i class="fa fa-filter text-muted"></i> DNS Filtering
            </h3>
            <div class="row">
                <div class="col-md-4">
                    <div class="form-group">
                        <label class="control-label">Enable DNS Filtering</label>
                        <select class="form-control" name="dns.enabled">
                            <option value="1">Enabled</option>
                            <option value="0">Disabled</option>
                        </select>
                        <span class="help-block">Injects blocklists into Unbound DNS resolver</span>
                    </div>
                </div>
                <div class="col-md-4">
                    <div class="form-group">
                        <label class="control-label">Force DNS Through Router</label>
                        <select class="form-control" name="dns.force_dns">
                            <option value="1">Enabled</option>
                            <option value="0">Disabled</option>
                        </select>
                        <span class="help-block">Redirect port 53 UDP/TCP to Unbound regardless of destination</span>
                    </div>
                </div>
                <div class="col-md-4">
                    <div class="form-group">
                        <label class="control-label">Block DNS-over-HTTPS (DoH)</label>
                        <select class="form-control" name="dns.block_doh">
                            <option value="1">Enabled</option>
                            <option value="0">Disabled</option>
                        </select>
                        <span class="help-block">Blocks NXDOMAIN for known DoH resolver domains</span>
                    </div>
                </div>
            </div>
            <div class="row">
                <div class="col-md-4">
                    <div class="form-group">
                        <label class="control-label">Block DNS-over-TLS (DoT)</label>
                        <select class="form-control" name="dns.block_dot">
                            <option value="1">Enabled</option>
                            <option value="0">Disabled</option>
                        </select>
                        <span class="help-block">Blocks port 853 outbound via firewall rule</span>
                    </div>
                </div>
                <div class="col-md-4">
                    <div class="form-group">
                        <label class="control-label">Google Safe Search</label>
                        <select class="form-control" name="dns.safe_search_google">
                            <option value="1">Enabled</option>
                            <option value="0">Disabled</option>
                        </select>
                    </div>
                </div>
                <div class="col-md-4">
                    <div class="form-group">
                        <label class="control-label">YouTube Restricted Mode</label>
                        <select class="form-control" name="dns.safe_search_youtube">
                            <option value="1">Enabled</option>
                            <option value="0">Disabled</option>
                        </select>
                    </div>
                </div>
            </div>
            <div class="row">
                <div class="col-md-4">
                    <div class="form-group">
                        <label class="control-label">Bing Safe Search</label>
                        <select class="form-control" name="dns.safe_search_bing">
                            <option value="1">Enabled</option>
                            <option value="0">Disabled</option>
                        </select>
                    </div>
                </div>
                <div class="col-md-4">
                    <div class="form-group">
                        <label class="control-label">NXDOMAIN Response</label>
                        <select class="form-control" name="dns.nxdomain_response">
                            <option value="nxdomain">NXDOMAIN (standard)</option>
                            <option value="refused">REFUSED</option>
                            <option value="sinkhole">Sinkhole (redirect to router IP)</option>
                        </select>
                        <span class="help-block">Response to send for blocked domains</span>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <!-- ===================================================
         SECTION: DETECTION
         =================================================== -->
    <div class="content-box" style="padding:0; margin-top:10px;">
        <div class="content-box-main" style="padding:10px 15px;">
            <h3 style="margin-top:5px; border-bottom:1px solid #eee; padding-bottom:8px;">
                <i class="fa fa-eye text-muted"></i> Detection
            </h3>
            <div class="row">
                <div class="col-md-4">
                    <div class="form-group">
                        <label class="control-label">Enable DPI (Deep Packet Inspection)</label>
                        <select class="form-control" name="detection.enable_dpi">
                            <option value="1">Enabled</option>
                            <option value="0">Disabled</option>
                        </select>
                        <span class="help-block">Requires Suricata with EVE JSON logging</span>
                    </div>
                </div>
                <div class="col-md-4">
                    <div class="form-group">
                        <label class="control-label">VPN / Tunnel Detection</label>
                        <select class="form-control" name="detection.vpn_detection">
                            <option value="1">Enabled</option>
                            <option value="0">Disabled</option>
                        </select>
                        <span class="help-block">Detects WireGuard, OpenVPN, VLESS, Shadowsocks, Tor</span>
                    </div>
                </div>
                <div class="col-md-4">
                    <div class="form-group">
                        <label class="control-label">Device Tracking</label>
                        <select class="form-control" name="detection.device_tracking">
                            <option value="1">Enabled</option>
                            <option value="0">Disabled</option>
                        </select>
                        <span class="help-block">Track devices by MAC, resolve hostnames, detect vendor</span>
                    </div>
                </div>
            </div>
            <div class="row">
                <div class="col-md-4">
                    <div class="form-group">
                        <label class="control-label">Suricata Integration</label>
                        <select class="form-control" name="detection.suricata_integration">
                            <option value="1">Enabled</option>
                            <option value="0">Disabled</option>
                        </select>
                    </div>
                </div>
                <div class="col-md-4">
                    <div class="form-group">
                        <label class="control-label">Suricata EVE Log Path</label>
                        <input type="text" class="form-control" name="detection.suricata_eve_path"
                               placeholder="/var/log/suricata/eve.json">
                    </div>
                </div>
                <div class="col-md-4">
                    <div class="form-group">
                        <label class="control-label">SNI-Based App Detection</label>
                        <select class="form-control" name="detection.sni_detection">
                            <option value="1">Enabled</option>
                            <option value="0">Disabled</option>
                        </select>
                        <span class="help-block">Identify apps via TLS SNI (Server Name Indication)</span>
                    </div>
                </div>
            </div>
            <div class="row">
                <div class="col-md-4">
                    <div class="form-group">
                        <label class="control-label">Unbound Query Log Path</label>
                        <input type="text" class="form-control" name="detection.unbound_log_path"
                               placeholder="/var/log/unbound.log">
                        <span class="help-block">Required for DNS-based detection</span>
                    </div>
                </div>
                <div class="col-md-4">
                    <div class="form-group">
                        <label class="control-label">Detection Sensitivity</label>
                        <select class="form-control" name="detection.sensitivity">
                            <option value="low">Low — fewer false positives</option>
                            <option value="medium" selected>Medium — balanced</option>
                            <option value="high">High — more aggressive</option>
                        </select>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <!-- ===================================================
         SECTION: ENFORCEMENT
         =================================================== -->
    <div class="content-box" style="padding:0; margin-top:10px;">
        <div class="content-box-main" style="padding:10px 15px;">
            <h3 style="margin-top:5px; border-bottom:1px solid #eee; padding-bottom:8px;">
                <i class="fa fa-lock text-muted"></i> Enforcement
            </h3>
            <div class="row">
                <div class="col-md-4">
                    <div class="form-group">
                        <label class="control-label">Block Common VPN Ports</label>
                        <select class="form-control" name="enforcement.block_vpn_ports">
                            <option value="1">Enabled</option>
                            <option value="0">Disabled</option>
                        </select>
                        <span class="help-block">Blocks UDP 1194, TCP 1723, UDP 4500</span>
                    </div>
                </div>
                <div class="col-md-4">
                    <div class="form-group">
                        <label class="control-label">Block Common Proxy Ports</label>
                        <select class="form-control" name="enforcement.block_proxy_ports">
                            <option value="1">Enabled</option>
                            <option value="0">Disabled</option>
                        </select>
                        <span class="help-block">Blocks TCP 3128, 8080, 8888</span>
                    </div>
                </div>
                <div class="col-md-4">
                    <div class="form-group">
                        <label class="control-label">Quarantine Action</label>
                        <select class="form-control" name="enforcement.quarantine_action">
                            <option value="block_all">Block all traffic</option>
                            <option value="block_internet">Block internet, allow LAN</option>
                            <option value="redirect_captive">Redirect to captive portal</option>
                        </select>
                    </div>
                </div>
            </div>
            <div class="row">
                <div class="col-md-4">
                    <div class="form-group">
                        <label class="control-label">Auto-Quarantine on Policy Violation</label>
                        <select class="form-control" name="enforcement.auto_quarantine">
                            <option value="0">Disabled</option>
                            <option value="1">Enabled</option>
                        </select>
                        <span class="help-block">Automatically quarantine devices that repeatedly violate policies</span>
                    </div>
                </div>
                <div class="col-md-4">
                    <div class="form-group">
                        <label class="control-label">Auto-Quarantine Threshold (violations)</label>
                        <input type="number" class="form-control" name="enforcement.auto_quarantine_threshold"
                               value="10" min="1" max="1000">
                        <span class="help-block">Number of violations before auto-quarantine</span>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <!-- ===================================================
         SECTION: ALERTS / NOTIFICATIONS
         =================================================== -->
    <div class="content-box" style="padding:0; margin-top:10px;">
        <div class="content-box-main" style="padding:10px 15px;">
            <h3 style="margin-top:5px; border-bottom:1px solid #eee; padding-bottom:8px;">
                <i class="fa fa-bell-o text-muted"></i> Alerts &amp; Notifications
            </h3>

            <h5><strong>Syslog</strong></h5>
            <div class="row">
                <div class="col-md-4">
                    <div class="form-group">
                        <label class="control-label">Syslog Host</label>
                        <input type="text" class="form-control" name="alerts.syslog_host"
                               placeholder="Hostname or IP address">
                    </div>
                </div>
                <div class="col-md-2">
                    <div class="form-group">
                        <label class="control-label">Port</label>
                        <input type="number" class="form-control" name="alerts.syslog_port"
                               placeholder="514" min="1" max="65535">
                    </div>
                </div>
                <div class="col-md-2">
                    <div class="form-group">
                        <label class="control-label">Protocol</label>
                        <select class="form-control" name="alerts.syslog_protocol">
                            <option value="udp">UDP</option>
                            <option value="tcp">TCP</option>
                        </select>
                    </div>
                </div>
                <div class="col-md-2">
                    <div class="form-group">
                        <label class="control-label">Facility</label>
                        <select class="form-control" name="alerts.syslog_facility">
                            <option value="local0">local0</option>
                            <option value="local1">local1</option>
                            <option value="local2">local2</option>
                            <option value="local3">local3</option>
                            <option value="local4">local4</option>
                        </select>
                    </div>
                </div>
                <div class="col-md-2" style="padding-top:25px;">
                    <button type="button" class="btn btn-sm btn-default" id="btn-test-syslog">
                        <i class="fa fa-paper-plane"></i> Test
                    </button>
                </div>
            </div>

            <h5><strong>Webhook</strong></h5>
            <div class="row">
                <div class="col-md-6">
                    <div class="form-group">
                        <label class="control-label">Webhook URL</label>
                        <input type="url" class="form-control" name="alerts.webhook_url"
                               placeholder="https://hooks.example.com/…">
                        <span class="help-block">POST JSON payload on each alert. Compatible with Slack, Teams, Discord, N8n, etc.</span>
                    </div>
                </div>
                <div class="col-md-3">
                    <div class="form-group">
                        <label class="control-label">Minimum Alert Level</label>
                        <select class="form-control" name="alerts.webhook_min_level">
                            <option value="all">All Alerts</option>
                            <option value="warning">Warning+</option>
                            <option value="critical">Critical Only</option>
                        </select>
                    </div>
                </div>
                <div class="col-md-3" style="padding-top:25px;">
                    <button type="button" class="btn btn-sm btn-default" id="btn-test-webhook">
                        <i class="fa fa-paper-plane"></i> Test Webhook
                    </button>
                </div>
            </div>
        </div>
    </div>

    <!-- ===================================================
         SECTION: GEOIP
         =================================================== -->
    <div class="content-box" style="padding:0; margin-top:10px;">
        <div class="content-box-main" style="padding:10px 15px;">
            <h3 style="margin-top:5px; border-bottom:1px solid #eee; padding-bottom:8px;">
                <i class="fa fa-map-o text-muted"></i> GeoIP
            </h3>
            <div class="row">
                <div class="col-md-4">
                    <div class="form-group">
                        <label class="control-label">Enable GeoIP Blocking</label>
                        <select class="form-control" name="geoip.enabled">
                            <option value="1">Enabled</option>
                            <option value="0">Disabled</option>
                        </select>
                    </div>
                </div>
                <div class="col-md-6">
                    <div class="form-group">
                        <label class="control-label">GeoIP Database Path (MaxMind .mmdb)</label>
                        <input type="text" class="form-control" name="geoip.db_path"
                               placeholder="/var/db/netshield/GeoLite2-Country.mmdb">
                        <span class="help-block">
                            Download from
                            <a href="https://dev.maxmind.com/geoip/geolite2-free-geolocation-data" target="_blank">
                                MaxMind GeoLite2
                            </a>
                            (free account required)
                        </span>
                    </div>
                </div>
            </div>
            <div class="row">
                <div class="col-md-4">
                    <div class="form-group">
                        <label class="control-label">GeoIP Update Schedule</label>
                        <select class="form-control" name="geoip.update_schedule">
                            <option value="weekly">Weekly</option>
                            <option value="monthly">Monthly</option>
                            <option value="manual">Manual only</option>
                        </select>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <!-- ===================================================
         SECTION: ADVANCED
         =================================================== -->
    <div class="content-box" style="padding:0; margin-top:10px;">
        <div class="content-box-main" style="padding:10px 15px;">
            <h3 style="margin-top:5px; border-bottom:1px solid #eee; padding-bottom:8px;">
                <i class="fa fa-wrench text-muted"></i> Advanced
            </h3>
            <div class="row">
                <div class="col-md-4">
                    <div class="form-group">
                        <label class="control-label">Web Category Sync Schedule</label>
                        <select class="form-control" name="advanced.category_sync_schedule">
                            <option value="daily">Daily</option>
                            <option value="weekly">Weekly</option>
                            <option value="manual">Manual only</option>
                        </select>
                    </div>
                </div>
                <div class="col-md-4">
                    <div class="form-group">
                        <label class="control-label">Target List Update Schedule</label>
                        <select class="form-control" name="advanced.targetlist_update_schedule">
                            <option value="hourly">Hourly</option>
                            <option value="daily">Daily</option>
                            <option value="weekly">Weekly</option>
                        </select>
                    </div>
                </div>
                <div class="col-md-4">
                    <div class="form-group">
                        <label class="control-label">HTTP Fetch Timeout (seconds)</label>
                        <input type="number" class="form-control" name="advanced.http_timeout"
                               value="30" min="5" max="300">
                    </div>
                </div>
            </div>
            <div class="row">
                <div class="col-md-4">
                    <div class="form-group">
                        <label class="control-label">Max Domains Per Category</label>
                        <input type="number" class="form-control" name="advanced.max_domains_per_category"
                               value="500000" min="1000" max="5000000">
                        <span class="help-block">Memory limit for large domain lists</span>
                    </div>
                </div>
                <div class="col-md-4">
                    <div class="form-group">
                        <label class="control-label">Daemon Workers</label>
                        <input type="number" class="form-control" name="advanced.daemon_workers"
                               value="2" min="1" max="16">
                        <span class="help-block">Number of parallel processing threads</span>
                    </div>
                </div>
            </div>
        </div>
    </div>

</form>

<!-- Save Buttons -->
<div class="content-box" style="padding:10px 15px; margin-top:5px;">
    <button type="button" class="btn btn-default" id="btn-save">
        <i class="fa fa-save"></i> Save
    </button>
    <button type="button" class="btn btn-primary" id="btn-apply" style="margin-left:8px;">
        <i class="fa fa-check"></i> Save &amp; Apply
    </button>
    <span class="text-muted" style="margin-left:15px; font-size:12px;">
        <i class="fa fa-info-circle"></i>
        "Save" stores settings without restarting the service.
        "Save &amp; Apply" reconfigures the running service.
    </span>
</div>
