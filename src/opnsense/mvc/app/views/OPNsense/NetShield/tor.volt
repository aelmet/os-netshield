{#
 # Copyright (C) 2025 NetShield
 # All rights reserved.
 #
 # Redistribution and use in source and binary forms, with or without
 # modification, are permitted provided that the following conditions are met:
 #
 # 1. Redistributions of source code must retain the above copyright notice,
 #    this list of conditions and the following disclaimer.
 #
 # 2. Redistributions in binary form must reproduce the above copyright
 #    notice, this list of conditions and the following disclaimer in the
 #    documentation and/or other materials provided with the distribution.
 #
 # THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
 # INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
 # AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 # AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
 # OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 # SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 # INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 # CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 # ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 # POSSIBILITY OF SUCH DAMAGE.
 #}

<div class="content-box">
    <div class="content-box-main">
        <h1>{{ lang._('Tor / Anonymizer Blocking') }}</h1>

        {# ------------------------------------------------------------------ #}
        {# Master Toggle + Stats Cards                                         #}
        {# ------------------------------------------------------------------ #}
        <div class="row" id="tor-stats-row">
            <div class="col-sm-3">
                <div class="panel panel-default" id="panel-master-toggle">
                    <div class="panel-body text-center">
                        <h4>{{ lang._('Tor Blocking') }}</h4>
                        <div id="tor-master-status" class="text-danger" style="font-size:1.5em;font-weight:bold;">
                            {{ lang._('Loading...') }}
                        </div>
                        <br>
                        <button class="btn btn-success btn-sm" id="btn-tor-enable">
                            <i class="fa fa-shield"></i> {{ lang._('Enable') }}
                        </button>
                        <button class="btn btn-danger btn-sm" id="btn-tor-disable">
                            <i class="fa fa-times"></i> {{ lang._('Disable') }}
                        </button>
                    </div>
                </div>
            </div>
            <div class="col-sm-3">
                <div class="panel panel-default">
                    <div class="panel-body text-center">
                        <h2 id="stat-total-ips">-</h2>
                        <p class="text-muted">{{ lang._('Blocked Tor IPs') }}</p>
                    </div>
                </div>
            </div>
            <div class="col-sm-3">
                <div class="panel panel-default">
                    <div class="panel-body text-center">
                        <h2 id="stat-exit-nodes">-</h2>
                        <p class="text-muted">{{ lang._('Exit Nodes') }}</p>
                    </div>
                </div>
            </div>
            <div class="col-sm-3">
                <div class="panel panel-default">
                    <div class="panel-body text-center">
                        <h2 id="stat-domains-blocked">-</h2>
                        <p class="text-muted">{{ lang._('Domains Blocked') }}</p>
                    </div>
                </div>
            </div>
        </div>

        {# ------------------------------------------------------------------ #}
        {# Blocking Layers                                                     #}
        {# ------------------------------------------------------------------ #}
        <div class="panel panel-default">
            <div class="panel-heading">
                <h3 class="panel-title">
                    {{ lang._('Blocking Layers') }}
                    <span class="pull-right">
                        <button class="btn btn-sm btn-primary" id="btn-update-tor">
                            <i class="fa fa-refresh"></i>
                            {{ lang._('Update Tor Lists Now') }}
                        </button>
                    </span>
                </h3>
            </div>
            <div class="panel-body">
                <table class="table table-striped">
                    <thead>
                        <tr>
                            <th>{{ lang._('Layer') }}</th>
                            <th>{{ lang._('Description') }}</th>
                            <th>{{ lang._('Status') }}</th>
                            <th>{{ lang._('Action') }}</th>
                        </tr>
                    </thead>
                    <tbody>
                        <tr>
                            <td><strong>{{ lang._('IP Blocklist') }}</strong></td>
                            <td>{{ lang._('Block all known Tor exit nodes, relays, and bridges by IP address. Auto-updated from multiple sources.') }}</td>
                            <td id="layer-block_ips-status">-</td>
                            <td>
                                <input type="checkbox" class="layer-toggle" data-layer="block_ips" id="toggle-block_ips">
                            </td>
                        </tr>
                        <tr>
                            <td><strong>{{ lang._('Port Blocking') }}</strong></td>
                            <td>{{ lang._('Block common Tor ports (9001, 9030, 9050, 9051, 9150) for all traffic.') }}</td>
                            <td id="layer-block_ports-status">-</td>
                            <td>
                                <input type="checkbox" class="layer-toggle" data-layer="block_ports" id="toggle-block_ports">
                            </td>
                        </tr>
                        <tr>
                            <td><strong>{{ lang._('DNS Blocking') }}</strong></td>
                            <td>{{ lang._('Block Tor-related domains (torproject.org, bridge directories, onion proxies, Tails, Whonix, I2P).') }}</td>
                            <td id="layer-block_dns-status">-</td>
                            <td>
                                <input type="checkbox" class="layer-toggle" data-layer="block_dns" id="toggle-block_dns">
                            </td>
                        </tr>
                        <tr>
                            <td><strong>{{ lang._('Alert on Attempt') }}</strong></td>
                            <td>{{ lang._('Log and send alerts when any device attempts to connect to Tor.') }}</td>
                            <td id="layer-alert_on_attempt-status">-</td>
                            <td>
                                <input type="checkbox" class="layer-toggle" data-layer="alert_on_attempt" id="toggle-alert_on_attempt">
                            </td>
                        </tr>
                    </tbody>
                </table>
            </div>
        </div>

        {# ------------------------------------------------------------------ #}
        {# IP Sources                                                          #}
        {# ------------------------------------------------------------------ #}
        <div class="panel panel-default">
            <div class="panel-heading">
                <h3 class="panel-title">{{ lang._('IP Sources') }}</h3>
            </div>
            <div class="panel-body">
                <table class="table table-condensed" id="tor-sources-table">
                    <thead>
                        <tr>
                            <th>{{ lang._('Source') }}</th>
                            <th>{{ lang._('IPs') }}</th>
                        </tr>
                    </thead>
                    <tbody id="tor-sources-body">
                        <tr><td colspan="2">{{ lang._('Loading...') }}</td></tr>
                    </tbody>
                </table>
                <p class="text-muted" id="tor-last-updated"></p>
            </div>
        </div>

        {# ------------------------------------------------------------------ #}
        {# IP Check Tool                                                       #}
        {# ------------------------------------------------------------------ #}
        <div class="panel panel-default">
            <div class="panel-heading">
                <h3 class="panel-title">{{ lang._('Check IP Address') }}</h3>
            </div>
            <div class="panel-body">
                <div class="input-group">
                    <input type="text" class="form-control" id="check-ip-input"
                           placeholder="{{ lang._('Enter IP address...') }}">
                    <span class="input-group-btn">
                        <button class="btn btn-primary" id="btn-check-ip">
                            <i class="fa fa-search"></i> {{ lang._('Check') }}
                        </button>
                    </span>
                </div>
                <div id="check-ip-result" class="alert" style="display:none;margin-top:10px;"></div>
            </div>
        </div>

        {# ------------------------------------------------------------------ #}
        {# Blocked Ports Reference                                             #}
        {# ------------------------------------------------------------------ #}
        <div class="panel panel-default">
            <div class="panel-heading">
                <h3 class="panel-title">{{ lang._('Blocked Ports Reference') }}</h3>
            </div>
            <div class="panel-body">
                <table class="table table-condensed">
                    <thead>
                        <tr>
                            <th>{{ lang._('Port') }}</th>
                            <th>{{ lang._('Protocol') }}</th>
                            <th>{{ lang._('Description') }}</th>
                        </tr>
                    </thead>
                    <tbody>
                        <tr><td>9001</td><td>TCP</td><td>{{ lang._('Tor OR (Onion Router) relay traffic') }}</td></tr>
                        <tr><td>9030</td><td>TCP</td><td>{{ lang._('Tor directory server') }}</td></tr>
                        <tr><td>9040</td><td>TCP</td><td>{{ lang._('Tor transparent proxy') }}</td></tr>
                        <tr><td>9050</td><td>TCP</td><td>{{ lang._('Tor SOCKS proxy (default)') }}</td></tr>
                        <tr><td>9051</td><td>TCP</td><td>{{ lang._('Tor control port') }}</td></tr>
                        <tr><td>9150</td><td>TCP</td><td>{{ lang._('Tor Browser SOCKS proxy') }}</td></tr>
                        <tr><td>9151</td><td>TCP</td><td>{{ lang._('Tor Browser control port') }}</td></tr>
                    </tbody>
                </table>
            </div>
        </div>

    </div>
</div>

<script>
    function _escape(s) {
        if (!s) return '';
        var d = document.createElement('div');
        d.appendChild(document.createTextNode(s));
        return d.innerHTML;
    }

    function loadStatus() {
        $.getJSON('/api/netshield/tor/status', function(data) {
            // Master toggle
            var enabled = data.enabled;
            var el = $('#tor-master-status');
            if (enabled) {
                el.text('{{ lang._("ACTIVE") }}').removeClass('text-danger').addClass('text-success');
                $('#panel-master-toggle').removeClass('panel-default').addClass('panel-success');
            } else {
                el.text('{{ lang._("DISABLED") }}').removeClass('text-success').addClass('text-danger');
                $('#panel-master-toggle').removeClass('panel-success').addClass('panel-default');
            }

            // Stats
            var ips = data.ip_stats || {};
            $('#stat-total-ips').text(ips.total || 0);
            $('#stat-exit-nodes').text(ips.exit_nodes || 0);
            $('#stat-domains-blocked').text(data.blocked_domains || 0);

            // Layers
            var layers = data.layers || {};
            $.each(layers, function(key, val) {
                var statusEl = $('#layer-' + key + '-status');
                var toggleEl = $('#toggle-' + key);
                if (val) {
                    statusEl.html('<span class="label label-success">{{ lang._("ON") }}</span>');
                    toggleEl.prop('checked', true);
                } else {
                    statusEl.html('<span class="label label-default">{{ lang._("OFF") }}</span>');
                    toggleEl.prop('checked', false);
                }
            });

            // Sources
            var sources = data.sources || [];
            var tbody = $('#tor-sources-body');
            tbody.empty();
            if (sources.length === 0) {
                tbody.append('<tr><td colspan="2">{{ lang._("No sources loaded yet. Click Update to fetch.") }}</td></tr>');
            } else {
                $.each(sources, function(i, s) {
                    tbody.append('<tr><td>' + _escape(s.source) + '</td><td>' + s.count + '</td></tr>');
                });
            }

            // Last updated
            if (data.last_updated) {
                $('#tor-last-updated').text('{{ lang._("Last updated:") }} ' + data.last_updated);
            }
        });
    }

    $(document).ready(function() {
        loadStatus();

        // Enable
        $('#btn-tor-enable').on('click', function() {
            var btn = $(this);
            btn.prop('disabled', true).html('<i class="fa fa-spinner fa-spin"></i> {{ lang._("Enabling...") }}');
            $.post('/api/netshield/tor/enable', function(data) {
                loadStatus();
                btn.prop('disabled', false).html('<i class="fa fa-shield"></i> {{ lang._("Enable") }}');
            }).fail(function() {
                btn.prop('disabled', false).html('<i class="fa fa-shield"></i> {{ lang._("Enable") }}');
            });
        });

        // Disable
        $('#btn-tor-disable').on('click', function() {
            if (!confirm('{{ lang._("Are you sure you want to disable Tor blocking?") }}')) return;
            $.post('/api/netshield/tor/disable', function() { loadStatus(); });
        });

        // Update
        $('#btn-update-tor').on('click', function() {
            var btn = $(this);
            btn.prop('disabled', true).html('<i class="fa fa-spinner fa-spin"></i> {{ lang._("Updating...") }}');
            $.post('/api/netshield/tor/update', function(data) {
                loadStatus();
                btn.prop('disabled', false).html('<i class="fa fa-refresh"></i> {{ lang._("Update Tor Lists Now") }}');
            }).fail(function() {
                btn.prop('disabled', false).html('<i class="fa fa-refresh"></i> {{ lang._("Update Tor Lists Now") }}');
            });
        });

        // Layer toggles
        $('.layer-toggle').on('change', function() {
            var layer = $(this).data('layer');
            var enabled = $(this).is(':checked') ? '1' : '0';
            $.post('/api/netshield/tor/toggleLayer', {layer: layer, enabled: enabled}, function() {
                loadStatus();
            });
        });

        // IP Check
        $('#btn-check-ip').on('click', function() {
            var ip = $.trim($('#check-ip-input').val());
            if (!ip) return;
            var res = $('#check-ip-result');
            $.getJSON('/api/netshield/tor/checkIp?ip=' + encodeURIComponent(ip), function(data) {
                res.show();
                if (data.is_tor) {
                    res.removeClass('alert-success').addClass('alert-danger');
                    res.html('<strong>' + _escape(ip) + '</strong> {{ lang._("is a known Tor node") }} (' +
                        _escape(data.node_type) + ' via ' + _escape(data.source) + ')');
                } else {
                    res.removeClass('alert-danger').addClass('alert-success');
                    res.html('<strong>' + _escape(ip) + '</strong> {{ lang._("is NOT a known Tor node") }}');
                }
            });
        });

        // Enter key for IP check
        $('#check-ip-input').on('keypress', function(e) {
            if (e.which === 13) $('#btn-check-ip').click();
        });
    });
</script>
