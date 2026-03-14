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
        <h1>{{ ('Threat Intelligence') }}</h1>

        {# ------------------------------------------------------------------ #}
        {# Stats Cards                                                         #}
        {# ------------------------------------------------------------------ #}
        <div class="row" id="threat-stats-row">
            <div class="col-sm-3">
                <div class="panel panel-default">
                    <div class="panel-body text-center">
                        <h2 id="stat-total-iocs">—</h2>
                        <p class="text-muted">{{ ('Active IoCs') }}</p>
                    </div>
                </div>
            </div>
            <div class="col-sm-3">
                <div class="panel panel-default">
                    <div class="panel-body text-center">
                        <h2 id="stat-feeds-active">—</h2>
                        <p class="text-muted">{{ ('Feeds Active') }}</p>
                    </div>
                </div>
            </div>
            <div class="col-sm-3">
                <div class="panel panel-default">
                    <div class="panel-body text-center">
                        <h2 id="stat-blocked-today">—</h2>
                        <p class="text-muted">{{ ('Threats Blocked Today') }}</p>
                    </div>
                </div>
            </div>
            <div class="col-sm-3">
                <div class="panel panel-default">
                    <div class="panel-body text-center">
                        <h2 id="stat-detections">—</h2>
                        <p class="text-muted">{{ ('Behavioral Detections') }}</p>
                    </div>
                </div>
            </div>
        </div>

        {# ------------------------------------------------------------------ #}
        {# Threat Feeds Panel                                                  #}
        {# ------------------------------------------------------------------ #}
        <div class="panel panel-default">
            <div class="panel-heading">
                <h3 class="panel-title">
                    {{ ('Threat Feeds') }}
                    <span class="pull-right">
                        <button class="btn btn-sm btn-primary" id="btn-update-all-feeds">
                            <i class="fa fa-refresh"></i>
                            {{ ('Update All Feeds') }}
                        </button>
                    </span>
                </h3>
            </div>
            <div class="panel-body">
                <table class="table table-condensed table-striped" id="threat-feeds-table">
                    <thead>
                        <tr>
                            <th>{{ ('Name') }}</th>
                            <th>{{ ('Type') }}</th>
                            <th>{{ ('IoC Count') }}</th>
                            <th>{{ ('Last Updated') }}</th>
                            <th>{{ ('Status') }}</th>
                            <th>{{ ('Actions') }}</th>
                        </tr>
                    </thead>
                    <tbody id="threat-feeds-body">
                        <tr>
                            <td colspan="6" class="text-center text-muted">
                                {{ ('Loading feeds…') }}
                            </td>
                        </tr>
                    </tbody>
                </table>
            </div>
        </div>

        {# ------------------------------------------------------------------ #}
        {# IP Check Tool                                                       #}
        {# ------------------------------------------------------------------ #}
        <div class="panel panel-default">
            <div class="panel-heading">
                <h3 class="panel-title">{{ ('IP Threat Check') }}</h3>
            </div>
            <div class="panel-body">
                <div class="input-group" style="max-width: 400px;">
                    <input type="text" class="form-control" id="check-ip-input"
                           placeholder="{{ ('Enter IP address…') }}">
                    <span class="input-group-btn">
                        <button class="btn btn-default" id="btn-check-ip">
                            <i class="fa fa-search"></i>
                            {{ ('Check') }}
                        </button>
                    </span>
                </div>
                <div id="check-ip-result" class="alert" style="display:none; margin-top:10px;"></div>
            </div>
        </div>

        {# ------------------------------------------------------------------ #}
        {# Behavioral Detections                                               #}
        {# ------------------------------------------------------------------ #}
        <div class="panel panel-default">
            <div class="panel-heading">
                <h3 class="panel-title">{{ ('Behavioral IDS Detections') }}</h3>
            </div>
            <div class="panel-body">
                <table id="detections-grid" class="table table-condensed table-hover"
                       data-editAlert="false"
                       data-deleteAlert="false">
                    <thead>
                        <tr>
                            <th data-column-id="time" data-sortable="true">
                                {{ ('Time') }}
                            </th>
                            <th data-column-id="src_ip" data-sortable="true">
                                {{ ('Source IP') }}
                            </th>
                            <th data-column-id="detection_type" data-sortable="true"
                                data-formatter="detectionType">
                                {{ ('Detection Type') }}
                            </th>
                            <th data-column-id="severity" data-sortable="true"
                                data-formatter="severity">
                                {{ ('Severity') }}
                            </th>
                            <th data-column-id="detail">
                                {{ ('Detail') }}
                            </th>
                        </tr>
                    </thead>
                    <tbody></tbody>
                    <tfoot>
                        <tr>
                            <td colspan="5">
                                <div class="pull-right">
                                    <nav data-toggle="bootgrid-pagination"></nav>
                                </div>
                                <div class="pull-left">
                                    <select data-toggle="bootgrid-rowcount" class="form-control">
                                        <option value="10">10</option>
                                        <option value="25" selected>25</option>
                                        <option value="50">50</option>
                                    </select>
                                </div>
                            </td>
                        </tr>
                    </tfoot>
                </table>
            </div>
        </div>

    </div>
</div>

<script>
$(function () {
    var SEVERITY_CLASS = {
        critical: 'danger',
        high:     'warning',
        medium:   'info',
        low:      'default'
    };
    var DETECTION_LABELS = {
        port_scan:        '{{ ("Port Scan") }}',
        data_exfil:       '{{ ("Data Exfil") }}',
        beaconing:        '{{ ("Beaconing") }}',
        lateral_movement: '{{ ("Lateral Movement") }}',
        dns_tunneling:    '{{ ("DNS Tunneling") }}'
    };

    // ---- Stats ----
    function loadStats() {
        $.getJSON('/api/netshield/threatintel/stats', function (data) {
            var s = data.stats || data;
            $('#stat-total-iocs').text(s.total_iocs !== undefined ? s.total_iocs.toLocaleString() : '—');
            $('#stat-feeds-active').text(s.feeds_active !== undefined ? s.feeds_active : '—');
        });
    }
    loadStats();

    // ---- Feeds table ----
    function loadFeeds() {
        $.getJSON('/api/netshield/threatintel/feeds', function (data) {
            var feeds = data.feeds || [];
            var tbody = $('#threat-feeds-body').empty();
            if (!feeds.length) {
                tbody.append('<tr><td colspan="6" class="text-center text-muted">{{ ("No feeds configured") }}</td></tr>');
                return;
            }
            $.each(feeds, function (_, f) {
                var statusBadge = f.enabled
                    ? '<span class="label label-success">{{ ("Enabled") }}</span>'
                    : '<span class="label label-default">{{ ("Disabled") }}</span>';
                var toggleLabel = f.enabled ? '{{ ("Disable") }}' : '{{ ("Enable") }}';
                var toggleVal   = f.enabled ? '0' : '1';
                var row = $('<tr>').append(
                    $('<td>').text(f.name),
                    $('<td>').text(f.ioc_type || 'ip'),
                    $('<td>').text(f.ioc_count !== undefined ? f.ioc_count.toLocaleString() : '—'),
                    $('<td>').text(f.last_updated || '—'),
                    $('<td>').html(statusBadge),
                    $('<td>').html(
                        '<button class="btn btn-xs btn-default btn-toggle-feed" '
                        + 'data-name="' + $('<div>').text(f.name).html() + '" '
                        + 'data-enabled="' + toggleVal + '">' + toggleLabel + '</button>'
                    )
                );
                tbody.append(row);
            });
        });
    }
    loadFeeds();

    // Toggle feed
    $(document).on('click', '.btn-toggle-feed', function () {
        var btn   = $(this);
        var name  = btn.data('name');
        var enval = btn.data('enabled');
        $.post('/api/netshield/threatintel/toggleFeed', {name: name, enabled: enval}, function () {
            loadFeeds();
        });
    });

    // Update all feeds
    $('#btn-update-all-feeds').on('click', function () {
        var btn = $(this).prop('disabled', true).html('<i class="fa fa-spinner fa-spin"></i> {{ ("Updating…") }}');
        $.post('/api/netshield/threatintel/updateFeeds', function () {
            loadStats();
            loadFeeds();
        }).always(function () {
            btn.prop('disabled', false).html('<i class="fa fa-refresh"></i> {{ ("Update All Feeds") }}');
        });
    });

    // ---- IP Check ----
    $('#btn-check-ip').on('click', function () {
        var ip  = $('#check-ip-input').val().trim();
        var div = $('#check-ip-result');
        if (!ip) return;
        div.hide();
        $.getJSON('/api/netshield/threatintel/checkIp', {ip: ip}, function (data) {
            var r = data.result || {};
            div.removeClass('alert-danger alert-warning alert-success alert-info');
            if (r.matched) {
                div.addClass('alert-danger').html(
                    '<strong>' + $('<div>').text(ip).html() + '</strong> '
                    + '{{ ("is listed in:") }} '
                    + (r.feeds || []).join(', ')
                    + ' &mdash; {{ ("Severity:") }} <strong>' + (r.severity || '') + '</strong>'
                ).show();
            } else {
                div.addClass('alert-success').html(
                    '<strong>' + $('<div>').text(ip).html() + '</strong> '
                    + '{{ ("is not in any threat feed.") }}'
                ).show();
            }
        }).fail(function () {
            div.addClass('alert-warning').text('{{ ("Lookup failed. Check console.") }}').show();
        });
    });

    // ---- Detections bootgrid ----
    $('#detections-grid').UIBootgrid({
            'search': '/api/netshield/threatintel/detections',
            'options': {
                selection: false,
                multiSelect: false,
                rowCount: [25, 50, 100],
        formatters: {
            detectionType: function (column, row) {
                var label = DETECTION_LABELS[row.detection_type] || row.detection_type;
                return '<span class="label label-info">' + label + '</span>';
            },
            severity: function (column, row) {
                var cls = SEVERITY_CLASS[row.severity] || 'default';
                return '<span class="label label-' + cls + '">' + (row.severity || '') + '</span>';
            }
        }
            }
        });
});
</script>
