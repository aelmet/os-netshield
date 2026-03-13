{#
 # NetShield — Network Security Suite for OPNsense
 # Alerts View — full alert log with filtering, details, and management
 #
 # SPDX-License-Identifier: BSD-2-Clause
 #}
<script>
$( document ).ready(function () {

    /*
     * =========================================================
     * HELPERS
     * =========================================================
     */
    function escHtml(s) {
        return $('<span>').text(s || '').html();
    }

    function fmtTs(ts) {
        if (!ts) return '—';
        return new Date(ts * 1000).toLocaleString();
    }

    function typeBadge(type) {
        var map = {
            'vpn':        'label-warning',
            'adult':      'label-danger',
            'dns_bypass': 'label-info',
            'proxy':      'label-default',
            'malware':    'label-danger',
            'geoip':      'label-primary',
            'policy':     'label-success'
        };
        var cls = map[String(type).toLowerCase()] || 'label-default';
        return '<span class="label ' + cls + '">' + escHtml(type) + '</span>';
    }

    /*
     * =========================================================
     * ALERTS BOOTGRID
     * =========================================================
     */
    $('#alerts-grid').UIBootgrid({
        search: '/api/netshield/alerts/search',
        options: {
            requestHandler: function(request) {
                var tf = $('#filter-type').val();
                var df = $('#filter-device').val().trim();
                var ds = $('#filter-date-start').val();
                var de = $('#filter-date-end').val();
                if (tf) request.type_filter   = tf;
                if (df) request.device_filter = df;
                if (ds) request.date_start    = ds;
                if (de) request.date_end      = de;
                return request;
            },
            formatters: {
                'timestamp': function(column, row) {
                    return escHtml(fmtTs(row.timestamp));
                },
                'device': function(column, row) {
                    var s = escHtml(row.device_ip || '');
                    if (row.device_name) s += ' <span class="text-muted">(' + escHtml(row.device_name) + ')</span>';
                    return s;
                },
                'type': function(column, row) {
                    return typeBadge(row.type);
                },
                'detail': function(column, row) {
                    var d = row.detail || '';
                    return d.length > 80 ? escHtml(d.substr(0, 77)) + '…' : escHtml(d);
                },
                'commands': function(column, row) {
                    return '<button type="button" class="btn btn-xs btn-default btn-alert-detail" ' +
                           'data-row-id="' + row.uuid + '" title="View Detail">' +
                           '<i class="fa fa-search"></i></button>';
                }
            }
        }
    });

    // Filter controls
    $('#filter-type, #filter-date-start, #filter-date-end').on('change', function() {
        $('#alerts-grid').bootgrid('reload');
    });

    var deviceFilterTimer = null;
    $('#filter-device').on('keyup', function() {
        clearTimeout(deviceFilterTimer);
        deviceFilterTimer = setTimeout(function() {
            $('#alerts-grid').bootgrid('reload');
        }, 400);
    });

    $('#btn-clear-filters').click(function() {
        $('#filter-type').val('');
        $('#filter-device').val('');
        $('#filter-date-start').val('');
        $('#filter-date-end').val('');
        $('#alerts-grid').bootgrid('reload');
    });

    /*
     * =========================================================
     * ALERT DETAIL DIALOG
     * =========================================================
     */
    $('#alerts-grid').on('click', '.btn-alert-detail', function() {
        var uuid = $(this).data('row-id');
        ajaxCall('/api/netshield/alerts/getAlert/' + uuid, {}, function(data) {
            if (!data || !data.alert) return;
            var a = data.alert;

            $('#adlg-ts').text(fmtTs(a.timestamp));
            $('#adlg-device').text(
                (a.device_ip || '—') + (a.device_name ? ' (' + a.device_name + ')' : '')
            );
            $('#adlg-mac').text(a.device_mac || '—');
            $('#adlg-type').html(typeBadge(a.type));
            $('#adlg-detail').text(a.detail || '—');
            $('#adlg-policy').text(a.policy_name || '—');
            $('#adlg-action-taken').text(a.action_taken || '—');
            $('#adlg-raw').text(JSON.stringify(a.raw || {}, null, 2));

            $('#dlg-alert-detail').modal('show');
        });
    });

    /*
     * =========================================================
     * FLUSH ALERTS
     * =========================================================
     */
    $('#btn-flush').click(function() {
        var days = parseInt($('#flush-days').val(), 10) || 30;
        BootstrapDialog.confirm({
            title: 'Flush Old Alerts',
            message: 'Delete all alerts older than <strong>' + days + ' days</strong>? This cannot be undone.',
            type: BootstrapDialog.TYPE_DANGER,
            callback: function(result) {
                if (!result) return;
                var btn = $('#btn-flush').prop('disabled', true)
                                        .html('<i class="fa fa-spinner fa-spin"></i> Flushing…');
                ajaxCall('/api/netshield/alerts/flush', {days: days}, function(data) {
                    btn.prop('disabled', false).html('<i class="fa fa-trash-o"></i> Flush Alerts');
                    if (data && data.status === 'ok') {
                        $('#alerts-grid').bootgrid('reload');
                        loadStats();
                        BootstrapDialog.show({
                            type: BootstrapDialog.TYPE_SUCCESS,
                            title: 'Flush Complete',
                            message: 'Removed ' + (data.deleted || 0) + ' old alert(s).',
                            buttons: [{ label: 'OK', action: function(d){ d.close(); } }]
                        });
                    }
                });
            }
        });
    });

    /*
     * =========================================================
     * EXPORT CSV
     * =========================================================
     */
    $('#btn-export-csv').click(function() {
        var tf = $('#filter-type').val();
        var df = $('#filter-device').val().trim();
        var ds = $('#filter-date-start').val();
        var de = $('#filter-date-end').val();
        var qs = '?format=csv';
        if (tf) qs += '&type_filter='   + encodeURIComponent(tf);
        if (df) qs += '&device_filter=' + encodeURIComponent(df);
        if (ds) qs += '&date_start='    + encodeURIComponent(ds);
        if (de) qs += '&date_end='      + encodeURIComponent(de);
        window.location.href = '/api/netshield/alerts/export' + qs;
    });

    /*
     * =========================================================
     * STATS
     * =========================================================
     */
    function loadStats() {
        ajaxCall('/api/netshield/alerts/stats', {}, function(data) {
            if (!data) return;
            $('#stat-total').text(data.total         || 0);
            $('#stat-today').text(data.today         || 0);
            $('#stat-vpn').text(data.vpn             || 0);
            $('#stat-adult').text(data.adult         || 0);
            $('#stat-dns-bypass').text(data.dns_bypass || 0);
            $('#stat-malware').text(data.malware     || 0);
            $('#stat-geoip').text(data.geoip         || 0);
            $('#stat-other').text(data.other         || 0);
        });
    }

    // Refresh stats every minute
    loadStats();
    setInterval(loadStats, 60000);
});
</script>

<!-- Page Header -->
<div class="content-box" style="padding:10px 15px; margin-bottom:0;">
    <h2 style="margin:0 0 5px 0;"><i class="fa fa-bell"></i> Alert Log</h2>
    <p class="text-muted" style="margin:0;">All security events detected by NetShield, with filtering and export.</p>
</div>

<!-- Summary Stats -->
<div class="content-box" style="padding:10px 15px; margin-bottom:5px;">
    <div class="row text-center">
        <div class="col-xs-6 col-sm-2">
            <strong id="stat-total">—</strong><br>
            <small class="text-muted">Total Alerts</small>
        </div>
        <div class="col-xs-6 col-sm-2">
            <strong class="text-primary" id="stat-today">—</strong><br>
            <small class="text-muted">Today</small>
        </div>
        <div class="col-xs-6 col-sm-2">
            <strong class="text-warning" id="stat-vpn">—</strong><br>
            <small class="text-muted">VPN</small>
        </div>
        <div class="col-xs-6 col-sm-2">
            <strong class="text-danger" id="stat-adult">—</strong><br>
            <small class="text-muted">Adult</small>
        </div>
        <div class="col-xs-6 col-sm-2">
            <strong class="text-info" id="stat-dns-bypass">—</strong><br>
            <small class="text-muted">DNS Bypass</small>
        </div>
        <div class="col-xs-6 col-sm-2">
            <strong class="text-danger" id="stat-malware">—</strong><br>
            <small class="text-muted">Malware</small>
        </div>
    </div>
</div>

<!-- Filters + Controls -->
<div class="content-box" style="padding:10px 15px;">

    <div class="row" style="margin-bottom:10px;">
        <!-- Type filter -->
        <div class="col-xs-12 col-sm-6 col-md-2">
            <select class="form-control input-sm" id="filter-type">
                <option value="">— All Types —</option>
                <option value="vpn">VPN</option>
                <option value="adult">Adult</option>
                <option value="dns_bypass">DNS Bypass</option>
                <option value="proxy">Proxy</option>
                <option value="malware">Malware</option>
                <option value="geoip">GeoIP</option>
                <option value="policy">Policy</option>
            </select>
        </div>
        <!-- Device IP filter -->
        <div class="col-xs-12 col-sm-6 col-md-2">
            <input type="text" class="form-control input-sm" id="filter-device"
                   placeholder="Device IP or name…">
        </div>
        <!-- Date range -->
        <div class="col-xs-6 col-md-2">
            <input type="date" class="form-control input-sm" id="filter-date-start"
                   title="From date">
        </div>
        <div class="col-xs-6 col-md-2">
            <input type="date" class="form-control input-sm" id="filter-date-end"
                   title="To date">
        </div>
        <!-- Action buttons -->
        <div class="col-xs-12 col-md-4 text-right" style="padding-top:2px;">
            <div class="btn-group btn-group-sm">
                <button id="btn-clear-filters" class="btn btn-default">
                    <i class="fa fa-times"></i> Clear Filters
                </button>
                <button id="btn-export-csv" class="btn btn-default">
                    <i class="fa fa-download"></i> Export CSV
                </button>
            </div>
            <div class="btn-group btn-group-sm" style="margin-left:5px;">
                <span class="input-group input-group-sm" style="display:inline-table; width:auto;">
                    <input type="number" class="form-control" id="flush-days"
                           value="30" min="1" max="365" style="width:60px; display:inline-block;">
                    <span class="input-group-btn">
                        <button id="btn-flush" class="btn btn-danger">
                            <i class="fa fa-trash-o"></i> Flush Older Than (days)
                        </button>
                    </span>
                </span>
            </div>
        </div>
    </div>

    <!-- Alerts Bootgrid -->
    <table id="alerts-grid" class="table table-condensed table-hover table-striped">
        <thead>
            <tr>
                <th data-column-id="uuid"       data-identifier="true" data-visible="false">UUID</th>
                <th data-column-id="timestamp"  data-sortable="true"  data-formatter="timestamp" style="width:160px;">Timestamp</th>
                <th data-column-id="device"     data-sortable="true"  data-formatter="device">Device</th>
                <th data-column-id="type"       data-sortable="true"  data-formatter="type" style="width:110px;">Type</th>
                <th data-column-id="detail"     data-sortable="false" data-formatter="detail">Detail</th>
                <th data-column-id="commands"   data-formatter="commands" data-sortable="false" style="width:50px;"></th>
            </tr>
        </thead>
        <tbody></tbody>
    </table>

</div>

<!-- ===================================================
     ALERT DETAIL DIALOG
     =================================================== -->
<div class="modal fade" id="dlg-alert-detail" tabindex="-1" role="dialog">
    <div class="modal-dialog modal-lg" role="document">
        <div class="modal-content">
            <div class="modal-header">
                <button type="button" class="close" data-dismiss="modal"><span>&times;</span></button>
                <h4 class="modal-title"><i class="fa fa-search"></i> Alert Detail</h4>
            </div>
            <div class="modal-body">
                <table class="table table-condensed">
                    <tbody>
                        <tr>
                            <th style="width:140px;">Timestamp</th>
                            <td id="adlg-ts"></td>
                        </tr>
                        <tr>
                            <th>Device</th>
                            <td id="adlg-device"></td>
                        </tr>
                        <tr>
                            <th>MAC Address</th>
                            <td id="adlg-mac"></td>
                        </tr>
                        <tr>
                            <th>Alert Type</th>
                            <td id="adlg-type"></td>
                        </tr>
                        <tr>
                            <th>Detail</th>
                            <td id="adlg-detail"></td>
                        </tr>
                        <tr>
                            <th>Policy Triggered</th>
                            <td id="adlg-policy"></td>
                        </tr>
                        <tr>
                            <th>Action Taken</th>
                            <td id="adlg-action-taken"></td>
                        </tr>
                    </tbody>
                </table>

                <div class="panel panel-default" style="margin-top:10px; margin-bottom:0;">
                    <div class="panel-heading">
                        <strong>Raw Event Data</strong>
                    </div>
                    <div class="panel-body" style="padding:8px;">
                        <pre id="adlg-raw" style="max-height:300px; overflow-y:auto; margin:0;
                                                   font-size:11px; background:#f5f5f5; border:none;"></pre>
                    </div>
                </div>
            </div>
            <div class="modal-footer">
                <button type="button" class="btn btn-default" data-dismiss="modal">Close</button>
            </div>
        </div>
    </div>
</div>
