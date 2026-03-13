{#
 # NetShield — Network Security Suite for OPNsense
 # Devices View — dedicated device management page
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
    function statusBadge(status) {
        var map = {
            'approved':    '<span class="label label-success">Approved</span>',
            'quarantined': '<span class="label label-danger">Quarantined</span>',
            'unknown':     '<span class="label label-warning">Unknown</span>'
        };
        return map[String(status).toLowerCase()] ||
               '<span class="label label-default">' + $('<span>').text(status).html() + '</span>';
    }

    function escHtml(s) {
        return $('<span>').text(s || '').html();
    }

    function fmtTs(ts) {
        if (!ts) return '—';
        return new Date(ts * 1000).toLocaleString();
    }

    /*
     * =========================================================
     * DEVICES BOOTGRID
     * =========================================================
     */
    $('#devices-grid').UIBootgrid({
        search: '/api/netshield/devices/search',
        get:    '/api/netshield/devices/getDevice/',
        set:    '/api/netshield/devices/setDevice/',
        add:    '/api/netshield/devices/addDevice/',
        del:    '/api/netshield/devices/delDevice/',
        options: {
            requestHandler: function(request) {
                var statusFilter = $('#filter-status').val();
                var catFilter    = $('#filter-category').val();
                if (statusFilter) request.status_filter   = statusFilter;
                if (catFilter)    request.category_filter = catFilter;
                return request;
            },
            formatters: {
                'status': function(column, row) {
                    return statusBadge(row.status);
                },
                'last_seen': function(column, row) {
                    return escHtml(fmtTs(row.last_seen));
                },
                'commands': function(column, row) {
                    var btns = '<button type="button" class="btn btn-xs btn-default btn-detail" ' +
                               'data-row-id="' + row.uuid + '" title="View Details">' +
                               '<i class="fa fa-info-circle"></i></button> ';

                    if (row.status === 'quarantined') {
                        btns += '<button type="button" class="btn btn-xs btn-success btn-approve" ' +
                                'data-row-id="' + row.uuid + '" title="Approve">' +
                                '<i class="fa fa-check"></i> Approve</button> ';
                        btns += '<button type="button" class="btn btn-xs btn-warning btn-unquarantine" ' +
                                'data-row-id="' + row.uuid + '" title="Remove from Quarantine">' +
                                '<i class="fa fa-unlock"></i> Unquarantine</button>';
                    } else if (row.status === 'approved') {
                        btns += '<button type="button" class="btn btn-xs btn-danger btn-quarantine" ' +
                                'data-row-id="' + row.uuid + '" title="Quarantine Device">' +
                                '<i class="fa fa-ban"></i> Quarantine</button>';
                    } else {
                        btns += '<button type="button" class="btn btn-xs btn-success btn-approve" ' +
                                'data-row-id="' + row.uuid + '" title="Approve">' +
                                '<i class="fa fa-check"></i> Approve</button> ';
                        btns += '<button type="button" class="btn btn-xs btn-danger btn-quarantine" ' +
                                'data-row-id="' + row.uuid + '" title="Quarantine Device">' +
                                '<i class="fa fa-ban"></i> Quarantine</button>';
                    }
                    return btns;
                }
            }
        }
    });

    // Action delegation
    $('#devices-grid').on('click', '[data-row-id]', function() {
        var uuid   = $(this).data('row-id');
        var action = '';
        if ($(this).hasClass('btn-detail'))        action = 'detail';
        else if ($(this).hasClass('btn-approve'))      action = 'approve';
        else if ($(this).hasClass('btn-quarantine'))   action = 'quarantine';
        else if ($(this).hasClass('btn-unquarantine')) action = 'unquarantine';

        if (action === 'detail') {
            openDetailDialog(uuid);
        } else if (action === 'approve') {
            ajaxCall('/api/netshield/devices/approve/' + uuid, {}, function() {
                $('#devices-grid').bootgrid('reload');
                loadStats();
            });
        } else if (action === 'quarantine') {
            BootstrapDialog.confirm({
                title: 'Quarantine Device',
                message: 'This will block all traffic from this device. Continue?',
                type: BootstrapDialog.TYPE_WARNING,
                callback: function(result) {
                    if (result) {
                        ajaxCall('/api/netshield/devices/quarantine/' + uuid, {}, function() {
                            $('#devices-grid').bootgrid('reload');
                            loadStats();
                        });
                    }
                }
            });
        } else if (action === 'unquarantine') {
            ajaxCall('/api/netshield/devices/unquarantine/' + uuid, {}, function() {
                $('#devices-grid').bootgrid('reload');
                loadStats();
            });
        }
    });

    // Filter change reloads grid
    $('#filter-status, #filter-category').change(function() {
        $('#devices-grid').bootgrid('reload');
    });

    /*
     * =========================================================
     * DEVICE DETAIL DIALOG
     * =========================================================
     */
    function openDetailDialog(uuid) {
        ajaxCall('/api/netshield/devices/getDevice/' + uuid, {}, function(data) {
            if (!data || !data.device) return;
            var d = data.device;

            // Populate read-only info
            $('#dev-detail-mac').text(d.mac       || '—');
            $('#dev-detail-ip').text(d.ip         || '—');
            $('#dev-detail-vendor').text(d.vendor || '—');
            $('#dev-detail-last-seen').text(fmtTs(d.last_seen));
            $('#dev-detail-first-seen').text(fmtTs(d.first_seen));
            $('#dev-detail-status').html(statusBadge(d.status));
            $('#dev-detail-alert-count').text(d.alert_count || 0);

            // Populate editable fields
            $('#dev-hostname').val(d.hostname || '');
            $('#dev-category').val(d.category || '');
            $('#dev-notes').val(d.notes || '');
            $('#dev-detail-uuid').val(uuid);

            // Alert history
            var tbody = $('#dev-alert-history').empty();
            if (d.recent_alerts && d.recent_alerts.length) {
                $.each(d.recent_alerts, function(i, a) {
                    tbody.append(
                        '<tr>' +
                        '<td>' + escHtml(fmtTs(a.timestamp)) + '</td>' +
                        '<td>' + escHtml(a.type)   + '</td>' +
                        '<td>' + escHtml(a.detail) + '</td>' +
                        '</tr>'
                    );
                });
            } else {
                tbody.append('<tr><td colspan="3" class="text-muted text-center">No recent alerts</td></tr>');
            }

            $('#dlg-device-detail').modal('show');
        });
    }

    $('#btn-device-save').click(function() {
        var uuid = $('#dev-detail-uuid').val();
        var payload = {
            device: {
                hostname: $('#dev-hostname').val(),
                category: $('#dev-category').val(),
                notes:    $('#dev-notes').val()
            }
        };
        ajaxCall('/api/netshield/devices/setDevice/' + uuid, payload, function(data) {
            if (data && data.result === 'saved') {
                $('#dlg-device-detail').modal('hide');
                $('#devices-grid').bootgrid('reload');
            }
        });
    });

    /*
     * =========================================================
     * BULK ACTIONS
     * =========================================================
     */
    $('#btn-approve-selected').click(function() {
        var selected = getSelectedUuids();
        if (!selected.length) return;
        $.each(selected, function(i, uuid) {
            ajaxCall('/api/netshield/devices/approve/' + uuid, {}, function() {});
        });
        setTimeout(function() {
            $('#devices-grid').bootgrid('reload');
            loadStats();
        }, 500);
    });

    $('#btn-quarantine-selected').click(function() {
        var selected = getSelectedUuids();
        if (!selected.length) return;
        BootstrapDialog.confirm({
            title: 'Quarantine Selected Devices',
            message: 'Quarantine ' + selected.length + ' selected device(s)?',
            type: BootstrapDialog.TYPE_WARNING,
            callback: function(result) {
                if (!result) return;
                $.each(selected, function(i, uuid) {
                    ajaxCall('/api/netshield/devices/quarantine/' + uuid, {}, function() {});
                });
                setTimeout(function() {
                    $('#devices-grid').bootgrid('reload');
                    loadStats();
                }, 500);
            }
        });
    });

    function getSelectedUuids() {
        var uuids = [];
        $('#devices-grid').find('tr.active input[type="checkbox"]').each(function() {
            uuids.push($(this).val());
        });
        return uuids;
    }

    /*
     * =========================================================
     * STATS
     * =========================================================
     */
    function loadStats() {
        ajaxCall('/api/netshield/devices/stats', {}, function(data) {
            if (data) {
                $('#stat-total').text(data.total          || 0);
                $('#stat-approved').text(data.approved    || 0);
                $('#stat-quarantined').text(data.quarantined || 0);
                $('#stat-unknown').text(data.unknown      || 0);
            }
        });
    }

    // Initial load
    loadStats();
});
</script>

<!-- Page Header -->
<div class="content-box" style="padding:10px 15px; margin-bottom:0;">
    <div class="row">
        <div class="col-xs-12">
            <h2 style="margin:0 0 5px 0;"><i class="fa fa-desktop"></i> Device Management</h2>
            <p class="text-muted" style="margin:0;">
                Track, categorize, approve, and quarantine network devices.
            </p>
        </div>
    </div>
</div>

<!-- Stats Bar -->
<div class="content-box" style="padding:10px 15px; margin-bottom:5px;">
    <div class="row text-center">
        <div class="col-xs-6 col-sm-3">
            <strong id="stat-total">—</strong><br>
            <small class="text-muted">Total Devices</small>
        </div>
        <div class="col-xs-6 col-sm-3">
            <strong class="text-success" id="stat-approved">—</strong><br>
            <small class="text-muted">Approved</small>
        </div>
        <div class="col-xs-6 col-sm-3">
            <strong class="text-danger" id="stat-quarantined">—</strong><br>
            <small class="text-muted">Quarantined</small>
        </div>
        <div class="col-xs-6 col-sm-3">
            <strong class="text-warning" id="stat-unknown">—</strong><br>
            <small class="text-muted">Unknown</small>
        </div>
    </div>
</div>

<!-- Controls -->
<div class="content-box" style="padding:10px 15px;">

    <div class="row" style="margin-bottom:10px;">
        <!-- Filters -->
        <div class="col-xs-12 col-sm-4 col-md-3">
            <select class="form-control input-sm" id="filter-status">
                <option value="">— All Statuses —</option>
                <option value="approved">Approved</option>
                <option value="quarantined">Quarantined</option>
                <option value="unknown">Unknown</option>
            </select>
        </div>
        <div class="col-xs-12 col-sm-4 col-md-3">
            <select class="form-control input-sm" id="filter-category">
                <option value="">— All Categories —</option>
                <option value="computer">Computer</option>
                <option value="mobile">Mobile</option>
                <option value="iot">IoT</option>
                <option value="tv">Smart TV</option>
                <option value="gaming">Gaming Console</option>
                <option value="printer">Printer</option>
                <option value="camera">Security Camera</option>
                <option value="other">Other</option>
            </select>
        </div>
        <!-- Bulk actions -->
        <div class="col-xs-12 col-sm-4 col-md-6 text-right">
            <div class="btn-group btn-group-sm">
                <button id="btn-approve-selected" class="btn btn-success">
                    <i class="fa fa-check"></i> Approve Selected
                </button>
                <button id="btn-quarantine-selected" class="btn btn-danger">
                    <i class="fa fa-ban"></i> Quarantine Selected
                </button>
            </div>
        </div>
    </div>

    <!-- Devices Bootgrid -->
    <table id="devices-grid" class="table table-condensed table-hover table-striped">
        <thead>
            <tr>
                <th data-column-id="uuid"      data-identifier="true" data-visible="false">UUID</th>
                <th data-column-id="mac"       data-sortable="true">MAC Address</th>
                <th data-column-id="ip"        data-sortable="true">IP Address</th>
                <th data-column-id="hostname"  data-sortable="true">Hostname</th>
                <th data-column-id="vendor"    data-sortable="true">Vendor</th>
                <th data-column-id="category"  data-sortable="true">Category</th>
                <th data-column-id="status"    data-sortable="true" data-formatter="status">Status</th>
                <th data-column-id="last_seen" data-sortable="true" data-formatter="last_seen">Last Seen</th>
                <th data-column-id="commands"  data-formatter="commands" data-sortable="false" style="width:220px;">Actions</th>
            </tr>
        </thead>
        <tbody></tbody>
    </table>

</div>

<!-- ===================================================
     DEVICE DETAIL / EDIT DIALOG
     =================================================== -->
<div class="modal fade" id="dlg-device-detail" tabindex="-1" role="dialog">
    <div class="modal-dialog modal-lg" role="document">
        <div class="modal-content">
            <div class="modal-header">
                <button type="button" class="close" data-dismiss="modal"><span>&times;</span></button>
                <h4 class="modal-title"><i class="fa fa-desktop"></i> Device Detail</h4>
            </div>
            <div class="modal-body">
                <input type="hidden" id="dev-detail-uuid">
                <div class="row">
                    <!-- Left: read-only info -->
                    <div class="col-md-6">
                        <h5><strong>Network Information</strong></h5>
                        <table class="table table-condensed">
                            <tr><th>MAC Address</th>  <td id="dev-detail-mac"></td></tr>
                            <tr><th>IP Address</th>   <td id="dev-detail-ip"></td></tr>
                            <tr><th>Vendor</th>       <td id="dev-detail-vendor"></td></tr>
                            <tr><th>Status</th>       <td id="dev-detail-status"></td></tr>
                            <tr><th>First Seen</th>   <td id="dev-detail-first-seen"></td></tr>
                            <tr><th>Last Seen</th>    <td id="dev-detail-last-seen"></td></tr>
                            <tr><th>Alert Count</th>  <td id="dev-detail-alert-count"></td></tr>
                        </table>
                    </div>
                    <!-- Right: editable fields -->
                    <div class="col-md-6">
                        <h5><strong>Device Settings</strong></h5>
                        <div class="form-group">
                            <label>Hostname / Friendly Name</label>
                            <input type="text" class="form-control" id="dev-hostname" placeholder="e.g. Johns-iPhone">
                        </div>
                        <div class="form-group">
                            <label>Category</label>
                            <select class="form-control" id="dev-category">
                                <option value="">— Uncategorized —</option>
                                <option value="computer">Computer</option>
                                <option value="mobile">Mobile</option>
                                <option value="iot">IoT</option>
                                <option value="tv">Smart TV</option>
                                <option value="gaming">Gaming Console</option>
                                <option value="printer">Printer</option>
                                <option value="camera">Security Camera</option>
                                <option value="other">Other</option>
                            </select>
                        </div>
                        <div class="form-group">
                            <label>Notes</label>
                            <textarea class="form-control" id="dev-notes" rows="4"
                                      placeholder="Any notes about this device…"></textarea>
                        </div>
                    </div>
                </div>

                <!-- Alert History -->
                <h5><strong>Recent Alert History</strong></h5>
                <table class="table table-condensed table-striped">
                    <thead>
                        <tr>
                            <th>Timestamp</th>
                            <th>Type</th>
                            <th>Detail</th>
                        </tr>
                    </thead>
                    <tbody id="dev-alert-history">
                        <tr><td colspan="3" class="text-center text-muted">Loading…</td></tr>
                    </tbody>
                </table>
            </div>
            <div class="modal-footer">
                <button type="button" class="btn btn-default" data-dismiss="modal">Close</button>
                <button type="button" class="btn btn-primary" id="btn-device-save">
                    <i class="fa fa-save"></i> Save Changes
                </button>
            </div>
        </div>
    </div>
</div>
