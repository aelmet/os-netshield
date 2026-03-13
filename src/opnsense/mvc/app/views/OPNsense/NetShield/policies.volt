{#
 # NetShield — Network Security Suite for OPNsense
 # Policies View — dedicated policy management page
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

    function actionBadge(action) {
        var map = {block: 'danger', allow: 'success', throttle: 'warning', log: 'info'};
        return '<span class="label label-' + (map[action] || 'default') + '">' + escHtml(action) + '</span>';
    }

    function scopeBadge(scope) {
        var map = {network: 'info', vlan: 'primary', device: 'warning', device_category: 'success'};
        return '<span class="label label-' + (map[scope] || 'default') + '">' + escHtml(scope) + '</span>';
    }

    function statusBadge(enabled) {
        return (enabled == '1' || enabled === true)
            ? '<span class="label label-success">Enabled</span>'
            : '<span class="label label-default">Disabled</span>';
    }

    function buildScheduleSummary(row) {
        var days = [];
        var dayMap = {sched_mon: 'Mon', sched_tue: 'Tue', sched_wed: 'Wed', sched_thu: 'Thu',
                      sched_fri: 'Fri', sched_sat: 'Sat', sched_sun: 'Sun'};
        $.each(dayMap, function(k, v) {
            if (row[k] == '1') days.push(v);
        });
        if (!days.length) return '<span class="text-muted">Always</span>';
        var time = '';
        if (row.start_time || row.end_time) {
            time = ' ' + (row.start_time || '00:00') + '–' + (row.end_time || '23:59');
        }
        return escHtml(days.join(', ') + time);
    }

    /*
     * =========================================================
     * POLICIES BOOTGRID
     * =========================================================
     */
    $('#policies-grid').UIBootgrid({
        search: '/api/netshield/policies/search',
        get:    '/api/netshield/policies/getPolicy/',
        set:    '/api/netshield/policies/setPolicy/',
        add:    '/api/netshield/policies/addPolicy/',
        del:    '/api/netshield/policies/delPolicy/',
        options: {
            formatters: {
                'enabled': function(column, row) {
                    return statusBadge(row.enabled);
                },
                'action': function(column, row) {
                    return actionBadge(row.action);
                },
                'scope': function(column, row) {
                    return scopeBadge(row.scope);
                },
                'schedule': function(column, row) {
                    return buildScheduleSummary(row);
                },
                'commands': function(column, row) {
                    var toggleLabel = (row.enabled == '1') ? 'Disable' : 'Enable';
                    var toggleClass = (row.enabled == '1') ? 'btn-default' : 'btn-success';
                    var toggleIcon  = (row.enabled == '1') ? 'fa-toggle-off' : 'fa-toggle-on';
                    return (
                        '<button type="button" class="btn btn-xs btn-primary btn-edit" ' +
                        'data-row-id="' + row.uuid + '" title="Edit"><i class="fa fa-pencil"></i></button> ' +
                        '<button type="button" class="btn btn-xs ' + toggleClass + ' btn-toggle" ' +
                        'data-row-id="' + row.uuid + '" data-enabled="' + row.enabled + '" title="' + toggleLabel + '">' +
                        '<i class="fa ' + toggleIcon + '"></i></button> ' +
                        '<button type="button" class="btn btn-xs btn-danger btn-delete" ' +
                        'data-row-id="' + row.uuid + '" title="Delete"><i class="fa fa-trash-o"></i></button>'
                    );
                }
            }
        }
    });

    // Action delegation
    $('#policies-grid').on('click', '[data-row-id]', function() {
        var uuid = $(this).data('row-id');
        if ($(this).hasClass('btn-edit')) {
            openEditDialog(uuid);
        } else if ($(this).hasClass('btn-toggle')) {
            var enabled = $(this).data('enabled');
            var newEnabled = (enabled == '1') ? 0 : 1;
            ajaxCall('/api/netshield/policies/setEnabled/' + uuid, {enabled: newEnabled}, function() {
                $('#policies-grid').bootgrid('reload');
                loadStats();
            });
        } else if ($(this).hasClass('btn-delete')) {
            BootstrapDialog.confirm({
                title: 'Delete Policy',
                message: 'Delete this policy? This cannot be undone.',
                type: BootstrapDialog.TYPE_DANGER,
                callback: function(result) {
                    if (result) {
                        ajaxCall('/api/netshield/policies/delPolicy/' + uuid, {}, function() {
                            $('#policies-grid').bootgrid('reload');
                            loadStats();
                        });
                    }
                }
            });
        }
    });

    /*
     * =========================================================
     * POLICY DIALOG
     * =========================================================
     */
    function clearDialog() {
        $('#policy-uuid').val('');
        $('#policy-name').val('');
        $('#policy-enabled').val('1');
        $('#policy-priority').val('100');
        $('#policy-scope').val('network');
        $('#policy-scope-value').val('');
        $('#policy-scope-value-label').text('CIDR (e.g. 192.168.1.0/24)');
        $('#policy-action').val('block');
        $('#policy-target-type').val('web_categories');
        $('#policy-target-value').val('');
        $('#policy-bandwidth').val('');
        $('#row-bandwidth').hide();
        $('[name^="sched_"]').prop('checked', false);
        $('#policy-start-time').val('00:00');
        $('#policy-end-time').val('23:59');
        $('#dlg-policy .modal-title').text('Add Policy');
    }

    function openEditDialog(uuid) {
        ajaxCall('/api/netshield/policies/getPolicy/' + uuid, {}, function(data) {
            if (!data || !data.policy) return;
            var p = data.policy;

            clearDialog();
            $('#policy-uuid').val(uuid);
            $('#policy-name').val(p.name || '');
            $('#policy-enabled').val(p.enabled || '1');
            $('#policy-priority').val(p.priority || '100');
            $('#policy-scope').val(p.scope || 'network');
            $('#policy-scope').trigger('change');
            $('#policy-scope-value').val(p.scope_value || '');
            $('#policy-action').val(p.action || 'block');
            $('#policy-action').trigger('change');
            $('#policy-target-type').val(p.target_type || 'web_categories');
            $('#policy-target-value').val(p.target_value || '');
            $('#policy-bandwidth').val(p.bandwidth_limit || '');
            $('#policy-start-time').val(p.start_time || '00:00');
            $('#policy-end-time').val(p.end_time || '23:59');

            // Checkboxes
            var dayMap = ['sched_mon','sched_tue','sched_wed','sched_thu','sched_fri','sched_sat','sched_sun'];
            $.each(dayMap, function(i, k) {
                $('[name="' + k + '"]').prop('checked', p[k] == '1');
            });

            $('#dlg-policy .modal-title').text('Edit Policy — ' + escHtml(p.name));
            $('#dlg-policy').modal('show');
        });
    }

    $('#btn-policy-add').click(function() {
        clearDialog();
        $('#dlg-policy').modal('show');
    });

    // Scope dropdown updates helper label
    $('#policy-scope').change(function() {
        var labels = {
            network: 'CIDR Range (e.g. 192.168.1.0/24)',
            vlan: 'VLAN ID (e.g. 10)',
            device: 'MAC Address (e.g. aa:bb:cc:dd:ee:ff)',
            device_category: 'Category Name (e.g. mobile)'
        };
        $('#policy-scope-value-label').text(labels[$(this).val()] || 'Value');
    });

    // Action dropdown shows/hides bandwidth
    $('#policy-action').change(function() {
        $('#row-bandwidth').toggle($(this).val() === 'throttle');
    });

    // Save policy
    $('#btn-policy-save').click(function() {
        var uuid = $('#policy-uuid').val();
        var endpoint = uuid
            ? '/api/netshield/policies/setPolicy/' + uuid
            : '/api/netshield/policies/addPolicy/';

        var days = {};
        $('[name^="sched_"]').each(function() {
            days[$(this).attr('name')] = $(this).is(':checked') ? '1' : '0';
        });

        var payload = {
            policy: $.extend({
                name:            $('#policy-name').val(),
                enabled:         $('#policy-enabled').val(),
                priority:        $('#policy-priority').val(),
                scope:           $('#policy-scope').val(),
                scope_value:     $('#policy-scope-value').val(),
                action:          $('#policy-action').val(),
                target_type:     $('#policy-target-type').val(),
                target_value:    $('#policy-target-value').val(),
                bandwidth_limit: $('#policy-bandwidth').val(),
                start_time:      $('#policy-start-time').val(),
                end_time:        $('#policy-end-time').val()
            }, days)
        };

        var btn = $(this).prop('disabled', true);
        ajaxCall(endpoint, payload, function(data) {
            btn.prop('disabled', false);
            if (data && (data.result === 'saved' || data.result === 'ok')) {
                $('#dlg-policy').modal('hide');
                $('#policies-grid').bootgrid('reload');
                loadStats();
            } else {
                BootstrapDialog.alert({
                    type: BootstrapDialog.TYPE_DANGER,
                    title: 'Error',
                    message: 'Failed to save policy. Check the fields and try again.'
                });
            }
        });
    });

    /*
     * =========================================================
     * APPLY POLICIES
     * =========================================================
     */
    $('#btn-apply-policies').click(function() {
        var btn = $(this).prop('disabled', true).html('<i class="fa fa-spinner fa-spin"></i> Applying…');
        ajaxCall('/api/netshield/policies/apply', {}, function(data) {
            btn.prop('disabled', false).html('<i class="fa fa-play"></i> Apply Policies');
            var ok = data && data.status === 'ok';
            BootstrapDialog.show({
                type: ok ? BootstrapDialog.TYPE_SUCCESS : BootstrapDialog.TYPE_DANGER,
                title: ok ? 'Policies Applied' : 'Apply Failed',
                message: ok
                    ? 'All active policies have been enforced successfully.'
                    : 'There was an error applying policies. Check the system log for details.',
                buttons: [{ label: 'OK', action: function(d){ d.close(); } }]
            });
            if (ok) loadEnforcementStatus();
        });
    });

    /*
     * =========================================================
     * ENFORCEMENT STATUS
     * =========================================================
     */
    function loadEnforcementStatus() {
        ajaxCall('/api/netshield/policies/enforcementStatus', {}, function(data) {
            if (!data) return;
            var $tbody = $('#enforcement-tbody').empty();
            if (data.rules && data.rules.length) {
                $.each(data.rules, function(i, r) {
                    $tbody.append(
                        '<tr>' +
                        '<td>' + escHtml(r.policy_name) + '</td>' +
                        '<td>' + escHtml(r.rule_type)   + '</td>' +
                        '<td>' + escHtml(r.rule_detail) + '</td>' +
                        '<td>' +
                        (r.active
                            ? '<span class="label label-success">Active</span>'
                            : '<span class="label label-default">Inactive</span>') +
                        '</td>' +
                        '</tr>'
                    );
                });
            } else {
                $tbody.append('<tr><td colspan="4" class="text-center text-muted">No enforcement rules active</td></tr>');
            }
        });
    }

    /*
     * =========================================================
     * STATS
     * =========================================================
     */
    function loadStats() {
        ajaxCall('/api/netshield/policies/stats', {}, function(data) {
            if (data) {
                $('#stat-total').text(data.total      || 0);
                $('#stat-enabled').text(data.enabled  || 0);
                $('#stat-disabled').text(data.disabled || 0);
                $('#stat-block').text(data.block      || 0);
                $('#stat-allow').text(data.allow      || 0);
                $('#stat-throttle').text(data.throttle || 0);
            }
        });
    }

    // Initial load
    loadStats();
    loadEnforcementStatus();
});
</script>

<!-- Page Header -->
<div class="content-box" style="padding:10px 15px; margin-bottom:0;">
    <div class="row">
        <div class="col-xs-12">
            <h2 style="margin:0 0 5px 0;"><i class="fa fa-shield"></i> Policy Management</h2>
            <p class="text-muted" style="margin:0;">
                Create, manage, and enforce traffic control policies across scopes and schedules.
            </p>
        </div>
    </div>
</div>

<!-- Stats Bar -->
<div class="content-box" style="padding:10px 15px; margin-bottom:5px;">
    <div class="row text-center">
        <div class="col-xs-4 col-sm-2">
            <strong id="stat-total">—</strong><br>
            <small class="text-muted">Total</small>
        </div>
        <div class="col-xs-4 col-sm-2">
            <strong class="text-success" id="stat-enabled">—</strong><br>
            <small class="text-muted">Enabled</small>
        </div>
        <div class="col-xs-4 col-sm-2">
            <strong class="text-muted" id="stat-disabled">—</strong><br>
            <small class="text-muted">Disabled</small>
        </div>
        <div class="col-xs-4 col-sm-2">
            <strong class="text-danger" id="stat-block">—</strong><br>
            <small class="text-muted">Block</small>
        </div>
        <div class="col-xs-4 col-sm-2">
            <strong class="text-success" id="stat-allow">—</strong><br>
            <small class="text-muted">Allow</small>
        </div>
        <div class="col-xs-4 col-sm-2">
            <strong class="text-warning" id="stat-throttle">—</strong><br>
            <small class="text-muted">Throttle</small>
        </div>
    </div>
</div>

<!-- Policies Table -->
<div class="content-box" style="padding:10px 15px;">

    <div class="row" style="margin-bottom:10px;">
        <div class="col-xs-12">
            <button id="btn-policy-add" class="btn btn-sm btn-success">
                <i class="fa fa-plus"></i> Add Policy
            </button>
            <button id="btn-apply-policies" class="btn btn-sm btn-primary" style="margin-left:6px;">
                <i class="fa fa-play"></i> Apply Policies
            </button>
        </div>
    </div>

    <table id="policies-grid" class="table table-condensed table-hover table-striped">
        <thead>
            <tr>
                <th data-column-id="uuid"        data-identifier="true" data-visible="false">UUID</th>
                <th data-column-id="name"        data-sortable="true">Name</th>
                <th data-column-id="scope"       data-sortable="true"  data-formatter="scope">Scope</th>
                <th data-column-id="scope_value" data-sortable="true">Value</th>
                <th data-column-id="action"      data-sortable="true"  data-formatter="action">Action</th>
                <th data-column-id="target_type" data-sortable="true">Target</th>
                <th data-column-id="schedule"    data-sortable="false" data-formatter="schedule">Schedule</th>
                <th data-column-id="priority"    data-sortable="true">Priority</th>
                <th data-column-id="enabled"     data-sortable="true"  data-formatter="enabled">Status</th>
                <th data-column-id="commands"    data-formatter="commands" data-sortable="false" style="width:130px;">Actions</th>
            </tr>
        </thead>
        <tbody></tbody>
    </table>

</div>

<!-- Enforcement Status Panel -->
<div class="content-box" style="padding:10px 15px;">
    <div class="panel panel-default" style="margin-bottom:0;">
        <div class="panel-heading">
            <strong><i class="fa fa-list-alt"></i> Active Enforcement Rules</strong>
            <span class="pull-right text-muted" style="font-size:12px;">Updated after Apply</span>
        </div>
        <div class="panel-body" style="padding:0;">
            <table class="table table-condensed table-striped" style="margin:0;">
                <thead>
                    <tr>
                        <th>Policy Name</th>
                        <th>Rule Type</th>
                        <th>Rule Detail</th>
                        <th>Status</th>
                    </tr>
                </thead>
                <tbody id="enforcement-tbody">
                    <tr><td colspan="4" class="text-center text-muted">Loading…</td></tr>
                </tbody>
            </table>
        </div>
    </div>
</div>

<!-- ===================================================
     POLICY ADD/EDIT DIALOG
     =================================================== -->
<div class="modal fade" id="dlg-policy" tabindex="-1" role="dialog">
    <div class="modal-dialog modal-lg" role="document">
        <div class="modal-content">
            <div class="modal-header">
                <button type="button" class="close" data-dismiss="modal"><span>&times;</span></button>
                <h4 class="modal-title">Add Policy</h4>
            </div>
            <div class="modal-body">
                <input type="hidden" id="policy-uuid">

                <div class="row">
                    <div class="col-md-6">
                        <div class="form-group">
                            <label>Policy Name <span class="text-danger">*</span></label>
                            <input type="text" class="form-control" id="policy-name"
                                   placeholder="e.g. Block Adult Content — Mobile Devices" required>
                        </div>
                    </div>
                    <div class="col-md-3">
                        <div class="form-group">
                            <label>Priority
                                <i class="fa fa-question-circle text-muted" title="Lower number = higher priority"></i>
                            </label>
                            <input type="number" class="form-control" id="policy-priority" value="100" min="1" max="999">
                        </div>
                    </div>
                    <div class="col-md-3">
                        <div class="form-group">
                            <label>Enabled</label>
                            <select class="form-control" id="policy-enabled">
                                <option value="1">Yes</option>
                                <option value="0">No</option>
                            </select>
                        </div>
                    </div>
                </div>

                <hr style="margin:10px 0;">
                <h5><strong>Scope — Who this policy applies to</strong></h5>
                <div class="row">
                    <div class="col-md-4">
                        <div class="form-group">
                            <label>Scope Type <span class="text-danger">*</span></label>
                            <select class="form-control" id="policy-scope">
                                <option value="network">Network (CIDR)</option>
                                <option value="vlan">VLAN</option>
                                <option value="device">Single Device (MAC)</option>
                                <option value="device_category">Device Category</option>
                            </select>
                        </div>
                    </div>
                    <div class="col-md-8">
                        <div class="form-group">
                            <label id="policy-scope-value-label">CIDR Range (e.g. 192.168.1.0/24)</label>
                            <input type="text" class="form-control" id="policy-scope-value">
                        </div>
                    </div>
                </div>

                <hr style="margin:10px 0;">
                <h5><strong>Action — What to do</strong></h5>
                <div class="row">
                    <div class="col-md-4">
                        <div class="form-group">
                            <label>Action <span class="text-danger">*</span></label>
                            <select class="form-control" id="policy-action">
                                <option value="block">Block</option>
                                <option value="allow">Allow (override block)</option>
                                <option value="throttle">Throttle (limit bandwidth)</option>
                                <option value="log">Log Only (no enforcement)</option>
                            </select>
                        </div>
                    </div>
                    <div class="col-md-4">
                        <div class="form-group">
                            <label>Target Type</label>
                            <select class="form-control" id="policy-target-type">
                                <option value="apps">Applications</option>
                                <option value="web_categories">Web Categories</option>
                                <option value="targetlists">Target Lists</option>
                                <option value="all">All Traffic</option>
                            </select>
                        </div>
                    </div>
                    <div class="col-md-4" id="row-bandwidth" style="display:none;">
                        <div class="form-group">
                            <label>Bandwidth Limit (Kbps)</label>
                            <input type="number" class="form-control" id="policy-bandwidth"
                                   min="0" placeholder="0 = unlimited">
                        </div>
                    </div>
                </div>
                <div class="form-group">
                    <label>Target Value(s)</label>
                    <input type="text" class="form-control" id="policy-target-value"
                           placeholder="Comma-separated (e.g. adult,gambling  or  block-vpn,block-ads)">
                    <span class="help-block">Leave blank to target all items in the selected type</span>
                </div>

                <hr style="margin:10px 0;">
                <h5><strong>Schedule — When this policy is active</strong></h5>
                <div class="row">
                    <div class="col-xs-12" style="margin-bottom:8px;">
                        <span class="text-muted" style="font-size:12px;">Leave all unchecked to apply every day</span>
                        &nbsp;
                        <div class="checkbox-inline" style="margin-left:10px;">
                            <label><input type="checkbox" name="sched_mon" value="1"> Mon</label>
                        </div>
                        <div class="checkbox-inline">
                            <label><input type="checkbox" name="sched_tue" value="1"> Tue</label>
                        </div>
                        <div class="checkbox-inline">
                            <label><input type="checkbox" name="sched_wed" value="1"> Wed</label>
                        </div>
                        <div class="checkbox-inline">
                            <label><input type="checkbox" name="sched_thu" value="1"> Thu</label>
                        </div>
                        <div class="checkbox-inline">
                            <label><input type="checkbox" name="sched_fri" value="1"> Fri</label>
                        </div>
                        <div class="checkbox-inline">
                            <label><input type="checkbox" name="sched_sat" value="1"> Sat</label>
                        </div>
                        <div class="checkbox-inline">
                            <label><input type="checkbox" name="sched_sun" value="1"> Sun</label>
                        </div>
                    </div>
                </div>
                <div class="row">
                    <div class="col-md-3">
                        <div class="form-group">
                            <label>Start Time</label>
                            <input type="time" class="form-control" id="policy-start-time" value="00:00">
                        </div>
                    </div>
                    <div class="col-md-3">
                        <div class="form-group">
                            <label>End Time</label>
                            <input type="time" class="form-control" id="policy-end-time" value="23:59">
                        </div>
                    </div>
                </div>
            </div>
            <div class="modal-footer">
                <button type="button" class="btn btn-default" data-dismiss="modal">Cancel</button>
                <button type="button" class="btn btn-primary" id="btn-policy-save">
                    <i class="fa fa-save"></i> Save Policy
                </button>
            </div>
        </div>
    </div>
</div>
