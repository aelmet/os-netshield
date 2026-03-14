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

        <!-- Page Header -->
        <div class="row">
            <div class="col-xs-12">
                <div class="page-header">
                    <h1><span class="fa fa-child fa-fw"></span> {{ lang._('Parental Controls') }}</h1>
                </div>
            </div>
        </div>

        <!-- Toolbar -->
        <div class="row" style="margin-bottom: 12px;">
            <div class="col-xs-12">
                <button id="btn-add-profile" type="button" class="btn btn-primary btn-sm">
                    <span class="fa fa-plus fa-fw"></span>
                    {{ lang._('Add Profile') }}
                </button>
                <button id="btn-refresh-profiles" type="button" class="btn btn-default btn-sm">
                    <span class="fa fa-refresh fa-fw"></span>
                    {{ lang._('Refresh') }}
                </button>
            </div>
        </div>

        <!-- Profiles Bootgrid -->
        <div class="row">
            <div class="col-xs-12">
                <table id="grid-profiles" class="table table-condensed table-hover table-striped"
                       data-url="/api/netshield/parental/search">
                    <thead>
                        <tr>
                            <th data-column-id="name"                data-type="string" data-sortable="true">{{ lang._('Name') }}</th>
                            <th data-column-id="time_limit_daily_min" data-type="numeric" data-formatter="timeLimitFmt">{{ lang._('Time Limit') }}</th>
                            <th data-column-id="bedtime_start"       data-type="string"  data-formatter="bedtimeFmt">{{ lang._('Bedtime') }}</th>
                            <th data-column-id="blocked_categories"  data-type="string"  data-formatter="categoriesFmt">{{ lang._('Blocked Categories') }}</th>
                            <th data-column-id="enabled"             data-type="string"  data-formatter="enabledBadge">{{ lang._('Enabled') }}</th>
                            <th data-column-id="actions"             data-formatter="profileActions" data-sortable="false">{{ lang._('Actions') }}</th>
                        </tr>
                    </thead>
                    <tbody></tbody>
                </table>
            </div>
        </div>

    </div><!-- .content-box-main -->
</div><!-- .content-box -->

<!-- ================================================================
     Add / Edit Profile Modal
     ================================================================ -->
<div class="modal fade" id="dialogEditProfile" tabindex="-1" role="dialog">
    <div class="modal-dialog" role="document">
        <div class="modal-content">
            <div class="modal-header">
                <button type="button" class="close" data-dismiss="modal"><span>&times;</span></button>
                <h4 class="modal-title" id="editProfileTitle">{{ lang._('Add Profile') }}</h4>
            </div>
            <div class="modal-body">
                <form id="form-edit-profile">
                    <input type="hidden" id="edit-profile-id" value=""/>

                    <div class="form-group">
                        <label for="edit-name">{{ lang._('Profile Name') }}</label>
                        <input type="text" class="form-control" id="edit-name" required
                               placeholder="{{ lang._('e.g. Kids') }}"/>
                    </div>

                    <div class="form-group">
                        <label for="edit-time-limit">
                            {{ lang._('Daily Time Limit') }}
                            <small class="text-muted">{{ lang._('(minutes, 0 = unlimited)') }}</small>
                        </label>
                        <div class="row">
                            <div class="col-xs-8">
                                <input type="range" id="edit-time-limit-slider" min="0" max="480" step="15"
                                       value="0" style="width:100%; margin-top:8px;"/>
                            </div>
                            <div class="col-xs-4">
                                <input type="number" class="form-control input-sm" id="edit-time-limit"
                                       min="0" max="1440" value="0"/>
                            </div>
                        </div>
                    </div>

                    <div class="row">
                        <div class="col-xs-6 form-group">
                            <label for="edit-bedtime-start">{{ lang._('Bedtime Start') }}</label>
                            <input type="time" class="form-control" id="edit-bedtime-start"/>
                        </div>
                        <div class="col-xs-6 form-group">
                            <label for="edit-bedtime-end">{{ lang._('Bedtime End') }}</label>
                            <input type="time" class="form-control" id="edit-bedtime-end"/>
                        </div>
                    </div>

                    <div class="form-group">
                        <label>{{ lang._('Blocked Categories') }}</label>
                        <div class="row">
                            <div class="col-xs-6">
                                <div class="checkbox">
                                    <label><input type="checkbox" class="cat-check" value="adult"/>
                                        {{ lang._('Adult') }}</label>
                                </div>
                                <div class="checkbox">
                                    <label><input type="checkbox" class="cat-check" value="gambling"/>
                                        {{ lang._('Gambling') }}</label>
                                </div>
                                <div class="checkbox">
                                    <label><input type="checkbox" class="cat-check" value="social"/>
                                        {{ lang._('Social Media') }}</label>
                                </div>
                            </div>
                            <div class="col-xs-6">
                                <div class="checkbox">
                                    <label><input type="checkbox" class="cat-check" value="gaming"/>
                                        {{ lang._('Gaming') }}</label>
                                </div>
                                <div class="checkbox">
                                    <label><input type="checkbox" class="cat-check" value="streaming"/>
                                        {{ lang._('Streaming') }}</label>
                                </div>
                                <div class="checkbox">
                                    <label><input type="checkbox" class="cat-check" value="vpn"/>
                                        {{ lang._('VPN / Proxy') }}</label>
                                </div>
                            </div>
                        </div>
                    </div>

                    <div class="form-group">
                        <div class="checkbox">
                            <label>
                                <input type="checkbox" id="edit-enabled" checked/>
                                {{ lang._('Enabled') }}
                            </label>
                        </div>
                    </div>
                </form>
            </div>
            <div class="modal-footer">
                <button type="button" class="btn btn-default" data-dismiss="modal">{{ lang._('Cancel') }}</button>
                <button type="button" class="btn btn-primary" id="btn-save-profile">{{ lang._('Save') }}</button>
            </div>
        </div>
    </div>
</div>

<!-- ================================================================
     Assign Device Modal
     ================================================================ -->
<div class="modal fade" id="dialogAssignDevice" tabindex="-1" role="dialog">
    <div class="modal-dialog modal-sm" role="document">
        <div class="modal-content">
            <div class="modal-header">
                <button type="button" class="close" data-dismiss="modal"><span>&times;</span></button>
                <h4 class="modal-title">{{ lang._('Assign Device') }}</h4>
            </div>
            <div class="modal-body">
                <input type="hidden" id="assign-profile-id" value=""/>
                <div class="form-group">
                    <label for="assign-mac">{{ lang._('Device MAC Address') }}</label>
                    <select class="form-control" id="assign-mac">
                        <option value="">{{ lang._('— select device —') }}</option>
                    </select>
                </div>
                <div class="form-group">
                    <label for="assign-mac-manual">{{ lang._('Or enter MAC manually') }}</label>
                    <input type="text" class="form-control" id="assign-mac-manual"
                           placeholder="AA:BB:CC:DD:EE:FF"/>
                </div>
            </div>
            <div class="modal-footer">
                <button type="button" class="btn btn-default" data-dismiss="modal">{{ lang._('Cancel') }}</button>
                <button type="button" class="btn btn-primary" id="btn-confirm-assign">{{ lang._('Assign') }}</button>
            </div>
        </div>
    </div>
</div>

<!-- ================================================================
     Usage Chart Modal
     ================================================================ -->
<div class="modal fade" id="dialogUsage" tabindex="-1" role="dialog">
    <div class="modal-dialog modal-lg" role="document">
        <div class="modal-content">
            <div class="modal-header">
                <button type="button" class="close" data-dismiss="modal"><span>&times;</span></button>
                <h4 class="modal-title" id="usageModalTitle">{{ lang._('Usage') }}</h4>
            </div>
            <div class="modal-body">
                <div id="usage-chart-placeholder" style="min-height:200px; display:flex; align-items:center; justify-content:center;">
                    <p class="text-muted">{{ lang._('Loading usage data...') }}</p>
                </div>
                <table class="table table-condensed table-striped" id="tbl-usage" style="margin-top:12px;">
                    <thead>
                        <tr>
                            <th>{{ lang._('Date') }}</th>
                            <th>{{ lang._('Minutes Used') }}</th>
                        </tr>
                    </thead>
                    <tbody id="usage-body"></tbody>
                </table>
            </div>
            <div class="modal-footer">
                <button type="button" class="btn btn-default" data-dismiss="modal">{{ lang._('Close') }}</button>
            </div>
        </div>
    </div>
</div>

<script>
$(function() {
    'use strict';

    /* Native HTML escape (no lodash dependency) */
    function _escape(s) {
        if (s == null) return '';
        var div = document.createElement('div');
        div.appendChild(document.createTextNode(String(s)));
        return div.innerHTML;
    }

    // ----------------------------------------------------------------
    // Formatters
    // ----------------------------------------------------------------
    function timeLimitFmt(val) {
        return (!val || val == 0)
            ? '<span class="text-muted">{{ lang._("Unlimited") }}</span>'
            : val + ' {{ lang._("min") }}';
    }

    function bedtimeFmt(val, row) {
        if (!val && !row.bedtime_end) return '<span class="text-muted">—</span>';
        return _escape(val || '?') + ' – ' + _escape(row.bedtime_end || '?');
    }

    function categoriesFmt(val) {
        try {
            var cats = (typeof val === 'string') ? JSON.parse(val) : val;
            if (!cats || !cats.length) return '<span class="text-muted">—</span>';
            return cats.map(function(c) {
                return '<span class="label label-warning">' + _escape(c) + '</span>';
            }).join(' ');
        } catch(e) { return '—'; }
    }

    function enabledBadge(val) {
        return val
            ? '<span class="label label-success">{{ lang._("Yes") }}</span>'
            : '<span class="label label-default">{{ lang._("No") }}</span>';
    }

    function profileActions(val, row) {
        return '<button type="button" class="btn btn-xs btn-default btn-edit-profile" data-row=\'' +
               JSON.stringify(row).replace(/'/g, "&#39;") + '\' title="{{ lang._("Edit") }}">' +
               '<span class="fa fa-pencil"></span></button> ' +
               '<button type="button" class="btn btn-xs btn-info btn-assign-device" data-id="' + row.id +
               '" title="{{ lang._("Assign Device") }}"><span class="fa fa-laptop"></span></button> ' +
               '<button type="button" class="btn btn-xs btn-success btn-view-usage" data-id="' + row.id +
               '" data-name="' + _escape(row.name) + '" title="{{ lang._("Usage") }}"><span class="fa fa-bar-chart"></span></button> ' +
               '<button type="button" class="btn btn-xs btn-danger btn-delete-profile" data-id="' + row.id +
               '" data-name="' + _escape(row.name) + '" title="{{ lang._("Delete") }}"><span class="fa fa-trash"></span></button>';
    }

    // ----------------------------------------------------------------
    // Load profiles table
    // ----------------------------------------------------------------
    function loadProfiles() {
        $.getJSON('/api/netshield/parental/search', function(data) {
            var rows = data.rows || [];
            var $tbody = $('#grid-profiles tbody').empty();
            if (!rows.length) {
                $tbody.append('<tr><td colspan="6" class="text-center text-muted">{{ lang._("No profiles configured") }}</td></tr>');
                return;
            }
            rows.forEach(function(r) {
                $tbody.append('<tr>'
                    + '<td>' + _escape(r.name) + '</td>'
                    + '<td>' + timeLimitFmt(r.time_limit_daily_min) + '</td>'
                    + '<td>' + bedtimeFmt(r.bedtime_start, r) + '</td>'
                    + '<td>' + categoriesFmt(r.blocked_categories) + '</td>'
                    + '<td>' + enabledBadge(r.enabled) + '</td>'
                    + '<td>' + profileActions(null, r) + '</td>'
                    + '</tr>');
            });
        });
    }

    // ----------------------------------------------------------------
    // Load available devices for assignment dropdown
    // ----------------------------------------------------------------
    function loadDevicesForAssign() {
        $.getJSON('/api/netshield/devices/search', function(data) {
            var rows = data.rows || [];
            var $sel = $('#assign-mac').empty().append('<option value="">{{ lang._("— select device —") }}</option>');
            rows.forEach(function(d) {
                var label = (d.hostname || d.mac) + ' (' + (d.mac || '') + ')';
                $sel.append('<option value="' + _escape(d.mac) + '">' + _escape(label) + '</option>');
            });
        });
    }

    // ----------------------------------------------------------------
    // Time limit slider sync
    // ----------------------------------------------------------------
    $('#edit-time-limit-slider').on('input', function() {
        $('#edit-time-limit').val($(this).val());
    });
    $('#edit-time-limit').on('input', function() {
        $('#edit-time-limit-slider').val($(this).val());
    });

    // ----------------------------------------------------------------
    // Add Profile button
    // ----------------------------------------------------------------
    $('#btn-add-profile').on('click', function() {
        $('#editProfileTitle').text('{{ lang._("Add Profile") }}');
        $('#form-edit-profile')[0].reset();
        $('#edit-profile-id').val('');
        $('#edit-time-limit').val(0);
        $('#edit-time-limit-slider').val(0);
        $('#dialogEditProfile').modal('show');
    });

    // Refresh button
    $('#btn-refresh-profiles').on('click', loadProfiles);

    // ----------------------------------------------------------------
    // Edit profile
    // ----------------------------------------------------------------
    $(document).on('click', '.btn-edit-profile', function() {
        var row = $(this).data('row');
        if (typeof row === 'string') { try { row = JSON.parse(row); } catch(e) {} }
        $('#editProfileTitle').text('{{ lang._("Edit Profile") }}');
        $('#edit-profile-id').val(row.id);
        $('#edit-name').val(row.name);
        var tl = row.time_limit_daily_min || 0;
        $('#edit-time-limit').val(tl);
        $('#edit-time-limit-slider').val(tl);
        $('#edit-bedtime-start').val(row.bedtime_start || '');
        $('#edit-bedtime-end').val(row.bedtime_end || '');
        // Categories
        $('.cat-check').prop('checked', false);
        var cats = row.blocked_categories;
        if (typeof cats === 'string') { try { cats = JSON.parse(cats); } catch(e) { cats = []; } }
        (cats || []).forEach(function(c) {
            $('.cat-check[value="' + c + '"]').prop('checked', true);
        });
        $('#edit-enabled').prop('checked', !!row.enabled);
        $('#dialogEditProfile').modal('show');
    });

    // ----------------------------------------------------------------
    // Save profile
    // ----------------------------------------------------------------
    $('#btn-save-profile').on('click', function() {
        var id      = $('#edit-profile-id').val();
        var name    = $('#edit-name').val().trim();
        var tl      = parseInt($('#edit-time-limit').val(), 10) || 0;
        var btStart = $('#edit-bedtime-start').val();
        var btEnd   = $('#edit-bedtime-end').val();
        var cats    = [];
        $('.cat-check:checked').each(function() { cats.push($(this).val()); });
        var enabled = $('#edit-enabled').is(':checked') ? '1' : '0';

        if (!name) {
            alert('{{ lang._("Profile name is required") }}');
            return;
        }

        var url    = id ? '/api/netshield/parental/update' : '/api/netshield/parental/add';
        var params = {
            name: name,
            time_limit: tl,
            bedtime_start: btStart,
            bedtime_end: btEnd,
            blocked_categories: cats.join(','),
            enabled: enabled,
        };
        if (id) params.id = id;

        $.post(url, params, function(data) {
            if (data.result === 'ok') {
                $('#dialogEditProfile').modal('hide');
                loadProfiles();
            } else {
                alert(data.message || '{{ lang._("Failed to save profile") }}');
            }
        });
    });

    // ----------------------------------------------------------------
    // Delete profile
    // ----------------------------------------------------------------
    $(document).on('click', '.btn-delete-profile', function() {
        var id   = $(this).data('id');
        var name = $(this).data('name');
        if (!confirm('{{ lang._("Delete profile") }} "' + name + '"?')) return;
        $.post('/api/netshield/parental/delete', {id: id}, function() {
            loadProfiles();
        });
    });

    // ----------------------------------------------------------------
    // Assign device modal
    // ----------------------------------------------------------------
    $(document).on('click', '.btn-assign-device', function() {
        var id = $(this).data('id');
        $('#assign-profile-id').val(id);
        $('#assign-mac-manual').val('');
        loadDevicesForAssign();
        $('#dialogAssignDevice').modal('show');
    });

    $('#btn-confirm-assign').on('click', function() {
        var id  = $('#assign-profile-id').val();
        var mac = $('#assign-mac-manual').val().trim() || $('#assign-mac').val();
        if (!mac) {
            alert('{{ lang._("Please select or enter a MAC address") }}');
            return;
        }
        $.post('/api/netshield/parental/assignDevice', {id: id, mac: mac}, function(data) {
            if (data.result === 'ok') {
                $('#dialogAssignDevice').modal('hide');
            } else {
                alert(data.message || '{{ lang._("Failed to assign device") }}');
            }
        });
    });

    // ----------------------------------------------------------------
    // Usage modal
    // ----------------------------------------------------------------
    $(document).on('click', '.btn-view-usage', function() {
        var id   = $(this).data('id');
        var name = $(this).data('name');
        $('#usageModalTitle').text('{{ lang._("Usage") }} — ' + name);
        $('#usage-body').empty();
        $('#usage-chart-placeholder').html('<p class="text-muted">{{ lang._("Loading...") }}</p>');
        $('#dialogUsage').modal('show');

        $.getJSON('/api/netshield/parental/usage?id=' + id + '&days=7', function(data) {
            var usage = data.usage || [];
            $('#usage-chart-placeholder').html(
                '<p class="text-muted"><span class="fa fa-bar-chart fa-2x"></span><br>'
                + '{{ lang._("Chart integration placeholder — connect your chart library here") }}</p>'
            );
            var $tbody = $('#usage-body').empty();
            if (!usage.length) {
                $tbody.append('<tr><td colspan="2" class="text-muted text-center">{{ lang._("No usage data") }}</td></tr>');
                return;
            }
            usage.forEach(function(u) {
                $tbody.append('<tr><td>' + _escape(u.date) + '</td><td>' + (u.minutes_used || 0) + ' min</td></tr>');
            });
        });
    });

    // ----------------------------------------------------------------
    // Initial load
    // ----------------------------------------------------------------
    loadProfiles();
});
</script>
