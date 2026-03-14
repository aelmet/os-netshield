{#
# Copyright (C) 2025 NetShield
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

<style>
/* Device detail side panel */
.ns-device-panel {
    position: fixed;
    top: 0; right: -380px; bottom: 0;
    width: 360px;
    background: #fff;
    border-left: 1px solid #ddd;
    box-shadow: -3px 0 15px rgba(0,0,0,0.15);
    z-index: 10000;
    transition: right 0.25s ease;
    overflow-y: auto;
    padding: 0;
}
.ns-device-panel.ns-panel-open { right: 0; }
.ns-panel-header {
    background: #34495e;
    color: #fff;
    padding: 14px 16px;
    display: flex;
    align-items: center;
    gap: 10px;
}
.ns-panel-close {
    margin-left: auto;
    background: none;
    border: none;
    color: #fff;
    font-size: 20px;
    cursor: pointer;
    line-height: 1;
}
.ns-panel-body { padding: 16px; }
.ns-panel-section { margin-bottom: 16px; }
.ns-panel-section h5 {
    font-weight: 700;
    border-bottom: 1px solid #eee;
    padding-bottom: 6px;
    margin-bottom: 10px;
    color: #34495e;
}
.ns-kv-row { display: flex; justify-content: space-between; padding: 4px 0; border-bottom: 1px solid #f5f5f5; font-size: 13px; }
.ns-kv-row:last-child { border-bottom: none; }
.ns-kv-key { color: #777; }
.ns-kv-val { font-weight: 600; text-align: right; max-width: 60%; word-break: break-all; }
.ns-overlay {
    display: none;
    position: fixed;
    top: 0; left: 0; right: 0; bottom: 0;
    background: rgba(0,0,0,0.2);
    z-index: 9999;
}
</style>

<!-- Overlay (closes panel on click) -->
<div class="ns-overlay" id="ns-overlay"></div>

<!-- Device Detail Panel -->
<div class="ns-device-panel" id="ns-device-panel">
    <div class="ns-panel-header">
        <span class="fa fa-laptop fa-lg"></span>
        <span id="panel-device-name" style="font-weight:600; font-size:15px;">Device</span>
        <button class="ns-panel-close" id="btn-close-panel">&times;</button>
    </div>
    <div class="ns-panel-body">
        <!-- Status + Quick Actions -->
        <div class="ns-panel-section">
            <div style="display:flex; gap:8px; margin-bottom:12px; flex-wrap:wrap;">
                <span id="panel-status-badge" class="label label-default" style="font-size:13px; padding:5px 10px;">—</span>
            </div>
            <div style="display:flex; gap:6px; flex-wrap:wrap;">
                <button id="panel-btn-quarantine"  class="btn btn-sm btn-danger"   style="display:none;">
                    <span class="fa fa-lock"></span> {{ lang._('Quarantine') }}
                </button>
                <button id="panel-btn-unquarantine" class="btn btn-sm btn-success"  style="display:none;">
                    <span class="fa fa-unlock"></span> {{ lang._('Unquarantine') }}
                </button>
                <button id="panel-btn-approve"     class="btn btn-sm btn-default"  style="display:none;">
                    <span class="fa fa-check"></span> {{ lang._('Approve') }}
                </button>
                <button id="panel-btn-wake"        class="btn btn-sm btn-info">
                    <span class="fa fa-bolt"></span> {{ lang._('Wake (WoL)') }}
                </button>
            </div>
        </div>

        <!-- Device Info -->
        <div class="ns-panel-section">
            <h5><span class="fa fa-info-circle"></span> {{ lang._('Device Info') }}</h5>
            <div class="ns-kv-row"><span class="ns-kv-key">{{ lang._('MAC') }}</span><span class="ns-kv-val" id="panel-mac">—</span></div>
            <div class="ns-kv-row"><span class="ns-kv-key">{{ lang._('IP Address') }}</span><span class="ns-kv-val" id="panel-ip">—</span></div>
            <div class="ns-kv-row"><span class="ns-kv-key">{{ lang._('Hostname') }}</span><span class="ns-kv-val" id="panel-hostname">—</span></div>
            <div class="ns-kv-row"><span class="ns-kv-key">{{ lang._('Vendor') }}</span><span class="ns-kv-val" id="panel-vendor">—</span></div>
            <div class="ns-kv-row"><span class="ns-kv-key">{{ lang._('First Seen') }}</span><span class="ns-kv-val" id="panel-first-seen">—</span></div>
            <div class="ns-kv-row"><span class="ns-kv-key">{{ lang._('Last Seen') }}</span><span class="ns-kv-val" id="panel-last-seen">—</span></div>
        </div>

        <!-- Bandwidth (from bandwidth API) -->
        <div class="ns-panel-section">
            <h5><span class="fa fa-exchange"></span> {{ lang._('Bandwidth Today') }}</h5>
            <div class="ns-kv-row"><span class="ns-kv-key">{{ lang._('Downloaded') }}</span><span class="ns-kv-val" id="panel-bw-down">—</span></div>
            <div class="ns-kv-row"><span class="ns-kv-key">{{ lang._('Uploaded') }}</span><span class="ns-kv-val" id="panel-bw-up">—</span></div>
        </div>

        <!-- Alert Summary -->
        <div class="ns-panel-section">
            <h5><span class="fa fa-bell"></span> {{ lang._('Alert Summary') }}</h5>
            <div class="ns-kv-row"><span class="ns-kv-key">{{ lang._('Alerts Today') }}</span><span class="ns-kv-val" id="panel-alerts-today">—</span></div>
            <div class="ns-kv-row"><span class="ns-kv-key">{{ lang._('Threats Detected') }}</span><span class="ns-kv-val" id="panel-threats">—</span></div>
        </div>
    </div>
</div>

<div class="content-box" style="padding: 15px;">

    <!-- Header + filter buttons -->
    <div style="margin-bottom: 12px; display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 8px;">
        <h4 style="margin: 0;">
            <span class="fa fa-laptop"></span> {{ lang._('Device List') }}
        </h4>
        <div style="display:flex; gap:8px; align-items:center; flex-wrap:wrap;">
            <div class="btn-group" role="group">
                <button id="btn-filter-all" class="btn btn-sm btn-primary active" data-filter="all">
                    <span class="fa fa-list"></span> {{ lang._('All') }}
                </button>
                <button id="btn-filter-new" class="btn btn-sm btn-default" data-filter="new">
                    <span class="fa fa-star"></span> {{ lang._('New') }}
                </button>
                <button id="btn-filter-quarantined" class="btn btn-sm btn-default" data-filter="quarantined">
                    <span class="fa fa-lock"></span> {{ lang._('Quarantined') }}
                </button>
                <button id="btn-filter-approved" class="btn btn-sm btn-default" data-filter="approved">
                    <span class="fa fa-check"></span> {{ lang._('Approved') }}
                </button>
            </div>
            <input type="text" id="device-search" class="form-control input-sm"
                   style="width:160px;" placeholder="{{ lang._('Search devices...') }}"/>
        </div>
    </div>

    <!-- Devices table -->
    <table id="devices-grid" class="table table-condensed table-hover table-striped" data-editDialog="none"
        data-store-response="true">
        <thead>
            <tr>
                <th data-column-id="mac" data-type="string" data-sortable="true">{{ lang._('MAC Address') }}</th>
                <th data-column-id="ip" data-type="string" data-sortable="true">{{ lang._('IP Address') }}</th>
                <th data-column-id="hostname" data-type="string" data-sortable="true">{{ lang._('Hostname') }}</th>
                <th data-column-id="vendor" data-type="string" data-sortable="true">{{ lang._('Vendor') }}</th>
                <th data-column-id="category" data-type="string" data-formatter="category" data-sortable="true">{{ lang._('Device Type') }}</th>
                <th data-column-id="last_seen" data-type="string" data-sortable="true">{{ lang._('Last Seen') }}</th>
                <th data-column-id="status" data-type="string" data-formatter="status" data-sortable="true">{{ lang._('Status') }}</th>
                <th data-column-id="commands" data-formatter="commands" data-sortable="false">{{ lang._('Actions') }}</th>
            </tr>
        </thead>
        <tbody></tbody>
        <tfoot>
            <tr>
                <td colspan="7">
                    <div id="devices-grid-header" class="pull-right"></div>
                </td>
            </tr>
        </tfoot>
    </table>

</div>

<script>
    $(document).ready(function () {

        var activeFilter = 'all';
        var currentDevice = null;

        /* ---- Status badge ---- */
        function statusBadge(status) {
            var m = {approved: 'success', quarantined: 'danger', new: 'warning'};
            var cls = m[status] || 'default';
            return '<span class="label label-' + cls + '">' +
                (status.charAt(0).toUpperCase() + status.slice(1)) + '</span>';
        }

        /* ---- Device commands ---- */
        function deviceCommands(column, row) {
            var btns = '';
            if (row.status === 'quarantined') {
                btns += '<button class="btn btn-xs btn-success btn-unquarantine" data-mac="' + row.mac + '" title="{{ lang._("Unquarantine") }}"><span class="fa fa-unlock"></span></button> ';
            } else {
                btns += '<button class="btn btn-xs btn-danger btn-quarantine" data-mac="' + row.mac + '" title="{{ lang._("Quarantine") }}"><span class="fa fa-lock"></span></button> ';
            }
            if (row.status !== 'approved') {
                btns += '<button class="btn btn-xs btn-default btn-approve" data-mac="' + row.mac + '" title="{{ lang._("Approve") }}"><span class="fa fa-check"></span></button> ';
            }
            btns += '<button class="btn btn-xs btn-info btn-details" data-row=\'' +
                JSON.stringify(row).replace(/\\/g,'\\\\').replace(/'/g,"&#39;") +
                '\' title="{{ lang._("Details") }}"><span class="fa fa-info-circle"></span></button>';
            return btns;
        }

        /* ---- Devices bootgrid ---- */
        var devicesGrid = $('#devices-grid').UIBootgrid({
            'search': '/api/netshield/devices/search',
            'options': {
                selection: false,
                multiSelect: false,
                rowCount: [25, 50, 100],
                requestHandler: function (request) {
                    if (activeFilter !== 'all') request.status = activeFilter;
                    var s = $('#device-search').val().trim();
                    if (s) request.searchPhrase = s;
                    return request;
                },
                formatters: {
                'category': function(column, row) {
                    var cat = row.category || 'other';
                    var icons = {
                        'smartphone': 'fa-mobile', 'laptop': 'fa-laptop', 'tablet': 'fa-tablet',
                        'desktop': 'fa-desktop', 'printer': 'fa-print', 'tv': 'fa-television',
                        'iot': 'fa-microchip', 'server': 'fa-server', 'gaming': 'fa-gamepad',
                        'camera': 'fa-video-camera', 'wearable': 'fa-clock-o', 'other': 'fa-question-circle'
                    };
                    var colors = {
                        'smartphone': '#3b82f6', 'laptop': '#8b5cf6', 'tablet': '#06b6d4',
                        'desktop': '#6366f1', 'printer': '#f59e0b', 'tv': '#ef4444',
                        'iot': '#10b981', 'server': '#6b7280', 'gaming': '#ec4899',
                        'camera': '#f97316', 'wearable': '#14b8a6', 'other': '#9ca3af'
                    };
                    var icon = icons[cat] || 'fa-question-circle';
                    var color = colors[cat] || '#9ca3af';
                    return '<span style="color:' + color + '"><i class="fa ' + icon + '"></i> ' +
                           cat.charAt(0).toUpperCase() + cat.slice(1) + '</span>';
                },
                
                    'status': function (c, r) { return statusBadge(r.status); },
                    'commands': deviceCommands
                }
            }
        });
        devicesGrid.on('loaded.rs.jquery.bootgrid', function () {
            bindDeviceActions();
        });

        function bindDeviceActions() {
            /* Quarantine */
            $('#devices-grid').find('.btn-quarantine').on('click', function (e) {
                e.stopPropagation();
                var mac = $(this).data('mac');
                BootstrapDialog.confirm({
                    title: '{{ lang._("Quarantine Device") }}',
                    message: '{{ lang._("Quarantine device with MAC: ") }}<strong>' + mac + '</strong>?',
                    type: BootstrapDialog.TYPE_DANGER,
                    btnOKLabel: '{{ lang._("Quarantine") }}',
                    callback: function (r) {
                        if (r) ajaxCall('/api/netshield/devices/quarantine', {uuid: mac}, function () { devicesGrid.bootgrid('reload'); });
                    }
                });
            });

            /* Unquarantine */
            $('#devices-grid').find('.btn-unquarantine').on('click', function (e) {
                e.stopPropagation();
                var mac = $(this).data('mac');
                BootstrapDialog.confirm({
                    title: '{{ lang._("Unquarantine Device") }}',
                    message: '{{ lang._("Remove quarantine from: ") }}<strong>' + mac + '</strong>?',
                    type: BootstrapDialog.TYPE_INFO,
                    btnOKLabel: '{{ lang._("Unquarantine") }}',
                    callback: function (r) {
                        if (r) ajaxCall('/api/netshield/devices/unquarantine', {uuid: mac}, function () { devicesGrid.bootgrid('reload'); });
                    }
                });
            });

            /* Approve */
            $('#devices-grid').find('.btn-approve').on('click', function (e) {
                e.stopPropagation();
                var mac = $(this).data('mac');
                BootstrapDialog.confirm({
                    title: '{{ lang._("Approve Device") }}',
                    message: '{{ lang._("Approve device with MAC: ") }}<strong>' + mac + '</strong>?',
                    type: BootstrapDialog.TYPE_SUCCESS,
                    btnOKLabel: '{{ lang._("Approve") }}',
                    callback: function (r) {
                        if (r) ajaxCall('/api/netshield/devices/approveNew', {uuid: mac}, function () { devicesGrid.bootgrid('reload'); });
                    }
                });
            });

            /* Details panel */
            $('#devices-grid').find('.btn-details').on('click', function (e) {
                e.stopPropagation();
                var row = $(this).data('row');
                if (typeof row === 'string') { try { row = JSON.parse(row); } catch(ex) {} }
                openDevicePanel(row);
            });
        }

        /* ---- Device Detail Panel ---- */
        function openDevicePanel(row) {
            currentDevice = row;
            var displayName = row.hostname || row.mac || '—';
            $('#panel-device-name').text(displayName);
            $('#panel-mac').text(row.mac || '—');
            $('#panel-ip').text(row.ip || '—');
            $('#panel-hostname').text(row.hostname || '—');
            $('#panel-vendor').text(row.vendor || '—');
            $('#panel-first-seen').text(row.first_seen || '—');
            $('#panel-last-seen').text(row.last_seen || '—');
            $('#panel-bw-down').text('—');
            $('#panel-bw-up').text('—');
            $('#panel-alerts-today').text('—');
            $('#panel-threats').text('—');

            // Status badge
            var statusMap = {approved:'success', quarantined:'danger', new:'warning'};
            var sCls = statusMap[row.status] || 'default';
            $('#panel-status-badge')
                .removeClass('label-success label-danger label-warning label-default')
                .addClass('label-' + sCls)
                .text(row.status ? row.status.charAt(0).toUpperCase() + row.status.slice(1) : '—');

            // Action buttons
            $('#panel-btn-quarantine').toggle(row.status !== 'quarantined');
            $('#panel-btn-unquarantine').toggle(row.status === 'quarantined');
            $('#panel-btn-approve').toggle(row.status !== 'approved');

            // Open panel
            $('#ns-device-panel').addClass('ns-panel-open');
            $('#ns-overlay').show();

            // Load bandwidth data
            $.getJSON('/api/netshield/bandwidth/device?mac=' + encodeURIComponent(row.mac), function(data) {
                if (data) {
                    var dl = data.bytes_down || data.download_today || 0;
                    var ul = data.bytes_up   || data.upload_today   || 0;
                    $('#panel-bw-down').text(formatBytes(dl));
                    $('#panel-bw-up').text(formatBytes(ul));
                }
            });
        }

        function formatBytes(bytes) {
            if (!bytes) return '0 B';
            var k = 1024;
            var sizes = ['B','KB','MB','GB'];
            var i = Math.floor(Math.log(bytes) / Math.log(k));
            return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
        }

        function closePanel() {
            $('#ns-device-panel').removeClass('ns-panel-open');
            $('#ns-overlay').hide();
            currentDevice = null;
        }

        $('#btn-close-panel').on('click', closePanel);
        $('#ns-overlay').on('click', closePanel);

        /* Panel quick actions */
        $('#panel-btn-quarantine').on('click', function() {
            if (!currentDevice) return;
            ajaxCall('/api/netshield/devices/quarantine', {uuid: currentDevice.mac}, function() {
                closePanel();
                devicesGrid.bootgrid('reload');
            });
        });
        $('#panel-btn-unquarantine').on('click', function() {
            if (!currentDevice) return;
            ajaxCall('/api/netshield/devices/unquarantine', {uuid: currentDevice.mac}, function() {
                closePanel();
                devicesGrid.bootgrid('reload');
            });
        });
        $('#panel-btn-approve').on('click', function() {
            if (!currentDevice) return;
            ajaxCall('/api/netshield/devices/approveNew', {uuid: currentDevice.mac}, function() {
                closePanel();
                devicesGrid.bootgrid('reload');
            });
        });
        $('#panel-btn-wake').on('click', function() {
            if (!currentDevice) return;
            ajaxCall('/api/netshield/network/wakeDevice', {mac: currentDevice.mac}, function(data) {
                BootstrapDialog.alert({
                    title: '{{ lang._("Wake on LAN") }}',
                    message: data && data.result === 'ok'
                        ? '{{ lang._("WoL packet sent to") }} ' + currentDevice.mac
                        : '{{ lang._("Failed to send WoL packet.") }}',
                    type: data && data.result === 'ok' ? BootstrapDialog.TYPE_SUCCESS : BootstrapDialog.TYPE_DANGER
                });
            });
        });

        /* ---- Filter buttons ---- */
        $('#btn-filter-all, #btn-filter-new, #btn-filter-quarantined, #btn-filter-approved').on('click', function () {
            $('#btn-filter-all, #btn-filter-new, #btn-filter-quarantined, #btn-filter-approved')
                .removeClass('active btn-primary').addClass('btn-default');
            $(this).removeClass('btn-default').addClass('active btn-primary');
            activeFilter = $(this).data('filter');
            devicesGrid.bootgrid('reload');
        });

        /* ---- Search ---- */
        var searchTimer;
        $('#device-search').on('input', function() {
            clearTimeout(searchTimer);
            searchTimer = setTimeout(function() { devicesGrid.bootgrid('reload'); }, 300);
        });

        /* ---- Auto-refresh ---- */
        setInterval(function () { devicesGrid.bootgrid('reload'); }, 60000);

    });
</script>

<!-- Set Device Category Dialog -->
<div class="modal fade" id="dlg-set-category" tabindex="-1">
    <div class="modal-dialog modal-sm">
        <div class="modal-content">
            <div class="modal-header">
                <button type="button" class="close" data-dismiss="modal">&times;</button>
                <h4 class="modal-title">{{ lang._('Set Device Type') }}</h4>
            </div>
            <div class="modal-body">
                <input type="hidden" id="cat-device-mac">
                <p id="cat-device-name" class="text-muted"></p>
                <select class="form-control" id="cat-device-type">
                    <option value="smartphone">Smartphone</option>
                    <option value="laptop">Laptop</option>
                    <option value="desktop">Desktop</option>
                    <option value="tablet">Tablet</option>
                    <option value="tv">Smart TV</option>
                    <option value="printer">Printer</option>
                    <option value="iot">IoT Device</option>
                    <option value="server">Server</option>
                    <option value="gaming">Gaming Console</option>
                    <option value="camera">Camera</option>
                    <option value="wearable">Wearable</option>
                    <option value="other">Other</option>
                </select>
            </div>
            <div class="modal-footer">
                <button type="button" class="btn btn-default" data-dismiss="modal">{{ lang._('Cancel') }}</button>
                <button type="button" class="btn btn-primary" id="btn-save-category">
                    <i class="fa fa-save"></i> {{ lang._('Save') }}
                </button>
            </div>
        </div>
    </div>
</div>

<script>
// Category dialog handlers
$(document).on('click', '.btn-set-category', function() {
    var mac = $(this).data('mac');
    var name = $(this).closest('tr').find('td:eq(2)').text() || mac;
    var currentCat = $(this).data('category') || 'other';
    $('#cat-device-mac').val(mac);
    $('#cat-device-name').text(name + ' (' + mac + ')');
    $('#cat-device-type').val(currentCat);
    $('#dlg-set-category').modal('show');
});

$('#btn-save-category').click(function() {
    var mac = $('#cat-device-mac').val();
    var cat = $('#cat-device-type').val();
    ajaxCall('/api/netshield/devices/setCategory', {mac: mac, category: cat}, function(data) {
        $('#dlg-set-category').modal('hide');
        $('#devices-grid').bootgrid('reload');
    });
});
</script>
