{#
 # NetShield — Network Security Suite for OPNsense
 # Main Dashboard View
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
    function badge(type) {
        var map = {
            'vpn':        '<span class="label label-warning">VPN</span>',
            'adult':      '<span class="label label-danger">Adult</span>',
            'dns_bypass': '<span class="label label-info">DNS Bypass</span>',
            'proxy':      '<span class="label label-default">Proxy</span>',
            'malware':    '<span class="label label-danger">Malware</span>',
            'geoip':      '<span class="label label-primary">GeoIP</span>',
            'policy':     '<span class="label label-success">Policy</span>'
        };
        return map[String(type).toLowerCase()] ||
               '<span class="label label-default">' + $('<span>').text(type).html() + '</span>';
    }

    function deviceStatusBadge(status) {
        var map = {
            'approved':    '<span class="label label-success">Approved</span>',
            'quarantined': '<span class="label label-danger">Quarantined</span>',
            'unknown':     '<span class="label label-warning">Unknown</span>'
        };
        return map[String(status).toLowerCase()] ||
               '<span class="label label-default">' + $('<span>').text(status).html() + '</span>';
    }

    function policyStatusBadge(enabled) {
        return (enabled == '1' || enabled === true)
            ? '<span class="label label-success">Enabled</span>'
            : '<span class="label label-default">Disabled</span>';
    }

    function fmtTs(ts) {
        if (!ts) return '—';
        var d = new Date(ts * 1000);
        return d.toLocaleString();
    }

    function escHtml(s) {
        return $('<span>').text(s || '').html();
    }

    /*
     * =========================================================
     * TAB 1 — DASHBOARD
     * =========================================================
     */
    function loadDashboard() {
        ajaxCall('/api/netshield/dashboard/stats', {}, function(data) {
            if (data) {
                $('#stat-alerts-today').text(data.alerts_today  || 0);
                $('#stat-devices').text(data.devices_tracked    || 0);
                $('#stat-policies').text(data.active_policies   || 0);
                $('#stat-blocked-domains').text(data.blocked_domains || 0);
            }
        });

        ajaxCall('/api/netshield/service/status', {}, function(data) {
            var running = data && data.status === 'running';
            $('#service-status-indicator')
                .removeClass('text-success text-danger')
                .addClass(running ? 'text-success' : 'text-danger')
                .html('<i class="fa fa-circle"></i> ' + (running ? 'Running' : 'Stopped'));
        });

        ajaxCall('/api/netshield/dashboard/top_devices', {}, function(data) {
            var tbody = $('#top-devices-tbody').empty();
            if (data && data.devices && data.devices.length) {
                $.each(data.devices, function(i, d) {
                    tbody.append(
                        '<tr>' +
                        '<td>' + escHtml(d.ip)       + '</td>' +
                        '<td>' + escHtml(d.hostname)  + '</td>' +
                        '<td>' + escHtml(d.mac)       + '</td>' +
                        '<td><span class="badge">' + escHtml(String(d.alert_count)) + '</span></td>' +
                        '</tr>'
                    );
                });
            } else {
                tbody.append('<tr><td colspan="4" class="text-center text-muted">No data available</td></tr>');
            }
        });

        ajaxCall('/api/netshield/dashboard/recent_alerts', {}, function(data) {
            var tbody = $('#recent-alerts-tbody').empty();
            if (data && data.alerts && data.alerts.length) {
                $.each(data.alerts, function(i, a) {
                    tbody.append(
                        '<tr>' +
                        '<td>' + escHtml(fmtTs(a.timestamp)) + '</td>' +
                        '<td>' + escHtml(a.device_ip)         + '</td>' +
                        '<td>' + badge(a.type)                + '</td>' +
                        '<td>' + escHtml(a.detail)            + '</td>' +
                        '</tr>'
                    );
                });
            } else {
                tbody.append('<tr><td colspan="4" class="text-center text-muted">No recent alerts</td></tr>');
            }
        });
    }

    // Service control buttons
    $('#btn-service-start').click(function() {
        ajaxCall('/api/netshield/service/start', {}, function() { loadDashboard(); });
    });
    $('#btn-service-stop').click(function() {
        ajaxCall('/api/netshield/service/stop', {}, function() { loadDashboard(); });
    });
    $('#btn-service-restart').click(function() {
        ajaxCall('/api/netshield/service/restart', {}, function() { loadDashboard(); });
    });

    /*
     * =========================================================
     * TAB 2 — DEVICES BOOTGRID
     * =========================================================
     */
    var deviceGrid = $("#devices-grid").UIBootgrid({
        search: '/api/netshield/devices/search',
        get:    '/api/netshield/devices/getDevice/',
        set:    '/api/netshield/devices/setDevice/',
        add:    '/api/netshield/devices/addDevice/',
        del:    '/api/netshield/devices/delDevice/',
        options: {
            formatters: {
                'status': function(column, row) {
                    return deviceStatusBadge(row.status);
                },
                'commands': function(column, row) {
                    var btns = '<button type="button" class="btn btn-xs btn-default" data-action="detail" data-row-id="' + row.uuid + '"><i class="fa fa-info-circle"></i></button> ';
                    if (row.status === 'quarantined') {
                        btns += '<button type="button" class="btn btn-xs btn-success" data-action="approve" data-row-id="' + row.uuid + '"><i class="fa fa-check"></i> Approve</button> ';
                        btns += '<button type="button" class="btn btn-xs btn-warning" data-action="unquarantine" data-row-id="' + row.uuid + '"><i class="fa fa-unlock"></i> Unquarantine</button>';
                    } else {
                        btns += '<button type="button" class="btn btn-xs btn-success" data-action="approve" data-row-id="' + row.uuid + '"><i class="fa fa-check"></i> Approve</button> ';
                        btns += '<button type="button" class="btn btn-xs btn-danger" data-action="quarantine" data-row-id="' + row.uuid + '"><i class="fa fa-ban"></i> Quarantine</button>';
                    }
                    return btns;
                }
            }
        }
    });

    // Device action delegation
    $('#devices-grid').on('click', '[data-action]', function() {
        var action = $(this).data('action');
        var uuid   = $(this).data('row-id');
        if (action === 'approve') {
            ajaxCall('/api/netshield/devices/approve/' + uuid, {}, function() {
                $('#devices-grid').bootgrid('reload');
            });
        } else if (action === 'quarantine') {
            ajaxCall('/api/netshield/devices/quarantine/' + uuid, {}, function() {
                $('#devices-grid').bootgrid('reload');
            });
        } else if (action === 'unquarantine') {
            ajaxCall('/api/netshield/devices/unquarantine/' + uuid, {}, function() {
                $('#devices-grid').bootgrid('reload');
            });
        } else if (action === 'detail') {
            ajaxCall('/api/netshield/devices/getDevice/' + uuid, {}, function(data) {
                if (data && data.device) {
                    mapDataToFormUI({'frm_device_detail': data.device});
                    $('#dlg-device-detail').modal('show');
                }
            });
        }
    });

    /*
     * =========================================================
     * TAB 3 — POLICIES BOOTGRID
     * =========================================================
     */
    var policyGrid = $("#policies-grid").UIBootgrid({
        search: '/api/netshield/policies/search',
        get:    '/api/netshield/policies/getPolicy/',
        set:    '/api/netshield/policies/setPolicy/',
        add:    '/api/netshield/policies/addPolicy/',
        del:    '/api/netshield/policies/delPolicy/',
        options: {
            formatters: {
                'status': function(column, row) {
                    return policyStatusBadge(row.enabled);
                },
                'scope': function(column, row) {
                    return '<span class="label label-info">' + escHtml(row.scope) + '</span>';
                },
                'action': function(column, row) {
                    var map = {block: 'danger', allow: 'success', throttle: 'warning', log: 'info'};
                    var cls = map[row.action] || 'default';
                    return '<span class="label label-' + cls + '">' + escHtml(row.action) + '</span>';
                },
                'commands': function(column, row) {
                    return stdGridCmdButtons(row.uuid);
                }
            }
        }
    });

    // Policy dialog: scope change updates scope_value label
    $('#policy_scope').change(function() {
        var scope = $(this).val();
        var labels = {network: 'CIDR (e.g. 192.168.1.0/24)', vlan: 'VLAN ID', device: 'MAC Address', device_category: 'Category Name'};
        $('#policy_scope_value_label').text(labels[scope] || 'Value');
    });

    // Policy action change: show/hide bandwidth limit
    $('#policy_action').change(function() {
        if ($(this).val() === 'throttle') {
            $('#row-bandwidth').show();
        } else {
            $('#row-bandwidth').hide();
        }
    });

    $('#btn-apply-policies').click(function() {
        var btn = $(this).prop('disabled', true).html('<i class="fa fa-spinner fa-spin"></i> Applying…');
        ajaxCall('/api/netshield/policies/apply', {}, function(data) {
            btn.prop('disabled', false).html('<i class="fa fa-play"></i> Apply Policies');
            if (data && data.status === 'ok') {
                BootstrapDialog.show({
                    type: BootstrapDialog.TYPE_SUCCESS,
                    title: 'Policies Applied',
                    message: 'All active policies have been enforced successfully.',
                    buttons: [{ label: 'OK', action: function(dlg){ dlg.close(); } }]
                });
            }
        });
    });

    // Load policy dialog for add/edit
    $('#btn-policy-add').click(function() {
        clearFormUI('frm_policy_edit');
        $('#row-bandwidth').hide();
        $('#dlg-policy-edit .modal-title').text('Add Policy');
        $('#dlg-policy-edit').modal('show');
    });

    $('#btn-policy-save').click(function() {
        var uuid = $('#policy_uuid').val();
        var endpoint = uuid ? '/api/netshield/policies/setPolicy/' + uuid : '/api/netshield/policies/addPolicy/';
        saveFormToEndpoint(endpoint, 'frm_policy_edit', function() {
            $('#dlg-policy-edit').modal('hide');
            $('#policies-grid').bootgrid('reload');
        });
    });

    /*
     * =========================================================
     * TAB 4 — APPLICATIONS BOOTGRID
     * =========================================================
     */
    $("#apps-grid").UIBootgrid({
        search: '/api/netshield/apps/search',
        get:    '/api/netshield/apps/getApp/',
        set:    '/api/netshield/apps/setApp/',
        add:    '/api/netshield/apps/addApp/',
        del:    '/api/netshield/apps/delApp/',
        options: {
            formatters: {
                'status': function(column, row) {
                    return (row.enabled == '1')
                        ? '<span class="label label-success">Active</span>'
                        : '<span class="label label-default">Inactive</span>';
                },
                'domains': function(column, row) {
                    var d = row.domains || '';
                    return d.length > 60 ? escHtml(d.substr(0, 57)) + '…' : escHtml(d);
                },
                'commands': function(column, row) {
                    return stdGridCmdButtons(row.uuid);
                }
            }
        }
    });

    $('#btn-app-add').click(function() {
        clearFormUI('frm_app_edit');
        $('#dlg-app-edit .modal-title').text('Add Application');
        $('#dlg-app-edit').modal('show');
    });

    $('#btn-app-save').click(function() {
        var uuid = $('#app_uuid').val();
        var endpoint = uuid ? '/api/netshield/apps/setApp/' + uuid : '/api/netshield/apps/addApp/';
        saveFormToEndpoint(endpoint, 'frm_app_edit', function() {
            $('#dlg-app-edit').modal('hide');
            $('#apps-grid').bootgrid('reload');
        });
    });

    /*
     * =========================================================
     * TAB 5 — WEB CATEGORIES BOOTGRID
     * =========================================================
     */
    $("#webcats-grid").UIBootgrid({
        search: '/api/netshield/webcategories/search',
        get:    '/api/netshield/webcategories/getCategory/',
        set:    '/api/netshield/webcategories/setCategory/',
        add:    '/api/netshield/webcategories/addCategory/',
        del:    '/api/netshield/webcategories/delCategory/',
        options: {
            formatters: {
                'status': function(column, row) {
                    return (row.enabled == '1')
                        ? '<span class="label label-success">Enabled</span>'
                        : '<span class="label label-default">Disabled</span>';
                },
                'commands': function(column, row) {
                    return stdGridCmdButtons(row.uuid);
                }
            }
        }
    });

    $('#btn-webcats-sync').click(function() {
        var btn = $(this).prop('disabled', true).html('<i class="fa fa-spinner fa-spin"></i> Syncing…');
        ajaxCall('/api/netshield/webcategories/syncAll', {}, function(data) {
            btn.prop('disabled', false).html('<i class="fa fa-refresh"></i> Sync All');
            if (data && data.status === 'ok') {
                $('#webcats-grid').bootgrid('reload');
                loadWebcatStats();
            }
        });
    });

    function loadWebcatStats() {
        ajaxCall('/api/netshield/webcategories/stats', {}, function(data) {
            if (data) {
                $('#stat-webcat-total').text(data.total_domains || 0);
                $('#stat-webcat-categories').text(data.total_categories || 0);
            }
        });
    }

    /*
     * =========================================================
     * TAB 6 — DNS FILTERING
     * =========================================================
     */
    function loadDnsStats() {
        ajaxCall('/api/netshield/dns/stats', {}, function(data) {
            if (data) {
                $('#stat-dns-blocked').text(data.total_blocked || 0);
                $('#stat-dns-queries').text(data.queries_today || 0);
            }
        });

        ajaxCall('/api/netshield/dns/recentBlocked', {}, function(data) {
            var tbody = $('#dns-blocked-tbody').empty();
            if (data && data.queries && data.queries.length) {
                $.each(data.queries, function(i, q) {
                    tbody.append(
                        '<tr>' +
                        '<td>' + escHtml(fmtTs(q.timestamp)) + '</td>' +
                        '<td>' + escHtml(q.device_ip) + '</td>' +
                        '<td>' + escHtml(q.domain)    + '</td>' +
                        '<td>' + escHtml(q.reason)    + '</td>' +
                        '</tr>'
                    );
                });
            } else {
                tbody.append('<tr><td colspan="4" class="text-center text-muted">No recent blocked queries</td></tr>');
            }
        });
    }

    $('#btn-dns-save').click(function() {
        saveFormToEndpoint('/api/netshield/settings/setDns', 'frm_dns', function() {
            ajaxCall('/api/netshield/service/reconfigure', {}, function() {
                loadDnsStats();
            });
        });
    });

    /*
     * =========================================================
     * TAB 7 — TARGET LISTS BOOTGRID
     * =========================================================
     */
    $("#targetlists-grid").UIBootgrid({
        search: '/api/netshield/targetlists/search',
        get:    '/api/netshield/targetlists/getList/',
        set:    '/api/netshield/targetlists/setList/',
        add:    '/api/netshield/targetlists/addList/',
        del:    '/api/netshield/targetlists/delList/',
        options: {
            formatters: {
                'type': function(column, row) {
                    var map = {domain: 'info', ip: 'warning', cidr: 'primary'};
                    return '<span class="label label-' + (map[row.type] || 'default') + '">' + escHtml(row.type) + '</span>';
                },
                'status': function(column, row) {
                    return (row.enabled == '1')
                        ? '<span class="label label-success">Active</span>'
                        : '<span class="label label-default">Inactive</span>';
                },
                'commands': function(column, row) {
                    return stdGridCmdButtons(row.uuid);
                }
            }
        }
    });

    $('#btn-targetlists-sync').click(function() {
        var btn = $(this).prop('disabled', true).html('<i class="fa fa-spinner fa-spin"></i> Syncing…');
        ajaxCall('/api/netshield/targetlists/syncAll', {}, function(data) {
            btn.prop('disabled', false).html('<i class="fa fa-refresh"></i> Sync All');
            $('#targetlists-grid').bootgrid('reload');
            loadTargetStats();
        });
    });

    function loadTargetStats() {
        ajaxCall('/api/netshield/targetlists/stats', {}, function(data) {
            if (data) {
                $('#stat-targetlists-total').text(data.total_entries || 0);
                $('#stat-targetlists-lists').text(data.total_lists   || 0);
            }
        });
    }

    /*
     * =========================================================
     * TAB 8 — GEOIP
     * =========================================================
     */
    function loadGeoip() {
        ajaxCall('/api/netshield/geoip/stats', {}, function(data) {
            if (data) {
                $('#stat-geoip-blocked-countries').text(data.blocked_countries  || 0);
                $('#stat-geoip-blocked-conns').text(data.blocked_connections    || 0);
            }
        });

        ajaxCall('/api/netshield/geoip/countries', {}, function(data) {
            var container = $('#geoip-countries-list').empty();
            if (data && data.countries && data.countries.length) {
                $.each(data.countries, function(i, c) {
                    var checked = c.blocked ? 'checked' : '';
                    container.append(
                        '<div class="col-xs-12 col-sm-6 col-md-4 col-lg-3 geoip-country-row" data-name="' + escHtml(c.code) + '">' +
                        '<div class="checkbox">' +
                        '<label>' +
                        '<input type="checkbox" class="geoip-toggle" data-code="' + escHtml(c.code) + '" ' + checked + '> ' +
                        escHtml(c.name) + ' <span class="text-muted">(' + escHtml(c.code) + ')</span>' +
                        '</label>' +
                        '</div>' +
                        '</div>'
                    );
                });
            }
        });
    }

    // Country search
    $('#geoip-search').on('keyup', function() {
        var q = $(this).val().toLowerCase();
        $('.geoip-country-row').each(function() {
            var txt = $(this).text().toLowerCase();
            $(this).toggle(txt.indexOf(q) !== -1);
        });
    });

    // Country toggle
    $('#geoip-countries-list').on('change', '.geoip-toggle', function() {
        var code    = $(this).data('code');
        var blocked = $(this).is(':checked') ? 1 : 0;
        ajaxCall('/api/netshield/geoip/setCountry', {code: code, blocked: blocked}, function() {
            loadGeoipStats();
        });
    });

    function loadGeoipStats() {
        ajaxCall('/api/netshield/geoip/stats', {}, function(data) {
            if (data) {
                $('#stat-geoip-blocked-countries').text(data.blocked_countries || 0);
                $('#stat-geoip-blocked-conns').text(data.blocked_connections   || 0);
            }
        });
    }

    /*
     * =========================================================
     * TAB 9 — ALERTS BOOTGRID
     * =========================================================
     */
    var alertsGrid = $("#alerts-grid").UIBootgrid({
        search: '/api/netshield/alerts/search',
        options: {
            requestHandler: function(request) {
                var typeFilter = $('#alert-filter-type').val();
                if (typeFilter) request.type_filter = typeFilter;
                return request;
            },
            formatters: {
                'type': function(column, row) {
                    return badge(row.type);
                },
                'timestamp': function(column, row) {
                    return escHtml(fmtTs(row.timestamp));
                },
                'device': function(column, row) {
                    var s = row.device_ip || '';
                    if (row.device_name) s += ' (' + row.device_name + ')';
                    return escHtml(s);
                },
                'commands': function(column, row) {
                    return '<button type="button" class="btn btn-xs btn-default alert-detail-btn" data-row-id="' + row.uuid + '"><i class="fa fa-search"></i> Detail</button>';
                }
            }
        }
    });

    // Alert filter
    $('#alert-filter-type').change(function() {
        $('#alerts-grid').bootgrid('reload');
    });

    // Alert detail
    $('#alerts-grid').on('click', '.alert-detail-btn', function() {
        var uuid = $(this).data('row-id');
        ajaxCall('/api/netshield/alerts/getAlert/' + uuid, {}, function(data) {
            if (data && data.alert) {
                var a = data.alert;
                $('#alert-detail-ts').text(fmtTs(a.timestamp));
                $('#alert-detail-device').text((a.device_ip || '') + (a.device_name ? ' (' + a.device_name + ')' : ''));
                $('#alert-detail-type').html(badge(a.type));
                $('#alert-detail-detail').text(a.detail || '—');
                $('#alert-detail-raw').text(JSON.stringify(a.raw || {}, null, 2));
                $('#dlg-alert-detail').modal('show');
            }
        });
    });

    // Flush alerts
    $('#btn-flush-alerts').click(function() {
        BootstrapDialog.confirm({
            title: 'Flush Old Alerts',
            message: 'Delete alerts older than 30 days? This cannot be undone.',
            type: BootstrapDialog.TYPE_WARNING,
            callback: function(result) {
                if (result) {
                    ajaxCall('/api/netshield/alerts/flush', {}, function() {
                        $('#alerts-grid').bootgrid('reload');
                        loadAlertStats();
                    });
                }
            }
        });
    });

    function loadAlertStats() {
        ajaxCall('/api/netshield/alerts/stats', {}, function(data) {
            if (data) {
                $('#stat-alerts-vpn').text(data.vpn          || 0);
                $('#stat-alerts-adult').text(data.adult      || 0);
                $('#stat-alerts-dns').text(data.dns_bypass   || 0);
                $('#stat-alerts-other').text(data.other      || 0);
            }
        });
    }

    /*
     * =========================================================
     * TAB 10 — SETTINGS
     * =========================================================
     */
    function loadSettings() {
        ajaxCall('/api/netshield/settings/get', {}, function(data) {
            if (data && data.netshield) {
                mapDataToFormUI({'frm_settings': data.netshield});
            }
        });
    }

    $('#btn-settings-save').click(function() {
        saveFormToEndpoint('/api/netshield/settings/set', 'frm_settings', function() {
            // Settings saved — no restart needed until Apply
        });
    });

    $('#btn-settings-apply').click(function() {
        var btn = $(this).prop('disabled', true).html('<i class="fa fa-spinner fa-spin"></i> Applying…');
        ajaxCall('/api/netshield/service/reconfigure', {}, function(data) {
            btn.prop('disabled', false).html('<i class="fa fa-check"></i> Save &amp; Apply');
            if (data && data.status === 'ok') {
                loadDashboard();
            }
        });
    });

    /*
     * =========================================================
     * AUTO-REFRESH
     * =========================================================
     */
    var refreshTimer = null;

    function startAutoRefresh() {
        refreshTimer = setInterval(function() {
            var activeTab = $('ul.nav-tabs .active a').attr('href');
            if (activeTab === '#tab-dashboard') loadDashboard();
        }, 30000);
    }

    // Tab switch handlers
    $('a[data-toggle="tab"]').on('shown.bs.tab', function(e) {
        var tab = $(e.target).attr('href');
        if (tab === '#tab-dashboard')   loadDashboard();
        if (tab === '#tab-dns')         loadDnsStats();
        if (tab === '#tab-geoip')       loadGeoip();
        if (tab === '#tab-alerts')      loadAlertStats();
        if (tab === '#tab-settings')    loadSettings();
        if (tab === '#tab-webcats')     loadWebcatStats();
        if (tab === '#tab-targetlists') loadTargetStats();
    });

    // Utility: standard command buttons for bootgrid
    function stdGridCmdButtons(uuid) {
        return '<button type="button" class="btn btn-xs btn-default command-edit" data-row-id="' + uuid + '"><i class="fa fa-pencil"></i></button> ' +
               '<button type="button" class="btn btn-xs btn-danger command-delete" data-row-id="' + uuid + '"><i class="fa fa-trash-o"></i></button>';
    }

    // Initial load
    loadDashboard();
    loadSettings();
    startAutoRefresh();
});
</script>

<ul class="nav nav-tabs" role="tablist" id="ns-tabs">
    <li role="presentation" class="active">
        <a href="#tab-dashboard" aria-controls="tab-dashboard" role="tab" data-toggle="tab">
            <i class="fa fa-tachometer"></i> Dashboard
        </a>
    </li>
    <li role="presentation">
        <a href="#tab-devices" aria-controls="tab-devices" role="tab" data-toggle="tab">
            <i class="fa fa-desktop"></i> Devices
        </a>
    </li>
    <li role="presentation">
        <a href="#tab-policies" aria-controls="tab-policies" role="tab" data-toggle="tab">
            <i class="fa fa-shield"></i> Policies
        </a>
    </li>
    <li role="presentation">
        <a href="#tab-apps" aria-controls="tab-apps" role="tab" data-toggle="tab">
            <i class="fa fa-th"></i> Applications
        </a>
    </li>
    <li role="presentation">
        <a href="#tab-webcats" aria-controls="tab-webcats" role="tab" data-toggle="tab">
            <i class="fa fa-globe"></i> Web Categories
        </a>
    </li>
    <li role="presentation">
        <a href="#tab-dns" aria-controls="tab-dns" role="tab" data-toggle="tab">
            <i class="fa fa-filter"></i> DNS Filtering
        </a>
    </li>
    <li role="presentation">
        <a href="#tab-targetlists" aria-controls="tab-targetlists" role="tab" data-toggle="tab">
            <i class="fa fa-list"></i> Target Lists
        </a>
    </li>
    <li role="presentation">
        <a href="#tab-geoip" aria-controls="tab-geoip" role="tab" data-toggle="tab">
            <i class="fa fa-map-marker"></i> GeoIP
        </a>
    </li>
    <li role="presentation">
        <a href="#tab-alerts" aria-controls="tab-alerts" role="tab" data-toggle="tab">
            <i class="fa fa-bell"></i> Alerts
        </a>
    </li>
    <li role="presentation">
        <a href="#tab-settings" aria-controls="tab-settings" role="tab" data-toggle="tab">
            <i class="fa fa-cog"></i> Settings
        </a>
    </li>
</ul>

<div class="tab-content content-box">

    <!-- ===================================================== -->
    <!-- TAB 1: DASHBOARD                                      -->
    <!-- ===================================================== -->
    <div role="tabpanel" class="tab-pane active" id="tab-dashboard">
        <div class="container-fluid">

            <!-- Service Status Bar -->
            <div class="row" style="margin-top:15px;">
                <div class="col-xs-12">
                    <div class="panel panel-default">
                        <div class="panel-body" style="padding:10px 15px;">
                            <div class="row">
                                <div class="col-xs-12 col-sm-6">
                                    <h4 style="margin:0;">
                                        <strong>NetShield Service</strong>
                                        &nbsp;
                                        <span id="service-status-indicator" class="text-muted">
                                            <i class="fa fa-circle-o-notch fa-spin"></i> Checking…
                                        </span>
                                    </h4>
                                </div>
                                <div class="col-xs-12 col-sm-6 text-right">
                                    <div class="btn-group">
                                        <button id="btn-service-start"   class="btn btn-sm btn-success"><i class="fa fa-play"></i> Start</button>
                                        <button id="btn-service-stop"    class="btn btn-sm btn-danger"><i class="fa fa-stop"></i> Stop</button>
                                        <button id="btn-service-restart" class="btn btn-sm btn-default"><i class="fa fa-refresh"></i> Restart</button>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Summary Cards -->
            <div class="row">
                <div class="col-xs-12 col-sm-6 col-md-3">
                    <div class="panel panel-danger">
                        <div class="panel-heading">
                            <div class="row">
                                <div class="col-xs-3"><i class="fa fa-bell fa-5x"></i></div>
                                <div class="col-xs-9 text-right">
                                    <div class="huge" id="stat-alerts-today">—</div>
                                    <div>Alerts Today</div>
                                </div>
                            </div>
                        </div>
                        <div class="panel-footer text-right">
                            <small class="text-muted">Updated every 30s</small>
                        </div>
                    </div>
                </div>
                <div class="col-xs-12 col-sm-6 col-md-3">
                    <div class="panel panel-info">
                        <div class="panel-heading">
                            <div class="row">
                                <div class="col-xs-3"><i class="fa fa-desktop fa-5x"></i></div>
                                <div class="col-xs-9 text-right">
                                    <div class="huge" id="stat-devices">—</div>
                                    <div>Devices Tracked</div>
                                </div>
                            </div>
                        </div>
                        <div class="panel-footer text-right">
                            <small class="text-muted">All categories</small>
                        </div>
                    </div>
                </div>
                <div class="col-xs-12 col-sm-6 col-md-3">
                    <div class="panel panel-success">
                        <div class="panel-heading">
                            <div class="row">
                                <div class="col-xs-3"><i class="fa fa-shield fa-5x"></i></div>
                                <div class="col-xs-9 text-right">
                                    <div class="huge" id="stat-policies">—</div>
                                    <div>Active Policies</div>
                                </div>
                            </div>
                        </div>
                        <div class="panel-footer text-right">
                            <small class="text-muted">Enabled policies</small>
                        </div>
                    </div>
                </div>
                <div class="col-xs-12 col-sm-6 col-md-3">
                    <div class="panel panel-warning">
                        <div class="panel-heading">
                            <div class="row">
                                <div class="col-xs-3"><i class="fa fa-ban fa-5x"></i></div>
                                <div class="col-xs-9 text-right">
                                    <div class="huge" id="stat-blocked-domains">—</div>
                                    <div>Blocked Domains</div>
                                </div>
                            </div>
                        </div>
                        <div class="panel-footer text-right">
                            <small class="text-muted">Across all lists</small>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Tables Row -->
            <div class="row">
                <!-- Top Alert Devices -->
                <div class="col-xs-12 col-md-5">
                    <div class="panel panel-default">
                        <div class="panel-heading"><strong><i class="fa fa-exclamation-triangle"></i> Top Alert-Generating Devices</strong></div>
                        <div class="panel-body" style="padding:0;">
                            <table class="table table-condensed table-hover" style="margin:0;">
                                <thead>
                                    <tr>
                                        <th>IP</th>
                                        <th>Hostname</th>
                                        <th>MAC</th>
                                        <th>Alerts</th>
                                    </tr>
                                </thead>
                                <tbody id="top-devices-tbody">
                                    <tr><td colspan="4" class="text-center text-muted"><i class="fa fa-spinner fa-spin"></i> Loading…</td></tr>
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>

                <!-- Recent Alerts -->
                <div class="col-xs-12 col-md-7">
                    <div class="panel panel-default">
                        <div class="panel-heading"><strong><i class="fa fa-clock-o"></i> Recent Alerts</strong></div>
                        <div class="panel-body" style="padding:0;">
                            <table class="table table-condensed table-hover" style="margin:0;">
                                <thead>
                                    <tr>
                                        <th>Time</th>
                                        <th>Device</th>
                                        <th>Type</th>
                                        <th>Detail</th>
                                    </tr>
                                </thead>
                                <tbody id="recent-alerts-tbody">
                                    <tr><td colspan="4" class="text-center text-muted"><i class="fa fa-spinner fa-spin"></i> Loading…</td></tr>
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>
            </div>

        </div><!-- /container-fluid -->
    </div><!-- /tab-dashboard -->


    <!-- ===================================================== -->
    <!-- TAB 2: DEVICES                                        -->
    <!-- ===================================================== -->
    <div role="tabpanel" class="tab-pane" id="tab-devices">
        <div class="container-fluid" style="padding-top:10px;">
            <table id="devices-grid" class="table table-condensed table-hover table-striped">
                <thead>
                    <tr>
                        <th data-column-id="mac"      data-sortable="true">MAC</th>
                        <th data-column-id="ip"       data-sortable="true">IP Address</th>
                        <th data-column-id="hostname" data-sortable="true">Hostname</th>
                        <th data-column-id="vendor"   data-sortable="true">Vendor</th>
                        <th data-column-id="category" data-sortable="true">Category</th>
                        <th data-column-id="status"   data-sortable="true" data-formatter="status">Status</th>
                        <th data-column-id="last_seen" data-sortable="true">Last Seen</th>
                        <th data-column-id="commands" data-formatter="commands" data-sortable="false">Actions</th>
                    </tr>
                </thead>
                <tbody></tbody>
            </table>
        </div>
    </div>

    <!-- Device Detail Dialog -->
    <div class="modal fade" id="dlg-device-detail" tabindex="-1" role="dialog">
        <div class="modal-dialog" role="document">
            <div class="modal-content">
                <div class="modal-header">
                    <button type="button" class="close" data-dismiss="modal"><span>&times;</span></button>
                    <h4 class="modal-title">Device Detail</h4>
                </div>
                <div class="modal-body">
                    <form id="frm_device_detail">
                        <div class="form-group">
                            <label>MAC Address</label>
                            <input type="text" class="form-control" id="device_mac" name="mac" readonly>
                        </div>
                        <div class="form-group">
                            <label>IP Address</label>
                            <input type="text" class="form-control" id="device_ip" name="ip" readonly>
                        </div>
                        <div class="form-group">
                            <label>Hostname</label>
                            <input type="text" class="form-control" id="device_hostname" name="hostname">
                        </div>
                        <div class="form-group">
                            <label>Vendor</label>
                            <input type="text" class="form-control" id="device_vendor" name="vendor" readonly>
                        </div>
                        <div class="form-group">
                            <label>Category</label>
                            <select class="form-control" id="device_category" name="category">
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
                            <textarea class="form-control" id="device_notes" name="notes" rows="3"></textarea>
                        </div>
                    </form>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-default" data-dismiss="modal">Close</button>
                    <button type="button" class="btn btn-primary" id="btn-device-detail-save">Save Changes</button>
                </div>
            </div>
        </div>
    </div>


    <!-- ===================================================== -->
    <!-- TAB 3: POLICIES                                       -->
    <!-- ===================================================== -->
    <div role="tabpanel" class="tab-pane" id="tab-policies">
        <div class="container-fluid" style="padding-top:10px;">
            <div class="row" style="margin-bottom:8px;">
                <div class="col-xs-12">
                    <button id="btn-policy-add" class="btn btn-sm btn-success">
                        <i class="fa fa-plus"></i> Add Policy
                    </button>
                    <button id="btn-apply-policies" class="btn btn-sm btn-primary" style="margin-left:5px;">
                        <i class="fa fa-play"></i> Apply Policies
                    </button>
                </div>
            </div>
            <table id="policies-grid" class="table table-condensed table-hover table-striped">
                <thead>
                    <tr>
                        <th data-column-id="name"         data-sortable="true">Name</th>
                        <th data-column-id="scope"        data-sortable="true" data-formatter="scope">Scope</th>
                        <th data-column-id="scope_value"  data-sortable="true">Scope Value</th>
                        <th data-column-id="action"       data-sortable="true" data-formatter="action">Action</th>
                        <th data-column-id="target_type"  data-sortable="true">Target</th>
                        <th data-column-id="priority"     data-sortable="true">Priority</th>
                        <th data-column-id="enabled"      data-sortable="true" data-formatter="status">Status</th>
                        <th data-column-id="commands"     data-formatter="commands" data-sortable="false">Actions</th>
                    </tr>
                </thead>
                <tbody></tbody>
            </table>
        </div>
    </div>

    <!-- Policy Edit Dialog -->
    <div class="modal fade" id="dlg-policy-edit" tabindex="-1" role="dialog">
        <div class="modal-dialog modal-lg" role="document">
            <div class="modal-content">
                <div class="modal-header">
                    <button type="button" class="close" data-dismiss="modal"><span>&times;</span></button>
                    <h4 class="modal-title">Add Policy</h4>
                </div>
                <div class="modal-body">
                    <form id="frm_policy_edit">
                        <input type="hidden" id="policy_uuid" name="uuid">
                        <div class="row">
                            <div class="col-md-6">
                                <div class="form-group">
                                    <label>Policy Name <span class="text-danger">*</span></label>
                                    <input type="text" class="form-control" id="policy_name" name="name" placeholder="e.g. Block Adult Content on Mobile" required>
                                </div>
                            </div>
                            <div class="col-md-3">
                                <div class="form-group">
                                    <label>Priority</label>
                                    <input type="number" class="form-control" id="policy_priority" name="priority" value="100" min="1" max="999">
                                </div>
                            </div>
                            <div class="col-md-3">
                                <div class="form-group">
                                    <label>Enabled</label>
                                    <select class="form-control" id="policy_enabled" name="enabled">
                                        <option value="1">Yes</option>
                                        <option value="0">No</option>
                                    </select>
                                </div>
                            </div>
                        </div>
                        <div class="row">
                            <div class="col-md-4">
                                <div class="form-group">
                                    <label>Scope <span class="text-danger">*</span></label>
                                    <select class="form-control" id="policy_scope" name="scope">
                                        <option value="network">Network (CIDR)</option>
                                        <option value="vlan">VLAN</option>
                                        <option value="device">Device (MAC)</option>
                                        <option value="device_category">Device Category</option>
                                    </select>
                                </div>
                            </div>
                            <div class="col-md-8">
                                <div class="form-group">
                                    <label id="policy_scope_value_label">Scope Value</label>
                                    <input type="text" class="form-control" id="policy_scope_value" name="scope_value" placeholder="e.g. 192.168.1.0/24">
                                </div>
                            </div>
                        </div>
                        <div class="row">
                            <div class="col-md-4">
                                <div class="form-group">
                                    <label>Action <span class="text-danger">*</span></label>
                                    <select class="form-control" id="policy_action" name="action">
                                        <option value="block">Block</option>
                                        <option value="allow">Allow</option>
                                        <option value="throttle">Throttle</option>
                                        <option value="log">Log Only</option>
                                    </select>
                                </div>
                            </div>
                            <div class="col-md-4">
                                <div class="form-group">
                                    <label>Target Type</label>
                                    <select class="form-control" id="policy_target_type" name="target_type">
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
                                    <input type="number" class="form-control" id="policy_bandwidth" name="bandwidth_limit" min="0" placeholder="0 = unlimited">
                                </div>
                            </div>
                        </div>
                        <div class="form-group">
                            <label>Target Value</label>
                            <input type="text" class="form-control" id="policy_target_value" name="target_value" placeholder="e.g. adult,gambling  (comma-separated)">
                            <span class="help-block">Comma-separated list of app names, category names, or list names</span>
                        </div>
                        <div class="row">
                            <div class="col-md-12">
                                <label>Schedule — Days Active</label>
                                <div class="checkbox-inline" style="margin-left:0;">
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
                        <div class="row" style="margin-top:10px;">
                            <div class="col-md-3">
                                <div class="form-group">
                                    <label>Start Time</label>
                                    <input type="time" class="form-control" id="policy_start_time" name="start_time" value="00:00">
                                </div>
                            </div>
                            <div class="col-md-3">
                                <div class="form-group">
                                    <label>End Time</label>
                                    <input type="time" class="form-control" id="policy_end_time" name="end_time" value="23:59">
                                </div>
                            </div>
                        </div>
                    </form>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-default" data-dismiss="modal">Cancel</button>
                    <button type="button" class="btn btn-primary" id="btn-policy-save">Save Policy</button>
                </div>
            </div>
        </div>
    </div>


    <!-- ===================================================== -->
    <!-- TAB 4: APPLICATIONS                                   -->
    <!-- ===================================================== -->
    <div role="tabpanel" class="tab-pane" id="tab-apps">
        <div class="container-fluid" style="padding-top:10px;">
            <div class="row" style="margin-bottom:8px;">
                <div class="col-xs-12">
                    <button id="btn-app-add" class="btn btn-sm btn-success">
                        <i class="fa fa-plus"></i> Add Custom Application
                    </button>
                </div>
            </div>
            <table id="apps-grid" class="table table-condensed table-hover table-striped">
                <thead>
                    <tr>
                        <th data-column-id="name"        data-sortable="true">Name</th>
                        <th data-column-id="category"    data-sortable="true">Category</th>
                        <th data-column-id="domains"     data-sortable="false" data-formatter="domains">Domains</th>
                        <th data-column-id="detections"  data-sortable="true">Detections</th>
                        <th data-column-id="enabled"     data-sortable="true" data-formatter="status">Status</th>
                        <th data-column-id="commands"    data-formatter="commands" data-sortable="false">Actions</th>
                    </tr>
                </thead>
                <tbody></tbody>
            </table>
        </div>
    </div>

    <!-- App Edit Dialog -->
    <div class="modal fade" id="dlg-app-edit" tabindex="-1" role="dialog">
        <div class="modal-dialog" role="document">
            <div class="modal-content">
                <div class="modal-header">
                    <button type="button" class="close" data-dismiss="modal"><span>&times;</span></button>
                    <h4 class="modal-title">Add Application</h4>
                </div>
                <div class="modal-body">
                    <form id="frm_app_edit">
                        <input type="hidden" id="app_uuid" name="uuid">
                        <div class="form-group">
                            <label>Application Name <span class="text-danger">*</span></label>
                            <input type="text" class="form-control" id="app_name" name="name" placeholder="e.g. MyApp" required>
                        </div>
                        <div class="form-group">
                            <label>Category</label>
                            <input type="text" class="form-control" id="app_category" name="category" placeholder="e.g. social_media">
                        </div>
                        <div class="form-group">
                            <label>Domains <span class="text-danger">*</span></label>
                            <textarea class="form-control" id="app_domains" name="domains" rows="4"
                                      placeholder="One domain per line, e.g.:&#10;example.com&#10;api.example.com"></textarea>
                        </div>
                        <div class="form-group">
                            <label>Enabled</label>
                            <select class="form-control" id="app_enabled" name="enabled">
                                <option value="1">Yes</option>
                                <option value="0">No</option>
                            </select>
                        </div>
                    </form>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-default" data-dismiss="modal">Cancel</button>
                    <button type="button" class="btn btn-primary" id="btn-app-save">Save</button>
                </div>
            </div>
        </div>
    </div>


    <!-- ===================================================== -->
    <!-- TAB 5: WEB CATEGORIES                                 -->
    <!-- ===================================================== -->
    <div role="tabpanel" class="tab-pane" id="tab-webcats">
        <div class="container-fluid" style="padding-top:10px;">
            <!-- Stats row -->
            <div class="row" style="margin-bottom:10px;">
                <div class="col-xs-12 col-sm-6 col-md-3">
                    <div class="well well-sm text-center">
                        <strong id="stat-webcat-total">—</strong><br>
                        <small class="text-muted">Total Domains</small>
                    </div>
                </div>
                <div class="col-xs-12 col-sm-6 col-md-3">
                    <div class="well well-sm text-center">
                        <strong id="stat-webcat-categories">—</strong><br>
                        <small class="text-muted">Categories</small>
                    </div>
                </div>
                <div class="col-xs-12 col-sm-6 col-md-6 text-right" style="padding-top:4px;">
                    <button id="btn-webcats-sync" class="btn btn-sm btn-info">
                        <i class="fa fa-refresh"></i> Sync All
                    </button>
                    <button id="btn-webcat-add" class="btn btn-sm btn-success" style="margin-left:5px;">
                        <i class="fa fa-plus"></i> Add Category
                    </button>
                </div>
            </div>
            <table id="webcats-grid" class="table table-condensed table-hover table-striped">
                <thead>
                    <tr>
                        <th data-column-id="name"         data-sortable="true">Category Name</th>
                        <th data-column-id="domain_count" data-sortable="true">Domain Count</th>
                        <th data-column-id="source_url"   data-sortable="false">Source URL</th>
                        <th data-column-id="enabled"      data-sortable="true" data-formatter="status">Status</th>
                        <th data-column-id="last_updated" data-sortable="true">Last Updated</th>
                        <th data-column-id="commands"     data-formatter="commands" data-sortable="false">Actions</th>
                    </tr>
                </thead>
                <tbody></tbody>
            </table>
        </div>
    </div>


    <!-- ===================================================== -->
    <!-- TAB 6: DNS FILTERING                                  -->
    <!-- ===================================================== -->
    <div role="tabpanel" class="tab-pane" id="tab-dns">
        <div class="container-fluid" style="padding-top:15px;">

            <!-- Stats -->
            <div class="row" style="margin-bottom:15px;">
                <div class="col-xs-12 col-sm-4">
                    <div class="well well-sm text-center">
                        <strong id="stat-dns-blocked">—</strong><br>
                        <small class="text-muted">Total Blocked Domains</small>
                    </div>
                </div>
                <div class="col-xs-12 col-sm-4">
                    <div class="well well-sm text-center">
                        <strong id="stat-dns-queries">—</strong><br>
                        <small class="text-muted">Queries Intercepted Today</small>
                    </div>
                </div>
            </div>

            <!-- DNS Settings Form -->
            <form id="frm_dns">
                <div class="panel panel-default">
                    <div class="panel-heading"><strong>DNS Filtering Options</strong></div>
                    <div class="panel-body">
                        <div class="row">
                            <div class="col-md-6">
                                <div class="form-group">
                                    <label class="control-label">Enable DNS Filtering</label>
                                    <div>
                                        <select class="form-control" id="dns_enabled" name="dns.enabled">
                                            <option value="1">Enabled</option>
                                            <option value="0">Disabled</option>
                                        </select>
                                    </div>
                                </div>
                                <div class="form-group">
                                    <label class="control-label">Force DNS Through Unbound</label>
                                    <div>
                                        <select class="form-control" id="dns_force" name="dns.force_dns">
                                            <option value="1">Enabled</option>
                                            <option value="0">Disabled</option>
                                        </select>
                                        <span class="help-block">Redirect all DNS queries to Unbound, even those targeting external DNS servers</span>
                                    </div>
                                </div>
                                <div class="form-group">
                                    <label class="control-label">Block DNS-over-HTTPS (DoH)</label>
                                    <div>
                                        <select class="form-control" id="dns_block_doh" name="dns.block_doh">
                                            <option value="1">Enabled</option>
                                            <option value="0">Disabled</option>
                                        </select>
                                        <span class="help-block">Blocks known DoH resolver domains to prevent DNS bypass</span>
                                    </div>
                                </div>
                                <div class="form-group">
                                    <label class="control-label">Block DNS-over-TLS (DoT)</label>
                                    <div>
                                        <select class="form-control" id="dns_block_dot" name="dns.block_dot">
                                            <option value="1">Enabled</option>
                                            <option value="0">Disabled</option>
                                        </select>
                                        <span class="help-block">Blocks port 853 outbound to prevent DoT bypass</span>
                                    </div>
                                </div>
                            </div>
                            <div class="col-md-6">
                                <div class="form-group">
                                    <label class="control-label">Google Safe Search</label>
                                    <div>
                                        <select class="form-control" id="dns_safe_google" name="dns.safe_search_google">
                                            <option value="1">Enabled</option>
                                            <option value="0">Disabled</option>
                                        </select>
                                    </div>
                                </div>
                                <div class="form-group">
                                    <label class="control-label">YouTube Restricted Mode</label>
                                    <div>
                                        <select class="form-control" id="dns_safe_youtube" name="dns.safe_search_youtube">
                                            <option value="1">Enabled</option>
                                            <option value="0">Disabled</option>
                                        </select>
                                    </div>
                                </div>
                                <div class="form-group">
                                    <label class="control-label">Bing Safe Search</label>
                                    <div>
                                        <select class="form-control" id="dns_safe_bing" name="dns.safe_search_bing">
                                            <option value="1">Enabled</option>
                                            <option value="0">Disabled</option>
                                        </select>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                    <div class="panel-footer">
                        <button type="button" class="btn btn-primary" id="btn-dns-save">
                            <i class="fa fa-save"></i> Save DNS Settings
                        </button>
                    </div>
                </div>
            </form>

            <!-- Recent Blocked Queries -->
            <div class="panel panel-default">
                <div class="panel-heading"><strong><i class="fa fa-history"></i> Recent Blocked Queries</strong></div>
                <div class="panel-body" style="padding:0;">
                    <table class="table table-condensed table-hover" style="margin:0;">
                        <thead>
                            <tr>
                                <th>Timestamp</th>
                                <th>Device IP</th>
                                <th>Domain</th>
                                <th>Reason</th>
                            </tr>
                        </thead>
                        <tbody id="dns-blocked-tbody">
                            <tr><td colspan="4" class="text-center text-muted">No data</td></tr>
                        </tbody>
                    </table>
                </div>
            </div>

        </div>
    </div>


    <!-- ===================================================== -->
    <!-- TAB 7: TARGET LISTS                                   -->
    <!-- ===================================================== -->
    <div role="tabpanel" class="tab-pane" id="tab-targetlists">
        <div class="container-fluid" style="padding-top:10px;">
            <div class="row" style="margin-bottom:10px;">
                <div class="col-xs-12 col-sm-4">
                    <div class="well well-sm text-center">
                        <strong id="stat-targetlists-total">—</strong><br>
                        <small class="text-muted">Total Entries</small>
                    </div>
                </div>
                <div class="col-xs-12 col-sm-4">
                    <div class="well well-sm text-center">
                        <strong id="stat-targetlists-lists">—</strong><br>
                        <small class="text-muted">Active Lists</small>
                    </div>
                </div>
                <div class="col-xs-12 col-sm-4 text-right" style="padding-top:4px;">
                    <button id="btn-targetlists-sync" class="btn btn-sm btn-info">
                        <i class="fa fa-refresh"></i> Sync All
                    </button>
                    <button id="btn-targetlist-add" class="btn btn-sm btn-success" style="margin-left:5px;">
                        <i class="fa fa-plus"></i> Add List
                    </button>
                </div>
            </div>
            <table id="targetlists-grid" class="table table-condensed table-hover table-striped">
                <thead>
                    <tr>
                        <th data-column-id="name"            data-sortable="true">List Name</th>
                        <th data-column-id="type"            data-sortable="true" data-formatter="type">Type</th>
                        <th data-column-id="entry_count"     data-sortable="true">Entries</th>
                        <th data-column-id="source_url"      data-sortable="false">Source URL</th>
                        <th data-column-id="update_interval" data-sortable="true">Update Interval</th>
                        <th data-column-id="enabled"         data-sortable="true" data-formatter="status">Status</th>
                        <th data-column-id="commands"        data-formatter="commands" data-sortable="false">Actions</th>
                    </tr>
                </thead>
                <tbody></tbody>
            </table>
        </div>
    </div>


    <!-- ===================================================== -->
    <!-- TAB 8: GEOIP                                          -->
    <!-- ===================================================== -->
    <div role="tabpanel" class="tab-pane" id="tab-geoip">
        <div class="container-fluid" style="padding-top:15px;">

            <!-- Stats -->
            <div class="row" style="margin-bottom:15px;">
                <div class="col-xs-12 col-sm-4">
                    <div class="well well-sm text-center">
                        <strong id="stat-geoip-blocked-countries">—</strong><br>
                        <small class="text-muted">Blocked Countries</small>
                    </div>
                </div>
                <div class="col-xs-12 col-sm-4">
                    <div class="well well-sm text-center">
                        <strong id="stat-geoip-blocked-conns">—</strong><br>
                        <small class="text-muted">Blocked Connections</small>
                    </div>
                </div>
                <div class="col-xs-12 col-sm-4" style="padding-top:4px;">
                    <div class="input-group">
                        <span class="input-group-addon"><i class="fa fa-search"></i></span>
                        <input type="text" class="form-control" id="geoip-search" placeholder="Search countries…">
                    </div>
                </div>
            </div>

            <div class="panel panel-default">
                <div class="panel-heading">
                    <strong>Country Blocking</strong>
                    <span class="pull-right text-muted" style="font-size:12px;">
                        Check to block all traffic from that country
                    </span>
                </div>
                <div class="panel-body">
                    <div class="row" id="geoip-countries-list">
                        <div class="col-xs-12 text-center text-muted">
                            <i class="fa fa-spinner fa-spin"></i> Loading country list…
                        </div>
                    </div>
                </div>
            </div>

        </div>
    </div>


    <!-- ===================================================== -->
    <!-- TAB 9: ALERTS                                         -->
    <!-- ===================================================== -->
    <div role="tabpanel" class="tab-pane" id="tab-alerts">
        <div class="container-fluid" style="padding-top:10px;">

            <!-- Stats -->
            <div class="row" style="margin-bottom:10px;">
                <div class="col-xs-6 col-sm-3">
                    <div class="well well-sm text-center">
                        <strong class="text-warning" id="stat-alerts-vpn">—</strong><br>
                        <small class="text-muted">VPN</small>
                    </div>
                </div>
                <div class="col-xs-6 col-sm-3">
                    <div class="well well-sm text-center">
                        <strong class="text-danger" id="stat-alerts-adult">—</strong><br>
                        <small class="text-muted">Adult</small>
                    </div>
                </div>
                <div class="col-xs-6 col-sm-3">
                    <div class="well well-sm text-center">
                        <strong class="text-info" id="stat-alerts-dns">—</strong><br>
                        <small class="text-muted">DNS Bypass</small>
                    </div>
                </div>
                <div class="col-xs-6 col-sm-3">
                    <div class="well well-sm text-center">
                        <strong id="stat-alerts-other">—</strong><br>
                        <small class="text-muted">Other</small>
                    </div>
                </div>
            </div>

            <!-- Filter + Controls -->
            <div class="row" style="margin-bottom:8px;">
                <div class="col-xs-12 col-sm-6 col-md-4">
                    <div class="input-group input-group-sm">
                        <span class="input-group-addon">Type</span>
                        <select class="form-control" id="alert-filter-type">
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
                </div>
                <div class="col-xs-12 col-sm-6 col-md-8 text-right">
                    <button id="btn-flush-alerts" class="btn btn-sm btn-danger">
                        <i class="fa fa-trash-o"></i> Flush Old Alerts
                    </button>
                </div>
            </div>

            <table id="alerts-grid" class="table table-condensed table-hover table-striped">
                <thead>
                    <tr>
                        <th data-column-id="timestamp"  data-sortable="true"  data-formatter="timestamp">Timestamp</th>
                        <th data-column-id="device"     data-sortable="true"  data-formatter="device">Device</th>
                        <th data-column-id="type"       data-sortable="true"  data-formatter="type">Type</th>
                        <th data-column-id="detail"     data-sortable="false">Detail</th>
                        <th data-column-id="commands"   data-formatter="commands" data-sortable="false">Actions</th>
                    </tr>
                </thead>
                <tbody></tbody>
            </table>

        </div>
    </div>

    <!-- Alert Detail Dialog -->
    <div class="modal fade" id="dlg-alert-detail" tabindex="-1" role="dialog">
        <div class="modal-dialog modal-lg" role="document">
            <div class="modal-content">
                <div class="modal-header">
                    <button type="button" class="close" data-dismiss="modal"><span>&times;</span></button>
                    <h4 class="modal-title"><i class="fa fa-search"></i> Alert Detail</h4>
                </div>
                <div class="modal-body">
                    <table class="table table-condensed">
                        <tr><th style="width:130px;">Timestamp</th>  <td id="alert-detail-ts"></td></tr>
                        <tr><th>Device</th>    <td id="alert-detail-device"></td></tr>
                        <tr><th>Type</th>      <td id="alert-detail-type"></td></tr>
                        <tr><th>Detail</th>    <td id="alert-detail-detail"></td></tr>
                    </table>
                    <div class="panel panel-default" style="margin-top:10px;">
                        <div class="panel-heading"><strong>Raw Data</strong></div>
                        <div class="panel-body">
                            <pre id="alert-detail-raw" style="max-height:250px; overflow-y:auto;"></pre>
                        </div>
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-default" data-dismiss="modal">Close</button>
                </div>
            </div>
        </div>
    </div>


    <!-- ===================================================== -->
    <!-- TAB 10: SETTINGS                                      -->
    <!-- ===================================================== -->
    <div role="tabpanel" class="tab-pane" id="tab-settings">
        <div class="container-fluid" style="padding-top:15px;">
            <form id="frm_settings">

                <!-- General -->
                <div class="panel panel-default">
                    <div class="panel-heading"><strong><i class="fa fa-cogs"></i> General</strong></div>
                    <div class="panel-body">
                        <div class="row">
                            <div class="col-md-4">
                                <div class="form-group">
                                    <label>Enable NetShield</label>
                                    <select class="form-control" id="cfg_enabled" name="general.enabled">
                                        <option value="1">Enabled</option>
                                        <option value="0">Disabled</option>
                                    </select>
                                </div>
                            </div>
                            <div class="col-md-4">
                                <div class="form-group">
                                    <label>Log Level</label>
                                    <select class="form-control" id="cfg_loglevel" name="general.log_level">
                                        <option value="error">Error</option>
                                        <option value="warning">Warning</option>
                                        <option value="info">Info</option>
                                        <option value="debug">Debug</option>
                                    </select>
                                </div>
                            </div>
                            <div class="col-md-4">
                                <div class="form-group">
                                    <label>Check Interval (seconds)</label>
                                    <input type="number" class="form-control" id="cfg_interval" name="general.check_interval" min="10" max="3600">
                                </div>
                            </div>
                        </div>
                        <div class="row">
                            <div class="col-md-4">
                                <div class="form-group">
                                    <label>Alert Cooldown (seconds)</label>
                                    <input type="number" class="form-control" id="cfg_cooldown" name="general.alert_cooldown" min="0" max="86400">
                                    <span class="help-block">Minimum time between identical alerts per device</span>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Detection -->
                <div class="panel panel-default">
                    <div class="panel-heading"><strong><i class="fa fa-eye"></i> Detection</strong></div>
                    <div class="panel-body">
                        <div class="row">
                            <div class="col-md-4">
                                <div class="form-group">
                                    <label>Enable DPI (Deep Packet Inspection)</label>
                                    <select class="form-control" name="detection.enable_dpi">
                                        <option value="1">Enabled</option>
                                        <option value="0">Disabled</option>
                                    </select>
                                    <span class="help-block">Requires Suricata</span>
                                </div>
                            </div>
                            <div class="col-md-4">
                                <div class="form-group">
                                    <label>VPN Detection</label>
                                    <select class="form-control" name="detection.vpn_detection">
                                        <option value="1">Enabled</option>
                                        <option value="0">Disabled</option>
                                    </select>
                                </div>
                            </div>
                            <div class="col-md-4">
                                <div class="form-group">
                                    <label>Device Tracking</label>
                                    <select class="form-control" name="detection.device_tracking">
                                        <option value="1">Enabled</option>
                                        <option value="0">Disabled</option>
                                    </select>
                                </div>
                            </div>
                        </div>
                        <div class="row">
                            <div class="col-md-4">
                                <div class="form-group">
                                    <label>Suricata Integration</label>
                                    <select class="form-control" name="detection.suricata_integration">
                                        <option value="1">Enabled</option>
                                        <option value="0">Disabled</option>
                                    </select>
                                </div>
                            </div>
                            <div class="col-md-4">
                                <div class="form-group">
                                    <label>SNI-based App Detection</label>
                                    <select class="form-control" name="detection.sni_detection">
                                        <option value="1">Enabled</option>
                                        <option value="0">Disabled</option>
                                    </select>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Enforcement -->
                <div class="panel panel-default">
                    <div class="panel-heading"><strong><i class="fa fa-lock"></i> Enforcement</strong></div>
                    <div class="panel-body">
                        <div class="row">
                            <div class="col-md-4">
                                <div class="form-group">
                                    <label>Force DNS Through Router</label>
                                    <select class="form-control" name="enforcement.force_dns">
                                        <option value="1">Enabled</option>
                                        <option value="0">Disabled</option>
                                    </select>
                                </div>
                            </div>
                            <div class="col-md-4">
                                <div class="form-group">
                                    <label>Block Common VPN Ports</label>
                                    <select class="form-control" name="enforcement.block_vpn_ports">
                                        <option value="1">Enabled</option>
                                        <option value="0">Disabled</option>
                                    </select>
                                    <span class="help-block">Blocks 1194/UDP, 1723/TCP, 4500/UDP</span>
                                </div>
                            </div>
                            <div class="col-md-4">
                                <div class="form-group">
                                    <label>Block Proxy Ports</label>
                                    <select class="form-control" name="enforcement.block_proxy_ports">
                                        <option value="1">Enabled</option>
                                        <option value="0">Disabled</option>
                                    </select>
                                    <span class="help-block">Blocks 3128, 8080, 8888</span>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Alerts / Notifications -->
                <div class="panel panel-default">
                    <div class="panel-heading"><strong><i class="fa fa-bell-o"></i> Alerts &amp; Notifications</strong></div>
                    <div class="panel-body">
                        <div class="row">
                            <div class="col-md-12">
                                <h5>Syslog</h5>
                            </div>
                            <div class="col-md-4">
                                <div class="form-group">
                                    <label>Syslog Host</label>
                                    <input type="text" class="form-control" name="alerts.syslog_host" placeholder="e.g. 192.168.1.100">
                                </div>
                            </div>
                            <div class="col-md-2">
                                <div class="form-group">
                                    <label>Port</label>
                                    <input type="number" class="form-control" name="alerts.syslog_port" placeholder="514" min="1" max="65535">
                                </div>
                            </div>
                            <div class="col-md-2">
                                <div class="form-group">
                                    <label>Protocol</label>
                                    <select class="form-control" name="alerts.syslog_protocol">
                                        <option value="udp">UDP</option>
                                        <option value="tcp">TCP</option>
                                    </select>
                                </div>
                            </div>
                        </div>
                        <div class="row">
                            <div class="col-md-12">
                                <h5>Webhook</h5>
                            </div>
                            <div class="col-md-8">
                                <div class="form-group">
                                    <label>Webhook URL</label>
                                    <input type="url" class="form-control" name="alerts.webhook_url" placeholder="https://hooks.example.com/…">
                                </div>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- GeoIP -->
                <div class="panel panel-default">
                    <div class="panel-heading"><strong><i class="fa fa-map-o"></i> GeoIP</strong></div>
                    <div class="panel-body">
                        <div class="row">
                            <div class="col-md-4">
                                <div class="form-group">
                                    <label>Enable GeoIP Blocking</label>
                                    <select class="form-control" name="geoip.enabled">
                                        <option value="1">Enabled</option>
                                        <option value="0">Disabled</option>
                                    </select>
                                </div>
                            </div>
                            <div class="col-md-4">
                                <div class="form-group">
                                    <label>GeoIP Database Path</label>
                                    <input type="text" class="form-control" name="geoip.db_path" placeholder="/var/db/netshield/GeoLite2-Country.mmdb">
                                </div>
                            </div>
                        </div>
                    </div>
                </div>

            </form>

            <div style="margin-bottom:20px;">
                <button type="button" class="btn btn-default" id="btn-settings-save">
                    <i class="fa fa-save"></i> Save
                </button>
                <button type="button" class="btn btn-primary" id="btn-settings-apply" style="margin-left:8px;">
                    <i class="fa fa-check"></i> Save &amp; Apply
                </button>
            </div>

        </div>
    </div><!-- /tab-settings -->

</div><!-- /tab-content -->
