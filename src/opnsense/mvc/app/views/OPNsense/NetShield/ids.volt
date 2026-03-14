{#
# Copyright (C) 2025-2026 NetShield
# All rights reserved.
#
# IDS/IPS Management - Zenarmor Style
#}

<style>
.ns-ids-header {
    display: flex;
    align-items: center;
    gap: 20px;
    padding: 20px;
    background: linear-gradient(135deg, #1e3a5f 0%, #2d5a87 100%);
    border-radius: 12px;
    color: #fff;
    margin-bottom: 20px;
}
.ns-ids-header .status-badge {
    padding: 8px 16px;
    border-radius: 20px;
    font-weight: 600;
    font-size: 14px;
}
.ns-ids-header .status-badge.active {
    background: rgba(74, 222, 128, 0.2);
    color: #4ade80;
    border: 1px solid #4ade80;
}
.ns-ids-header .status-badge.inactive {
    background: rgba(239, 68, 68, 0.2);
    color: #ef4444;
    border: 1px solid #ef4444;
}

.ns-ids-stats {
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 20px;
    margin-bottom: 20px;
}
.ns-ids-stat {
    background: #fff;
    border-radius: 12px;
    padding: 20px;
    text-align: center;
    box-shadow: 0 2px 8px rgba(0,0,0,0.08);
}
.ns-ids-stat .value {
    font-size: 32px;
    font-weight: 700;
    color: #111827;
}
.ns-ids-stat .label {
    color: #6b7280;
    font-size: 13px;
    margin-top: 4px;
}
.ns-ids-stat.danger .value { color: #dc2626; }
.ns-ids-stat.warning .value { color: #f59e0b; }
.ns-ids-stat.success .value { color: #16a34a; }

.ns-category-grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
    gap: 16px;
}
.ns-category-card {
    background: #fff;
    border-radius: 10px;
    padding: 16px;
    border: 1px solid #e5e7eb;
    display: flex;
    align-items: center;
    justify-content: space-between;
}
.ns-category-card .info {
    display: flex;
    align-items: center;
    gap: 12px;
}
.ns-category-card .icon {
    width: 40px; height: 40px;
    border-radius: 8px;
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 18px;
}
.ns-category-card .icon.exploit { background: #fee2e2; color: #dc2626; }
.ns-category-card .icon.malware { background: #fef3c7; color: #d97706; }
.ns-category-card .icon.dos { background: #dbeafe; color: #2563eb; }
.ns-category-card .icon.scan { background: #f3e8ff; color: #9333ea; }
.ns-category-card .icon.misc { background: #f3f4f6; color: #6b7280; }
.ns-category-card .name { font-weight: 600; color: #111827; }
.ns-category-card .count { font-size: 12px; color: #6b7280; }

.ns-alert-severity {
    display: inline-flex;
    align-items: center;
    gap: 4px;
    padding: 4px 10px;
    border-radius: 12px;
    font-size: 12px;
    font-weight: 600;
}
.ns-alert-severity.critical { background: #fee2e2; color: #dc2626; }
.ns-alert-severity.high { background: #ffedd5; color: #ea580c; }
.ns-alert-severity.medium { background: #fef3c7; color: #d97706; }
.ns-alert-severity.low { background: #dbeafe; color: #2563eb; }
.ns-alert-severity.info { background: #f3f4f6; color: #6b7280; }

.ns-signature-row {
    display: flex;
    align-items: center;
    padding: 12px;
    border-bottom: 1px solid #f3f4f6;
}
.ns-signature-row:hover {
    background: #f9fafb;
}
.ns-signature-row .sid {
    font-family: monospace;
    color: #6b7280;
    width: 100px;
}
.ns-signature-row .msg {
    flex: 1;
    font-weight: 500;
}
.ns-signature-row .actions {
    display: flex;
    gap: 8px;
}

.ns-panel {
    background: #fff;
    border-radius: 12px;
    box-shadow: 0 2px 8px rgba(0,0,0,0.08);
    margin-bottom: 20px;
}
.ns-panel-header {
    padding: 16px 20px;
    border-bottom: 1px solid #e5e7eb;
    display: flex;
    align-items: center;
    justify-content: space-between;
}
.ns-panel-header h3 {
    margin: 0;
    font-size: 16px;
    font-weight: 600;
}
.ns-panel-body {
    padding: 20px;
}

@media (max-width: 768px) {
    .ns-ids-stats { grid-template-columns: repeat(2, 1fr); }
}
</style>

<script>
$(document).ready(function() {

    /* Native HTML escape (no lodash dependency) */
    function _escape(s) {
        if (s == null) return '';
        var div = document.createElement('div');
        div.appendChild(document.createTextNode(String(s)));
        return div.innerHTML;
    }

    function loadIdsStatus() {
        $.getJSON('/api/netshield/ids/status', function(data) {
            if (!data || !data.status) return;

            var running = data.status.running;
            $('#ids-status-badge')
                .removeClass('active inactive')
                .addClass(running ? 'active' : 'inactive')
                .text(running ? '{{ lang._("ACTIVE") }}' : '{{ lang._("INACTIVE") }}');

            $('#ids-mode').text(data.status.mode || 'IDS');
            $('#ids-version').text(data.status.suricata_version || '-');

            $('#stat-signatures').text((data.status.signatures_loaded || 0).toLocaleString());
            $('#stat-alerts-today').text(data.status.alerts_today || 0);
            $('#stat-blocked-today').text(data.status.blocked_today || 0);
            $('#stat-packets').text(formatNumber(data.status.packets_analyzed || 0));
        });
    }

    function loadAlertStats() {
        $.getJSON('/api/netshield/ids/alertStats', function(data) {
            if (!data) return;

            // By severity
            $('#severity-critical').text(data.by_severity?.critical || 0);
            $('#severity-high').text(data.by_severity?.high || 0);
            $('#severity-medium').text(data.by_severity?.medium || 0);
            $('#severity-low').text(data.by_severity?.low || 0);
        });
    }

    function loadCategories() {
        $.getJSON('/api/netshield/ids/categories', function(data) {
            var $grid = $('#categories-grid').empty();
            var categories = data.categories || [];

            if (!categories.length) {
                $grid.html('<div class="text-muted">{{ lang._("No categories available") }}</div>');
                return;
            }

            categories.forEach(function(cat) {
                var iconClass = getCategoryIcon(cat.name);
                $grid.append(
                    '<div class="ns-category-card">' +
                        '<div class="info">' +
                            '<div class="icon ' + iconClass + '"><i class="fa ' + getCategoryFa(cat.name) + '"></i></div>' +
                            '<div>' +
                                '<div class="name">' + _escape(cat.name) + '</div>' +
                                '<div class="count">' + (cat.signatures || 0) + ' {{ lang._("signatures") }}</div>' +
                            '</div>' +
                        '</div>' +
                        '<div class="form-check form-switch">' +
                            '<input type="checkbox" class="category-toggle" data-category="' + _escape(cat.name) + '" ' +
                                (cat.enabled ? 'checked' : '') + '>' +
                        '</div>' +
                    '</div>'
                );
            });

            $('.category-toggle').change(function() {
                var cat = $(this).data('category');
                var enabled = $(this).prop('checked');
                ajaxCall('/api/netshield/ids/' + (enabled ? 'enableCategory' : 'disableCategory'),
                    {category: cat}, function() {
                        loadIdsStatus();
                    });
            });
        });
    }

    function loadRecentAlerts() {
        $.getJSON('/api/netshield/ids/alerts?limit=20', function(data) {
            var $tbody = $('#alerts-tbody').empty();
            var alerts = data.alerts || [];

            if (!alerts.length) {
                $tbody.html('<tr><td colspan="6" class="text-center text-muted">{{ lang._("No recent alerts") }}</td></tr>');
                return;
            }

            alerts.forEach(function(alert) {
                $tbody.append(
                    '<tr>' +
                        '<td>' + _escape(alert.timestamp || '') + '</td>' +
                        '<td><span class="ns-alert-severity ' + (alert.severity || 'info') + '">' +
                            _escape(alert.severity || 'info') + '</span></td>' +
                        '<td>' + _escape(alert.signature || alert.msg || '') + '</td>' +
                        '<td><code>' + _escape(alert.src_ip || '') + '</code></td>' +
                        '<td><code>' + _escape(alert.dest_ip || '') + '</code></td>' +
                        '<td>' +
                            '<button class="btn btn-xs btn-default btn-block-ip" data-ip="' + (alert.src_ip || '') + '">' +
                                '<i class="fa fa-ban"></i>' +
                            '</button>' +
                        '</td>' +
                    '</tr>'
                );
            });

            $('.btn-block-ip').click(function() {
                var ip = $(this).data('ip');
                if (!ip) return;
                BootstrapDialog.confirm({
                    title: '{{ lang._("Block IP") }}',
                    message: '{{ lang._("Block all traffic from") }} ' + ip + '?',
                    type: BootstrapDialog.TYPE_DANGER,
                    callback: function(r) {
                        if (r) {
                            ajaxCall('/api/netshield/policies/blockIp', {ip: ip}, function() {
                                loadRecentAlerts();
                            });
                        }
                    }
                });
            });
        });
    }

    function loadTopSignatures() {
        $.getJSON('/api/netshield/ids/topSignatures', function(data) {
            var $list = $('#top-signatures').empty();
            var sigs = data.signatures || [];

            if (!sigs.length) {
                $list.html('<div class="text-muted">{{ lang._("No data") }}</div>');
                return;
            }

            sigs.slice(0, 10).forEach(function(sig) {
                $list.append(
                    '<div class="ns-signature-row">' +
                        '<div class="sid">' + (sig.sid || '-') + '</div>' +
                        '<div class="msg">' + _escape(sig.msg || sig.signature || '') + '</div>' +
                        '<div class="count"><span class="label label-danger">' + (sig.count || 0) + '</span></div>' +
                    '</div>'
                );
            });
        });
    }

    function loadTopAttackers() {
        $.getJSON('/api/netshield/ids/topAttackers', function(data) {
            var $list = $('#top-attackers').empty();
            var attackers = data.attackers || [];

            if (!attackers.length) {
                $list.html('<div class="text-muted">{{ lang._("No data") }}</div>');
                return;
            }

            attackers.slice(0, 10).forEach(function(att) {
                $list.append(
                    '<div class="ns-signature-row">' +
                        '<div style="flex:1;"><code>' + _escape(att.ip || att.src_ip || '') + '</code></div>' +
                        '<div style="width:80px; text-align:center;">' +
                            '<span class="label label-danger">' + (att.count || att.alerts || 0) + '</span>' +
                        '</div>' +
                        '<div style="width:80px;">' +
                            '<button class="btn btn-xs btn-danger btn-block-attacker" data-ip="' + (att.ip || att.src_ip || '') + '">' +
                                '{{ lang._("Block") }}' +
                            '</button>' +
                        '</div>' +
                    '</div>'
                );
            });

            $('.btn-block-attacker').click(function() {
                var ip = $(this).data('ip');
                ajaxCall('/api/netshield/policies/blockIp', {ip: ip}, function() {
                    loadTopAttackers();
                });
            });
        });
    }

    function getCategoryIcon(name) {
        if (/exploit|attack|overflow/i.test(name)) return 'exploit';
        if (/malware|trojan|virus|worm/i.test(name)) return 'malware';
        if (/dos|ddos|flood/i.test(name)) return 'dos';
        if (/scan|recon|probe/i.test(name)) return 'scan';
        return 'misc';
    }

    function getCategoryFa(name) {
        if (/exploit|attack/i.test(name)) return 'fa-crosshairs';
        if (/malware|trojan/i.test(name)) return 'fa-bug';
        if (/dos|ddos/i.test(name)) return 'fa-bomb';
        if (/scan|recon/i.test(name)) return 'fa-search';
        return 'fa-shield';
    }

    function formatNumber(n) {
        if (n >= 1000000000) return (n/1000000000).toFixed(1) + 'B';
        if (n >= 1000000) return (n/1000000).toFixed(1) + 'M';
        if (n >= 1000) return (n/1000).toFixed(1) + 'K';
        return n.toString();
    }

    // Service controls
    $('#btn-ids-start').click(function() {
        ajaxCall('/api/netshield/ids/start', {}, function() {
            setTimeout(loadIdsStatus, 2000);
        });
    });

    $('#btn-ids-stop').click(function() {
        BootstrapDialog.confirm({
            title: '{{ lang._("Stop IDS") }}',
            message: '{{ lang._("Stop the intrusion detection system? Network monitoring will be disabled.") }}',
            type: BootstrapDialog.TYPE_WARNING,
            callback: function(r) {
                if (r) {
                    ajaxCall('/api/netshield/ids/stop', {}, function() {
                        setTimeout(loadIdsStatus, 2000);
                    });
                }
            }
        });
    });

    $('#btn-reload-rules').click(function() {
        var $btn = $(this);
        $btn.prop('disabled', true).html('<i class="fa fa-spinner fa-spin"></i> {{ lang._("Reloading...") }}');
        ajaxCall('/api/netshield/ids/reloadRules', {}, function() {
            setTimeout(function() {
                loadIdsStatus();
                $btn.prop('disabled', false).html('<i class="fa fa-refresh"></i> {{ lang._("Reload Rules") }}');
            }, 3000);
        });
    });

    // Initialize
    loadIdsStatus();
    loadAlertStats();
    loadCategories();
    loadRecentAlerts();
    loadTopSignatures();
    loadTopAttackers();

    // Auto-refresh
    setInterval(function() {
        loadIdsStatus();
        loadAlertStats();
        loadRecentAlerts();
    }, 30000);
});
</script>

<!-- Header -->
<div class="ns-ids-header">
    <div>
        <h2 style="margin: 0; font-weight: 600;"><i class="fa fa-shield"></i> {{ lang._('Intrusion Detection System') }}</h2>
        <div style="margin-top: 4px; opacity: 0.8;">
            {{ lang._('Mode') }}: <strong id="ids-mode">-</strong> |
            {{ lang._('Suricata') }} <span id="ids-version">-</span>
        </div>
    </div>
    <span class="status-badge inactive" id="ids-status-badge">{{ lang._('CHECKING') }}</span>
    <div class="btn-group" style="margin-left: auto;">
        <button id="btn-ids-start" class="btn btn-success"><i class="fa fa-play"></i> {{ lang._('Start') }}</button>
        <button id="btn-ids-stop" class="btn btn-danger"><i class="fa fa-stop"></i> {{ lang._('Stop') }}</button>
        <button id="btn-reload-rules" class="btn btn-default"><i class="fa fa-refresh"></i> {{ lang._('Reload Rules') }}</button>
    </div>
</div>

<!-- Stats -->
<div class="ns-ids-stats">
    <div class="ns-ids-stat">
        <div class="value" id="stat-signatures">0</div>
        <div class="label">{{ lang._('Signatures Loaded') }}</div>
    </div>
    <div class="ns-ids-stat danger">
        <div class="value" id="stat-alerts-today">0</div>
        <div class="label">{{ lang._('Alerts Today') }}</div>
    </div>
    <div class="ns-ids-stat warning">
        <div class="value" id="stat-blocked-today">0</div>
        <div class="label">{{ lang._('Blocked Today') }}</div>
    </div>
    <div class="ns-ids-stat success">
        <div class="value" id="stat-packets">0</div>
        <div class="label">{{ lang._('Packets Analyzed') }}</div>
    </div>
</div>

<!-- Severity Breakdown -->
<div class="ns-panel">
    <div class="ns-panel-header">
        <h3><i class="fa fa-bar-chart"></i> {{ lang._('Alert Severity Breakdown') }}</h3>
    </div>
    <div class="ns-panel-body">
        <div class="row">
            <div class="col-sm-3 text-center">
                <span class="ns-alert-severity critical" style="font-size: 24px;" id="severity-critical">0</span>
                <div class="text-muted" style="margin-top: 4px;">{{ lang._('Critical') }}</div>
            </div>
            <div class="col-sm-3 text-center">
                <span class="ns-alert-severity high" style="font-size: 24px;" id="severity-high">0</span>
                <div class="text-muted" style="margin-top: 4px;">{{ lang._('High') }}</div>
            </div>
            <div class="col-sm-3 text-center">
                <span class="ns-alert-severity medium" style="font-size: 24px;" id="severity-medium">0</span>
                <div class="text-muted" style="margin-top: 4px;">{{ lang._('Medium') }}</div>
            </div>
            <div class="col-sm-3 text-center">
                <span class="ns-alert-severity low" style="font-size: 24px;" id="severity-low">0</span>
                <div class="text-muted" style="margin-top: 4px;">{{ lang._('Low') }}</div>
            </div>
        </div>
    </div>
</div>

<!-- Tabs -->
<ul class="nav nav-tabs" style="margin-bottom: 20px;">
    <li class="active"><a data-toggle="tab" href="#tab-alerts">{{ lang._('Recent Alerts') }}</a></li>
    <li><a data-toggle="tab" href="#tab-categories">{{ lang._('Categories') }}</a></li>
    <li><a data-toggle="tab" href="#tab-top">{{ lang._('Top Threats') }}</a></li>
</ul>

<div class="tab-content">
    <!-- Recent Alerts Tab -->
    <div id="tab-alerts" class="tab-pane fade in active">
        <div class="ns-panel">
            <div class="ns-panel-body" style="padding: 0;">
                <table class="table table-hover" style="margin: 0;">
                    <thead>
                        <tr>
                            <th>{{ lang._('Time') }}</th>
                            <th>{{ lang._('Severity') }}</th>
                            <th>{{ lang._('Signature') }}</th>
                            <th>{{ lang._('Source') }}</th>
                            <th>{{ lang._('Destination') }}</th>
                            <th>{{ lang._('Actions') }}</th>
                        </tr>
                    </thead>
                    <tbody id="alerts-tbody">
                        <tr><td colspan="6" class="text-center text-muted">{{ lang._('Loading...') }}</td></tr>
                    </tbody>
                </table>
            </div>
        </div>
    </div>

    <!-- Categories Tab -->
    <div id="tab-categories" class="tab-pane fade">
        <div class="ns-category-grid" id="categories-grid">
            <div class="text-muted">{{ lang._('Loading categories...') }}</div>
        </div>
    </div>

    <!-- Top Threats Tab -->
    <div id="tab-top" class="tab-pane fade">
        <div class="row">
            <div class="col-md-6">
                <div class="ns-panel">
                    <div class="ns-panel-header">
                        <h3><i class="fa fa-list"></i> {{ lang._('Top Triggered Signatures') }}</h3>
                    </div>
                    <div class="ns-panel-body" style="padding: 0;" id="top-signatures">
                        <div class="text-muted p-4">{{ lang._('Loading...') }}</div>
                    </div>
                </div>
            </div>
            <div class="col-md-6">
                <div class="ns-panel">
                    <div class="ns-panel-header">
                        <h3><i class="fa fa-user-secret"></i> {{ lang._('Top Attackers') }}</h3>
                    </div>
                    <div class="ns-panel-body" style="padding: 0;" id="top-attackers">
                        <div class="text-muted p-4">{{ lang._('Loading...') }}</div>
                    </div>
                </div>
            </div>
        </div>
    </div>
</div>
