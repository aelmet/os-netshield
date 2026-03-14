{#
# Copyright (C) 2025-2026 NetShield
# All rights reserved.
#
# Security Alerts Dashboard - Zenarmor Style
#}

<style>
.ns-alerts-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 20px;
    background: linear-gradient(135deg, #dc2626 0%, #b91c1c 100%);
    border-radius: 12px;
    color: #fff;
    margin-bottom: 20px;
}
.ns-alerts-header h2 {
    margin: 0;
    font-size: 24px;
    display: flex;
    align-items: center;
    gap: 12px;
}
.ns-alerts-header .alert-count {
    background: rgba(255,255,255,0.2);
    padding: 8px 16px;
    border-radius: 20px;
    font-size: 14px;
}

.ns-alerts-stats {
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 20px;
    margin-bottom: 20px;
}
.ns-alerts-stat {
    background: #fff;
    border-radius: 12px;
    padding: 20px;
    text-align: center;
    box-shadow: 0 2px 8px rgba(0,0,0,0.08);
}
.ns-alerts-stat .value {
    font-size: 32px;
    font-weight: 700;
    color: #111827;
}
.ns-alerts-stat .label {
    color: #6b7280;
    font-size: 13px;
    margin-top: 4px;
}
.ns-alerts-stat.critical .value { color: #dc2626; }
.ns-alerts-stat.high .value { color: #ea580c; }
.ns-alerts-stat.medium .value { color: #f59e0b; }
.ns-alerts-stat.low .value { color: #16a34a; }

.ns-filter-bar {
    display: flex;
    gap: 12px;
    margin-bottom: 20px;
    flex-wrap: wrap;
}
.ns-filter-bar select, .ns-filter-bar input {
    padding: 10px 14px;
    border: 1px solid #e5e7eb;
    border-radius: 8px;
    font-size: 14px;
    background: #fff;
}
.ns-filter-bar .btn-refresh {
    padding: 10px 20px;
    background: #3b82f6;
    color: #fff;
    border: none;
    border-radius: 8px;
    cursor: pointer;
    font-weight: 500;
}
.ns-filter-bar .btn-refresh:hover { background: #2563eb; }

.ns-alerts-table {
    background: #fff;
    border-radius: 12px;
    overflow: hidden;
    box-shadow: 0 2px 8px rgba(0,0,0,0.08);
}
.ns-alerts-table table {
    width: 100%;
    border-collapse: collapse;
}
.ns-alerts-table th {
    background: #f9fafb;
    padding: 14px 16px;
    text-align: left;
    font-weight: 600;
    color: #374151;
    border-bottom: 1px solid #e5e7eb;
}
.ns-alerts-table td {
    padding: 14px 16px;
    border-bottom: 1px solid #f3f4f6;
    color: #374151;
}
.ns-alerts-table tr:hover { background: #f9fafb; }

.severity-badge {
    padding: 4px 10px;
    border-radius: 12px;
    font-size: 12px;
    font-weight: 600;
    text-transform: uppercase;
}
.severity-badge.critical { background: #fee2e2; color: #dc2626; }
.severity-badge.high { background: #ffedd5; color: #ea580c; }
.severity-badge.medium { background: #fef3c7; color: #d97706; }
.severity-badge.low { background: #dcfce7; color: #16a34a; }
.severity-badge.info { background: #dbeafe; color: #2563eb; }

.alert-type-icon {
    width: 32px;
    height: 32px;
    border-radius: 6px;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    margin-right: 10px;
}
.alert-type-icon.ids { background: #fee2e2; color: #dc2626; }
.alert-type-icon.dns { background: #dbeafe; color: #2563eb; }
.alert-type-icon.threat { background: #fef3c7; color: #d97706; }
.alert-type-icon.policy { background: #f3e8ff; color: #9333ea; }
.alert-type-icon.geo { background: #d1fae5; color: #059669; }

.ns-empty-state {
    text-align: center;
    padding: 60px 20px;
    color: #6b7280;
}
.ns-empty-state i { font-size: 48px; margin-bottom: 16px; color: #d1d5db; }
</style>

<div class="ns-alerts-header">
    <h2><i class="fa fa-bell"></i> Security Alerts</h2>
    <div class="alert-count" id="totalAlertCount">Loading...</div>
</div>

<div class="ns-alerts-stats">
    <div class="ns-alerts-stat critical">
        <div class="value" id="criticalCount">0</div>
        <div class="label">Critical</div>
    </div>
    <div class="ns-alerts-stat high">
        <div class="value" id="highCount">0</div>
        <div class="label">High</div>
    </div>
    <div class="ns-alerts-stat medium">
        <div class="value" id="mediumCount">0</div>
        <div class="label">Medium</div>
    </div>
    <div class="ns-alerts-stat low">
        <div class="value" id="lowCount">0</div>
        <div class="label">Low / Info</div>
    </div>
</div>

<div class="ns-filter-bar">
    <select id="severityFilter">
        <option value="">All Severities</option>
        <option value="critical">Critical</option>
        <option value="high">High</option>
        <option value="medium">Medium</option>
        <option value="low">Low</option>
        <option value="info">Info</option>
    </select>
    <select id="typeFilter">
        <option value="">All Types</option>
        <option value="ids">IDS/IPS</option>
        <option value="dns">DNS Block</option>
        <option value="threat">Threat Intel</option>
        <option value="policy">Policy Violation</option>
        <option value="geo">GeoIP Block</option>
    </select>
    <select id="timeFilter">
        <option value="1h">Last Hour</option>
        <option value="24h" selected>Last 24 Hours</option>
        <option value="7d">Last 7 Days</option>
        <option value="30d">Last 30 Days</option>
    </select>
    <input type="text" id="searchFilter" placeholder="Search alerts...">
    <button class="btn-refresh" onclick="loadAlerts()"><i class="fa fa-refresh"></i> Refresh</button>
</div>

<div class="ns-alerts-table">
    <table>
        <thead>
            <tr>
                <th>Type</th>
                <th>Severity</th>
                <th>Source</th>
                <th>Destination</th>
                <th>Description</th>
                <th>Time</th>
                <th>Actions</th>
            </tr>
        </thead>
        <tbody id="alertsTableBody">
            <tr>
                <td colspan="7" class="ns-empty-state">
                    <i class="fa fa-spinner fa-spin"></i>
                    <p>Loading alerts...</p>
                </td>
            </tr>
        </tbody>
    </table>
</div>

<script>
$(document).ready(function() {
    loadAlerts();

    // Auto-refresh every 30 seconds
    setInterval(loadAlerts, 30000);

    // Filter handlers
    $('#severityFilter, #typeFilter, #timeFilter').change(loadAlerts);
    $('#searchFilter').on('input', debounce(loadAlerts, 300));
});

function debounce(func, wait) {
    let timeout;
    return function(...args) {
        clearTimeout(timeout);
        timeout = setTimeout(() => func.apply(this, args), wait);
    };
}

function loadAlerts() {
    const params = {
        severity: $('#severityFilter').val(),
        type: $('#typeFilter').val(),
        time: $('#timeFilter').val(),
        search: $('#searchFilter').val()
    };

    $.ajax({
        url: '/api/netshield/alerts/list',
        data: params,
        success: function(data) {
            if (data && data.alerts) {
                renderAlerts(data.alerts);
                updateStats(data.stats || {});
                $('#totalAlertCount').text(data.alerts.length + ' alerts');
            } else {
                showEmptyState('No alerts found');
            }
        },
        error: function() {
            showEmptyState('Failed to load alerts');
        }
    });
}

function renderAlerts(alerts) {
    const tbody = $('#alertsTableBody');

    if (!alerts || alerts.length === 0) {
        showEmptyState('No alerts in the selected time period');
        return;
    }

    let html = '';
    alerts.forEach(function(alert) {
        const typeIcon = getTypeIcon(alert.type);
        const severityClass = (alert.severity || 'info').toLowerCase();

        html += `
            <tr>
                <td>
                    <span class="alert-type-icon ${alert.type}">${typeIcon}</span>
                    ${formatType(alert.type)}
                </td>
                <td><span class="severity-badge ${severityClass}">${alert.severity || 'Info'}</span></td>
                <td>${alert.src_ip || '-'}</td>
                <td>${alert.dst_ip || '-'}</td>
                <td>${escapeHtml(alert.description || alert.message || '-')}</td>
                <td>${formatTime(alert.timestamp)}</td>
                <td>
                    <button class="btn btn-xs btn-default" onclick="viewAlert('${alert.id}')" title="View Details">
                        <i class="fa fa-eye"></i>
                    </button>
                    <button class="btn btn-xs btn-default" onclick="dismissAlert('${alert.id}')" title="Dismiss">
                        <i class="fa fa-check"></i>
                    </button>
                </td>
            </tr>
        `;
    });

    tbody.html(html);
}

function updateStats(stats) {
    $('#criticalCount').text(stats.critical || 0);
    $('#highCount').text(stats.high || 0);
    $('#mediumCount').text(stats.medium || 0);
    $('#lowCount').text((stats.low || 0) + (stats.info || 0));
}

function getTypeIcon(type) {
    const icons = {
        'ids': '<i class="fa fa-shield"></i>',
        'dns': '<i class="fa fa-globe"></i>',
        'threat': '<i class="fa fa-bug"></i>',
        'policy': '<i class="fa fa-gavel"></i>',
        'geo': '<i class="fa fa-map-marker"></i>'
    };
    return icons[type] || '<i class="fa fa-exclamation-triangle"></i>';
}

function formatType(type) {
    const names = {
        'ids': 'IDS/IPS',
        'dns': 'DNS Block',
        'threat': 'Threat Intel',
        'policy': 'Policy',
        'geo': 'GeoIP'
    };
    return names[type] || type || 'Unknown';
}

function formatTime(timestamp) {
    if (!timestamp) return '-';
    const date = new Date(timestamp * 1000);
    return date.toLocaleString();
}

function escapeHtml(text) {
    if (!text) return '';
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

function showEmptyState(message) {
    $('#alertsTableBody').html(`
        <tr>
            <td colspan="7" class="ns-empty-state">
                <i class="fa fa-check-circle"></i>
                <p>${message}</p>
            </td>
        </tr>
    `);
}

function viewAlert(id) {
    // TODO: Show alert details modal
    console.log('View alert:', id);
}

function dismissAlert(id) {
    if (!confirm('Dismiss this alert?')) return;

    $.ajax({
        url: '/api/netshield/alerts/dismiss',
        method: 'POST',
        data: { id: id },
        success: function() { loadAlerts(); },
        error: function() { alert('Failed to dismiss alert'); }
    });
}
</script>
