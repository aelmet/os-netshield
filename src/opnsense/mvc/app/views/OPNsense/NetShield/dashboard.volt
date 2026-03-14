{#
# Copyright (C) 2025-2026 NetShield
# All rights reserved.
#
# Enhanced Dashboard - Firewalla/Zenarmor Style
#}

<style>
/* === NetShield Enhanced Dashboard CSS === */

/* Service Status Bar */
.ns-status-bar {
    display: flex;
    align-items: center;
    gap: 20px;
    padding: 12px 20px;
    border-radius: 8px;
    margin-bottom: 20px;
    background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
    color: #fff;
    box-shadow: 0 4px 15px rgba(0,0,0,0.2);
}
.ns-status-bar.ns-running {
    background: linear-gradient(135deg, #134e5e 0%, #71b280 100%);
}
.ns-status-bar.ns-stopped {
    background: linear-gradient(135deg, #c31432 0%, #240b36 100%);
}
.ns-status-dot {
    width: 12px; height: 12px;
    border-radius: 50%;
    background: #aaa;
    animation: pulse 2s infinite;
}
.ns-running .ns-status-dot { background: #4ade80; }
.ns-stopped .ns-status-dot { background: #ef4444; }
@keyframes pulse {
    0%, 100% { opacity: 1; transform: scale(1); }
    50% { opacity: 0.7; transform: scale(1.1); }
}

/* Dashboard Grid */
.ns-dashboard {
    display: grid;
    grid-template-columns: repeat(12, 1fr);
    gap: 20px;
    padding: 0;
}

/* Stat Cards - Firewalla Style */
.ns-stat-card {
    background: #fff;
    border-radius: 12px;
    padding: 20px;
    box-shadow: 0 2px 12px rgba(0,0,0,0.08);
    border: 1px solid #e5e7eb;
    transition: transform 0.2s, box-shadow 0.2s;
}
.ns-stat-card:hover {
    transform: translateY(-2px);
    box-shadow: 0 8px 25px rgba(0,0,0,0.12);
}
.ns-stat-card .stat-icon {
    width: 48px; height: 48px;
    border-radius: 12px;
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 24px;
    margin-bottom: 12px;
}
.ns-stat-card .stat-icon.red { background: #fee2e2; color: #dc2626; }
.ns-stat-card .stat-icon.blue { background: #dbeafe; color: #2563eb; }
.ns-stat-card .stat-icon.green { background: #dcfce7; color: #16a34a; }
.ns-stat-card .stat-icon.orange { background: #ffedd5; color: #ea580c; }
.ns-stat-card .stat-icon.purple { background: #f3e8ff; color: #9333ea; }
.ns-stat-card .stat-icon.gray { background: #f3f4f6; color: #6b7280; }
.ns-stat-card .stat-value {
    font-size: 32px;
    font-weight: 700;
    line-height: 1;
    color: #111827;
    margin-bottom: 4px;
}
.ns-stat-card .stat-label {
    font-size: 13px;
    color: #6b7280;
    text-transform: uppercase;
    letter-spacing: 0.5px;
}
.ns-stat-card .stat-trend {
    font-size: 12px;
    margin-top: 8px;
}
.ns-stat-card .stat-trend.up { color: #16a34a; }
.ns-stat-card .stat-trend.down { color: #dc2626; }

/* Panel Cards */
.ns-panel {
    background: #fff;
    border-radius: 12px;
    box-shadow: 0 2px 12px rgba(0,0,0,0.08);
    border: 1px solid #e5e7eb;
    overflow: hidden;
}
.ns-panel-header {
    padding: 16px 20px;
    border-bottom: 1px solid #e5e7eb;
    display: flex;
    align-items: center;
    justify-content: space-between;
    background: #f9fafb;
}
.ns-panel-header h3 {
    margin: 0;
    font-size: 16px;
    font-weight: 600;
    color: #111827;
}
.ns-panel-body {
    padding: 20px;
}

/* Bandwidth Chart Container */
.ns-bandwidth-chart {
    height: 200px;
    position: relative;
}

/* Device Cards Grid */
.ns-devices-grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
    gap: 16px;
}
.ns-device-card {
    background: #fff;
    border-radius: 12px;
    padding: 16px;
    border: 1px solid #e5e7eb;
    display: flex;
    align-items: center;
    gap: 12px;
    transition: all 0.2s;
    cursor: pointer;
}
.ns-device-card:hover {
    border-color: #3b82f6;
    box-shadow: 0 4px 12px rgba(59,130,246,0.15);
}
.ns-device-card.quarantined {
    border-color: #ef4444;
    background: #fef2f2;
}
.ns-device-card .device-icon {
    width: 48px; height: 48px;
    border-radius: 50%;
    background: #f3f4f6;
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 20px;
    color: #6b7280;
    flex-shrink: 0;
}
.ns-device-card .device-info {
    flex: 1;
    min-width: 0;
}
.ns-device-card .device-name {
    font-weight: 600;
    color: #111827;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
}
.ns-device-card .device-ip {
    font-size: 12px;
    color: #6b7280;
}
.ns-device-card .device-traffic {
    text-align: right;
    font-size: 12px;
}
.ns-device-card .device-traffic .up { color: #16a34a; }
.ns-device-card .device-traffic .down { color: #2563eb; }
.ns-device-card .device-status {
    width: 8px; height: 8px;
    border-radius: 50%;
    background: #d1d5db;
}
.ns-device-card .device-status.online { background: #4ade80; }
.ns-device-card .device-status.offline { background: #ef4444; }

/* Alarm Feed - Firewalla Style */
.ns-alarm-feed {
    max-height: 400px;
    overflow-y: auto;
}
.ns-alarm-item {
    display: flex;
    align-items: flex-start;
    gap: 12px;
    padding: 14px 16px;
    border-bottom: 1px solid #f3f4f6;
    transition: background 0.2s;
}
.ns-alarm-item:hover {
    background: #f9fafb;
}
.ns-alarm-item:last-child {
    border-bottom: none;
}
.ns-alarm-icon {
    width: 40px; height: 40px;
    border-radius: 10px;
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 18px;
    flex-shrink: 0;
}
.ns-alarm-icon.threat { background: #fee2e2; color: #dc2626; }
.ns-alarm-icon.warning { background: #fef3c7; color: #d97706; }
.ns-alarm-icon.info { background: #dbeafe; color: #2563eb; }
.ns-alarm-icon.device { background: #dcfce7; color: #16a34a; }
.ns-alarm-icon.dns { background: #f3e8ff; color: #9333ea; }
.ns-alarm-content {
    flex: 1;
    min-width: 0;
}
.ns-alarm-title {
    font-weight: 600;
    color: #111827;
    margin-bottom: 2px;
}
.ns-alarm-detail {
    font-size: 13px;
    color: #6b7280;
    margin-bottom: 4px;
}
.ns-alarm-meta {
    font-size: 12px;
    color: #9ca3af;
}
.ns-alarm-actions {
    display: flex;
    gap: 6px;
    flex-shrink: 0;
}
.ns-alarm-actions .btn {
    padding: 4px 10px;
    font-size: 12px;
    border-radius: 6px;
}

/* Top Apps/Devices Charts */
.ns-chart-container {
    height: 250px;
    position: relative;
}

/* IDS Status Widget */
.ns-ids-status {
    display: flex;
    gap: 20px;
    align-items: center;
}
.ns-ids-indicator {
    display: flex;
    align-items: center;
    gap: 8px;
}
.ns-ids-indicator .dot {
    width: 10px; height: 10px;
    border-radius: 50%;
}
.ns-ids-indicator .dot.active { background: #4ade80; }
.ns-ids-indicator .dot.inactive { background: #d1d5db; }

/* GeoIP Map Container */
.ns-geoip-map {
    height: 300px;
    background: #1a1a2e;
    border-radius: 8px;
    position: relative;
    overflow: hidden;
}
.ns-geoip-map #world-map {
    width: 100%;
    height: 100%;
}

/* Connection Stats Banner */
.ns-conn-banner {
    grid-column: span 12;
    background: linear-gradient(135deg, #1e3a5f 0%, #2d5a87 100%);
    border-radius: 12px;
    padding: 24px 28px;
    color: #fff;
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 20px;
    box-shadow: 0 4px 15px rgba(0,0,0,0.15);
}
.ns-conn-banner .banner-text {
    font-size: 18px;
    font-weight: 500;
    line-height: 1.4;
}
.ns-conn-banner .banner-text strong {
    font-size: 28px;
    font-weight: 700;
}
.ns-conn-banner .banner-stats {
    display: flex;
    gap: 24px;
}
.ns-conn-banner .banner-stat {
    text-align: center;
}
.ns-conn-banner .banner-stat .val {
    font-size: 24px;
    font-weight: 700;
}
.ns-conn-banner .banner-stat .lbl {
    font-size: 11px;
    opacity: 0.8;
    text-transform: uppercase;
    letter-spacing: 0.5px;
}

/* Top Categories List */
.ns-top-list {
    list-style: none;
    padding: 0;
    margin: 0;
}
.ns-top-list li {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 10px 0;
    border-bottom: 1px solid #f3f4f6;
    font-size: 13px;
}
.ns-top-list li:last-child { border-bottom: none; }
.ns-top-list .rank {
    width: 24px;
    height: 24px;
    border-radius: 6px;
    background: #f3f4f6;
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 11px;
    font-weight: 700;
    color: #6b7280;
    margin-right: 10px;
    flex-shrink: 0;
}
.ns-top-list .name {
    flex: 1;
    font-weight: 500;
    color: #111827;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
}
.ns-top-list .count {
    font-weight: 600;
    color: #6b7280;
    margin-left: 8px;
}
.ns-top-list .bar-bg {
    width: 80px;
    height: 6px;
    background: #f3f4f6;
    border-radius: 3px;
    overflow: hidden;
    margin-left: 12px;
    flex-shrink: 0;
}
.ns-top-list .bar-fill {
    height: 100%;
    border-radius: 3px;
    transition: width 0.3s;
}

/* Category Pills */
.ns-category-pill {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    padding: 6px 12px;
    border-radius: 20px;
    font-size: 13px;
    background: #f3f4f6;
    color: #374151;
    margin: 4px;
}
.ns-category-pill.blocked {
    background: #fee2e2;
    color: #dc2626;
}
.ns-category-pill .count {
    background: rgba(0,0,0,0.1);
    padding: 2px 8px;
    border-radius: 10px;
    font-size: 11px;
    font-weight: 600;
}

/* Grid Layout Classes */
.ns-col-3 { grid-column: span 3; }
.ns-col-4 { grid-column: span 4; }
.ns-col-6 { grid-column: span 6; }
.ns-col-8 { grid-column: span 8; }
.ns-col-12 { grid-column: span 12; }

@media (max-width: 1200px) {
    .ns-col-3 { grid-column: span 6; }
    .ns-col-4 { grid-column: span 6; }
}
@media (max-width: 768px) {
    .ns-col-3, .ns-col-4, .ns-col-6, .ns-col-8 { grid-column: span 12; }
}

/* Real-time indicator */
.ns-realtime {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    font-size: 12px;
    color: #6b7280;
}
.ns-realtime .dot {
    width: 6px; height: 6px;
    border-radius: 50%;
    background: #4ade80;
    animation: blink 1s infinite;
}
@keyframes blink {
    0%, 100% { opacity: 1; }
    50% { opacity: 0.3; }
}
</style>

<!-- Chart.js -->
<script src="/ui/js/chart.min.js"></script>

<script>
$(document).ready(function() {
    var bandwidthChart, appsChart, devicesChart;
    var bandwidthData = { labels: [], upload: [], download: [] };

    /* Native HTML escape (no lodash dependency) */
    function _escape(s) {
        if (s == null) return '';
        var div = document.createElement('div');
        div.appendChild(document.createTextNode(String(s)));
        return div.innerHTML;
    }

    /* ================================================================
     * Service Status
     * ================================================================ */
    function updateServiceStatus() {
        ajaxCall('/api/netshield/service/status', {}, function(data) {
            var running = data && (data.status === 'running' || data.result === 'running');
            $('#ns-status-bar')
                .removeClass('ns-running ns-stopped')
                .addClass(running ? 'ns-running' : 'ns-stopped');
            $('#ns-status-text').text(running
                ? '{{ lang._("Protection Active") }}'
                : '{{ lang._("Protection Disabled") }}');
            $('#ns-status-label')
                .removeClass('label-success label-danger')
                .addClass(running ? 'label-success' : 'label-danger')
                .text(running ? '{{ lang._("ACTIVE") }}' : '{{ lang._("STOPPED") }}');
        });
    }

    function svcAction(action) {
        ajaxCall('/api/netshield/service/' + action, {}, function() {
            setTimeout(updateServiceStatus, 1500);
        });
    }

    $('#btn-svc-start').click(function() { svcAction('start'); });
    $('#btn-svc-stop').click(function() { svcAction('stop'); });
    $('#btn-svc-restart').click(function() { svcAction('restart'); });

    /* ================================================================
     * Stats Cards
     * ================================================================ */
    function refreshStats() {
        // Alerts stats
        ajaxCall('/api/netshield/alerts/stats', {}, function(data) {
            if (!data) return;
            $('#stat-alerts').text(data.total_alerts_today || 0);
            $('#stat-threats').text(data.threat_alerts || 0);
            $('#stat-new-devices').text(data.new_devices || 0);
            $('#stat-quarantined').text(data.quarantined_devices || 0);
        });

        // DNS stats
        $.getJSON('/api/netshield/dns/stats', function(data) {
            $('#stat-dns-blocked').text((data.total_blocked || 0).toLocaleString());
        });

        // Bandwidth
        $.getJSON('/api/netshield/bandwidth/summary', function(data) {
            if (data && data.total_bytes_today !== undefined) {
                var val = data.total_bytes_today;
                var unit = 'B';
                if (val >= 1073741824) { val = (val / 1073741824).toFixed(1); unit = 'GB'; }
                else if (val >= 1048576) { val = (val / 1048576).toFixed(1); unit = 'MB'; }
                else if (val >= 1024) { val = (val / 1024).toFixed(1); unit = 'KB'; }
                $('#stat-bandwidth').text(val + ' ' + unit);
            }
        });

        // IDS stats
        $.getJSON('/api/netshield/ids/status', function(data) {
            if (data) {
                var active = data.engine_running || (data.suricata && data.suricata.status === 'running');
                $('#ids-status-dot').removeClass('active inactive').addClass(active ? 'active' : 'inactive');
                $('#ids-status-text').text(active ? '{{ lang._("Active") }}' : '{{ lang._("Inactive") }}');
                $('#ids-signatures').text((data.signatures_loaded || 0).toLocaleString());
                var alertsToday = (data.alerts_24h && data.alerts_24h.total) ? data.alerts_24h.total : 0;
                $('#ids-alerts-today').text(alertsToday);
            }
        });
    }

    /* ================================================================
     * Real-time Bandwidth Chart
     * ================================================================ */
    function initBandwidthChart() {
        var ctx = document.getElementById('bandwidth-chart');
        if (!ctx) return;

        bandwidthChart = new Chart(ctx.getContext('2d'), {
            type: 'line',
            data: {
                labels: [],
                datasets: [{
                    label: '{{ lang._("Download") }}',
                    data: [],
                    borderColor: '#3b82f6',
                    backgroundColor: 'rgba(59,130,246,0.1)',
                    fill: true,
                    tension: 0.4
                }, {
                    label: '{{ lang._("Upload") }}',
                    data: [],
                    borderColor: '#10b981',
                    backgroundColor: 'rgba(16,185,129,0.1)',
                    fill: true,
                    tension: 0.4
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { position: 'top' }
                },
                scales: {
                    y: {
                        beginAtZero: true,
                        ticks: {
                            callback: function(v) {
                                if (v >= 1048576) return (v/1048576).toFixed(1) + ' MB/s';
                                if (v >= 1024) return (v/1024).toFixed(0) + ' KB/s';
                                return v + ' B/s';
                            }
                        }
                    }
                },
                animation: { duration: 300 }
            }
        });
    }

    function updateBandwidthChart() {
        $.getJSON('/api/netshield/bandwidth/realtime', function(data) {
            if (!data || !bandwidthChart) return;

            var now = new Date().toLocaleTimeString();
            bandwidthData.labels.push(now);
            bandwidthData.download.push(data.download_bps || 0);
            bandwidthData.upload.push(data.upload_bps || 0);

            // Keep last 30 points
            if (bandwidthData.labels.length > 30) {
                bandwidthData.labels.shift();
                bandwidthData.download.shift();
                bandwidthData.upload.shift();
            }

            bandwidthChart.data.labels = bandwidthData.labels;
            bandwidthChart.data.datasets[0].data = bandwidthData.download;
            bandwidthChart.data.datasets[1].data = bandwidthData.upload;
            bandwidthChart.update('none');
        });
    }

    /* ================================================================
     * Top Applications Pie Chart
     * ================================================================ */
    function initAppsChart() {
        var ctx = document.getElementById('apps-chart');
        if (!ctx) return;

        appsChart = new Chart(ctx.getContext('2d'), {
            type: 'doughnut',
            data: {
                labels: [],
                datasets: [{
                    data: [],
                    backgroundColor: [
                        '#3b82f6', '#10b981', '#f59e0b', '#ef4444', '#8b5cf6',
                        '#ec4899', '#06b6d4', '#84cc16', '#f97316', '#6366f1'
                    ]
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { position: 'right', labels: { boxWidth: 12 } }
                }
            }
        });
    }

    function updateAppsChart() {
        $.getJSON('/api/netshield/sessions/stats', function(data) {
            if (!data || !data.data || !appsChart) return;
            var today = data.data.today || {};
            // Prefer top_apps (actual app names), fallback to top_categories
            var apps = today.top_apps || [];
            if (!apps.length) {
                apps = (today.top_categories || []).map(function(c) {
                    return { app: (c.category || 'Unknown').replace(/_/g, ' '), count: c.count };
                });
            }
            if (!apps.length) return;

            var labels = [], values = [];
            apps.slice(0, 10).forEach(function(a) {
                labels.push(a.app || 'Unknown');
                values.push(a.count || 0);
            });

            appsChart.data.labels = labels;
            appsChart.data.datasets[0].data = values;
            appsChart.update();
        });
    }

    /* ================================================================
     * Top Devices Bar Chart
     * ================================================================ */
    function initDevicesChart() {
        var ctx = document.getElementById('devices-chart');
        if (!ctx) return;

        devicesChart = new Chart(ctx.getContext('2d'), {
            type: 'bar',
            data: {
                labels: [],
                datasets: [{
                    label: '{{ lang._("Traffic") }}',
                    data: [],
                    backgroundColor: '#3b82f6'
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                indexAxis: 'y',
                plugins: {
                    legend: { display: false }
                },
                scales: {
                    x: {
                        ticks: {
                            callback: function(v) {
                                if (v >= 1073741824) return (v/1073741824).toFixed(1) + ' GB';
                                if (v >= 1048576) return (v/1048576).toFixed(0) + ' MB';
                                return (v/1024).toFixed(0) + ' KB';
                            }
                        }
                    }
                }
            }
        });
    }

    function updateDevicesChart() {
        $.getJSON('/api/netshield/sessions/stats', function(data) {
            if (!data || !data.data || !devicesChart) return;
            var today = data.data.today || {};
            var devs = today.top_devices || [];
            if (!devs.length) return;

            var labels = [], values = [];
            devs.slice(0, 8).forEach(function(dev) {
                labels.push(dev.name || dev.ip);
                values.push(dev.count || 0);
            });

            devicesChart.data.labels = labels;
            devicesChart.data.datasets[0].data = values;
            devicesChart.update();
        });
    }

    /* ================================================================
     * Device Cards (Firewalla Style)
     * ================================================================ */
    function loadDevices() {
        $.getJSON('/api/netshield/devices/list', function(data) {
            var $grid = $('#devices-grid').empty();
            var devices = data.devices || data.rows || [];

            if (!devices.length) {
                $grid.html('<div class="text-center text-muted p-4">{{ lang._("No devices found") }}</div>');
                return;
            }

            devices.slice(0, 12).forEach(function(dev) {
                var iconClass = getDeviceIcon(dev.type || dev.device_type);
                var statusClass = dev.online ? 'online' : 'offline';
                var quarantined = dev.quarantined ? 'quarantined' : '';

                var traffic = '';
                if (dev.bytes_up || dev.bytes_down) {
                    traffic = '<div class="device-traffic">' +
                        '<div class="up">↑ ' + formatBytes(dev.bytes_up || 0) + '</div>' +
                        '<div class="down">↓ ' + formatBytes(dev.bytes_down || 0) + '</div>' +
                    '</div>';
                }

                $grid.append(
                    '<div class="ns-device-card ' + quarantined + '" data-mac="' + (dev.mac || '') + '">' +
                        '<div class="device-icon"><i class="fa ' + iconClass + '"></i></div>' +
                        '<div class="device-info">' +
                            '<div class="device-name">' + _escape(dev.name || dev.hostname || 'Unknown') + '</div>' +
                            '<div class="device-ip">' + _escape(dev.ip || dev.mac || '') + '</div>' +
                        '</div>' +
                        traffic +
                        '<div class="device-status ' + statusClass + '"></div>' +
                    '</div>'
                );
            });
        });
    }

    function getDeviceIcon(type) {
        var icons = {
            'phone': 'fa-mobile', 'mobile': 'fa-mobile',
            'tablet': 'fa-tablet', 'laptop': 'fa-laptop',
            'desktop': 'fa-desktop', 'computer': 'fa-desktop',
            'tv': 'fa-tv', 'smart_tv': 'fa-tv',
            'iot': 'fa-microchip', 'camera': 'fa-video-camera',
            'printer': 'fa-print', 'router': 'fa-sitemap',
            'server': 'fa-server', 'gaming': 'fa-gamepad'
        };
        return icons[type] || 'fa-question-circle';
    }

    function formatBytes(bytes) {
        if (bytes >= 1073741824) return (bytes/1073741824).toFixed(1) + ' GB';
        if (bytes >= 1048576) return (bytes/1048576).toFixed(1) + ' MB';
        if (bytes >= 1024) return (bytes/1024).toFixed(0) + ' KB';
        return bytes + ' B';
    }

    /* ================================================================
     * Alarm Feed (Firewalla Style)
     * ================================================================ */
    function loadAlarmFeed() {
        $.getJSON('/api/netshield/alerts/search?rowCount=20', function(data) {
            var $feed = $('#alarm-feed').empty();
            var alerts = data.rows || [];

            if (!alerts.length) {
                $feed.html('<div class="text-center text-muted p-4">{{ lang._("No recent alarms") }}</div>');
                return;
            }

            alerts.forEach(function(alert) {
                var iconClass = getAlarmIcon(alert.type);
                var typeClass = getAlarmTypeClass(alert.type, alert.severity);

                $feed.append(
                    '<div class="ns-alarm-item" data-id="' + alert.id + '">' +
                        '<div class="ns-alarm-icon ' + typeClass + '"><i class="fa ' + iconClass + '"></i></div>' +
                        '<div class="ns-alarm-content">' +
                            '<div class="ns-alarm-title">' + _escape(alert.title || getAlarmTitle(alert)) + '</div>' +
                            '<div class="ns-alarm-detail">' + _escape(alert.detail || alert.message || '') + '</div>' +
                            '<div class="ns-alarm-meta">' +
                                '<span class="fa fa-clock-o"></span> ' + _escape(alert.timestamp || '') +
                                (alert.device ? ' • ' + _escape(alert.device) : '') +
                            '</div>' +
                        '</div>' +
                        '<div class="ns-alarm-actions">' +
                            (alert.acknowledged ? '' :
                                '<button class="btn btn-xs btn-default btn-ack" data-id="' + alert.id + '" title="{{ lang._("Acknowledge") }}">' +
                                    '<i class="fa fa-check"></i>' +
                                '</button>') +
                            '<button class="btn btn-xs btn-danger btn-block-src" data-ip="' + (alert.source_ip || '') + '" title="{{ lang._("Block Source") }}">' +
                                '<i class="fa fa-ban"></i>' +
                            '</button>' +
                            '<button class="btn btn-xs btn-warning btn-mute" data-id="' + alert.id + '" title="{{ lang._("Mute Similar") }}">' +
                                '<i class="fa fa-bell-slash"></i>' +
                            '</button>' +
                        '</div>' +
                    '</div>'
                );
            });

            // Bind actions
            $feed.find('.btn-ack').click(function(e) {
                e.stopPropagation();
                var id = $(this).data('id');
                ajaxCall('/api/netshield/alerts/acknowledge', {id: id}, function() {
                    loadAlarmFeed();
                    refreshStats();
                });
            });

            $feed.find('.btn-block-src').click(function(e) {
                e.stopPropagation();
                var ip = $(this).data('ip');
                if (!ip) return;
                BootstrapDialog.confirm({
                    title: '{{ lang._("Block Source") }}',
                    message: '{{ lang._("Block all traffic from") }} ' + ip + '?',
                    type: BootstrapDialog.TYPE_DANGER,
                    btnOKLabel: '{{ lang._("Block") }}',
                    callback: function(r) {
                        if (r) {
                            ajaxCall('/api/netshield/policies/blockIp', {ip: ip}, function() {
                                loadAlarmFeed();
                            });
                        }
                    }
                });
            });

            $feed.find('.btn-mute').click(function(e) {
                e.stopPropagation();
                var id = $(this).data('id');
                ajaxCall('/api/netshield/alerts/mute', {id: id}, function() {
                    loadAlarmFeed();
                });
            });
        });
    }

    function getAlarmIcon(type) {
        var icons = {
            'threat': 'fa-shield', 'ids': 'fa-shield',
            'malware': 'fa-bug', 'virus': 'fa-bug',
            'dns': 'fa-filter', 'adult': 'fa-eye-slash',
            'device': 'fa-desktop', 'new_device': 'fa-plus-circle',
            'vpn': 'fa-lock', 'bandwidth': 'fa-tachometer',
            'blocked': 'fa-ban', 'category': 'fa-tags'
        };
        return icons[type] || 'fa-bell';
    }

    function getAlarmTypeClass(type, severity) {
        if (severity === 'critical' || severity === 'high') return 'threat';
        if (type === 'threat' || type === 'malware' || type === 'ids') return 'threat';
        if (type === 'dns' || type === 'blocked') return 'dns';
        if (type === 'device' || type === 'new_device') return 'device';
        if (severity === 'medium') return 'warning';
        return 'info';
    }

    function getAlarmTitle(alert) {
        if (alert.type === 'threat') return '{{ lang._("Security Threat Detected") }}';
        if (alert.type === 'dns') return '{{ lang._("DNS Request Blocked") }}';
        if (alert.type === 'device') return '{{ lang._("New Device Connected") }}';
        if (alert.type === 'ids') return '{{ lang._("Intrusion Attempt") }}';
        return '{{ lang._("Security Alert") }}';
    }

    /* ================================================================
     * Connection Stats (Phase 6)
     * ================================================================ */
    function loadConnectionStats() {
        $.getJSON('/api/netshield/sessions/stats', function(data) {
            if (!data || !data.data) return;
            var d = data.data;
            var today = d.today || {};
            var totalToday = today.total || 0;
            var blockedToday = today.blocked || 0;

            $('#conn-total-today').text(totalToday.toLocaleString());
            $('#conn-blocked-today').text(blockedToday.toLocaleString());
            $('#conn-total-all').text((d.total_connections || 0).toLocaleString());

            // Banner text
            var bannerHtml = 'Today NetShield processed <strong>' + totalToday.toLocaleString() + '</strong> connections';
            if (blockedToday > 0) {
                bannerHtml += ' and blocked <strong>' + blockedToday.toLocaleString() + '</strong>';
            }
            $('#conn-banner-text').html(bannerHtml);

            // Top domains today
            var $domains = $('#top-domains-list').empty();
            var topDomains = today.top_domains || [];
            var maxDomain = topDomains.length > 0 ? topDomains[0].count : 1;
            topDomains.slice(0, 8).forEach(function(d, i) {
                var pct = Math.round((d.count / maxDomain) * 100);
                $domains.append(
                    '<li>' +
                        '<span class="rank">' + (i + 1) + '</span>' +
                        '<span class="name">' + _escape(d.domain) + '</span>' +
                        '<span class="count">' + d.count + '</span>' +
                        '<span class="bar-bg"><span class="bar-fill" style="width:' + pct + '%;background:#3b82f6;"></span></span>' +
                    '</li>'
                );
            });

            // Top app categories today
            var $cats = $('#top-app-categories-list').empty();
            var topCats = today.top_categories || [];
            var maxCat = topCats.length > 0 ? topCats[0].count : 1;
            var catColors = ['#3b82f6','#10b981','#f59e0b','#ef4444','#8b5cf6','#ec4899','#06b6d4','#84cc16','#f97316','#6366f1'];
            topCats.slice(0, 8).forEach(function(c, i) {
                var pct = Math.round((c.count / maxCat) * 100);
                var color = catColors[i % catColors.length];
                $cats.append(
                    '<li>' +
                        '<span class="rank">' + (i + 1) + '</span>' +
                        '<span class="name">' + _escape(c.category.replace(/_/g, ' ')) + '</span>' +
                        '<span class="count">' + c.count + '</span>' +
                        '<span class="bar-bg"><span class="bar-fill" style="width:' + pct + '%;background:' + color + ';"></span></span>' +
                    '</li>'
                );
            });

            // Top devices today
            var $devs = $('#top-conn-devices-list').empty();
            var topDevs = today.top_devices || [];
            var maxDev = topDevs.length > 0 ? topDevs[0].count : 1;
            topDevs.slice(0, 8).forEach(function(d, i) {
                var pct = Math.round((d.count / maxDev) * 100);
                $devs.append(
                    '<li>' +
                        '<span class="rank">' + (i + 1) + '</span>' +
                        '<span class="name">' + _escape(d.name || d.ip) + '</span>' +
                        '<span class="count">' + d.count + '</span>' +
                        '<span class="bar-bg"><span class="bar-fill" style="width:' + pct + '%;background:#10b981;"></span></span>' +
                    '</li>'
                );
            });
        });
    }

    /* ================================================================
     * Web Categories Blocked
     * ================================================================ */
    function loadCategoriesBlocked() {
        $.getJSON('/api/netshield/sessions/stats', function(data) {
            var $container = $('#categories-blocked').empty();
            var today = (data.data || {}).today || {};
            var categories = today.top_categories || [];

            if (!categories.length) {
                $container.html('<span class="text-muted">{{ lang._("No blocked categories yet") }}</span>');
                return;
            }

            categories.slice(0, 8).forEach(function(cat) {
                $container.append(
                    '<span class="ns-category-pill">' +
                        '<i class="fa fa-tags"></i> ' + _escape((cat.category || cat.name || '').replace(/_/g, ' ')) +
                        '<span class="count">' + (cat.count || 0) + '</span>' +
                    '</span>'
                );
            });
        });
    }

    /* ================================================================
     * Initialize & Auto-refresh
     * ================================================================ */
    updateServiceStatus();
    refreshStats();
    loadDevices();
    loadAlarmFeed();
    loadCategoriesBlocked();
    loadConnectionStats();

    initBandwidthChart();
    initAppsChart();
    initDevicesChart();

    updateBandwidthChart();
    updateAppsChart();
    updateDevicesChart();

    // Real-time updates
    setInterval(updateBandwidthChart, 2000);
    setInterval(function() {
        refreshStats();
        updateAppsChart();
        updateDevicesChart();
    }, 30000);
    setInterval(function() {
        loadDevices();
        loadAlarmFeed();
        loadCategoriesBlocked();
        loadConnectionStats();
    }, 60000);
    setInterval(updateServiceStatus, 60000);
});
</script>

<!-- ================================================================ -->
<!-- SERVICE STATUS BAR                                                -->
<!-- ================================================================ -->
<div class="ns-status-bar" id="ns-status-bar">
    <div class="ns-status-dot"></div>
    <span id="ns-status-label" class="label label-default" style="font-size: 11px; padding: 4px 10px;">{{ lang._('CHECKING') }}</span>
    <span id="ns-status-text" style="flex: 1; font-weight: 500;">{{ lang._('Checking protection status...') }}</span>
    <span class="ns-realtime"><span class="dot"></span> {{ lang._('Real-time') }}</span>
    <div class="btn-group btn-group-sm">
        <button id="btn-svc-start" class="btn btn-success btn-sm"><i class="fa fa-play"></i></button>
        <button id="btn-svc-stop" class="btn btn-danger btn-sm"><i class="fa fa-stop"></i></button>
        <button id="btn-svc-restart" class="btn btn-warning btn-sm"><i class="fa fa-refresh"></i></button>
    </div>
</div>

<!-- ================================================================ -->
<!-- DASHBOARD GRID                                                    -->
<!-- ================================================================ -->
<div class="ns-dashboard">

    <!-- Stat Cards Row -->
    <div class="ns-stat-card ns-col-3">
        <div class="stat-icon red"><i class="fa fa-bell"></i></div>
        <div class="stat-value" id="stat-alerts">0</div>
        <div class="stat-label">{{ lang._('Alerts Today') }}</div>
    </div>
    <div class="ns-stat-card ns-col-3">
        <div class="stat-icon orange"><i class="fa fa-shield"></i></div>
        <div class="stat-value" id="stat-threats">0</div>
        <div class="stat-label">{{ lang._('Threats Blocked') }}</div>
    </div>
    <div class="ns-stat-card ns-col-3">
        <div class="stat-icon purple"><i class="fa fa-filter"></i></div>
        <div class="stat-value" id="stat-dns-blocked">0</div>
        <div class="stat-label">{{ lang._('DNS Blocked') }}</div>
    </div>
    <div class="ns-stat-card ns-col-3">
        <div class="stat-icon blue"><i class="fa fa-exchange"></i></div>
        <div class="stat-value" id="stat-bandwidth">0 B</div>
        <div class="stat-label">{{ lang._('Bandwidth Today') }}</div>
    </div>

    <!-- Connection Stats Banner (Phase 6) -->
    <div class="ns-conn-banner">
        <div>
            <div class="banner-text" id="conn-banner-text">
                Today NetShield processed <strong id="conn-total-today">0</strong> connections
            </div>
        </div>
        <div class="banner-stats">
            <div class="banner-stat">
                <div class="val" id="conn-blocked-today" style="color: #fca5a5;">0</div>
                <div class="lbl">Blocked Today</div>
            </div>
            <div class="banner-stat">
                <div class="val" id="conn-total-all">0</div>
                <div class="lbl">All-Time</div>
            </div>
        </div>
    </div>

    <!-- Bandwidth Chart -->
    <div class="ns-panel ns-col-8">
        <div class="ns-panel-header">
            <h3><i class="fa fa-area-chart"></i> {{ lang._('Real-time Bandwidth') }}</h3>
        </div>
        <div class="ns-panel-body">
            <div class="ns-bandwidth-chart">
                <canvas id="bandwidth-chart"></canvas>
            </div>
        </div>
    </div>

    <!-- IDS Status Widget -->
    <div class="ns-panel ns-col-4">
        <div class="ns-panel-header">
            <h3><i class="fa fa-shield"></i> {{ lang._('IDS/IPS Status') }}</h3>
        </div>
        <div class="ns-panel-body">
            <div class="ns-ids-status">
                <div class="ns-ids-indicator">
                    <span class="dot inactive" id="ids-status-dot"></span>
                    <span id="ids-status-text">{{ lang._('Checking...') }}</span>
                </div>
            </div>
            <hr style="margin: 15px 0;">
            <div class="row">
                <div class="col-xs-6 text-center">
                    <div style="font-size: 24px; font-weight: 700;" id="ids-signatures">0</div>
                    <div class="text-muted" style="font-size: 12px;">{{ lang._('Signatures') }}</div>
                </div>
                <div class="col-xs-6 text-center">
                    <div style="font-size: 24px; font-weight: 700; color: #dc2626;" id="ids-alerts-today">0</div>
                    <div class="text-muted" style="font-size: 12px;">{{ lang._('Alerts Today') }}</div>
                </div>
            </div>
        </div>
    </div>

    <!-- Alarm Feed (Firewalla Style) -->
    <div class="ns-panel ns-col-6">
        <div class="ns-panel-header">
            <h3><i class="fa fa-bell"></i> {{ lang._('Recent Alarms') }}</h3>
            <a href="/ui/netshield/alerts" class="btn btn-xs btn-default">{{ lang._('View All') }}</a>
        </div>
        <div class="ns-panel-body" style="padding: 0;">
            <div class="ns-alarm-feed" id="alarm-feed">
                <div class="text-center text-muted p-4">{{ lang._('Loading...') }}</div>
            </div>
        </div>
    </div>

    <!-- Top Applications Pie Chart -->
    <div class="ns-panel ns-col-6">
        <div class="ns-panel-header">
            <h3><i class="fa fa-pie-chart"></i> {{ lang._('Top Applications') }}</h3>
        </div>
        <div class="ns-panel-body">
            <div class="ns-chart-container">
                <canvas id="apps-chart"></canvas>
            </div>
        </div>
    </div>

    <!-- Device Cards Grid -->
    <div class="ns-panel ns-col-8">
        <div class="ns-panel-header">
            <h3><i class="fa fa-desktop"></i> {{ lang._('Connected Devices') }}</h3>
            <div>
                <span class="text-muted" style="font-size: 12px; margin-right: 10px;">
                    <span id="stat-new-devices">0</span> {{ lang._('new') }} •
                    <span id="stat-quarantined">0</span> {{ lang._('quarantined') }}
                </span>
                <a href="/ui/netshield/devices" class="btn btn-xs btn-default">{{ lang._('Manage') }}</a>
            </div>
        </div>
        <div class="ns-panel-body">
            <div class="ns-devices-grid" id="devices-grid">
                <div class="text-center text-muted">{{ lang._('Loading devices...') }}</div>
            </div>
        </div>
    </div>

    <!-- Top Devices Bar Chart -->
    <div class="ns-panel ns-col-4">
        <div class="ns-panel-header">
            <h3><i class="fa fa-bar-chart"></i> {{ lang._('Top Devices') }}</h3>
        </div>
        <div class="ns-panel-body">
            <div class="ns-chart-container">
                <canvas id="devices-chart"></canvas>
            </div>
        </div>
    </div>

    <!-- Top Domains Today (Phase 6) -->
    <div class="ns-panel ns-col-4">
        <div class="ns-panel-header">
            <h3><i class="fa fa-globe"></i> {{ lang._('Top Domains') }}</h3>
            <a href="/ui/netshield/sessions" class="btn btn-xs btn-default">{{ lang._('Sessions') }}</a>
        </div>
        <div class="ns-panel-body" style="padding: 12px 16px;">
            <ul class="ns-top-list" id="top-domains-list">
                <li class="text-center text-muted">{{ lang._('Loading...') }}</li>
            </ul>
        </div>
    </div>

    <!-- Top App Categories Today (Phase 6) -->
    <div class="ns-panel ns-col-4">
        <div class="ns-panel-header">
            <h3><i class="fa fa-cubes"></i> {{ lang._('Top App Categories') }}</h3>
        </div>
        <div class="ns-panel-body" style="padding: 12px 16px;">
            <ul class="ns-top-list" id="top-app-categories-list">
                <li class="text-center text-muted">{{ lang._('Loading...') }}</li>
            </ul>
        </div>
    </div>

    <!-- Top Devices by Connections (Phase 6) -->
    <div class="ns-panel ns-col-4">
        <div class="ns-panel-header">
            <h3><i class="fa fa-laptop"></i> {{ lang._('Top Devices (DNS)') }}</h3>
        </div>
        <div class="ns-panel-body" style="padding: 12px 16px;">
            <ul class="ns-top-list" id="top-conn-devices-list">
                <li class="text-center text-muted">{{ lang._('Loading...') }}</li>
            </ul>
        </div>
    </div>

    <!-- Web Categories Blocked -->
    <div class="ns-panel ns-col-12">
        <div class="ns-panel-header">
            <h3><i class="fa fa-tags"></i> {{ lang._('Blocked Categories') }}</h3>
            <a href="/ui/netshield/webcategories" class="btn btn-xs btn-default">{{ lang._('Manage') }}</a>
        </div>
        <div class="ns-panel-body" id="categories-blocked">
            <span class="text-muted">{{ lang._('Loading...') }}</span>
        </div>
    </div>

</div>
