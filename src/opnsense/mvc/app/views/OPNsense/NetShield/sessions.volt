{#
    NetShield — Sessions (Connection Log) View
    Phase 6: Live session tracking similar to Zenarmor
#}

<style>
    :root {
        --bg-primary: #0f172a;
        --bg-card: #1e293b;
        --bg-card-alt: #253349;
        --border: #334155;
        --text: #e2e8f0;
        --text-muted: #94a3b8;
        --accent: #3b82f6;
        --accent-hover: #2563eb;
        --success: #22c55e;
        --danger: #ef4444;
        --warning: #f59e0b;
    }

    body, .page-content-main {
        background: var(--bg-primary) !important;
        color: var(--text) !important;
    }

    /* ── Stats Bar ─────────────────────────────── */
    .ns-stats-bar {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
        gap: 16px;
        margin-bottom: 20px;
    }
    .ns-stat-card {
        background: var(--bg-card);
        border: 1px solid var(--border);
        border-radius: 10px;
        padding: 18px 22px;
        text-align: center;
    }
    .ns-stat-card .stat-value {
        font-size: 2.4rem;
        font-weight: 700;
        color: var(--accent);
        line-height: 1.2;
    }
    .ns-stat-card .stat-label {
        font-size: 1.02rem;
        color: var(--text-muted);
        margin-top: 4px;
    }
    .ns-stat-card.blocked .stat-value { color: var(--danger); }
    .ns-stat-card.devices .stat-value { color: var(--success); }
    .ns-stat-card.category .stat-value { color: var(--warning); font-size: 1.32rem; }

    /* ── Filter Bar ────────────────────────────── */
    .ns-filter-bar {
        background: var(--bg-card);
        border: 1px solid var(--border);
        border-radius: 10px;
        padding: 16px 20px;
        margin-bottom: 20px;
        display: flex;
        flex-wrap: wrap;
        gap: 12px;
        align-items: flex-end;
    }
    .ns-filter-group {
        display: flex;
        flex-direction: column;
        gap: 4px;
    }
    .ns-filter-group label {
        font-size: 0.9rem;
        color: var(--text-muted);
        text-transform: uppercase;
        letter-spacing: 0.5px;
    }
    .ns-filter-group select,
    .ns-filter-group input {
        background: var(--bg-primary);
        border: 1px solid var(--border);
        border-radius: 6px;
        color: var(--text);
        padding: 6px 10px;
        font-size: 1.05rem;
        min-width: 140px;
    }
    .ns-filter-group select:focus,
    .ns-filter-group input:focus {
        outline: none;
        border-color: var(--accent);
    }
    .ns-btn {
        background: var(--accent);
        color: #fff;
        border: none;
        border-radius: 6px;
        padding: 8px 18px;
        font-size: 1.05rem;
        cursor: pointer;
        font-weight: 600;
        transition: background 0.15s;
    }
    .ns-btn:hover { background: var(--accent-hover); }
    .ns-btn-sm { padding: 5px 12px; font-size: 0.96rem; }
    .ns-btn-danger { background: var(--danger); }
    .ns-btn-danger:hover { background: #dc2626; }
    .ns-btn-outline {
        background: transparent;
        border: 1px solid var(--border);
        color: var(--text);
    }
    .ns-btn-outline:hover { border-color: var(--accent); color: var(--accent); }

    /* ── Toggle group ──────────────────────────── */
    .ns-toggle-group {
        display: inline-flex;
        border: 1px solid var(--border);
        border-radius: 6px;
        overflow: hidden;
    }
    .ns-toggle-group button {
        background: transparent;
        border: none;
        color: var(--text-muted);
        padding: 6px 14px;
        font-size: 0.96rem;
        cursor: pointer;
        border-right: 1px solid var(--border);
        transition: all 0.15s;
    }
    .ns-toggle-group button:last-child { border-right: none; }
    .ns-toggle-group button.active {
        background: var(--accent);
        color: #fff;
    }

    /* ── Top toolbar ───────────────────────────── */
    .ns-toolbar {
        display: flex;
        justify-content: space-between;
        align-items: center;
        margin-bottom: 16px;
        flex-wrap: wrap;
        gap: 10px;
    }
    .ns-toolbar-left, .ns-toolbar-right {
        display: flex;
        align-items: center;
        gap: 10px;
    }
    .ns-auto-refresh label {
        font-size: 0.96rem;
        color: var(--text-muted);
        cursor: pointer;
        display: flex;
        align-items: center;
        gap: 5px;
    }

    /* ── Table ─────────────────────────────────── */
    .ns-table-wrap {
        background: var(--bg-card);
        border: 1px solid var(--border);
        border-radius: 10px;
        overflow: hidden;
    }
    .ns-table {
        width: 100%;
        border-collapse: collapse;
        font-size: 1.02rem;
    }
    .ns-table thead th {
        background: var(--bg-primary);
        color: var(--text-muted);
        font-weight: 600;
        text-transform: uppercase;
        font-size: 0.9rem;
        letter-spacing: 0.5px;
        padding: 12px 14px;
        text-align: left;
        border-bottom: 1px solid var(--border);
        white-space: nowrap;
    }
    .ns-table tbody tr {
        border-bottom: 1px solid var(--border);
        transition: background 0.1s;
    }
    .ns-table tbody tr:nth-child(even) {
        background: var(--bg-card-alt);
    }
    .ns-table tbody tr:hover {
        background: rgba(59, 130, 246, 0.08);
    }
    .ns-table tbody td {
        padding: 10px 14px;
        color: var(--text);
        white-space: nowrap;
        overflow: hidden;
        text-overflow: ellipsis;
        max-width: 220px;
    }

    /* ── Badges ────────────────────────────────── */
    .ns-badge {
        display: inline-flex;
        align-items: center;
        gap: 4px;
        padding: 3px 10px;
        border-radius: 12px;
        font-size: 0.9rem;
        font-weight: 600;
    }
    .ns-badge-allowed {
        background: rgba(34, 197, 94, 0.15);
        color: var(--success);
    }
    .ns-badge-blocked {
        background: rgba(239, 68, 68, 0.15);
        color: var(--danger);
    }
    .ns-badge-threat {
        background: rgba(245, 158, 11, 0.15);
        color: var(--warning);
    }
    .ns-badge-policy {
        background: rgba(168, 85, 247, 0.15);
        color: #a855f7;
    }
    .ns-badge-category {
        background: rgba(59, 130, 246, 0.15);
        color: var(--accent);
    }

    /* ── Pagination ────────────────────────────── */
    .ns-pagination {
        display: flex;
        justify-content: space-between;
        align-items: center;
        padding: 12px 18px;
        border-top: 1px solid var(--border);
        flex-wrap: wrap;
        gap: 10px;
    }
    .ns-pagination .page-info {
        font-size: 0.96rem;
        color: var(--text-muted);
    }
    .ns-pagination .page-controls {
        display: flex;
        gap: 4px;
    }
    .ns-pagination .page-controls button {
        background: var(--bg-primary);
        border: 1px solid var(--border);
        color: var(--text);
        padding: 5px 12px;
        border-radius: 4px;
        cursor: pointer;
        font-size: 0.96rem;
    }
    .ns-pagination .page-controls button:hover { border-color: var(--accent); }
    .ns-pagination .page-controls button.active { background: var(--accent); border-color: var(--accent); }
    .ns-pagination .page-controls button:disabled { opacity: 0.4; cursor: default; }

    .ns-rows-select {
        background: var(--bg-primary);
        border: 1px solid var(--border);
        color: var(--text);
        border-radius: 4px;
        padding: 4px 8px;
        font-size: 0.96rem;
    }

    /* ── Charts ─────────────────────────────────── */
    .ns-charts-row {
        display: grid;
        grid-template-columns: 1fr 1fr;
        gap: 16px;
        margin-bottom: 20px;
    }
    .ns-chart-card {
        background: var(--bg-card);
        border: 1px solid var(--border);
        border-radius: 10px;
        padding: 18px;
    }
    .ns-chart-card h4 {
        color: var(--text);
        margin: 0 0 12px 0;
        font-size: 1.08rem;
    }
    .ns-chart-container {
        position: relative;
        height: 220px;
    }

    /* ── Purge Modal ───────────────────────────── */
    .ns-modal-overlay {
        display: none;
        position: fixed;
        inset: 0;
        background: rgba(0,0,0,0.6);
        z-index: 9999;
        justify-content: center;
        align-items: center;
    }
    .ns-modal-overlay.active { display: flex; }
    .ns-modal {
        background: var(--bg-card);
        border: 1px solid var(--border);
        border-radius: 12px;
        padding: 28px;
        min-width: 360px;
    }
    .ns-modal h3 { margin: 0 0 16px 0; color: var(--text); }
    .ns-modal p { color: var(--text-muted); font-size: 1.08rem; margin-bottom: 16px; }
    .ns-modal-actions { display: flex; gap: 10px; justify-content: flex-end; }

    /* ── Loading ────────────────────────────────── */
    .ns-loading {
        text-align: center;
        padding: 40px;
        color: var(--text-muted);
    }
    .ns-spinner {
        display: inline-block;
        width: 24px; height: 24px;
        border: 3px solid var(--border);
        border-top-color: var(--accent);
        border-radius: 50%;
        animation: ns-spin 0.8s linear infinite;
    }
    @keyframes ns-spin { to { transform: rotate(360deg); } }

    /* ── Blocked/Threat Row Highlighting ──────────── */
    .ns-table tbody tr.ns-row-blocked {
        background: rgba(239, 68, 68, 0.06) !important;
    }
    .ns-table tbody tr.ns-row-blocked:hover {
        background: rgba(239, 68, 68, 0.12) !important;
    }
    .ns-btn-block {
        background: var(--danger);
        color: #fff;
        border: none;
        border-radius: 4px;
        padding: 3px 10px;
        font-size: 0.9rem;
        cursor: pointer;
        font-weight: 600;
    }
    .ns-btn-block:hover { background: #dc2626; }
    .ns-btn-unblock {
        background: var(--success);
        color: #fff;
        border: none;
        border-radius: 4px;
        padding: 3px 10px;
        font-size: 0.9rem;
        cursor: pointer;
        font-weight: 600;
    }
    .ns-btn-unblock:hover { background: #16a34a; }

    /* ── Responsive ─────────────────────────────── */
    @media (max-width: 900px) {
        .ns-charts-row { grid-template-columns: 1fr; }
        .ns-stats-bar { grid-template-columns: repeat(2, 1fr); }
    }
    @media (max-width: 600px) {
        .ns-stats-bar { grid-template-columns: 1fr; }
        .ns-filter-bar { flex-direction: column; }
    }
</style>

<script src="/ui/js/chart.min.js"></script>

<!-- ── Page Header ──────────────────────────────── -->
<div class="ns-toolbar">
    <div class="ns-toolbar-left">
        <h2 style="margin:0; font-size: 1.68rem;">
            <i class="fa fa-list"></i>&nbsp; {{ lang._('Sessions') }}
        </h2>
        <span style="font-size: 0.96rem; color:var(--text-muted);" id="lastUpdated"></span>
    </div>
    <div class="ns-toolbar-right">
        <div class="ns-auto-refresh">
            <label>
                <input type="checkbox" id="autoRefreshToggle" checked>
                {{ lang._('Auto-refresh (30s)') }}
            </label>
        </div>
        <button class="ns-btn ns-btn-sm ns-btn-outline" id="btnExportCsv" title="{{ lang._('Export CSV') }}">
            <i class="fa fa-download"></i>&nbsp; {{ lang._('CSV') }}
        </button>
        <button class="ns-btn ns-btn-sm ns-btn-danger" id="btnPurgeOpen" title="{{ lang._('Purge Old Data') }}">
            <i class="fa fa-trash"></i>&nbsp; {{ lang._('Purge') }}
        </button>
    </div>
</div>

<!-- ── Stats Bar ────────────────────────────────── -->
<div class="ns-stats-bar">
    <div class="ns-stat-card">
        <div class="stat-value" id="statTotalConn">-</div>
        <div class="stat-label">{{ lang._('Total Connections (Today)') }}</div>
    </div>
    <div class="ns-stat-card blocked">
        <div class="stat-value" id="statBlocked">-</div>
        <div class="stat-label">{{ lang._('Blocked (Today)') }}</div>
    </div>
    <div class="ns-stat-card devices">
        <div class="stat-value" id="statActiveDevices">-</div>
        <div class="stat-label">{{ lang._('Active Devices') }}</div>
    </div>
    <div class="ns-stat-card" style="--threat-color: var(--warning);">
        <div class="stat-value" id="statThreats" style="color: var(--warning);">-</div>
        <div class="stat-label">{{ lang._('Threats (Today)') }}</div>
    </div>
    <div class="ns-stat-card category">
        <div class="stat-value" id="statTopCategory">-</div>
        <div class="stat-label">{{ lang._('Top App Category') }}</div>
    </div>
</div>

<!-- ── Charts ───────────────────────────────────── -->
<div class="ns-charts-row">
    <div class="ns-chart-card">
        <h4><i class="fa fa-pie-chart"></i>&nbsp; {{ lang._('Top Apps') }}</h4>
        <div class="ns-chart-container">
            <canvas id="chartCategories"></canvas>
        </div>
    </div>
    <div class="ns-chart-card">
        <h4><i class="fa fa-desktop"></i>&nbsp; {{ lang._('Top Devices') }}</h4>
        <div class="ns-chart-container">
            <canvas id="chartDevices"></canvas>
        </div>
    </div>
</div>

<!-- ── Filter Bar ───────────────────────────────── -->
<div class="ns-filter-bar">
    <div class="ns-filter-group">
        <label>{{ lang._('Device') }}</label>
        <select id="filterDevice">
            <option value="">{{ lang._('All Devices') }}</option>
        </select>
    </div>
    <div class="ns-filter-group">
        <label>{{ lang._('Status') }}</label>
        <div class="ns-toggle-group" id="filterStatusGroup">
            <button data-val="" class="active">{{ lang._('All') }}</button>
            <button data-val="allowed">{{ lang._('Allowed') }}</button>
            <button data-val="blocked">{{ lang._('Blocked') }}</button>
            <button data-val="threats" style="color:var(--warning);">{{ lang._('Threats') }}</button>
        </div>
    </div>
    <div class="ns-filter-group">
        <label>{{ lang._('App Category') }}</label>
        <select id="filterCategory">
            <option value="">{{ lang._('All Categories') }}</option>
        </select>
    </div>
    <div class="ns-filter-group">
        <label>{{ lang._('From') }}</label>
        <input type="datetime-local" id="filterDateFrom">
    </div>
    <div class="ns-filter-group">
        <label>{{ lang._('To') }}</label>
        <input type="datetime-local" id="filterDateTo">
    </div>
    <div class="ns-filter-group">
        <label>{{ lang._('Search') }}</label>
        <input type="text" id="filterSearch" placeholder="{{ lang._('domain, IP, app...') }}" style="min-width:180px;">
    </div>
    <div class="ns-filter-group" style="justify-content:flex-end;">
        <button class="ns-btn" id="btnApplyFilter">
            <i class="fa fa-search"></i>&nbsp; {{ lang._('Apply') }}
        </button>
    </div>
</div>

<!-- ── Data Table ───────────────────────────────── -->
<div class="ns-table-wrap">
    <table class="ns-table" id="sessionsTable">
        <thead>
            <tr>
                <th>{{ lang._('Time') }}</th>
                <th>{{ lang._('Device') }}</th>
                <th>{{ lang._('Device IP') }}</th>
                <th>{{ lang._('Destination') }}</th>
                <th>{{ lang._('Dest IP') }}</th>
                <th>{{ lang._('Protocol') }}</th>
                <th>{{ lang._('App Category') }}</th>
                <th>{{ lang._('Application') }}</th>
                <th>{{ lang._('Data') }}</th>
                <th>{{ lang._('Status') }}</th>
                <th>{{ lang._('Security Category') }}</th>
                <th>{{ lang._('Block Reason') }}</th>
                <th>{{ lang._('Actions') }}</th>
            </tr>
        </thead>
        <tbody id="sessionsBody">
            <tr><td colspan="13" class="ns-loading"><div class="ns-spinner"></div><br>{{ lang._('Loading sessions...') }}</td></tr>
        </tbody>
    </table>
    <div class="ns-pagination">
        <div class="page-info">
            <span id="pageInfo">-</span>
            &nbsp;&nbsp;
            <label style="font-size: 0.96rem; color:var(--text-muted);">
                {{ lang._('Rows:') }}
                <select class="ns-rows-select" id="rowsPerPage">
                    <option value="25">25</option>
                    <option value="50" selected>50</option>
                    <option value="100">100</option>
                    <option value="250">250</option>
                </select>
            </label>
        </div>
        <div class="page-controls" id="pageControls"></div>
    </div>
</div>

<!-- ── Purge Modal ──────────────────────────────── -->
<div class="ns-modal-overlay" id="purgeModal">
    <div class="ns-modal">
        <h3><i class="fa fa-trash"></i>&nbsp; {{ lang._('Purge Old Sessions') }}</h3>
        <p>{{ lang._('Delete session logs older than the specified number of days. This action cannot be undone.') }}</p>
        <div class="ns-filter-group" style="margin-bottom:20px;">
            <label>{{ lang._('Days to keep') }}</label>
            <input type="number" id="purgeDays" value="7" min="1" max="365" style="width:100px;">
        </div>
        <div class="ns-modal-actions">
            <button class="ns-btn ns-btn-outline" id="btnPurgeCancel">{{ lang._('Cancel') }}</button>
            <button class="ns-btn ns-btn-danger" id="btnPurgeConfirm">
                <i class="fa fa-trash"></i>&nbsp; {{ lang._('Purge Now') }}
            </button>
        </div>
    </div>
</div>

<script>
$(document).ready(function () {

    /* ── HTML escape (native, no lodash) ────────── */
    var _escMap = {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'};
    function _escape(s) {
        if (s == null) return '';
        return String(s).replace(/[&<>"']/g, function(c){ return _escMap[c]; });
    }

    /* ── State ──────────────────────────────────── */
    var currentPage = 1;
    var totalRows = 0;
    var totalPages = 0;
    var autoRefreshTimer = null;
    var chartCategories = null;
    var chartDevices = null;

    var chartColors = [
        '#3b82f6','#22c55e','#f59e0b','#ef4444','#a855f7',
        '#06b6d4','#ec4899','#f97316','#14b8a6','#8b5cf6'
    ];

    /* ── Helpers ────────────────────────────────── */
    function getFilters() {
        var statusVal = $('#filterStatusGroup button.active').data('val') || '';
        return {
            device:   $('#filterDevice').val(),
            status:   statusVal,
            blocked:  statusVal === 'blocked' ? '1' : (statusVal === 'allowed' ? '0' : ''),
            category: $('#filterCategory').val(),
            app_category: $('#filterCategory').val(),
            from:     $('#filterDateFrom').val(),
            to:       $('#filterDateTo').val(),
            start_date: $('#filterDateFrom').val(),
            end_date: $('#filterDateTo').val(),
            search:   $('#filterSearch').val(),
            limit:    parseInt($('#rowsPerPage').val()),
            page:     currentPage
        };
    }

    function formatTime(ts) {
        if (!ts) return '-';
        var d = new Date(ts);
        if (isNaN(d)) return _escape(ts);
        var pad = function(n){ return n < 10 ? '0'+n : n; };
        return d.getFullYear()+'-'+pad(d.getMonth()+1)+'-'+pad(d.getDate())+' '+
               pad(d.getHours())+':'+pad(d.getMinutes())+':'+pad(d.getSeconds());
    }

    function statusBadge(status) {
        if (status === 'blocked') {
            return '<span class="ns-badge ns-badge-blocked"><i class="fa fa-ban"></i> Blocked</span>';
        }
        return '<span class="ns-badge ns-badge-allowed"><i class="fa fa-check"></i> Allowed</span>';
    }

    function securityBadge(secCat, blockType) {
        if (!secCat && !blockType) return '-';
        var label = secCat || blockType || '';
        var cls = 'ns-badge-category';
        var lcLabel = label.toLowerCase();
        if (lcLabel.indexOf('malware') >= 0 || lcLabel.indexOf('threat') >= 0 || lcLabel.indexOf('phish') >= 0) {
            cls = 'ns-badge-threat';
        } else if (lcLabel.indexOf('policy') >= 0 || lcLabel.indexOf('no internet') >= 0 || lcLabel.indexOf('device') >= 0) {
            cls = 'ns-badge-policy';
        } else if (lcLabel.indexOf('ad') >= 0 || lcLabel.indexOf('track') >= 0) {
            cls = 'ns-badge-blocked';
        }
        return '<span class="ns-badge ' + cls + '">' + _escape(label) + '</span>';
    }

    function formatBytes(bytesIn, bytesOut) {
        var total = (parseInt(bytesIn) || 0) + (parseInt(bytesOut) || 0);
        if (total === 0) return '-';
        if (total < 1024) return total + ' B';
        if (total < 1048576) return (total / 1024).toFixed(1) + ' KB';
        if (total < 1073741824) return (total / 1048576).toFixed(1) + ' MB';
        return (total / 1073741824).toFixed(1) + ' GB';
    }

    /* ── Load Stats ─────────────────────────────── */
    function loadStats() {
        $.ajax({
            url: '/api/netshield/sessions/stats',
            type: 'GET',
            dataType: 'json',
            success: function(data) {
                if (data && data.status === 'ok') {
                    var d = data.data || {};
                    var today = d.today || {};
                    $('#statTotalConn').text(d.total_connections != null ? d.total_connections.toLocaleString() : '0');
                    $('#statBlocked').text(d.blocked_count != null ? d.blocked_count.toLocaleString() : '0');
                    $('#statActiveDevices').text(today.top_devices ? today.top_devices.length.toLocaleString() : '0');
                    $('#statThreats').text('0');
                    $('#statTopCategory').text(today.top_categories && today.top_categories.length ? today.top_categories[0].category : '-');

                    /* Populate filter dropdowns */
                    if (today.top_devices && today.top_devices.length) {
                        var cur = $('#filterDevice').val();
                        $('#filterDevice').find('option:not(:first)').remove();
                        $.each(today.top_devices, function(i, d) {
                            $('#filterDevice').append('<option value="' + _escape(d.ip) + '">' + _escape(d.name || d.ip) + '</option>');
                        });
                        if (cur) $('#filterDevice').val(cur);
                    }
                    if (today.top_categories && today.top_categories.length) {
                        var curCat = $('#filterCategory').val();
                        $('#filterCategory').find('option:not(:first)').remove();
                        $.each(today.top_categories, function(i, c) {
                            $('#filterCategory').append('<option value="' + _escape(c.category) + '">' + _escape(c.category) + '</option>');
                        });
                        if (curCat) $('#filterCategory').val(curCat);
                    }

                    /* Charts */
                    updateCharts(today);
                }
            }
        });
    }

    /* ── Charts ─────────────────────────────────── */
    function updateCharts(stats) {
        /* Top Apps donut (prefer top_apps with real app names, fallback to categories) */
        var appData = stats.top_apps || [];
        var catLabels = [], catValues = [];
        if (appData.length) {
            $.each(appData, function(i, a) {
                catLabels.push(a.app || 'Unknown');
                catValues.push(a.count || 0);
            });
        } else {
            $.each(stats.top_categories || [], function(i, c) {
                catLabels.push(c.category || 'Unknown');
                catValues.push(c.count || 0);
            });
        }

        if (chartCategories) chartCategories.destroy();
        var ctxCat = document.getElementById('chartCategories').getContext('2d');
        chartCategories = new Chart(ctxCat, {
            type: 'doughnut',
            data: {
                labels: catLabels,
                datasets: [{
                    data: catValues,
                    backgroundColor: chartColors.slice(0, catLabels.length),
                    borderColor: 'rgba(0,0,0,0.3)',
                    borderWidth: 1
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'right',
                        labels: { color: '#94a3b8', font: { size: 11 }, padding: 8 }
                    }
                },
                cutout: '55%'
            }
        });

        /* Top Devices donut */
        var devData = stats.top_devices || [];
        var devLabels = [], devValues = [];
        $.each(devData, function(i, d) {
            devLabels.push(d.name || d.ip || 'Unknown');
            devValues.push(d.count || 0);
        });

        if (chartDevices) chartDevices.destroy();
        var ctxDev = document.getElementById('chartDevices').getContext('2d');
        chartDevices = new Chart(ctxDev, {
            type: 'doughnut',
            data: {
                labels: devLabels,
                datasets: [{
                    data: devValues,
                    backgroundColor: chartColors.slice(0, devLabels.length),
                    borderColor: 'rgba(0,0,0,0.3)',
                    borderWidth: 1
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'right',
                        labels: { color: '#94a3b8', font: { size: 11 }, padding: 8 }
                    }
                },
                cutout: '55%'
            }
        });
    }

    /* ── Load Sessions (server-side pagination) ── */
    function loadSessions() {
        var filters = getFilters();
        var $body = $('#sessionsBody');
        $body.html('<tr><td colspan="13" class="ns-loading"><div class="ns-spinner"></div></td></tr>');

        $.ajax({
            url: '/api/netshield/sessions/search',
            type: 'POST',
            dataType: 'json',
            contentType: 'application/json',
            data: JSON.stringify(filters),
            success: function(data) {
                if (!data || data.status !== 'ok') {
                    $body.html('<tr><td colspan="13" class="ns-loading">' + _escape(data && data.message ? data.message : 'Error loading sessions') + '</td></tr>');
                    return;
                }

                totalRows = data.total || 0;
                totalPages = Math.ceil(totalRows / filters.limit) || 1;
                var rows = data.rows || [];

                if (rows.length === 0) {
                    $body.html('<tr><td colspan="13" class="ns-loading" style="padding:30px;">{{ lang._("No sessions found matching your filters.") }}</td></tr>');
                } else {
                    var html = '';
                    $.each(rows, function(i, r) {
                        var isBlocked = (r.status === 'blocked' || r.blocked == 1);
                        var rowClass = isBlocked ? ' class="ns-row-blocked"' : '';
                        var statusVal = isBlocked ? 'blocked' : 'allowed';
                        var domain = r.dst_hostname || r.destination || '';
                        var actionBtn = '';
                        if (isBlocked) {
                            actionBtn = '<button class="ns-btn-unblock" data-domain="' + _escape(domain) + '"><i class="fa fa-check"></i> Unblock</button>';
                        } else if (domain) {
                            actionBtn = '<button class="ns-btn-block" data-domain="' + _escape(domain) + '"><i class="fa fa-ban"></i> Block</button>';
                        }
                        var statusHtml = statusBadge(statusVal);
                        var secCatHtml = isBlocked ? securityBadge(r.security_category, r.block_type) : '-';
                        var blockReasonHtml = isBlocked ? _escape(r.block_reason || r.block_policy || '-') : '-';

                        html += '<tr' + rowClass + '>' +
                            '<td>' + formatTime(r.timestamp) + '</td>' +
                            '<td>' + _escape(r.device_name || '-') + '</td>' +
                            '<td>' + _escape(r.device_ip || '-') + '</td>' +
                            '<td title="' + _escape(domain) + '">' + _escape(domain || '-') + '</td>' +
                            '<td>' + _escape(r.dst_ip || '-') + '</td>' +
                            '<td>' + _escape(r.protocol || 'DNS') + '</td>' +
                            '<td>' + _escape(r.app_category || '-') + '</td>' +
                            '<td>' + _escape(r.application || '-') + '</td>' +
                            '<td>' + formatBytes(r.bytes_in, r.bytes_out) + '</td>' +
                            '<td>' + statusHtml + '</td>' +
                            '<td>' + secCatHtml + '</td>' +
                            '<td>' + blockReasonHtml + '</td>' +
                            '<td>' + actionBtn + '</td>' +
                            '</tr>';
                    });
                    $body.html(html);
                }

                updatePagination();
                updateTimestamp();
            },
            error: function(xhr) {
                $body.html('<tr><td colspan="13" class="ns-loading">{{ lang._("Failed to load sessions. Check API connection.") }}</td></tr>');
            }
        });
    }

    /* ── Pagination Controls ────────────────────── */
    function updatePagination() {
        var limit = parseInt($('#rowsPerPage').val());
        var from = totalRows === 0 ? 0 : ((currentPage - 1) * limit + 1);
        var to = Math.min(currentPage * limit, totalRows);
        $('#pageInfo').text(from + '-' + to + ' of ' + totalRows.toLocaleString());

        var $pc = $('#pageControls');
        $pc.empty();

        $pc.append('<button ' + (currentPage <= 1 ? 'disabled' : '') + ' data-page="1" title="First"><i class="fa fa-angle-double-left"></i></button>');
        $pc.append('<button ' + (currentPage <= 1 ? 'disabled' : '') + ' data-page="' + (currentPage - 1) + '"><i class="fa fa-angle-left"></i></button>');

        var startP = Math.max(1, currentPage - 2);
        var endP = Math.min(totalPages, currentPage + 2);
        for (var p = startP; p <= endP; p++) {
            $pc.append('<button data-page="' + p + '"' + (p === currentPage ? ' class="active"' : '') + '>' + p + '</button>');
        }

        $pc.append('<button ' + (currentPage >= totalPages ? 'disabled' : '') + ' data-page="' + (currentPage + 1) + '"><i class="fa fa-angle-right"></i></button>');
        $pc.append('<button ' + (currentPage >= totalPages ? 'disabled' : '') + ' data-page="' + totalPages + '" title="Last"><i class="fa fa-angle-double-right"></i></button>');
    }

    function updateTimestamp() {
        var now = new Date();
        var pad = function(n){ return n < 10 ? '0'+n : n; };
        $('#lastUpdated').text('Updated: ' + pad(now.getHours()) + ':' + pad(now.getMinutes()) + ':' + pad(now.getSeconds()));
    }

    /* ── Events ─────────────────────────────────── */

    /* Pagination click */
    $(document).on('click', '#pageControls button:not(:disabled)', function() {
        currentPage = parseInt($(this).data('page'));
        loadSessions();
    });

    /* Rows per page */
    $('#rowsPerPage').on('change', function() {
        currentPage = 1;
        loadSessions();
    });

    /* Status toggle */
    $('#filterStatusGroup button').on('click', function() {
        $('#filterStatusGroup button').removeClass('active');
        $(this).addClass('active');
    });

    /* Apply filter */
    $('#btnApplyFilter').on('click', function() {
        currentPage = 1;
        loadSessions();
        loadStats();
    });

    /* Enter key in search */
    $('#filterSearch').on('keypress', function(e) {
        if (e.which === 13) {
            currentPage = 1;
            loadSessions();
            loadStats();
        }
    });

    /* Block domain */
    $(document).on('click', '.ns-btn-block', function() {
        var domain = $(this).data('domain');
        if (!domain) return;
        if (!confirm('Block domain "' + domain + '"?\nThis will add it to the DNS blocklist.')) return;
        var $btn = $(this);
        $btn.prop('disabled', true).html('<i class="fa fa-spinner fa-spin"></i>');
        $.ajax({
            url: '/api/netshield/sessions/blockDomain',
            type: 'POST',
            dataType: 'json',
            contentType: 'application/json',
            data: JSON.stringify({domain: domain}),
            success: function(data) {
                if (data && data.status === 'ok') {
                    loadSessions();
                    loadStats();
                } else {
                    alert('Block failed: ' + (data && data.message ? data.message : 'Unknown error'));
                    $btn.prop('disabled', false).html('<i class="fa fa-ban"></i> Block');
                }
            },
            error: function() {
                alert('Block request failed.');
                $btn.prop('disabled', false).html('<i class="fa fa-ban"></i> Block');
            }
        });
    });

    /* Unblock domain */
    $(document).on('click', '.ns-btn-unblock', function() {
        var domain = $(this).data('domain');
        if (!domain) return;
        if (!confirm('Unblock domain "' + domain + '"?\nThis will remove it from the blocklist.')) return;
        var $btn = $(this);
        $btn.prop('disabled', true).html('<i class="fa fa-spinner fa-spin"></i>');
        $.ajax({
            url: '/api/netshield/sessions/unblockDomain',
            type: 'POST',
            dataType: 'json',
            contentType: 'application/json',
            data: JSON.stringify({domain: domain}),
            success: function(data) {
                if (data && data.status === 'ok') {
                    loadSessions();
                    loadStats();
                } else {
                    alert('Unblock failed: ' + (data && data.message ? data.message : 'Unknown error'));
                    $btn.prop('disabled', false).html('<i class="fa fa-check"></i> Unblock');
                }
            },
            error: function() {
                alert('Unblock request failed.');
                $btn.prop('disabled', false).html('<i class="fa fa-check"></i> Unblock');
            }
        });
    });

    /* Auto-refresh */
    function startAutoRefresh() {
        stopAutoRefresh();
        autoRefreshTimer = setInterval(function() {
            loadSessions();
            loadStats();
        }, 30000);
    }
    function stopAutoRefresh() {
        if (autoRefreshTimer) {
            clearInterval(autoRefreshTimer);
            autoRefreshTimer = null;
        }
    }

    $('#autoRefreshToggle').on('change', function() {
        if ($(this).is(':checked')) {
            startAutoRefresh();
        } else {
            stopAutoRefresh();
        }
    });

    /* Export CSV */
    $('#btnExportCsv').on('click', function() {
        var filters = getFilters();
        filters.limit = 0; /* 0 = all */
        filters.format = 'csv';

        $.ajax({
            url: '/api/netshield/sessions/search',
            type: 'POST',
            dataType: 'text',
            contentType: 'application/json',
            data: JSON.stringify(filters),
            success: function(csv) {
                var blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
                var url = URL.createObjectURL(blob);
                var a = document.createElement('a');
                a.href = url;
                a.download = 'netshield_sessions_' + new Date().toISOString().slice(0,10) + '.csv';
                document.body.appendChild(a);
                a.click();
                document.body.removeChild(a);
                URL.revokeObjectURL(url);
            },
            error: function() {
                alert('Export failed. Please try again.');
            }
        });
    });

    /* Purge modal */
    $('#btnPurgeOpen').on('click', function() {
        $('#purgeModal').addClass('active');
    });
    $('#btnPurgeCancel').on('click', function() {
        $('#purgeModal').removeClass('active');
    });
    $('#purgeModal').on('click', function(e) {
        if (e.target === this) $(this).removeClass('active');
    });

    $('#btnPurgeConfirm').on('click', function() {
        var days = parseInt($('#purgeDays').val());
        if (isNaN(days) || days < 1) {
            alert('Please enter a valid number of days (1-365).');
            return;
        }
        var $btn = $(this);
        $btn.prop('disabled', true).html('<i class="fa fa-spinner fa-spin"></i>&nbsp; Purging...');

        $.ajax({
            url: '/api/netshield/sessions/purge',
            type: 'POST',
            dataType: 'json',
            contentType: 'application/json',
            data: JSON.stringify({ days: days }),
            success: function(data) {
                $('#purgeModal').removeClass('active');
                $btn.prop('disabled', false).html('<i class="fa fa-trash"></i>&nbsp; {{ lang._("Purge Now") }}');
                if (data && data.status === 'ok') {
                    var msg = data.deleted != null ? data.deleted + ' records deleted.' : 'Purge completed.';
                    alert(msg);
                    loadSessions();
                    loadStats();
                } else {
                    alert('Purge failed: ' + (data && data.message ? data.message : 'Unknown error'));
                }
            },
            error: function() {
                $btn.prop('disabled', false).html('<i class="fa fa-trash"></i>&nbsp; {{ lang._("Purge Now") }}');
                alert('Purge request failed. Check API connection.');
            }
        });
    });

    /* ── Set default date range (today) ─────────── */
    function setDefaultDateRange() {
        var now = new Date();
        var y = now.getFullYear();
        var m = (now.getMonth()+1 < 10 ? '0' : '') + (now.getMonth()+1);
        var d = (now.getDate() < 10 ? '0' : '') + now.getDate();
        $('#filterDateFrom').val(y + '-' + m + '-' + d + 'T00:00');
        $('#filterDateTo').val(y + '-' + m + '-' + d + 'T23:59');
    }

    /* ── Init ───────────────────────────────────── */
    setDefaultDateRange();
    loadStats();
    loadSessions();
    startAutoRefresh();

});
</script>
