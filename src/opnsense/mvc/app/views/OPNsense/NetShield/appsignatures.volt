{#
# Copyright (C) 2025-2026 NetShield
# All rights reserved.
#
# Application Signatures - DPI Application Identification
#}

<style>
.ns-apps-header {
    background: linear-gradient(135deg, #0891b2 0%, #06b6d4 100%);
    border-radius: 12px;
    padding: 24px;
    color: #fff;
    margin-bottom: 24px;
    display: flex;
    align-items: center;
    justify-content: space-between;
}
.ns-apps-header h2 { margin: 0; font-weight: 600; }
.ns-apps-stats {
    display: flex;
    gap: 24px;
}
.ns-apps-stats .stat {
    text-align: center;
}
.ns-apps-stats .stat-value {
    font-size: 28px;
    font-weight: 700;
}
.ns-apps-stats .stat-label {
    font-size: 12px;
    opacity: 0.8;
}

.ns-apps-search {
    display: flex;
    gap: 12px;
    margin-bottom: 24px;
}
.ns-apps-search input {
    flex: 1;
    padding: 12px 16px;
    border: 2px solid #e5e7eb;
    border-radius: 10px;
    font-size: 15px;
}
.ns-apps-search input:focus {
    outline: none;
    border-color: #06b6d4;
}
.ns-apps-search select {
    padding: 12px 16px;
    border: 2px solid #e5e7eb;
    border-radius: 10px;
    font-size: 14px;
    min-width: 200px;
}

.ns-apps-categories {
    display: flex;
    flex-wrap: wrap;
    gap: 10px;
    margin-bottom: 24px;
}
.ns-category-btn {
    padding: 8px 16px;
    border-radius: 20px;
    border: 2px solid #e5e7eb;
    background: #fff;
    cursor: pointer;
    transition: all 0.2s;
    font-size: 13px;
    font-weight: 500;
}
.ns-category-btn:hover {
    border-color: #06b6d4;
    background: #ecfeff;
}
.ns-category-btn.active {
    border-color: #06b6d4;
    background: #06b6d4;
    color: #fff;
}
.ns-category-btn .count {
    background: rgba(0,0,0,0.1);
    padding: 2px 8px;
    border-radius: 10px;
    font-size: 11px;
    margin-left: 6px;
}

.ns-apps-grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
    gap: 16px;
}
.ns-app-card {
    background: #fff;
    border-radius: 12px;
    border: 1px solid #e5e7eb;
    padding: 16px;
    display: flex;
    align-items: center;
    gap: 12px;
    transition: all 0.2s;
}
.ns-app-card:hover {
    border-color: #06b6d4;
    box-shadow: 0 4px 12px rgba(6, 182, 212, 0.15);
}
.ns-app-card .app-icon {
    width: 48px; height: 48px;
    border-radius: 12px;
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 24px;
    flex-shrink: 0;
}
.ns-app-card .app-icon.streaming { background: #dcfce7; color: #16a34a; }
.ns-app-card .app-icon.social { background: #dbeafe; color: #2563eb; }
.ns-app-card .app-icon.gaming { background: #f3e8ff; color: #9333ea; }
.ns-app-card .app-icon.vpn { background: #fef3c7; color: #d97706; }
.ns-app-card .app-icon.p2p { background: #fee2e2; color: #dc2626; }
.ns-app-card .app-icon.productivity { background: #e0e7ff; color: #4f46e5; }
.ns-app-card .app-icon.default { background: #f3f4f6; color: #6b7280; }
.ns-app-card .app-info { flex: 1; }
.ns-app-card .app-name {
    font-weight: 600;
    font-size: 15px;
    color: #111827;
}
.ns-app-card .app-category {
    font-size: 12px;
    color: #6b7280;
}
.ns-app-card .app-risk {
    font-size: 11px;
    padding: 3px 8px;
    border-radius: 6px;
}
.ns-app-card .app-risk.high { background: #fee2e2; color: #dc2626; }
.ns-app-card .app-risk.medium { background: #fef3c7; color: #d97706; }
.ns-app-card .app-risk.low { background: #dcfce7; color: #16a34a; }
.ns-app-card .app-traffic {
    text-align: right;
    font-size: 12px;
}
.ns-app-card .app-traffic .bytes {
    font-weight: 600;
    color: #111827;
}
.ns-app-card .app-traffic .label {
    color: #9ca3af;
}

.ns-app-detail {
    background: #fff;
    border-radius: 12px;
    border: 1px solid #e5e7eb;
    padding: 20px;
    margin-bottom: 24px;
}
.ns-app-detail h3 {
    margin: 0 0 16px 0;
    font-weight: 600;
}
.ns-app-detail .info-grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));
    gap: 16px;
}
.ns-app-detail .info-item {
    padding: 12px;
    background: #f9fafb;
    border-radius: 8px;
}
.ns-app-detail .info-label {
    font-size: 12px;
    color: #6b7280;
    margin-bottom: 4px;
}
.ns-app-detail .info-value {
    font-weight: 600;
    color: #111827;
}
.ns-app-detail .domains-list {
    margin-top: 16px;
    padding: 12px;
    background: #f9fafb;
    border-radius: 8px;
    max-height: 150px;
    overflow-y: auto;
}
.ns-app-detail .domain-item {
    font-family: monospace;
    font-size: 13px;
    padding: 4px 0;
    border-bottom: 1px solid #e5e7eb;
}
.ns-app-detail .domain-item:last-child {
    border-bottom: none;
}

.ns-panel {
    background: #fff;
    border-radius: 12px;
    border: 1px solid #e5e7eb;
    margin-bottom: 24px;
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
</style>

<script>
$(document).ready(function() {
    // HTML escape helper
    function escapeHtml(str) {
        if (!str) return '';
        return String(str).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;');
    }

    var selectedCategory = null;
    var selectedApp = null;

    function loadStats() {
        $.getJSON('/api/netshield/appsignatures/stats', function(data) {
            if (!data) return;
            $('#stat-total-apps').text(data.total_apps || 0);
            $('#stat-categories').text(data.total_categories || 0);
            $('#stat-domains').text((data.total_domains || 0).toLocaleString());
        });
    }

    function loadCategories() {
        $.getJSON('/api/netshield/appsignatures/categories', function(data) {
            var $container = $('#categories-container').empty();
            var categories = data.categories || [];

            // Add "All" button
            $container.append(
                '<button class="ns-category-btn active" data-category="">' +
                    '{{ lang._("All") }}' +
                '</button>'
            );

            categories.forEach(function(cat) {
                $container.append(
                    '<button class="ns-category-btn" data-category="' + escapeHtml(cat.id || cat.name) + '">' +
                        escapeHtml(cat.name) +
                        '<span class="count">' + (cat.count || 0) + '</span>' +
                    '</button>'
                );
            });

            // Also populate dropdown
            var $select = $('#category-filter').empty();
            $select.append('<option value="">{{ lang._("All Categories") }}</option>');
            categories.forEach(function(cat) {
                $select.append('<option value="' + escapeHtml(cat.id || cat.name) + '">' + escapeHtml(cat.name) + '</option>');
            });

            // Category button click
            $('.ns-category-btn').click(function() {
                $('.ns-category-btn').removeClass('active');
                $(this).addClass('active');
                selectedCategory = $(this).data('category');
                loadApps(selectedCategory);
            });
        });
    }

    function loadApps(category, search) {
        var url = '/api/netshield/appsignatures/list';
        var params = [];
        if (category) params.push('category=' + encodeURIComponent(category));
        if (search) params.push('search=' + encodeURIComponent(search));
        if (params.length) url += '?' + params.join('&');

        $.getJSON(url, function(data) {
            var $grid = $('#apps-grid').empty();
            var apps = data.apps || [];

            if (!apps.length) {
                $grid.html('<div class="text-center text-muted p-4">{{ lang._("No applications found") }}</div>');
                return;
            }

            apps.forEach(function(app) {
                var iconClass = getCategoryIcon(app.category);
                var riskClass = (app.risk || 'low').toLowerCase();

                $grid.append(
                    '<div class="ns-app-card" data-app="' + escapeHtml(app.id) + '">' +
                        '<div class="app-icon ' + iconClass + '">' +
                            '<i class="fa ' + getCategoryFa(app.category) + '"></i>' +
                        '</div>' +
                        '<div class="app-info">' +
                            '<div class="app-name">' + escapeHtml(app.name) + '</div>' +
                            '<div class="app-category">' + escapeHtml(app.category) + '</div>' +
                        '</div>' +
                        '<span class="app-risk ' + riskClass + '">' + escapeHtml(app.risk || 'low') + '</span>' +
                    '</div>'
                );
            });

            // App card click
            $('.ns-app-card').click(function() {
                var appId = $(this).data('app');
                showAppDetail(appId);
            });
        });
    }

    function showAppDetail(appId) {
        // Find app in loaded data or fetch it
        $.getJSON('/api/netshield/appsignatures/list', function(data) {
            var app = (data.apps || []).find(function(a) { return a.id === appId; });
            if (!app) return;

            selectedApp = app;
            var $detail = $('#app-detail');

            $('#detail-app-name').text(app.name);
            $('#detail-app-category').text(app.category);
            $('#detail-app-risk').text(app.risk || 'low');

            // Domains
            var $domains = $('#detail-domains').empty();
            (app.domains || []).forEach(function(domain) {
                $domains.append('<div class="domain-item">' + escapeHtml(domain) + '</div>');
            });

            // Ports
            var ports = (app.ports || []).join(', ') || '{{ lang._("Any") }}';
            $('#detail-ports').text(ports);

            $detail.show();
        });
    }

    function getCategoryIcon(cat) {
        if (/stream|video|netflix|youtube|twitch/i.test(cat)) return 'streaming';
        if (/social|facebook|instagram|twitter/i.test(cat)) return 'social';
        if (/gam(e|ing)/i.test(cat)) return 'gaming';
        if (/vpn|proxy|tunnel/i.test(cat)) return 'vpn';
        if (/p2p|torrent|file.*shar/i.test(cat)) return 'p2p';
        if (/productiv|office|business/i.test(cat)) return 'productivity';
        return 'default';
    }

    function getCategoryFa(cat) {
        if (/stream|video/i.test(cat)) return 'fa-play-circle';
        if (/social/i.test(cat)) return 'fa-users';
        if (/gam(e|ing)/i.test(cat)) return 'fa-gamepad';
        if (/vpn|proxy/i.test(cat)) return 'fa-shield';
        if (/p2p|torrent/i.test(cat)) return 'fa-cloud-download';
        if (/productiv|office/i.test(cat)) return 'fa-briefcase';
        if (/messag|chat/i.test(cat)) return 'fa-comments';
        if (/music|audio/i.test(cat)) return 'fa-music';
        if (/news/i.test(cat)) return 'fa-newspaper-o';
        if (/shop|commerce/i.test(cat)) return 'fa-shopping-cart';
        return 'fa-cube';
    }

    // Search
    var searchTimeout;
    $('#app-search').on('input', function() {
        var query = $(this).val().trim();
        clearTimeout(searchTimeout);
        searchTimeout = setTimeout(function() {
            loadApps(selectedCategory, query);
        }, 300);
    });

    // Category filter dropdown
    $('#category-filter').change(function() {
        var cat = $(this).val();
        selectedCategory = cat;
        // Update button states
        $('.ns-category-btn').removeClass('active');
        $('.ns-category-btn[data-category="' + cat + '"]').addClass('active');
        loadApps(cat);
    });

    // Test domain
    $('#btn-test-domain').click(function() {
        var domain = $('#test-domain-input').val().trim();
        if (!domain) return;

        $.getJSON('/api/netshield/appsignatures/matchDomain?domain=' + encodeURIComponent(domain), function(data) {
            var $result = $('#domain-test-result');
            if (data && data.matched) {
                $result.html(
                    '<div class="alert alert-success">' +
                        '<strong>' + escapeHtml(domain) + '</strong> {{ lang._("matched to") }} ' +
                        '<strong>' + escapeHtml(data.name || data.app_id) + '</strong>' +
                        ' (' + escapeHtml(data.category) + ')' +
                    '</div>'
                ).show();
            } else {
                $result.html(
                    '<div class="alert alert-warning">' +
                        '<strong>' + escapeHtml(domain) + '</strong> {{ lang._("did not match any application") }}' +
                    '</div>'
                ).show();
            }
        });
    });

    // Close detail
    $('#btn-close-detail').click(function() {
        $('#app-detail').hide();
        selectedApp = null;
    });

    // Initialize
    loadStats();
    loadCategories();
    loadApps();
});
</script>

<!-- Header -->
<div class="ns-apps-header">
    <div>
        <h2><i class="fa fa-th-large"></i> {{ lang._('Application Signatures') }}</h2>
        <div style="margin-top: 8px; opacity: 0.9;">{{ lang._('Deep Packet Inspection application identification') }}</div>
    </div>
    <div class="ns-apps-stats">
        <div class="stat">
            <div class="stat-value" id="stat-total-apps">0</div>
            <div class="stat-label">{{ lang._('Applications') }}</div>
        </div>
        <div class="stat">
            <div class="stat-value" id="stat-categories">0</div>
            <div class="stat-label">{{ lang._('Categories') }}</div>
        </div>
        <div class="stat">
            <div class="stat-value" id="stat-domains">0</div>
            <div class="stat-label">{{ lang._('Domains') }}</div>
        </div>
    </div>
</div>

<!-- Domain Test -->
<div class="ns-panel">
    <div class="ns-panel-header">
        <h3><i class="fa fa-search"></i> {{ lang._('Test Domain') }}</h3>
    </div>
    <div class="ns-panel-body">
        <div class="ns-apps-search">
            <input type="text" id="test-domain-input" placeholder="{{ lang._('Enter domain to identify (e.g., netflix.com)') }}">
            <button class="btn btn-primary" id="btn-test-domain">
                <i class="fa fa-search"></i> {{ lang._('Identify') }}
            </button>
        </div>
        <div id="domain-test-result" style="display: none;"></div>
    </div>
</div>

<!-- Search & Filter -->
<div class="ns-apps-search">
    <input type="text" id="app-search" placeholder="{{ lang._('Search applications...') }}">
    <select id="category-filter">
        <option value="">{{ lang._('All Categories') }}</option>
    </select>
</div>

<!-- Categories -->
<div class="ns-apps-categories" id="categories-container">
    <span class="text-muted">{{ lang._('Loading categories...') }}</span>
</div>

<!-- App Detail (initially hidden) -->
<div class="ns-app-detail" id="app-detail" style="display: none;">
    <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 16px;">
        <h3 id="detail-app-name">-</h3>
        <button class="btn btn-sm btn-default" id="btn-close-detail">
            <i class="fa fa-times"></i>
        </button>
    </div>
    <div class="info-grid">
        <div class="info-item">
            <div class="info-label">{{ lang._('Category') }}</div>
            <div class="info-value" id="detail-app-category">-</div>
        </div>
        <div class="info-item">
            <div class="info-label">{{ lang._('Risk Level') }}</div>
            <div class="info-value" id="detail-app-risk">-</div>
        </div>
        <div class="info-item">
            <div class="info-label">{{ lang._('Ports') }}</div>
            <div class="info-value" id="detail-ports">-</div>
        </div>
    </div>
    <div class="domains-list">
        <div class="info-label" style="margin-bottom: 8px;">{{ lang._('Associated Domains') }}</div>
        <div id="detail-domains">-</div>
    </div>
</div>

<!-- Apps Grid -->
<div class="ns-apps-grid" id="apps-grid">
    <div class="text-muted">{{ lang._('Loading applications...') }}</div>
</div>
