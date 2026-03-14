{#
# Copyright (C) 2025-2026 NetShield
# All rights reserved.
#
# Web Categories Management - Zenarmor Style
#}

<style>
.ns-wc-header {
    background: linear-gradient(135deg, #7c3aed 0%, #a855f7 100%);
    border-radius: 12px;
    padding: 24px;
    color: #fff;
    margin-bottom: 24px;
    display: flex;
    align-items: center;
    justify-content: space-between;
}
.ns-wc-header h2 {
    margin: 0;
    font-weight: 600;
}
.ns-wc-header .stats {
    display: flex;
    gap: 30px;
}
.ns-wc-header .stat {
    text-align: center;
}
.ns-wc-header .stat-value {
    font-size: 28px;
    font-weight: 700;
}
.ns-wc-header .stat-label {
    font-size: 12px;
    opacity: 0.8;
}

.ns-wc-search {
    display: flex;
    gap: 12px;
    margin-bottom: 24px;
}
.ns-wc-search input {
    flex: 1;
    padding: 12px 16px;
    border: 2px solid #e5e7eb;
    border-radius: 10px;
    font-size: 15px;
    transition: border-color 0.2s;
}
.ns-wc-search input:focus {
    outline: none;
    border-color: #7c3aed;
}
.ns-wc-search .btn {
    padding: 12px 24px;
    border-radius: 10px;
}

.ns-category-groups {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
    gap: 16px;
    margin-bottom: 24px;
}
.ns-category-group {
    background: #fff;
    border-radius: 12px;
    padding: 16px;
    border: 2px solid #e5e7eb;
    cursor: pointer;
    transition: all 0.2s;
}
.ns-category-group:hover {
    border-color: #7c3aed;
    box-shadow: 0 4px 12px rgba(124, 58, 237, 0.15);
}
.ns-category-group.selected {
    border-color: #7c3aed;
    background: #faf5ff;
}
.ns-category-group .header {
    display: flex;
    align-items: center;
    gap: 12px;
    margin-bottom: 12px;
}
.ns-category-group .icon {
    width: 44px; height: 44px;
    border-radius: 10px;
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 20px;
}
.ns-category-group .icon.adult { background: #fee2e2; color: #dc2626; }
.ns-category-group .icon.malware { background: #fef3c7; color: #d97706; }
.ns-category-group .icon.social { background: #dbeafe; color: #2563eb; }
.ns-category-group .icon.streaming { background: #dcfce7; color: #16a34a; }
.ns-category-group .icon.gaming { background: #f3e8ff; color: #9333ea; }
.ns-category-group .icon.ads { background: #fce7f3; color: #db2777; }
.ns-category-group .icon.default { background: #f3f4f6; color: #6b7280; }
.ns-category-group .name {
    font-weight: 600;
    font-size: 16px;
    color: #111827;
}
.ns-category-group .count {
    font-size: 12px;
    color: #6b7280;
}
.ns-category-group .categories {
    display: flex;
    flex-wrap: wrap;
    gap: 6px;
}
.ns-category-group .cat-tag {
    font-size: 11px;
    padding: 4px 8px;
    border-radius: 6px;
    background: #f3f4f6;
    color: #4b5563;
}
.ns-category-group .cat-tag.blocked {
    background: #fee2e2;
    color: #dc2626;
}

.ns-category-list {
    background: #fff;
    border-radius: 12px;
    border: 1px solid #e5e7eb;
    overflow: hidden;
}
.ns-category-list-header {
    padding: 16px 20px;
    background: #f9fafb;
    border-bottom: 1px solid #e5e7eb;
    display: flex;
    align-items: center;
    justify-content: space-between;
}
.ns-category-list-header h3 {
    margin: 0;
    font-size: 16px;
    font-weight: 600;
}
.ns-category-item {
    display: flex;
    align-items: center;
    padding: 14px 20px;
    border-bottom: 1px solid #f3f4f6;
    transition: background 0.2s;
}
.ns-category-item:hover {
    background: #f9fafb;
}
.ns-category-item:last-child {
    border-bottom: none;
}
.ns-category-item .info {
    flex: 1;
}
.ns-category-item .name {
    font-weight: 500;
    color: #111827;
}
.ns-category-item .desc {
    font-size: 12px;
    color: #6b7280;
    margin-top: 2px;
}
.ns-category-item .stats {
    display: flex;
    gap: 16px;
    align-items: center;
}
.ns-category-item .stat {
    text-align: center;
    min-width: 60px;
}
.ns-category-item .stat-value {
    font-weight: 600;
    color: #111827;
}
.ns-category-item .stat-label {
    font-size: 10px;
    color: #9ca3af;
}
.ns-category-item .toggle {
    margin-left: 16px;
}

.ns-domain-test {
    background: #fff;
    border-radius: 12px;
    padding: 20px;
    border: 1px solid #e5e7eb;
    margin-bottom: 24px;
}
.ns-domain-test h4 {
    margin: 0 0 16px 0;
    font-weight: 600;
}
.ns-domain-test .result {
    margin-top: 16px;
    padding: 16px;
    border-radius: 8px;
    display: none;
}
.ns-domain-test .result.found {
    background: #f0fdf4;
    border: 1px solid #86efac;
}
.ns-domain-test .result.not-found {
    background: #f3f4f6;
    border: 1px solid #d1d5db;
}

/* Toggle switch */
.ns-toggle {
    position: relative;
    width: 48px;
    height: 26px;
}
.ns-toggle input {
    opacity: 0;
    width: 0;
    height: 0;
}
.ns-toggle .slider {
    position: absolute;
    cursor: pointer;
    top: 0; left: 0; right: 0; bottom: 0;
    background-color: #d1d5db;
    transition: 0.3s;
    border-radius: 26px;
}
.ns-toggle .slider:before {
    position: absolute;
    content: "";
    height: 20px;
    width: 20px;
    left: 3px;
    bottom: 3px;
    background-color: white;
    transition: 0.3s;
    border-radius: 50%;
}
.ns-toggle input:checked + .slider {
    background-color: #dc2626;
}
.ns-toggle input:checked + .slider:before {
    transform: translateX(22px);
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

    var selectedGroup = null;

    function loadStats() {
        $.getJSON('/api/netshield/webcategories/stats', function(data) {
            if (!data) return;
            $('#stat-total-categories').text(data.total_categories || 0);
            $('#stat-blocked-categories').text(data.blocked_categories || 0);
            $('#stat-queries-blocked').text((data.queries_blocked || 0).toLocaleString());
        });
    }

    function loadGroups() {
        $.getJSON('/api/netshield/webcategories/groups', function(data) {
            var $container = $('#category-groups').empty();
            var groups = data.groups || [];

            if (!groups.length) {
                $container.html('<div class="text-muted">{{ lang._("No category groups available") }}</div>');
                return;
            }

            groups.forEach(function(group) {
                var iconClass = getGroupIcon(group.name);
                var catTags = (group.categories || []).slice(0, 4).map(function(c) {
                    return '<span class="cat-tag' + (c.blocked ? ' blocked' : '') + '">' + _escape(c.name) + '</span>';
                }).join('');

                if ((group.categories || []).length > 4) {
                    catTags += '<span class="cat-tag">+' + ((group.categories || []).length - 4) + '</span>';
                }

                $container.append(
                    '<div class="ns-category-group" data-group="' + _escape(group.id || group.name) + '">' +
                        '<div class="header">' +
                            '<div class="icon ' + iconClass + '"><i class="fa ' + getGroupFa(group.name) + '"></i></div>' +
                            '<div>' +
                                '<div class="name">' + _escape(group.name) + '</div>' +
                                '<div class="count">' + (group.categories || []).length + ' {{ lang._("categories") }}</div>' +
                            '</div>' +
                        '</div>' +
                        '<div class="categories">' + catTags + '</div>' +
                    '</div>'
                );
            });

            $('.ns-category-group').click(function() {
                var group = $(this).data('group');
                $('.ns-category-group').removeClass('selected');
                $(this).addClass('selected');
                selectedGroup = group;
                loadCategoriesByGroup(group);
            });

            // Select first group
            if (groups.length) {
                $('.ns-category-group').first().click();
            }
        });
    }

    function loadCategoriesByGroup(group) {
        $.getJSON('/api/netshield/webcategories/list?group=' + encodeURIComponent(group), function(data) {
            var $list = $('#category-list').empty();
            var categories = data.categories || [];

            if (!categories.length) {
                $list.html('<div class="text-center text-muted p-4">{{ lang._("No categories in this group") }}</div>');
                return;
            }

            categories.forEach(function(cat) {
                $list.append(
                    '<div class="ns-category-item">' +
                        '<div class="info">' +
                            '<div class="name">' + _escape(cat.name) + '</div>' +
                            '<div class="desc">' + _escape(cat.description || '') + '</div>' +
                        '</div>' +
                        '<div class="stats">' +
                            '<div class="stat">' +
                                '<div class="stat-value">' + (cat.domains_count || 0).toLocaleString() + '</div>' +
                                '<div class="stat-label">{{ lang._("Domains") }}</div>' +
                            '</div>' +
                            '<div class="stat">' +
                                '<div class="stat-value">' + (cat.hits_today || 0) + '</div>' +
                                '<div class="stat-label">{{ lang._("Hits Today") }}</div>' +
                            '</div>' +
                        '</div>' +
                        '<label class="ns-toggle toggle">' +
                            '<input type="checkbox" class="cat-toggle" data-cat="' + _escape(cat.id || cat.name) + '" ' +
                                (cat.blocked ? 'checked' : '') + '>' +
                            '<span class="slider"></span>' +
                        '</label>' +
                    '</div>'
                );
            });

            $('.cat-toggle').change(function() {
                var cat = $(this).data('cat');
                var blocked = $(this).prop('checked');
                ajaxCall('/api/netshield/webcategories/' + (blocked ? 'enable' : 'disable'),
                    {category: cat}, function() {
                        loadStats();
                        loadGroups();
                    });
            });
        });
    }

    function loadAllCategories(search) {
        var url = '/api/netshield/webcategories/list';
        if (search) url += '?search=' + encodeURIComponent(search);

        $.getJSON(url, function(data) {
            var $list = $('#category-list').empty();
            var categories = data.categories || [];

            if (!categories.length) {
                $list.html('<div class="text-center text-muted p-4">{{ lang._("No categories found") }}</div>');
                return;
            }

            categories.forEach(function(cat) {
                $list.append(
                    '<div class="ns-category-item">' +
                        '<div class="info">' +
                            '<div class="name">' + _escape(cat.name) + '</div>' +
                            '<div class="desc">' + _escape(cat.description || cat.group || '') + '</div>' +
                        '</div>' +
                        '<div class="stats">' +
                            '<div class="stat">' +
                                '<div class="stat-value">' + (cat.domains_count || 0).toLocaleString() + '</div>' +
                                '<div class="stat-label">{{ lang._("Domains") }}</div>' +
                            '</div>' +
                        '</div>' +
                        '<label class="ns-toggle toggle">' +
                            '<input type="checkbox" class="cat-toggle" data-cat="' + _escape(cat.id || cat.name) + '" ' +
                                (cat.blocked ? 'checked' : '') + '>' +
                            '<span class="slider"></span>' +
                        '</label>' +
                    '</div>'
                );
            });

            $('.cat-toggle').change(function() {
                var cat = $(this).data('cat');
                var blocked = $(this).prop('checked');
                ajaxCall('/api/netshield/webcategories/' + (blocked ? 'enable' : 'disable'),
                    {category: cat}, function() {
                        loadStats();
                    });
            });
        });
    }

    // Search
    var searchTimeout;
    $('#category-search').on('input', function() {
        var query = $(this).val().trim();
        clearTimeout(searchTimeout);
        searchTimeout = setTimeout(function() {
            if (query.length >= 2) {
                $('.ns-category-group').removeClass('selected');
                selectedGroup = null;
                loadAllCategories(query);
            } else if (!query) {
                // Reset to groups view
                if ($('.ns-category-group').length) {
                    $('.ns-category-group').first().click();
                }
            }
        }, 300);
    });

    // Domain test
    $('#btn-test-domain').click(function() {
        var domain = $('#test-domain').val().trim();
        if (!domain) return;

        var $result = $('#domain-result');
        $result.removeClass('found not-found').hide();

        $.getJSON('/api/netshield/webcategories/classify?domain=' + encodeURIComponent(domain), function(data) {
            if (data && data.categories && data.categories.length) {
                var cats = data.categories.map(function(c) {
                    return '<span class="label label-' + (c.blocked ? 'danger' : 'info') + '">' + _escape(c.name) + '</span>';
                }).join(' ');
                $result.addClass('found').html(
                    '<strong>' + _escape(domain) + '</strong><br>' +
                    '{{ lang._("Categories") }}: ' + cats
                ).show();
            } else {
                $result.addClass('not-found').html(
                    '<strong>' + _escape(domain) + '</strong><br>' +
                    '{{ lang._("No category match found") }}'
                ).show();
            }
        });
    });

    // Block all in group
    $('#btn-block-group').click(function() {
        if (!selectedGroup) return;
        BootstrapDialog.confirm({
            title: '{{ lang._("Block All Categories") }}',
            message: '{{ lang._("Block all categories in this group?") }}',
            type: BootstrapDialog.TYPE_WARNING,
            callback: function(r) {
                if (r) {
                    ajaxCall('/api/netshield/webcategories/blockGroup', {group: selectedGroup}, function() {
                        loadStats();
                        loadGroups();
                        loadCategoriesByGroup(selectedGroup);
                    });
                }
            }
        });
    });

    // Unblock all in group
    $('#btn-unblock-group').click(function() {
        if (!selectedGroup) return;
        ajaxCall('/api/netshield/webcategories/unblockGroup', {group: selectedGroup}, function() {
            loadStats();
            loadGroups();
            loadCategoriesByGroup(selectedGroup);
        });
    });

    function getGroupIcon(name) {
        if (/adult|porn|xxx/i.test(name)) return 'adult';
        if (/malware|phishing|threat/i.test(name)) return 'malware';
        if (/social/i.test(name)) return 'social';
        if (/stream|video|media/i.test(name)) return 'streaming';
        if (/gam(e|ing)/i.test(name)) return 'gaming';
        if (/ad|track|market/i.test(name)) return 'ads';
        return 'default';
    }

    function getGroupFa(name) {
        if (/adult|porn/i.test(name)) return 'fa-eye-slash';
        if (/malware|phishing/i.test(name)) return 'fa-bug';
        if (/social/i.test(name)) return 'fa-users';
        if (/stream|video/i.test(name)) return 'fa-play-circle';
        if (/gam(e|ing)/i.test(name)) return 'fa-gamepad';
        if (/ad|track/i.test(name)) return 'fa-ban';
        if (/news/i.test(name)) return 'fa-newspaper-o';
        if (/shop/i.test(name)) return 'fa-shopping-cart';
        return 'fa-tags';
    }

    // Initialize
    loadStats();
    loadGroups();
});
</script>

<!-- Header -->
<div class="ns-wc-header">
    <div>
        <h2><i class="fa fa-tags"></i> {{ lang._('Web Categories') }}</h2>
        <div style="margin-top: 8px; opacity: 0.9;">{{ lang._('Block access to websites by content category') }}</div>
    </div>
    <div class="stats">
        <div class="stat">
            <div class="stat-value" id="stat-total-categories">0</div>
            <div class="stat-label">{{ lang._('Total Categories') }}</div>
        </div>
        <div class="stat">
            <div class="stat-value" id="stat-blocked-categories">0</div>
            <div class="stat-label">{{ lang._('Blocked') }}</div>
        </div>
        <div class="stat">
            <div class="stat-value" id="stat-queries-blocked">0</div>
            <div class="stat-label">{{ lang._('Queries Blocked') }}</div>
        </div>
    </div>
</div>

<!-- Domain Test -->
<div class="ns-domain-test">
    <h4><i class="fa fa-search"></i> {{ lang._('Test Domain Classification') }}</h4>
    <div class="ns-wc-search">
        <input type="text" id="test-domain" placeholder="{{ lang._('Enter domain to test (e.g., facebook.com)') }}">
        <button class="btn btn-primary" id="btn-test-domain">
            <i class="fa fa-search"></i> {{ lang._('Classify') }}
        </button>
    </div>
    <div class="result" id="domain-result"></div>
</div>

<!-- Search -->
<div class="ns-wc-search">
    <input type="text" id="category-search" placeholder="{{ lang._('Search categories...') }}">
</div>

<!-- Category Groups -->
<div class="ns-category-groups" id="category-groups">
    <div class="text-muted">{{ lang._('Loading categories...') }}</div>
</div>

<!-- Category List -->
<div class="ns-category-list">
    <div class="ns-category-list-header">
        <h3><i class="fa fa-list"></i> {{ lang._('Categories') }}</h3>
        <div class="btn-group">
            <button class="btn btn-sm btn-danger" id="btn-block-group">
                <i class="fa fa-ban"></i> {{ lang._('Block All') }}
            </button>
            <button class="btn btn-sm btn-default" id="btn-unblock-group">
                <i class="fa fa-check"></i> {{ lang._('Unblock All') }}
            </button>
        </div>
    </div>
    <div id="category-list">
        <div class="text-center text-muted p-4">{{ lang._('Select a category group') }}</div>
    </div>
</div>
