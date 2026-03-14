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

<style>
/* Zenarmor-style category tiles */
.ns-cat-grid {
    display: flex;
    flex-wrap: wrap;
    gap: 10px;
    padding: 10px 0;
}
.ns-cat-tile {
    width: 130px;
    border: 2px solid #ddd;
    border-radius: 8px;
    padding: 12px 8px;
    text-align: center;
    cursor: pointer;
    transition: all 0.2s;
    background: #fafafa;
    user-select: none;
}
.ns-cat-tile:hover {
    border-color: #aaa;
    background: #f0f0f0;
}
.ns-cat-tile.ns-cat-on {
    border-color: #d9534f;
    background: #fdf3f3;
}
.ns-cat-tile.ns-cat-on .ns-cat-icon { color: #d9534f; }
.ns-cat-tile.ns-cat-on .ns-cat-status { color: #d9534f; font-weight: bold; }
.ns-cat-icon { font-size: 28px; color: #aaa; margin-bottom: 6px; }
.ns-cat-name { font-size: 12px; font-weight: 600; color: #444; line-height: 1.3; }
.ns-cat-count { font-size: 10px; color: #999; margin-top: 2px; }
.ns-cat-status { font-size: 11px; color: #aaa; margin-top: 4px; }

/* Safe Search toggle button */
.ns-safe-search-btn {
    min-width: 120px;
}
</style>

<div class="content-box">
    <div class="content-box-main">

        <!-- Page Header -->
        <div class="row">
            <div class="col-xs-12">
                <div class="page-header">
                    <h1><span class="fa fa-filter fa-fw"></span> {{ lang._('DNS Filtering') }}</h1>
                </div>
            </div>
        </div>

        <!-- Stats Cards -->
        <div class="row" id="dns-stats-row">
            <div class="col-xs-6 col-sm-3">
                <div class="panel panel-default text-center">
                    <div class="panel-body">
                        <h2 id="stat-blocked-today" class="text-danger" style="margin:0 0 4px;">—</h2>
                        <p style="margin:0;">{{ lang._('Blocked Today') }}</p>
                    </div>
                </div>
            </div>
            <div class="col-xs-6 col-sm-3">
                <div class="panel panel-default text-center">
                    <div class="panel-body">
                        <h2 id="stat-active-rules" class="text-primary" style="margin:0 0 4px;">—</h2>
                        <p style="margin:0;">{{ lang._('Custom Rules') }}</p>
                    </div>
                </div>
            </div>
            <div class="col-xs-6 col-sm-3">
                <div class="panel panel-default text-center">
                    <div class="panel-body">
                        <h2 id="stat-blocklists-active" class="text-warning" style="margin:0 0 4px;">—</h2>
                        <p style="margin:0;">{{ lang._('Blocklists Active') }}</p>
                    </div>
                </div>
            </div>
            <div class="col-xs-6 col-sm-3">
                <div class="panel panel-default text-center">
                    <div class="panel-body" style="display:flex;align-items:center;justify-content:center;gap:10px;flex-wrap:wrap;">
                        <div>
                            <div class="text-muted" style="font-size:12px;">{{ lang._('Safe Search') }}</div>
                            <div id="safe-search-status" style="font-size:11px;margin-top:2px;">—</div>
                        </div>
                        <button id="btn-safe-search-toggle" class="btn btn-sm ns-safe-search-btn btn-default">
                            <span class="fa fa-google"></span> {{ lang._('Toggle') }}
                        </button>
                    </div>
                </div>
            </div>
        </div>

        <!-- ============================================================ -->
        <!-- WEB CATEGORIES (Zenarmor-style)                              -->
        <!-- ============================================================ -->
        <div class="panel panel-default">
            <div class="panel-heading">
                <h3 class="panel-title">
                    <span class="fa fa-th fa-fw"></span>
                    {{ lang._('Web Categories') }}
                    <small class="text-muted" style="font-size:11px; margin-left:8px;">
                        {{ lang._('Click a category to block / unblock all sites in it') }}
                    </small>
                    <span class="pull-right">
                        <button id="btn-block-all-cats" class="btn btn-xs btn-danger">
                            <span class="fa fa-ban"></span> {{ lang._('Block All') }}
                        </button>
                        <button id="btn-allow-all-cats" class="btn btn-xs btn-success" style="margin-left:4px;">
                            <span class="fa fa-check"></span> {{ lang._('Allow All') }}
                        </button>
                    </span>
                </h3>
            </div>
            <div class="panel-body">
                <div class="ns-cat-grid" id="cat-grid">
                    <div class="text-muted">
                        <span class="fa fa-spinner fa-spin"></span> {{ lang._('Loading categories...') }}
                    </div>
                </div>
            </div>
        </div>

        <!-- ============================================================ -->
        <!-- BLOCKLISTS                                                     -->
        <!-- ============================================================ -->
        <div class="panel panel-default">
            <div class="panel-heading">
                <h3 class="panel-title">
                    <span class="fa fa-list fa-fw"></span>
                    {{ lang._('Blocklists') }}
                    <span class="pull-right">
                        <button id="btn-update-all" type="button" class="btn btn-primary btn-sm">
                            <span class="fa fa-download fa-fw"></span>
                            {{ lang._('Update All') }}
                        </button>
                        <span id="update-all-spinner" style="display:none; margin-left:6px;">
                            <span class="fa fa-spinner fa-spin"></span>
                            {{ lang._('Updating...') }}
                        </span>
                    </span>
                </h3>
            </div>
            <div class="panel-body">
                <div class="table-responsive">
                    <table class="table table-condensed table-hover table-striped" id="tbl-blocklists">
                        <thead>
                            <tr>
                                <th>{{ lang._('Name') }}</th>
                                <th>{{ lang._('Category') }}</th>
                                <th>{{ lang._('Domains') }}</th>
                                <th>{{ lang._('Last Updated') }}</th>
                                <th>{{ lang._('Enabled') }}</th>
                                <th>{{ lang._('Actions') }}</th>
                            </tr>
                        </thead>
                        <tbody id="blocklists-body">
                            <tr><td colspan="6" class="text-center text-muted">{{ lang._('Loading...') }}</td></tr>
                        </tbody>
                    </table>
                </div>
            </div>
        </div>

        <!-- ============================================================ -->
        <!-- CUSTOM RULES                                                  -->
        <!-- ============================================================ -->
        <div class="panel panel-default">
            <div class="panel-heading">
                <h3 class="panel-title">
                    <span class="fa fa-gavel fa-fw"></span>
                    {{ lang._('Custom Rules') }}
                </h3>
            </div>
            <div class="panel-body">
                <!-- Add Rule Form -->
                <div class="row" style="margin-bottom: 12px;">
                    <div class="col-xs-12 col-sm-5">
                        <input type="text" id="input-rule-domain" class="form-control input-sm"
                               placeholder="{{ lang._('domain.example.com') }}"/>
                    </div>
                    <div class="col-xs-12 col-sm-3">
                        <select id="select-rule-action" class="form-control input-sm">
                            <option value="block">{{ lang._('Block') }}</option>
                            <option value="allow">{{ lang._('Allow') }}</option>
                            <option value="redirect">{{ lang._('Redirect') }}</option>
                        </select>
                    </div>
                    <div class="col-xs-12 col-sm-2">
                        <button id="btn-add-rule" type="button" class="btn btn-success btn-sm">
                            <span class="fa fa-plus fa-fw"></span>
                            {{ lang._('Add Rule') }}
                        </button>
                    </div>
                </div>

                <!-- Rules Table -->
                <table class="table table-condensed table-hover table-striped" id="tbl-rules">
                    <thead>
                        <tr>
                            <th>{{ lang._('Domain') }}</th>
                            <th>{{ lang._('Action') }}</th>
                            <th>{{ lang._('Source') }}</th>
                            <th>{{ lang._('Created') }}</th>
                            <th></th>
                        </tr>
                    </thead>
                    <tbody id="rules-body">
                        <tr><td colspan="5" class="text-center text-muted">{{ lang._('Loading...') }}</td></tr>
                    </tbody>
                </table>
            </div>
        </div>

        <!-- ============================================================ -->
        <!-- QUERY LOG                                                     -->
        <!-- ============================================================ -->
        <div class="panel panel-default">
            <div class="panel-heading">
                <h3 class="panel-title">
                    <span class="fa fa-history fa-fw"></span>
                    {{ lang._('Query Log') }}
                    <small class="text-muted" style="font-size:11px; margin-left:8px;">
                        {{ lang._('Last 100 entries — auto-refreshes every 60s') }}
                    </small>
                    <span class="pull-right">
                        <input type="text" id="querylog-search" class="form-control input-sm"
                               style="display:inline-block;width:160px;"
                               placeholder="{{ lang._('Filter log...') }}"/>
                    </span>
                </h3>
            </div>
            <div class="panel-body">
                <div class="table-responsive">
                    <table class="table table-condensed table-hover table-striped" id="tbl-querylog">
                        <thead>
                            <tr>
                                <th>{{ lang._('Time') }}</th>
                                <th>{{ lang._('Client') }}</th>
                                <th>{{ lang._('Domain') }}</th>
                                <th>{{ lang._('Action') }}</th>
                                <th>{{ lang._('Blocklist') }}</th>
                            </tr>
                        </thead>
                        <tbody id="querylog-body">
                            <tr><td colspan="5" class="text-center text-muted">{{ lang._('Loading...') }}</td></tr>
                        </tbody>
                    </table>
                </div>
            </div>
        </div>

    </div><!-- .content-box-main -->
</div><!-- .content-box -->

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
    // Category icon map
    // ----------------------------------------------------------------
    var CAT_ICONS = {
        'adult':          'fa-eye-slash',
        'advertising':    'fa-bullhorn',
        'social_media':   'fa-users',
        'social media':   'fa-users',
        'gaming':         'fa-gamepad',
        'streaming':      'fa-film',
        'news':           'fa-newspaper-o',
        'malware':        'fa-bug',
        'phishing':       'fa-exclamation-triangle',
        'spam':           'fa-envelope',
        'cryptomining':   'fa-bitcoin',
        'tracking':       'fa-crosshairs',
        'vpn':            'fa-shield',
        'proxy':          'fa-random',
        'gambling':       'fa-money',
        'violence':       'fa-fist',
        'drugs':          'fa-flask',
        'piracy':         'fa-anchor',
        'dating':         'fa-heart',
        'weapons':        'fa-crosshairs'
    };

    function catIcon(name) {
        var key = (name || '').toLowerCase();
        return CAT_ICONS[key] || 'fa-globe';
    }

    function catDisplayName(name) {
        return (name || '').replace(/_/g, ' ').replace(/\b\w/g, function(c){ return c.toUpperCase(); });
    }

    // ----------------------------------------------------------------
    // Categories grid
    // ----------------------------------------------------------------
    var categoryData = [];

    function loadCategories() {
        $.getJSON('/api/netshield/dns/categories', function(data) {
            categoryData = data.categories || [];
            renderCategories();
        });
    }

    function renderCategories() {
        var $grid = $('#cat-grid').empty();
        if (!categoryData.length) {
            $grid.append('<p class="text-muted">{{ lang._("No categories available. Blocklists may not have categories assigned.") }}</p>');
            return;
        }
        categoryData.forEach(function(cat) {
            var isOn = cat.enabled;
            var tile = $('<div>')
                .addClass('ns-cat-tile' + (isOn ? ' ns-cat-on' : ''))
                .attr('data-cat', cat.name)
                .html(
                    '<div class="ns-cat-icon"><span class="fa ' + catIcon(cat.name) + '"></span></div>'
                    + '<div class="ns-cat-name">' + _escape(catDisplayName(cat.name)) + '</div>'
                    + '<div class="ns-cat-count">' + (cat.domain_count || 0).toLocaleString() + ' {{ lang._("domains") }}</div>'
                    + '<div class="ns-cat-status">' + (isOn ? '{{ lang._("BLOCKED") }}' : '{{ lang._("Allowed") }}') + '</div>'
                );
            $grid.append(tile);
        });
    }

    $(document).on('click', '.ns-cat-tile', function() {
        var $tile = $(this);
        var name  = $tile.data('cat');
        var isOn  = $tile.hasClass('ns-cat-on');
        var newVal = isOn ? '0' : '1';

        $tile.css('opacity', 0.5);
        $.post('/api/netshield/dns/toggleCategory', {name: name, enabled: newVal}, function(resp) {
            // Update local data
            categoryData.forEach(function(c) {
                if (c.name === name) c.enabled = newVal === '1';
            });
            renderCategories();
            loadBlocklists();
            loadStats();
        }).fail(function() {
            $tile.css('opacity', 1);
        });
    });

    $('#btn-block-all-cats').on('click', function() {
        BootstrapDialog.confirm({
            title: '{{ lang._("Block All Categories") }}',
            message: '{{ lang._("Block ALL web categories? This will enable all category blocklists.") }}',
            type: BootstrapDialog.TYPE_DANGER,
            btnOKLabel: '{{ lang._("Block All") }}',
            callback: function(result) {
                if (!result) return;
                var proms = categoryData.map(function(c) {
                    return $.post('/api/netshield/dns/toggleCategory', {name: c.name, enabled: '1'});
                });
                $.when.apply($, proms).then(function() {
                    loadCategories();
                    loadBlocklists();
                    loadStats();
                });
            }
        });
    });

    $('#btn-allow-all-cats').on('click', function() {
        BootstrapDialog.confirm({
            title: '{{ lang._("Allow All Categories") }}',
            message: '{{ lang._("Allow ALL web categories? This will disable all category blocklists.") }}',
            type: BootstrapDialog.TYPE_WARNING,
            btnOKLabel: '{{ lang._("Allow All") }}',
            callback: function(result) {
                if (!result) return;
                var proms = categoryData.map(function(c) {
                    return $.post('/api/netshield/dns/toggleCategory', {name: c.name, enabled: '0'});
                });
                $.when.apply($, proms).then(function() {
                    loadCategories();
                    loadBlocklists();
                    loadStats();
                });
            }
        });
    });

    // ----------------------------------------------------------------
    // Utility
    // ----------------------------------------------------------------
    function actionBadge(val) {
        var cls = {block: 'danger', allow: 'success', redirect: 'warning'}[val] || 'default';
        return '<span class="label label-' + cls + '">' + (val || '') + '</span>';
    }

    // ----------------------------------------------------------------
    // Stats
    // ----------------------------------------------------------------
    var safeSearchEnabled = false;

    function loadStats() {
        $.getJSON('/api/netshield/dns/stats', function(data) {
            $('#stat-blocked-today').text(data.total_blocked !== undefined ? data.total_blocked.toLocaleString() : '—');
            var blActive = 0;
            if (data.blocklist_counts) {
                data.blocklist_counts.forEach(function(bl) { if (bl.enabled) blActive++; });
            }
            $('#stat-blocklists-active').text(blActive);
            safeSearchEnabled = !!data.safe_search_enabled;
            updateSafeSearchUI();
        });
    }

    function updateSafeSearchUI() {
        if (safeSearchEnabled) {
            $('#safe-search-status').html('<span class="label label-success">ON</span>');
            $('#btn-safe-search-toggle').removeClass('btn-default').addClass('btn-success');
        } else {
            $('#safe-search-status').html('<span class="label label-default">OFF</span>');
            $('#btn-safe-search-toggle').removeClass('btn-success').addClass('btn-default');
        }
    }

    $('#btn-safe-search-toggle').on('click', function() {
        var newVal = safeSearchEnabled ? '0' : '1';
        $(this).prop('disabled', true);
        $.post('/api/netshield/dns/safeSearch', {enabled: newVal}, function(data) {
            safeSearchEnabled = newVal === '1';
            updateSafeSearchUI();
            $('#btn-safe-search-toggle').prop('disabled', false);
        }).fail(function() {
            $('#btn-safe-search-toggle').prop('disabled', false);
        });
    });

    // ----------------------------------------------------------------
    // Blocklists table
    // ----------------------------------------------------------------
    function loadBlocklists() {
        $.getJSON('/api/netshield/dns/blocklists', function(data) {
            var lists  = data.blocklists || [];
            var $tbody = $('#blocklists-body').empty();
            if (!lists.length) {
                $tbody.append('<tr><td colspan="6" class="text-center text-muted">{{ lang._("No blocklists configured") }}</td></tr>');
                return;
            }
            lists.forEach(function(bl) {
                var enabledCheck = '<input type="checkbox" class="toggle-blocklist" data-name="' +
                    _escape(bl.name) + '"' + (bl.enabled ? ' checked' : '') + '>';
                var catBadge = bl.category
                    ? '<span class="label label-info">' + _escape(bl.category) + '</span>'
                    : '<span class="text-muted">—</span>';
                var updateBtn = '<button type="button" class="btn btn-xs btn-default btn-update-one" data-name="' +
                    _escape(bl.name) + '" title="{{ lang._("Update now") }}"><span class="fa fa-refresh"></span></button>';
                $tbody.append('<tr>'
                    + '<td><strong>' + _escape(bl.name) + '</strong></td>'
                    + '<td>' + catBadge + '</td>'
                    + '<td>' + (bl.domain_count || 0).toLocaleString() + '</td>'
                    + '<td><small>' + (bl.last_updated || '—') + '</small></td>'
                    + '<td>' + enabledCheck + '</td>'
                    + '<td>' + updateBtn + '</td>'
                    + '</tr>');
            });
        });
    }

    // ----------------------------------------------------------------
    // Custom rules
    // ----------------------------------------------------------------
    function loadRules() {
        $.getJSON('/api/netshield/dns/rules', function(data) {
            var rules  = data.rules || [];
            var $tbody = $('#rules-body').empty();
            $('#stat-active-rules').text(rules.filter(function(r){ return r.source === 'custom'; }).length);
            if (!rules.length) {
                $tbody.append('<tr><td colspan="5" class="text-center text-muted">{{ lang._("No custom rules") }}</td></tr>');
                return;
            }
            rules.forEach(function(r) {
                var removeBtn = r.source === 'custom'
                    ? '<button type="button" class="btn btn-xs btn-danger btn-remove-rule" data-domain="' +
                      _escape(r.domain) + '"><span class="fa fa-trash"></span></button>'
                    : '';
                $tbody.append('<tr>'
                    + '<td>' + _escape(r.domain) + '</td>'
                    + '<td>' + actionBadge(r.action) + '</td>'
                    + '<td><span class="label label-default">' + _escape(r.source) + '</span></td>'
                    + '<td><small>' + _escape(r.created) + '</small></td>'
                    + '<td>' + removeBtn + '</td>'
                    + '</tr>');
            });
        });
    }

    // ----------------------------------------------------------------
    // Query log
    // ----------------------------------------------------------------
    var querylogRaw = [];

    function loadQueryLog() {
        $.getJSON('/api/netshield/dns/queryLog?limit=100', function(data) {
            querylogRaw = data.log || [];
            renderQueryLog();
        });
    }

    function renderQueryLog() {
        var filter = $('#querylog-search').val().toLowerCase();
        var $tbody = $('#querylog-body').empty();
        var entries = filter
            ? querylogRaw.filter(function(e){
                return (e.domain || '').toLowerCase().indexOf(filter) !== -1
                    || (e.client_ip || '').indexOf(filter) !== -1;
              })
            : querylogRaw;

        if (!entries.length) {
            $tbody.append('<tr><td colspan="5" class="text-center text-muted">{{ lang._("No log entries") }}</td></tr>');
            return;
        }
        entries.forEach(function(e) {
            $tbody.append('<tr>'
                + '<td><small>' + _escape(e.timestamp) + '</small></td>'
                + '<td>' + _escape(e.client_ip || '—') + '</td>'
                + '<td><strong>' + _escape(e.domain || '—') + '</strong></td>'
                + '<td>' + actionBadge(e.action) + '</td>'
                + '<td><small>' + _escape(e.blocklist_name || '—') + '</small></td>'
                + '</tr>');
        });
    }

    $('#querylog-search').on('input', renderQueryLog);

    // ----------------------------------------------------------------
    // Events
    // ----------------------------------------------------------------

    // Update all blocklists
    $('#btn-update-all').on('click', function() {
        $('#update-all-spinner').show();
        $(this).prop('disabled', true);
        $.post('/api/netshield/dns/updateBlocklists', function() {
            loadBlocklists();
            loadStats();
            loadCategories();
        }).always(function() {
            $('#update-all-spinner').hide();
            $('#btn-update-all').prop('disabled', false);
        });
    });

    // Toggle blocklist enabled
    $(document).on('change', '.toggle-blocklist', function() {
        var name    = $(this).data('name');
        var enabled = $(this).is(':checked') ? '1' : '0';
        $.post('/api/netshield/dns/toggleBlocklist', {name: name, enabled: enabled}, function() {
            loadCategories();
            loadStats();
        });
    });

    // Update single blocklist
    $(document).on('click', '.btn-update-one', function() {
        var btn = $(this).prop('disabled', true);
        $.post('/api/netshield/dns/updateBlocklists', function() {
            loadBlocklists();
            btn.prop('disabled', false);
        });
    });

    // Add custom rule
    $('#btn-add-rule').on('click', function() {
        var domain = $('#input-rule-domain').val().trim();
        var action = $('#select-rule-action').val();
        if (!domain) { $('#input-rule-domain').focus(); return; }
        $.post('/api/netshield/dns/addRule', {domain: domain, action: action}, function(data) {
            if (data.result === 'ok') {
                $('#input-rule-domain').val('');
                loadRules();
            } else {
                BootstrapDialog.alert({
                    title: '{{ lang._("Error") }}',
                    message: data.message || '{{ lang._("Failed to add rule") }}',
                    type: BootstrapDialog.TYPE_DANGER
                });
            }
        });
    });

    // Remove rule
    $(document).on('click', '.btn-remove-rule', function() {
        var domain = $(this).data('domain');
        BootstrapDialog.confirm({
            title: '{{ lang._("Remove Rule") }}',
            message: '{{ lang._("Remove DNS rule for") }} <strong>' + _escape(domain) + '</strong>?',
            type: BootstrapDialog.TYPE_DANGER,
            btnOKLabel: '{{ lang._("Remove") }}',
            callback: function(result) {
                if (result) {
                    $.post('/api/netshield/dns/removeRule', {domain: domain}, function() {
                        loadRules();
                    });
                }
            }
        });
    });

    // Enter key for domain input
    $('#input-rule-domain').on('keypress', function(e) {
        if (e.which === 13) $('#btn-add-rule').trigger('click');
    });

    // ----------------------------------------------------------------
    // Initial load + auto-refresh
    // ----------------------------------------------------------------
    loadStats();
    loadCategories();
    loadBlocklists();
    loadRules();
    loadQueryLog();

    setInterval(function() {
        loadStats();
        loadQueryLog();
    }, 60000);
});
</script>
