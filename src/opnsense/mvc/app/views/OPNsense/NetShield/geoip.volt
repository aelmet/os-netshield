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
        <h1>{{ ('GeoIP Filtering') }}</h1>

        {# ------------------------------------------------------------------ #}
        {# World Map Placeholder                                               #}
        {# ------------------------------------------------------------------ #}
        <div class="panel panel-default">
            <div class="panel-heading">
                <h3 class="panel-title">{{ ('Geographic Traffic Map') }}</h3>
            </div>
            <div class="panel-body">
                <div id="geoip-map"
                     style="width:100%; height:300px; background:#f5f5f5; border:1px solid #ddd;
                            display:flex; align-items:center; justify-content:center; color:#999;">
                    <span>
                        <i class="fa fa-globe fa-3x"></i><br>
                        {{ ('World map visualization (D3.js — coming soon)') }}
                    </span>
                </div>
            </div>
        </div>

        {# ------------------------------------------------------------------ #}
        {# Stats Cards                                                         #}
        {# ------------------------------------------------------------------ #}
        <div class="row" id="geoip-stats-row">
            <div class="col-sm-4">
                <div class="panel panel-default">
                    <div class="panel-body text-center">
                        <h2 id="stat-countries-blocked">—</h2>
                        <p class="text-muted">{{ ('Countries Blocked') }}</p>
                    </div>
                </div>
            </div>
            <div class="col-sm-4">
                <div class="panel panel-default">
                    <div class="panel-body text-center">
                        <h2 id="stat-connections-today">—</h2>
                        <p class="text-muted">{{ ('Connections Today') }}</p>
                    </div>
                </div>
            </div>
            <div class="col-sm-4">
                <div class="panel panel-default">
                    <div class="panel-body text-center">
                        <h2 id="stat-blocked-today">—</h2>
                        <p class="text-muted">{{ ('Blocked Today') }}</p>
                    </div>
                </div>
            </div>
        </div>

        {# ------------------------------------------------------------------ #}
        {# Add Rule Form                                                       #}
        {# ------------------------------------------------------------------ #}
        <div class="panel panel-default">
            <div class="panel-heading">
                <h3 class="panel-title">{{ ('Add Country Rule') }}</h3>
            </div>
            <div class="panel-body">
                <form class="form-inline" id="add-geoip-rule-form">
                    <div class="form-group">
                        <label for="geoip-country-input">{{ ('Country Code') }}</label>
                        <input type="text" class="form-control" id="geoip-country-input"
                               maxlength="2" style="width:80px; text-transform:uppercase;"
                               placeholder="{{ ('e.g. CN') }}">
                    </div>
                    &nbsp;
                    <div class="form-group">
                        <label for="geoip-action-select">{{ ('Action') }}</label>
                        <select class="form-control" id="geoip-action-select">
                            <option value="block">{{ ('Block') }}</option>
                            <option value="log">{{ ('Log') }}</option>
                            <option value="allow">{{ ('Allow') }}</option>
                        </select>
                    </div>
                    &nbsp;
                    <button type="submit" class="btn btn-primary">
                        <i class="fa fa-plus"></i>
                        {{ ('Add Rule') }}
                    </button>
                    &nbsp;
                    <button type="button" class="btn btn-default" id="btn-apply-geoip">
                        <i class="fa fa-check"></i>
                        {{ ('Apply to Firewall') }}
                    </button>
                    <span id="add-rule-feedback" class="text-success" style="margin-left:10px;display:none;"></span>
                </form>
            </div>
        </div>

        {# ------------------------------------------------------------------ #}
        {# Country Rules Bootgrid                                              #}
        {# ------------------------------------------------------------------ #}
        <div class="panel panel-default">
            <div class="panel-heading">
                <h3 class="panel-title">{{ ('Country Rules') }}</h3>
            </div>
            <div class="panel-body">
                <table id="geoip-rules-grid" class="table table-condensed table-hover">
                    <thead>
                        <tr>
                            <th data-column-id="country_code" data-sortable="true">
                                {{ ('Country Code') }}
                            </th>
                            <th data-column-id="country_name" data-sortable="true">
                                {{ ('Country Name') }}
                            </th>
                            <th data-column-id="action" data-sortable="true"
                                data-formatter="actionBadge">
                                {{ ('Action') }}
                            </th>
                            <th data-column-id="created" data-sortable="true">
                                {{ ('Created') }}
                            </th>
                            <th data-column-id="commands" data-formatter="commands"
                                data-sortable="false">
                                {{ ('Actions') }}
                            </th>
                        </tr>
                    </thead>
                    <tbody></tbody>
                    <tfoot>
                        <tr>
                            <td colspan="5">
                                <div class="pull-right">
                                    <nav data-toggle="bootgrid-pagination"></nav>
                                </div>
                                <div class="pull-left">
                                    <select data-toggle="bootgrid-rowcount" class="form-control">
                                        <option value="10">10</option>
                                        <option value="25" selected>25</option>
                                        <option value="50">50</option>
                                    </select>
                                </div>
                            </td>
                        </tr>
                    </tfoot>
                </table>
            </div>
        </div>

        {# ------------------------------------------------------------------ #}
        {# IP Lookup Tool                                                      #}
        {# ------------------------------------------------------------------ #}
        <div class="panel panel-default">
            <div class="panel-heading">
                <h3 class="panel-title">{{ ('IP Country Lookup') }}</h3>
            </div>
            <div class="panel-body">
                <div class="input-group" style="max-width: 400px;">
                    <input type="text" class="form-control" id="geoip-lookup-input"
                           placeholder="{{ ('Enter IP address…') }}">
                    <span class="input-group-btn">
                        <button class="btn btn-default" id="btn-geoip-lookup">
                            <i class="fa fa-search"></i>
                            {{ ('Lookup') }}
                        </button>
                    </span>
                </div>
                <div id="geoip-lookup-result" class="alert alert-info" style="display:none; margin-top:10px;"></div>
            </div>
        </div>

        {# ------------------------------------------------------------------ #}
        {# Top Countries                                                       #}
        {# ------------------------------------------------------------------ #}
        <div class="panel panel-default">
            <div class="panel-heading">
                <h3 class="panel-title">{{ ('Top Countries by Connections') }}</h3>
            </div>
            <div class="panel-body">
                <table class="table table-condensed table-striped" id="top-countries-table">
                    <thead>
                        <tr>
                            <th>{{ ('Country') }}</th>
                            <th>{{ ('Code') }}</th>
                            <th>{{ ('Connections') }}</th>
                        </tr>
                    </thead>
                    <tbody id="top-countries-body">
                        <tr>
                            <td colspan="3" class="text-center text-muted">
                                {{ ('Loading…') }}
                            </td>
                        </tr>
                    </tbody>
                </table>
            </div>
        </div>

    </div>
</div>

<script>
$(function () {
    var ACTION_CLASS = {block: 'danger', log: 'warning', allow: 'success'};
    var rulesGrid;

    // ---- Stats ----
    function loadStats() {
        $.getJSON('/api/netshield/geoip/stats', function (data) {
            var s = data.stats || data;
            var blocked = 0;
            if (data.rules) {
                $.each(data.rules || [], function (_, r) {
                    if (r.action === 'block') blocked++;
                });
            }
            $('#stat-countries-blocked').text(blocked || '—');
            $('#stat-connections-today').text(
                s.total_connections !== undefined ? s.total_connections.toLocaleString() : '—'
            );
            $('#stat-blocked-today').text(
                s.blocked_count !== undefined ? s.blocked_count.toLocaleString() : '—'
            );

            // Top countries
            var tbody = $('#top-countries-body').empty();
            var countries = s.connections_by_country || [];
            if (!countries.length) {
                tbody.append('<tr><td colspan="3" class="text-center text-muted">{{ ("No data") }}</td></tr>');
                return;
            }
            $.each(countries.slice(0, 10), function (_, c) {
                tbody.append($('<tr>').append(
                    $('<td>').text(c.country_name || '—'),
                    $('<td>').text(c.country_code),
                    $('<td>').text(c.count.toLocaleString())
                ));
            });
        });
    }
    loadStats();

    // ---- Rules bootgrid ----
    rulesGrid = $('#geoip-rules-grid').UIBootgrid({
            'search': '/api/netshield/geoip/rules',
            'options': {
                selection: false,
                multiSelect: false,
                rowCount: [25, 50, 100],
        formatters: {
            actionBadge: function (column, row) {
                var cls = ACTION_CLASS[row.action] || 'default';
                return '<span class="label label-' + cls + '">' + row.action + '</span>';
            },
            commands: function (column, row) {
                return '<button class="btn btn-xs btn-danger btn-delete-rule" '
                    + 'data-country="' + $('<div>').text(row.country_code).html() + '">'
                    + '<i class="fa fa-trash"></i></button>';
            }
        }
            }
        });

    // Delete rule
    $(document).on('click', '.btn-delete-rule', function () {
        var cc = $(this).data('country');
        if (!confirm('{{ ("Remove rule for") }} ' + cc + '?')) return;
        $.post('/api/netshield/geoip/removeRule', {country: cc}, function () {
            rulesGrid.bootgrid('reload');
            loadStats();
        });
    });

    // ---- Add rule ----
    $('#add-geoip-rule-form').on('submit', function (e) {
        e.preventDefault();
        var cc     = $('#geoip-country-input').val().trim().toUpperCase();
        var action = $('#geoip-action-select').val();
        var fb     = $('#add-rule-feedback');
        if (!cc || cc.length !== 2) {
            fb.removeClass('text-success').addClass('text-danger')
              .text('{{ ("Enter a valid 2-letter country code.") }}').show();
            return;
        }
        $.post('/api/netshield/geoip/addRule', {country: cc, action: action}, function (data) {
            if (data.status === 'ok') {
                fb.removeClass('text-danger').addClass('text-success')
                  .text('{{ ("Rule added.") }}').show();
                $('#geoip-country-input').val('');
                rulesGrid.bootgrid('reload');
                loadStats();
            } else {
                fb.removeClass('text-success').addClass('text-danger')
                  .text(data.message || '{{ ("Failed.") }}').show();
            }
            setTimeout(function () { fb.fadeOut(); }, 3000);
        });
    });

    // ---- Apply to firewall ----
    $('#btn-apply-geoip').on('click', function () {
        var btn = $(this).prop('disabled', true);
        $.post('/api/netshield/geoip/apply', function (data) {
            alert(data.message || '{{ ("Rules applied.") }}');
        }).always(function () { btn.prop('disabled', false); });
    });

    // ---- IP Lookup ----
    $('#btn-geoip-lookup').on('click', function () {
        var ip  = $('#geoip-lookup-input').val().trim();
        var div = $('#geoip-lookup-result').hide();
        if (!ip) return;
        $.getJSON('/api/netshield/geoip/lookup', {ip: ip}, function (data) {
            var g = data.geo || {};
            div.html(
                '<strong>' + $('<div>').text(ip).html() + '</strong> &rarr; '
                + (g.country_name || '—') + ' (' + (g.country_code || '—') + ')'
                + ' &mdash; ' + (g.continent || '')
            ).show();
        }).fail(function () {
            div.text('{{ ("Lookup failed.") }}').show();
        });
    });
});
</script>
