{# Copyright (c) 2025 NetShield. BSD 2-Clause License. #}

<script src="/js/d3.min.js"></script>
<script src="/js/netshield/topology.js"></script>
<script>
$(document).ready(function() {

    /* Topology */
    function loadTopology() {
        ajaxCall('/api/netshield/network/topology', {}, function(data) {
            if (data && data.nodes) {
                renderTopology('topology-graph', data);
            }
        });
    }
    loadTopology();
    $('#btn-refresh-topo').on('click', loadTopology);

    /* Speed Test — Raw WAN speed via pppoe0 (bypasses VPN) */
    function loadSpeedHistory() {
        $.getJSON('/api/netshield/network/speedtestHistory', function(data) {
            if (!data || !data.results || !data.results.length) return;
            var last = data.results[0];
            $('#speed-download').text((last.download_mbps || 0).toFixed(1) + ' Mbps');
            $('#speed-upload').text((last.upload_mbps || 0).toFixed(1) + ' Mbps');
            $('#speed-ping').text((last.ping_ms || 0).toFixed(0) + ' ms');
            $('#speed-server').text((last.server || '-') + ' via ' + (last.wan_interface || 'WAN'));
            $('#speed-wan-info').text('WAN: ' + (last.wan_ip || '-') + ' (' + (last.wan_interface || '-') + ')');
            $('#speed-timestamp').text('Last test: ' + (last.timestamp || '-'));
            $('#speed-results').show();
        });
    }
    loadSpeedHistory();

    $('#btn-speedtest').on('click', function() {
        var btn = $(this);
        btn.prop('disabled', true).html('<i class="fa fa-spinner fa-spin"></i> {{ ("Testing raw WAN speed...") }}');
        ajaxCall('/api/netshield/network/speedtest', {}, function(data) {
            btn.prop('disabled', false).html('<i class="fa fa-tachometer"></i> {{ ("Run Speed Test") }}');
            if (data && data.status !== 'error') {
                $('#speed-download').text((data.download_mbps || 0).toFixed(1) + ' Mbps');
                $('#speed-upload').text((data.upload_mbps || 0).toFixed(1) + ' Mbps');
                $('#speed-ping').text((data.ping_ms || 0).toFixed(0) + ' ms');
                $('#speed-server').text((data.server || '-') + ' via ' + (data.wan_interface || 'WAN'));
                $('#speed-wan-info').text('WAN: ' + (data.wan_ip || '-') + ' (' + (data.wan_interface || '-') + ')');
                $('#speed-timestamp').text('Last test: ' + (data.timestamp || '-'));
                $('#speed-results').show();
            } else {
                BootstrapDialog.show({type: BootstrapDialog.TYPE_DANGER, title: '{{ ("Error") }}', message: data.message || '{{ ("Speed test failed") }}'});
            }
        });
    });

    /* WoL */
    $('#btn-wol').on('click', function() {
        var mac = $('#wol-mac').val().trim();
        if (!mac) return;
        ajaxCall('/api/netshield/network/wake', {mac: mac}, function(data) {
            BootstrapDialog.show({
                type: (data && data.status === 'ok') ? BootstrapDialog.TYPE_SUCCESS : BootstrapDialog.TYPE_DANGER,
                title: '{{ ("Wake-on-LAN") }}',
                message: (data && data.status === 'ok') ? '{{ ("Magic packet sent to ") }}' + mac : '{{ ("Failed to send WoL packet") }}'
            });
        });
    });

    /* Quarantined devices */
    var qGrid = $('#grid-quarantined').UIBootgrid({
            'search': '/api/netshield/devices/search',
            'options': {
                selection: false,
                multiSelect: false,
                requestHandler: function(req) { req.quarantined = 1; return req; },
        formatters: {
            'actions': function(col, row) {
                return '<button class="btn btn-xs btn-success btn-unquarantine" data-mac="' + row.mac + '"><i class="fa fa-unlock"></i></button>';
            }
        }
            }
        }).on('loaded.rs.jquery.bootgrid', function() {
        $(this).find('.btn-unquarantine').on('click', function() {
            var mac = $(this).data('mac');
            ajaxCall('/api/netshield/devices/unquarantine', {uuid: mac}, function() { qGrid.bootgrid('reload'); });
        });
    });
});
</script>

<ul class="nav nav-tabs" role="tablist" id="maintabs">
    <li class="active"><a data-toggle="tab" href="#tab-topology"><b>{{ ('Topology') }}</b></a></li>
    <li><a data-toggle="tab" href="#tab-tools"><b>{{ ('Tools') }}</b></a></li>
    <li><a data-toggle="tab" href="#tab-quarantine"><b>{{ ('Quarantine') }}</b></a></li>
</ul>

<div class="tab-content content-box">

    <div id="tab-topology" class="tab-pane fade in active">
        <div style="margin:16px 0;">
            <button id="btn-refresh-topo" class="btn btn-default btn-sm"><i class="fa fa-refresh"></i> {{ ('Refresh') }}</button>
        </div>
        <div id="topology-graph" style="height:500px; border:1px solid #ddd; border-radius:4px; background:#fafafa;"></div>
    </div>

    <div id="tab-tools" class="tab-pane fade">
        <div class="row" style="margin:16px 0;">
            <div class="col-md-6">
                <div class="panel panel-default">
                    <div class="panel-heading"><h3 class="panel-title">{{ ('Speed Test') }}</h3></div>
                    <div class="panel-body">
                        <button id="btn-speedtest" class="btn btn-primary"><i class="fa fa-tachometer"></i> {{ ('Run Speed Test') }}</button>
                        <p class="text-muted" style="margin-top:8px;font-size:12px;"><i class="fa fa-info-circle"></i> Tests raw WAN speed via pppoe0 — bypasses VPN routing</p>
                        <div id="speed-results" style="display:none; margin-top:16px;">
                            <table class="table table-condensed">
                                <tr><td><b>{{ ('Download') }}</b></td><td id="speed-download">-</td></tr>
                                <tr><td><b>{{ ('Upload') }}</b></td><td id="speed-upload">-</td></tr>
                                <tr><td><b>{{ ('Ping') }}</b></td><td id="speed-ping">-</td></tr>
                                <tr><td><b>{{ ('Server') }}</b></td><td id="speed-server">-</td></tr>
                                <tr><td><b>{{ ('WAN') }}</b></td><td id="speed-wan-info">-</td></tr>
                                <tr><td colspan="2" class="text-muted" style="font-size:12px;" id="speed-timestamp">-</td></tr>
                            </table>
                        </div>
                    </div>
                </div>
            </div>
            <div class="col-md-6">
                <div class="panel panel-default">
                    <div class="panel-heading"><h3 class="panel-title">{{ ('Wake-on-LAN') }}</h3></div>
                    <div class="panel-body">
                        <div class="input-group">
                            <input type="text" id="wol-mac" class="form-control" placeholder="AA:BB:CC:DD:EE:FF"/>
                            <span class="input-group-btn"><button id="btn-wol" class="btn btn-primary">{{ ('Wake') }}</button></span>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <div id="tab-quarantine" class="tab-pane fade">
        <table id="grid-quarantined" class="table table-condensed table-hover table-striped">
            <thead><tr>
                <th data-column-id="mac" data-type="string">{{ ('MAC') }}</th>
                <th data-column-id="ip" data-type="string">{{ ('IP') }}</th>
                <th data-column-id="hostname" data-type="string">{{ ('Hostname') }}</th>
                <th data-column-id="actions" data-formatter="actions" data-sortable="false" data-width="80px">{{ ('Actions') }}</th>
            </tr></thead>
            <tbody></tbody>
        </table>
    </div>

</div>
