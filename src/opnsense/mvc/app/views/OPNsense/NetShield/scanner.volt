{# Copyright (c) 2025 NetShield. BSD 2-Clause License. #}

<script>
$(document).ready(function() {

    var resultsGrid = $('#grid-results').UIBootgrid({
            'search': '/api/netshield/scanner/results',
            'options': {
                selection: false,
                multiSelect: false,
                rowCount: [20, 50],
        formatters: {
            'ports': function(col, row) {
                var ports = row.open_ports || '';
                return '<code>' + $('<span>').text(ports).html() + '</code>';
            }
        }
            }
        });

    $('#btn-scan-device').on('click', function() {
        var ip = $('#scan-ip').val().trim();
        if (!ip) return;
        var btn = $(this);
        btn.prop('disabled', true).html('<i class="fa fa-spinner fa-spin"></i> {{ ("Scanning...") }}');
        var ports = $('#scan-ports').val().trim() || '1-1024';
        $.post('/api/netshield/scanner/scanDevice', {ip: ip, ports: ports}, function(data) {
            btn.prop('disabled', false).html('<i class="fa fa-crosshairs"></i> {{ ("Scan") }}');
            if (data && data.status !== 'error') {
                resultsGrid.bootgrid('reload');
                BootstrapDialog.show({type: BootstrapDialog.TYPE_SUCCESS, title: '{{ ("Scan Complete") }}', message: '{{ ("Found ") }}' + (data.open_ports_count || 0) + '{{ (" open ports") }}'});
            } else {
                BootstrapDialog.show({type: BootstrapDialog.TYPE_DANGER, title: '{{ ("Error") }}', message: data.message || '{{ ("Scan failed") }}'});
            }
        }, 'json');
    });

    $('#btn-scan-network').on('click', function() {
        var subnet = $('#scan-subnet').val().trim();
        if (!subnet) return;
        var btn = $(this);
        btn.prop('disabled', true).html('<i class="fa fa-spinner fa-spin"></i> {{ ("Scanning...") }}');
        $.post('/api/netshield/scanner/scanNetwork', {subnet: subnet}, function(data) {
            btn.prop('disabled', false).html('<i class="fa fa-sitemap"></i> {{ ("Scan Network") }}');
            resultsGrid.bootgrid('reload');
        }, 'json');
    });
});
</script>

<div class="content-box">

    <div class="row" style="margin:16px 0;">
        <div class="col-md-6">
            <div class="panel panel-default">
                <div class="panel-heading"><h3 class="panel-title">{{ ('Scan Device') }}</h3></div>
                <div class="panel-body">
                    <div class="form-group">
                        <label>{{ ('Target IP') }}</label>
                        <input type="text" id="scan-ip" class="form-control" placeholder="192.168.1.100"/>
                    </div>
                    <div class="form-group">
                        <label>{{ ('Port Range (optional)') }}</label>
                        <input type="text" id="scan-ports" class="form-control" placeholder="1-1024"/>
                    </div>
                    <button id="btn-scan-device" class="btn btn-primary"><i class="fa fa-crosshairs"></i> {{ ('Scan') }}</button>
                </div>
            </div>
        </div>
        <div class="col-md-6">
            <div class="panel panel-default">
                <div class="panel-heading"><h3 class="panel-title">{{ ('Scan Network') }}</h3></div>
                <div class="panel-body">
                    <div class="form-group">
                        <label>{{ ('Subnet') }}</label>
                        <input type="text" id="scan-subnet" class="form-control" placeholder="192.168.1.0/24"/>
                    </div>
                    <button id="btn-scan-network" class="btn btn-warning"><i class="fa fa-sitemap"></i> {{ ('Scan Network') }}</button>
                    <small class="text-muted">{{ ('This may take several minutes for large subnets.') }}</small>
                </div>
            </div>
        </div>
    </div>

    <h3>{{ ('Scan Results') }}</h3>
    <table id="grid-results" class="table table-condensed table-hover table-striped">
        <thead><tr>
            <th data-column-id="timestamp" data-type="string" data-width="160px">{{ ('Time') }}</th>
            <th data-column-id="target_ip" data-type="string">{{ ('Target') }}</th>
            <th data-column-id="open_ports" data-formatter="ports">{{ ('Open Ports') }}</th>
            <th data-column-id="services" data-type="string">{{ ('Services') }}</th>
            <th data-column-id="os_guess" data-type="string">{{ ('OS') }}</th>
        </tr></thead>
        <tbody></tbody>
    </table>

</div>
