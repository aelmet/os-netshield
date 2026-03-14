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

        <!-- Page heading + time range selector -->
        <div class="row">
            <div class="col-xs-8">
                <div class="page-header">
                    <h1>{{ ('Bandwidth') }}</h1>
                </div>
            </div>
            <div class="col-xs-4 text-right" style="padding-top: 20px;">
                <div class="btn-group" id="time-range-selector" data-toggle="buttons">
                    <label class="btn btn-default btn-sm active" data-hours="1">
                        <input type="radio" name="timerange" value="1" checked/> 1h
                    </label>
                    <label class="btn btn-default btn-sm" data-hours="6">
                        <input type="radio" name="timerange" value="6"/> 6h
                    </label>
                    <label class="btn btn-default btn-sm" data-hours="24">
                        <input type="radio" name="timerange" value="24"/> 24h
                    </label>
                    <label class="btn btn-default btn-sm" data-hours="168">
                        <input type="radio" name="timerange" value="168"/> 7d
                    </label>
                </div>
            </div>
        </div>

        <!-- Summary cards -->
        <div class="row" id="bandwidth-summary-cards" style="margin-bottom: 20px;">
            <div class="col-sm-3">
                <div class="panel panel-default text-center">
                    <div class="panel-body">
                        <div class="text-muted small">{{ ('Total In') }}</div>
                        <div class="h3" id="card-total-in">--</div>
                    </div>
                </div>
            </div>
            <div class="col-sm-3">
                <div class="panel panel-default text-center">
                    <div class="panel-body">
                        <div class="text-muted small">{{ ('Total Out') }}</div>
                        <div class="h3" id="card-total-out">--</div>
                    </div>
                </div>
            </div>
            <div class="col-sm-3">
                <div class="panel panel-default text-center">
                    <div class="panel-body">
                        <div class="text-muted small">{{ ('Active Devices') }}</div>
                        <div class="h3" id="card-active-devices">--</div>
                    </div>
                </div>
            </div>
            <div class="col-sm-3">
                <div class="panel panel-default text-center">
                    <div class="panel-body">
                        <div class="text-muted small">{{ ('Top App') }}</div>
                        <div class="h3" id="card-top-app">--</div>
                    </div>
                </div>
            </div>
        </div>

        <!-- Bandwidth chart placeholder -->
        <div class="row" style="margin-bottom: 20px;">
            <div class="col-xs-12">
                <div class="panel panel-default">
                    <div class="panel-heading">
                        <h3 class="panel-title">{{ ('Bandwidth Over Time') }}</h3>
                    </div>
                    <div class="panel-body">
                        <canvas id="bandwidth-chart" height="80"></canvas>
                    </div>
                </div>
            </div>
        </div>

        <!-- Top Devices table -->
        <div class="row" style="margin-bottom: 20px;">
            <div class="col-xs-12">
                <div class="panel panel-default">
                    <div class="panel-heading">
                        <h3 class="panel-title">{{ ('Top Devices') }}</h3>
                    </div>
                    <div class="panel-body">
                        <table id="grid-top-devices" class="table table-condensed table-hover table-striped">
                            <thead>
                                <tr>
                                    <th data-column-id="device"       data-type="string">{{ ('Device') }}</th>
                                    <th data-column-id="hostname"     data-type="string">{{ ('Hostname') }}</th>
                                    <th data-column-id="bytes_in"     data-type="numeric" data-formatter="bytesFormatter">{{ ('Bytes In') }}</th>
                                    <th data-column-id="bytes_out"    data-type="numeric" data-formatter="bytesFormatter">{{ ('Bytes Out') }}</th>
                                    <th data-column-id="bytes_total"  data-type="numeric" data-formatter="bytesFormatter">{{ ('Total') }}</th>
                                    <th data-column-id="last_updated" data-type="string">{{ ('Last Updated') }}</th>
                                </tr>
                            </thead>
                            <tbody></tbody>
                        </table>
                    </div>
                </div>
            </div>
        </div>

        <!-- Top Apps table -->
        <div class="row">
            <div class="col-xs-12">
                <div class="panel panel-default">
                    <div class="panel-heading">
                        <h3 class="panel-title">{{ ('Top Applications') }}</h3>
                    </div>
                    <div class="panel-body">
                        <table id="grid-top-apps" class="table table-condensed table-hover table-striped">
                            <thead>
                                <tr>
                                    <th data-column-id="name"        data-type="string">{{ ('App Name') }}</th>
                                    <th data-column-id="category"    data-type="string">{{ ('Category') }}</th>
                                    <th data-column-id="bytes"       data-type="numeric" data-formatter="bytesFormatter">{{ ('Bytes') }}</th>
                                    <th data-column-id="connections" data-type="numeric">{{ ('Connections') }}</th>
                                </tr>
                            </thead>
                            <tbody></tbody>
                        </table>
                    </div>
                </div>
            </div>
        </div>

    </div><!-- /content-box-main -->
</div><!-- /content-box -->

<script>
$(document).ready(function () {

    var currentHours = 1;
    var refreshTimer  = null;

    /* ------------------------------------------------------------------ */
    /* Utility: human-readable bytes                                        */
    /* ------------------------------------------------------------------ */
    function formatBytes(bytes) {
        if (!bytes || isNaN(bytes)) return '0 B';
        bytes = parseInt(bytes);
        var units = ['B', 'KB', 'MB', 'GB', 'TB'];
        var i = 0;
        while (bytes >= 1024 && i < units.length - 1) {
            bytes /= 1024;
            i++;
        }
        return bytes.toFixed(2) + ' ' + units[i];
    }

    var bytesFormatter = function (column, row) {
        return formatBytes(row[column.id]);
    };

    /* ------------------------------------------------------------------ */
    /* Bootgrid: Top Devices                                                */
    /* ------------------------------------------------------------------ */
    var devicesGrid = $('#grid-top-devices').UIBootgrid({
        'search': '',
        'options': {
            ajax: false,
            selection: false,
            multiSelect: false,
            formatters: {
                'bytesFormatter': bytesFormatter
            }
        }
    });

    /* ------------------------------------------------------------------ */
    /* Bootgrid: Top Apps                                                   */
    /* ------------------------------------------------------------------ */
    var appsGrid = $('#grid-top-apps').UIBootgrid({
        'search': '',
        'options': {
            ajax: false,
            selection: false,
            multiSelect: false,
            formatters: {
                'bytesFormatter': bytesFormatter
            }
        }
    });

    /* ------------------------------------------------------------------ */
    /* Chart.js setup                                                        */
    /* ------------------------------------------------------------------ */
    var bandwidthChart = null;

    function initChart(labels, dataIn, dataOut) {
        var ctx = document.getElementById('bandwidth-chart').getContext('2d');
        if (bandwidthChart) {
            bandwidthChart.destroy();
        }
        bandwidthChart = new Chart(ctx, {
            type: 'line',
            data: {
                labels: labels,
                datasets: [
                    {
                        label: '{{ ('Bytes In') }}',
                        data:  dataIn,
                        borderColor:     'rgba(66, 139, 202, 1)',
                        backgroundColor: 'rgba(66, 139, 202, 0.1)',
                        fill: true,
                        tension: 0.3
                    },
                    {
                        label: '{{ ('Bytes Out') }}',
                        data:  dataOut,
                        borderColor:     'rgba(92, 184, 92, 1)',
                        backgroundColor: 'rgba(92, 184, 92, 0.1)',
                        fill: true,
                        tension: 0.3
                    }
                ]
            },
            options: {
                responsive: true,
                scales: {
                    y: {
                        beginAtZero: true,
                        ticks: {
                            callback: function (value) { return formatBytes(value); }
                        }
                    }
                },
                plugins: {
                    tooltip: {
                        callbacks: {
                            label: function (context) {
                                return context.dataset.label + ': ' + formatBytes(context.parsed.y);
                            }
                        }
                    }
                }
            }
        });
    }

    /* ------------------------------------------------------------------ */
    /* Data loading                                                          */
    /* ------------------------------------------------------------------ */
    function loadCurrentSummary() {
        $.get('/api/netshield/bandwidth/current', function (data) {
            $('#card-total-in').text(formatBytes(data.bytes_in   || data.total_in   || 0));
            $('#card-total-out').text(formatBytes(data.bytes_out || data.total_out  || 0));
            $('#card-active-devices').text(data.active_devices   || data.devices    || '--');
            $('#card-top-app').text(data.top_app || '--');
        });
    }

    function loadHistory(hours) {
        $.get('/api/netshield/bandwidth/history', { hours: hours }, function (data) {
            var history = data.history || data.data || [];
            var labels  = history.map(function (r) { return r.timestamp || r.time || ''; });
            var dataIn  = history.map(function (r) { return r.bytes_in  || 0; });
            var dataOut = history.map(function (r) { return r.bytes_out || 0; });
            initChart(labels, dataIn, dataOut);
        });
    }

    function loadTopDevices(hours) {
        $.get('/api/netshield/bandwidth/topDevices', { hours: hours, limit: 20 }, function (data) {
            var rows = data.devices || data.rows || [];
            devicesGrid.bootgrid('clear');
            if (rows.length) {
                devicesGrid.bootgrid('append', rows);
            }
        });
    }

    function loadTopApps(hours) {
        $.get('/api/netshield/bandwidth/byApp', { hours: hours, limit: 20 }, function (data) {
            var rows = data.apps || data.rows || [];
            appsGrid.bootgrid('clear');
            if (rows.length) {
                appsGrid.bootgrid('append', rows);
            }
        });
    }

    function refreshAll() {
        loadCurrentSummary();
        loadHistory(currentHours);
        loadTopDevices(currentHours);
        loadTopApps(currentHours);
    }

    /* ------------------------------------------------------------------ */
    /* Auto-refresh every 15 seconds (summary cards only for live feel)    */
    /* ------------------------------------------------------------------ */
    function startAutoRefresh() {
        if (refreshTimer) {
            clearInterval(refreshTimer);
        }
        refreshTimer = setInterval(function () {
            loadCurrentSummary();
        }, 15000);
    }

    /* ------------------------------------------------------------------ */
    /* Time range selector                                                   */
    /* ------------------------------------------------------------------ */
    $('#time-range-selector label').on('click', function () {
        currentHours = parseInt($(this).data('hours'), 10);
        refreshAll();
    });

    /* ------------------------------------------------------------------ */
    /* Initial load                                                          */
    /* ------------------------------------------------------------------ */
    refreshAll();
    startAutoRefresh();
});
</script>
