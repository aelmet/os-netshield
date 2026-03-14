{#
 # Copyright (C) 2025-2026 NetShield
 # Fusion VPN - Asus VPN Fusion Style Multi-VPN Management
 #}

<style>
/* Fusion VPN Asus-inspired styling - Dark Mode Optimized */
.fusion-header {
    background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
    color: #fff;
    padding: 24px;
    border-radius: 12px;
    margin-bottom: 24px;
    display: flex;
    justify-content: space-between;
    align-items: center;
}
.fusion-header h2 {
    margin: 0;
    font-size: 24px;
    display: flex;
    align-items: center;
    gap: 12px;
}
.fusion-header .fusion-logo {
    width: 40px;
    height: 40px;
    background: linear-gradient(45deg, #00d4ff, #0099ff);
    border-radius: 8px;
    display: flex;
    align-items: center;
    justify-content: center;
}
.fusion-header .stats {
    display: flex;
    gap: 32px;
}
.fusion-header .stat-item {
    text-align: center;
}
.fusion-header .stat-value {
    font-size: 28px;
    font-weight: 700;
    color: #00d4ff;
}
.fusion-header .stat-label {
    font-size: 12px;
    color: rgba(255,255,255,0.85);
    text-transform: uppercase;
}

/* Profile Cards Grid */
.profiles-grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(320px, 1fr));
    gap: 20px;
    margin-bottom: 24px;
}
.profile-card {
    background: #1e1e2e;
    border-radius: 12px;
    box-shadow: 0 2px 12px rgba(0,0,0,0.3);
    overflow: hidden;
    transition: transform 0.2s, box-shadow 0.2s;
}
.profile-card:hover {
    transform: translateY(-2px);
    box-shadow: 0 4px 20px rgba(0,0,0,0.4);
}
.profile-card-header {
    padding: 16px 20px;
    display: flex;
    justify-content: space-between;
    align-items: center;
    border-bottom: 1px solid #333;
}
.profile-card-header .name {
    font-size: 18px;
    font-weight: 600;
    color: #ffffff;
}
.profile-card-header .protocol-badge {
    padding: 4px 12px;
    border-radius: 20px;
    font-size: 11px;
    font-weight: 600;
    text-transform: uppercase;
}
.protocol-badge.openvpn { background: #1565c0; color: #ffffff; }
.protocol-badge.wireguard { background: #2e7d32; color: #ffffff; }

.profile-card-body {
    padding: 20px;
}
.profile-status {
    display: flex;
    align-items: center;
    gap: 12px;
    margin-bottom: 16px;
}
.status-indicator {
    width: 12px;
    height: 12px;
    border-radius: 50%;
    animation: pulse 2s infinite;
}
.status-indicator.connected { background: #00c853; }
.status-indicator.connecting { background: #ffc107; }
.status-indicator.disconnected { background: #9e9e9e; }
.status-indicator.error { background: #f44336; }

@keyframes pulse {
    0%, 100% { opacity: 1; }
    50% { opacity: 0.5; }
}

.status-text {
    font-size: 14px;
    font-weight: 500;
}
.status-text.connected { color: #69f0ae; }
.status-text.connecting { color: #ffeb3b; }
.status-text.disconnected { color: #b0bec5; }
.status-text.error { color: #ff8a80; }

.profile-stats {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 12px;
    margin-bottom: 16px;
    padding: 12px;
    background: #2a2a3a;
    border-radius: 8px;
}
.profile-stat {
    text-align: center;
}
.profile-stat .value {
    font-size: 16px;
    font-weight: 600;
    color: #ffffff;
}
.profile-stat .label {
    font-size: 11px;
    color: #b0bec5;
    text-transform: uppercase;
}

.profile-options {
    display: flex;
    gap: 8px;
    margin-bottom: 16px;
}
.option-badge {
    padding: 4px 10px;
    border-radius: 4px;
    font-size: 11px;
    background: #333;
    color: #ffffff;
}
.option-badge.active { background: #1565c0; color: #ffffff; }
.option-badge.danger { background: #c62828; color: #ffffff; }

.profile-card-actions {
    display: flex;
    gap: 8px;
    padding-top: 16px;
    border-top: 1px solid #333;
}
.btn-connect {
    flex: 1;
    padding: 10px;
    background: linear-gradient(135deg, #00c853, #00e676);
    color: #fff;
    border: none;
    border-radius: 8px;
    font-weight: 600;
    cursor: pointer;
    transition: opacity 0.2s;
}
.btn-connect:hover { opacity: 0.9; }
.btn-connect:disabled { background: #555; color: #888; cursor: not-allowed; }

.btn-disconnect {
    flex: 1;
    padding: 10px;
    background: linear-gradient(135deg, #f44336, #e53935);
    color: #fff;
    border: none;
    border-radius: 8px;
    font-weight: 600;
    cursor: pointer;
}
.btn-disconnect:hover { opacity: 0.9; }

.btn-edit, .btn-delete {
    padding: 10px 16px;
    border: 1px solid #555;
    background: #2a2a3a;
    color: #ffffff;
    border-radius: 8px;
    cursor: pointer;
}
.btn-edit:hover { background: #3a3a4a; }
.btn-delete:hover { background: #c62828; border-color: #f44336; color: #ffffff; }

/* Add Profile Card */
.add-profile-card {
    background: #1e1e2e;
    border: 2px dashed #555;
    border-radius: 12px;
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    min-height: 280px;
    cursor: pointer;
    transition: all 0.2s;
}
.add-profile-card:hover {
    border-color: #00d4ff;
    background: #252535;
}
.add-profile-card i {
    font-size: 48px;
    color: #888;
    margin-bottom: 12px;
}
.add-profile-card:hover i { color: #00d4ff; }
.add-profile-card span {
    font-size: 16px;
    color: #ffffff;
}

/* Tabs */
.fusion-tabs {
    display: flex;
    gap: 4px;
    margin-bottom: 24px;
    background: #1e1e2e;
    padding: 4px;
    border-radius: 10px;
}
.fusion-tab {
    padding: 12px 24px;
    border: none;
    background: transparent;
    color: #b0bec5;
    font-weight: 500;
    cursor: pointer;
    border-radius: 8px;
    transition: all 0.2s;
}
.fusion-tab:hover { background: #2a2a3a; color: #ffffff; }
.fusion-tab.active {
    background: #2a2a3a;
    color: #ffffff;
    box-shadow: 0 2px 8px rgba(0,0,0,0.3);
}

/* Device Assignment Table */
.assignment-table {
    width: 100%;
    background: #1e1e2e;
    border-radius: 12px;
    overflow: hidden;
    box-shadow: 0 2px 12px rgba(0,0,0,0.3);
}
.assignment-table th {
    background: #2a2a3a;
    padding: 14px 16px;
    text-align: left;
    font-weight: 600;
    color: #ffffff;
    font-size: 12px;
    text-transform: uppercase;
}
.assignment-table td {
    padding: 14px 16px;
    border-top: 1px solid #333;
    color: #ffffff;
}
.assignment-table tr:hover td { background: #252535; }

/* Empty state */
.empty-state {
    text-align: center;
    padding: 60px 20px;
    color: #b0bec5;
}
.empty-state i { font-size: 48px; margin-bottom: 16px; color: #888; }
.empty-state p { color: #b0bec5; }

/* Panel overrides for dark mode */
.panel-default { background: #1e1e2e; border-color: #333; }
.panel-heading { background: #2a2a3a !important; border-color: #333; }
.panel-title { color: #ffffff !important; }
.panel-body { color: #b0bec5; }
.panel-body p { color: #b0bec5; }
.text-muted { color: #888 !important; }

/* Modal Form */
.fusion-modal .form-group { margin-bottom: 20px; }
.fusion-modal label {
    display: block;
    margin-bottom: 8px;
    font-weight: 500;
    color: #ffffff;
}
.fusion-modal input[type="text"],
.fusion-modal input[type="password"],
.fusion-modal textarea,
.fusion-modal select {
    width: 100%;
    padding: 12px;
    border: 1px solid #555;
    border-radius: 8px;
    font-size: 14px;
    background: #1e1e2e;
    color: #ffffff;
}
.fusion-modal textarea { min-height: 200px; font-family: monospace; }
.fusion-modal .switch-group {
    display: flex;
    align-items: center;
    gap: 12px;
}
.fusion-modal .switch-group label { color: #ffffff; margin-bottom: 0; }
.fusion-modal small { color: #888; }
</style>

<!-- Fusion VPN Header -->
<div class="fusion-header">
    <h2>
        <div class="fusion-logo"><i class="fa fa-shield"></i></div>
        Fusion VPN
    </h2>
    <div class="stats">
        <div class="stat-item">
            <div class="stat-value" id="totalProfiles">0</div>
            <div class="stat-label">Profiles</div>
        </div>
        <div class="stat-item">
            <div class="stat-value" id="connectedProfiles">0</div>
            <div class="stat-label">Connected</div>
        </div>
        <div class="stat-item">
            <div class="stat-value" id="totalTraffic">0 B</div>
            <div class="stat-label">Traffic</div>
        </div>
    </div>
</div>

<!-- Tabs -->
<div class="fusion-tabs">
    <button class="fusion-tab active" data-tab="profiles"><i class="fa fa-server"></i> VPN Profiles</button>
    <button class="fusion-tab" data-tab="devices"><i class="fa fa-laptop"></i> Device Routing</button>
    <button class="fusion-tab" data-tab="exceptions"><i class="fa fa-ban"></i> Exceptions</button>
</div>

<!-- Tab: VPN Profiles -->
<div id="tab-profiles" class="tab-content">
    <div class="profiles-grid" id="profilesGrid">
        <!-- Profiles loaded dynamically -->
        <div class="add-profile-card" onclick="showAddProfileModal()">
            <i class="fa fa-plus-circle"></i>
            <span>Add VPN Profile</span>
        </div>
    </div>
</div>

<!-- Tab: Device Routing -->
<div id="tab-devices" class="tab-content" style="display: none;">
    <div class="panel panel-default">
        <div class="panel-heading">
            <h3 class="panel-title"><i class="fa fa-laptop"></i> Device VPN Assignments</h3>
        </div>
        <div class="panel-body">
            <p class="text-muted" style="margin-bottom: 16px;">
                <i class="fa fa-info-circle"></i> Assign specific devices to route their traffic through a VPN profile.
                Devices not assigned will use the default gateway unless a profile has "Apply to All Devices" enabled.
            </p>
            <button class="btn btn-primary" onclick="showAssignDeviceModal()">
                <i class="fa fa-plus"></i> Assign Device
            </button>
        </div>
        <table class="assignment-table">
            <thead>
                <tr>
                    <th>Device</th>
                    <th>MAC Address</th>
                    <th>VPN Profile</th>
                    <th>Assigned</th>
                    <th>Actions</th>
                </tr>
            </thead>
            <tbody id="assignmentsTable">
                <tr>
                    <td colspan="5" class="empty-state">
                        <i class="fa fa-laptop"></i>
                        <p>No device assignments configured</p>
                    </td>
                </tr>
            </tbody>
        </table>
    </div>
</div>

<!-- Tab: Exceptions -->
<div id="tab-exceptions" class="tab-content" style="display: none;">
    <div class="panel panel-default">
        <div class="panel-heading">
            <h3 class="panel-title"><i class="fa fa-ban"></i> Exception Devices (Bypass VPN)</h3>
        </div>
        <div class="panel-body">
            <p class="text-muted" style="margin-bottom: 16px;">
                <i class="fa fa-info-circle"></i> Devices in this list will always bypass VPN and use the default gateway,
                regardless of other VPN settings.
            </p>
            <button class="btn btn-primary" onclick="showAddExceptionModal()">
                <i class="fa fa-plus"></i> Add Exception
            </button>
        </div>
        <table class="assignment-table">
            <thead>
                <tr>
                    <th>Device</th>
                    <th>MAC Address</th>
                    <th>Reason</th>
                    <th>Added</th>
                    <th>Actions</th>
                </tr>
            </thead>
            <tbody id="exceptionsTable">
                <tr>
                    <td colspan="5" class="empty-state">
                        <i class="fa fa-check-circle"></i>
                        <p>No exception devices configured</p>
                    </td>
                </tr>
            </tbody>
        </table>
    </div>
</div>

<script>
$(document).ready(function() {
    loadStatus();
    loadProfiles();
    loadAssignments();
    loadExceptions();

    // Auto-refresh every 30 seconds
    setInterval(function() {
        loadStatus();
        loadProfiles();
    }, 30000);

    // Tab switching
    $('.fusion-tab').on('click', function() {
        var tab = $(this).data('tab');
        $('.fusion-tab').removeClass('active');
        $(this).addClass('active');
        $('.tab-content').hide();
        $('#tab-' + tab).show();
    });
});

function formatBytes(bytes) {
    if (!bytes || bytes === 0) return '0 B';
    var k = 1024;
    var sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    var i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
}

function escapeHtml(text) {
    if (!text) return '';
    var div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

function loadStatus() {
    $.getJSON('/api/netshield/fusionvpn/status', function(data) {
        $('#totalProfiles').text(data.total_profiles || 0);
        $('#connectedProfiles').text(data.connected_profiles || 0);
        var totalBytes = (data.total_bytes_in || 0) + (data.total_bytes_out || 0);
        $('#totalTraffic').text(formatBytes(totalBytes));
    });
}

function loadProfiles() {
    $.getJSON('/api/netshield/fusionvpn/profiles', function(data) {
        var grid = $('#profilesGrid');
        grid.find('.profile-card').remove();

        var profiles = data.profiles || [];
        profiles.forEach(function(profile) {
            var statusClass = (profile.status || 'disconnected').toLowerCase();
            var card = `
                <div class="profile-card" data-id="${profile.id}">
                    <div class="profile-card-header">
                        <span class="name">${escapeHtml(profile.name)}</span>
                        <span class="protocol-badge ${profile.protocol}">${profile.protocol}</span>
                    </div>
                    <div class="profile-card-body">
                        <div class="profile-status">
                            <span class="status-indicator ${statusClass}"></span>
                            <span class="status-text ${statusClass}">${profile.status || 'Disconnected'}</span>
                        </div>
                        <div class="profile-stats">
                            <div class="profile-stat">
                                <div class="value">${formatBytes(profile.bytes_in)}</div>
                                <div class="label">Download</div>
                            </div>
                            <div class="profile-stat">
                                <div class="value">${formatBytes(profile.bytes_out)}</div>
                                <div class="label">Upload</div>
                            </div>
                        </div>
                        <div class="profile-options">
                            <span class="option-badge ${profile.apply_to_all ? 'active' : ''}">
                                <i class="fa fa-${profile.apply_to_all ? 'check' : 'times'}"></i> All Devices
                            </span>
                            <span class="option-badge ${profile.kill_switch ? 'danger' : ''}">
                                <i class="fa fa-${profile.kill_switch ? 'check' : 'times'}"></i> Kill Switch
                            </span>
                        </div>
                        <div class="profile-card-actions">
                            ${profile.status === 'connected'
                                ? `<button class="btn-disconnect" onclick="disconnectProfile(${profile.id})"><i class="fa fa-stop"></i> Disconnect</button>`
                                : `<button class="btn-connect" onclick="connectProfile(${profile.id})" ${profile.status === 'connecting' ? 'disabled' : ''}><i class="fa fa-play"></i> Connect</button>`
                            }
                            <button class="btn-edit" onclick="editProfile(${profile.id})"><i class="fa fa-cog"></i></button>
                            <button class="btn-delete" onclick="deleteProfile(${profile.id})"><i class="fa fa-trash"></i></button>
                        </div>
                    </div>
                </div>
            `;
            grid.prepend(card);
        });
    });
}

function loadAssignments() {
    $.getJSON('/api/netshield/fusionvpn/assignments', function(data) {
        var tbody = $('#assignmentsTable');
        tbody.empty();

        var assignments = data.assignments || [];
        if (assignments.length === 0) {
            tbody.html('<tr><td colspan="5" class="empty-state"><i class="fa fa-laptop"></i><p>No device assignments configured</p></td></tr>');
            return;
        }

        assignments.forEach(function(a) {
            tbody.append(`
                <tr>
                    <td><strong>${escapeHtml(a.device_name || 'Unknown')}</strong></td>
                    <td><code>${escapeHtml(a.device_mac)}</code></td>
                    <td><span class="label label-primary">${escapeHtml(a.profile_name)}</span></td>
                    <td>${escapeHtml(a.created_at)}</td>
                    <td>
                        <button class="btn btn-xs btn-danger" onclick="unassignDevice(${a.id})">
                            <i class="fa fa-trash"></i> Remove
                        </button>
                    </td>
                </tr>
            `);
        });
    });
}

function loadExceptions() {
    $.getJSON('/api/netshield/fusionvpn/exceptions', function(data) {
        var tbody = $('#exceptionsTable');
        tbody.empty();

        var exceptions = data.exceptions || [];
        if (exceptions.length === 0) {
            tbody.html('<tr><td colspan="5" class="empty-state"><i class="fa fa-check-circle"></i><p>No exception devices configured</p></td></tr>');
            return;
        }

        exceptions.forEach(function(e) {
            tbody.append(`
                <tr>
                    <td><strong>${escapeHtml(e.device_name || 'Unknown')}</strong></td>
                    <td><code>${escapeHtml(e.device_mac)}</code></td>
                    <td>${escapeHtml(e.reason || '-')}</td>
                    <td>${escapeHtml(e.created_at)}</td>
                    <td>
                        <button class="btn btn-xs btn-danger" onclick="removeException(${e.id})">
                            <i class="fa fa-trash"></i> Remove
                        </button>
                    </td>
                </tr>
            `);
        });
    });
}

function connectProfile(id) {
    $.post('/api/netshield/fusionvpn/connect', {id: id}, function(data) {
        if (data.status === 'ok') {
            loadProfiles();
            loadStatus();
        } else {
            alert('Failed to connect: ' + (data.message || 'Unknown error'));
        }
    });
}

function disconnectProfile(id) {
    if (!confirm('Disconnect this VPN?')) return;
    $.post('/api/netshield/fusionvpn/disconnect', {id: id}, function(data) {
        if (data.status === 'ok') {
            loadProfiles();
            loadStatus();
        } else {
            alert('Failed to disconnect: ' + (data.message || 'Unknown error'));
        }
    });
}

function deleteProfile(id) {
    if (!confirm('Delete this VPN profile? This cannot be undone.')) return;
    $.post('/api/netshield/fusionvpn/deleteProfile', {id: id}, function(data) {
        if (data.status === 'ok') {
            loadProfiles();
            loadStatus();
        } else {
            alert('Failed to delete: ' + (data.message || 'Unknown error'));
        }
    });
}

function showAddProfileModal() {
    var html = `
        <div class="fusion-modal">
            <div class="form-group">
                <label>Profile Name</label>
                <input type="text" id="profileName" placeholder="e.g., NordVPN US">
            </div>
            <div class="form-group">
                <label>Protocol</label>
                <select id="profileProtocol">
                    <option value="openvpn">OpenVPN</option>
                    <option value="wireguard">WireGuard</option>
                </select>
            </div>
            <div class="form-group">
                <label>Configuration</label>
                <textarea id="profileConfig" placeholder="Paste your .ovpn or WireGuard config here..."></textarea>
                <small class="text-muted">Or upload a file: <input type="file" id="configFile" accept=".ovpn,.conf"></small>
            </div>
            <div class="form-group">
                <label>Username (optional)</label>
                <input type="text" id="profileUsername" placeholder="VPN username">
            </div>
            <div class="form-group">
                <label>Password (optional)</label>
                <input type="password" id="profilePassword" placeholder="VPN password">
            </div>
            <div class="form-group">
                <div class="switch-group">
                    <input type="checkbox" id="applyToAll" checked>
                    <label for="applyToAll">Apply to All Devices</label>
                </div>
            </div>
            <div class="form-group">
                <div class="switch-group">
                    <input type="checkbox" id="killSwitch">
                    <label for="killSwitch">Kill Switch (block internet if VPN disconnects)</label>
                </div>
            </div>
        </div>
    `;

    BootstrapDialog.show({
        title: '<i class="fa fa-plus"></i> Add VPN Profile',
        message: html,
        size: BootstrapDialog.SIZE_WIDE,
        onshown: function(dialog) {
            $('#configFile').on('change', function(e) {
                var file = e.target.files[0];
                if (file) {
                    var reader = new FileReader();
                    reader.onload = function(e) {
                        $('#profileConfig').val(e.target.result);
                        var name = file.name.replace(/\.(ovpn|conf)$/i, '');
                        if (!$('#profileName').val()) {
                            $('#profileName').val(name);
                        }
                        if (file.name.endsWith('.conf')) {
                            $('#profileProtocol').val('wireguard');
                        }
                    };
                    reader.readAsText(file);
                }
            });
        },
        buttons: [
            {label: 'Cancel', action: function(d) { d.close(); }},
            {
                label: '<i class="fa fa-check"></i> Create Profile',
                cssClass: 'btn-primary',
                action: function(dialog) {
                    var data = {
                        name: $('#profileName').val(),
                        protocol: $('#profileProtocol').val(),
                        config_content: $('#profileConfig').val(),
                        username: $('#profileUsername').val(),
                        password: $('#profilePassword').val(),
                        apply_to_all: $('#applyToAll').is(':checked') ? '1' : '0',
                        kill_switch: $('#killSwitch').is(':checked') ? '1' : '0'
                    };

                    if (!data.name || !data.config_content) {
                        alert('Name and configuration are required');
                        return;
                    }

                    $.post('/api/netshield/fusionvpn/createProfile', data, function(resp) {
                        if (resp.status === 'ok') {
                            dialog.close();
                            loadProfiles();
                            loadStatus();
                        } else {
                            alert('Failed: ' + (resp.message || 'Unknown error'));
                        }
                    });
                }
            }
        ]
    });
}

function editProfile(id) {
    $.getJSON('/api/netshield/fusionvpn/profile', {id: id}, function(profile) {
        var html = `
            <div class="fusion-modal">
                <div class="form-group">
                    <label>Profile Name</label>
                    <input type="text" id="editProfileName" value="${escapeHtml(profile.name)}">
                </div>
                <div class="form-group">
                    <label>Username</label>
                    <input type="text" id="editProfileUsername" value="${escapeHtml(profile.username || '')}">
                </div>
                <div class="form-group">
                    <label>Password (leave blank to keep current)</label>
                    <input type="password" id="editProfilePassword" placeholder="••••••••">
                </div>
                <div class="form-group">
                    <div class="switch-group">
                        <input type="checkbox" id="editApplyToAll" ${profile.apply_to_all ? 'checked' : ''}>
                        <label for="editApplyToAll">Apply to All Devices</label>
                    </div>
                </div>
                <div class="form-group">
                    <div class="switch-group">
                        <input type="checkbox" id="editKillSwitch" ${profile.kill_switch ? 'checked' : ''}>
                        <label for="editKillSwitch">Kill Switch</label>
                    </div>
                </div>
            </div>
        `;

        BootstrapDialog.show({
            title: '<i class="fa fa-cog"></i> Edit VPN Profile',
            message: html,
            buttons: [
                {label: 'Cancel', action: function(d) { d.close(); }},
                {
                    label: '<i class="fa fa-save"></i> Save Changes',
                    cssClass: 'btn-primary',
                    action: function(dialog) {
                        var data = {
                            id: id,
                            name: $('#editProfileName').val(),
                            username: $('#editProfileUsername').val(),
                            apply_to_all: $('#editApplyToAll').is(':checked') ? '1' : '0',
                            kill_switch: $('#editKillSwitch').is(':checked') ? '1' : '0'
                        };
                        var pwd = $('#editProfilePassword').val();
                        if (pwd) data.password = pwd;

                        $.post('/api/netshield/fusionvpn/updateProfile', data, function(resp) {
                            if (resp.status === 'ok') {
                                dialog.close();
                                loadProfiles();
                            } else {
                                alert('Failed: ' + (resp.message || 'Unknown error'));
                            }
                        });
                    }
                }
            ]
        });
    });
}

function showAssignDeviceModal() {
    // First load profiles and devices
    $.when(
        $.getJSON('/api/netshield/fusionvpn/profiles'),
        $.getJSON('/api/netshield/devices/search')
    ).done(function(profilesResp, devicesResp) {
        var profiles = profilesResp[0].profiles || [];
        var devices = devicesResp[0].rows || [];

        var profileOptions = profiles.map(p => `<option value="${p.id}">${escapeHtml(p.name)}</option>`).join('');
        var deviceOptions = devices.map(d => `<option value="${d.mac}" data-name="${escapeHtml(d.hostname || '')}">${escapeHtml(d.hostname || d.mac)} (${d.mac})</option>`).join('');

        var html = `
            <div class="fusion-modal">
                <div class="form-group">
                    <label>VPN Profile</label>
                    <select id="assignProfileId">${profileOptions}</select>
                </div>
                <div class="form-group">
                    <label>Device</label>
                    <select id="assignDeviceMac">${deviceOptions}</select>
                </div>
            </div>
        `;

        BootstrapDialog.show({
            title: '<i class="fa fa-laptop"></i> Assign Device to VPN',
            message: html,
            buttons: [
                {label: 'Cancel', action: function(d) { d.close(); }},
                {
                    label: '<i class="fa fa-check"></i> Assign',
                    cssClass: 'btn-primary',
                    action: function(dialog) {
                        var mac = $('#assignDeviceMac').val();
                        var name = $('#assignDeviceMac option:selected').data('name');
                        $.post('/api/netshield/fusionvpn/assignDevice', {
                            profile_id: $('#assignProfileId').val(),
                            device_mac: mac,
                            device_name: name
                        }, function(resp) {
                            if (resp.status === 'ok') {
                                dialog.close();
                                loadAssignments();
                            } else {
                                alert('Failed: ' + (resp.message || 'Unknown error'));
                            }
                        });
                    }
                }
            ]
        });
    });
}

function unassignDevice(id) {
    if (!confirm('Remove this device assignment?')) return;
    $.post('/api/netshield/fusionvpn/unassignDevice', {id: id}, function(resp) {
        if (resp.status === 'ok') {
            loadAssignments();
        } else {
            alert('Failed: ' + (resp.message || 'Unknown error'));
        }
    });
}

function showAddExceptionModal() {
    $.getJSON('/api/netshield/devices/search', function(data) {
        var devices = data.rows || [];
        var deviceOptions = devices.map(d => `<option value="${d.mac}" data-name="${escapeHtml(d.hostname || '')}">${escapeHtml(d.hostname || d.mac)} (${d.mac})</option>`).join('');

        var html = `
            <div class="fusion-modal">
                <div class="form-group">
                    <label>Device</label>
                    <select id="exceptionDeviceMac">${deviceOptions}</select>
                </div>
                <div class="form-group">
                    <label>Reason (optional)</label>
                    <input type="text" id="exceptionReason" placeholder="e.g., Gaming console - needs direct connection">
                </div>
            </div>
        `;

        BootstrapDialog.show({
            title: '<i class="fa fa-ban"></i> Add VPN Exception',
            message: html,
            buttons: [
                {label: 'Cancel', action: function(d) { d.close(); }},
                {
                    label: '<i class="fa fa-check"></i> Add Exception',
                    cssClass: 'btn-primary',
                    action: function(dialog) {
                        var mac = $('#exceptionDeviceMac').val();
                        var name = $('#exceptionDeviceMac option:selected').data('name');
                        $.post('/api/netshield/fusionvpn/addException', {
                            device_mac: mac,
                            device_name: name,
                            reason: $('#exceptionReason').val()
                        }, function(resp) {
                            if (resp.status === 'ok') {
                                dialog.close();
                                loadExceptions();
                            } else {
                                alert('Failed: ' + (resp.message || 'Unknown error'));
                            }
                        });
                    }
                }
            ]
        });
    });
}

function removeException(id) {
    if (!confirm('Remove this exception?')) return;
    $.post('/api/netshield/fusionvpn/removeException', {id: id}, function(resp) {
        if (resp.status === 'ok') {
            loadExceptions();
        } else {
            alert('Failed: ' + (resp.message || 'Unknown error'));
        }
    });
}
</script>
