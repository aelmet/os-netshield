{#
 # Copyright (C) 2025-2026 NetShield
 # Policies - Zenarmor-style 8-tab security policy editor
 #}

<style>
/* Dark Mode Policy Styles */
.policy-header {
    background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
    color: #fff;
    padding: 24px;
    border-radius: 12px;
    margin-bottom: 24px;
    display: flex;
    justify-content: space-between;
    align-items: center;
}
.policy-header h2 {
    margin: 0;
    font-size: 24px;
    display: flex;
    align-items: center;
    gap: 12px;
}
.policy-header .stats {
    display: flex;
    gap: 32px;
}
.policy-header .stat-item {
    text-align: center;
}
.policy-header .stat-value {
    font-size: 28px;
    font-weight: 700;
    color: #00d4ff;
}
.policy-header .stat-label {
    font-size: 12px;
    color: rgba(255,255,255,0.85);
    text-transform: uppercase;
}

/* Policy Cards */
.policies-container {
    display: flex;
    flex-direction: column;
    gap: 16px;
}
.policy-card {
    background: #1e1e2e;
    border-radius: 12px;
    box-shadow: 0 2px 12px rgba(0,0,0,0.3);
    overflow: hidden;
    border-left: 4px solid #00d4ff;
}
.policy-card.disabled {
    opacity: 0.6;
    border-left-color: #555;
}
.policy-card.action-block { border-left-color: #f44336; }
.policy-card.action-allow { border-left-color: #4caf50; }
.policy-card.action-log { border-left-color: #ff9800; }
.policy-card.action-throttle { border-left-color: #9c27b0; }

.policy-card-header {
    padding: 16px 20px;
    display: flex;
    justify-content: space-between;
    align-items: center;
    border-bottom: 1px solid #333;
}
.policy-card-header .policy-name {
    font-size: 18px;
    font-weight: 600;
    color: #ffffff;
    display: flex;
    align-items: center;
    gap: 12px;
}
.policy-card-header .policy-actions {
    display: flex;
    gap: 8px;
    align-items: center;
}

.policy-card-body {
    padding: 20px;
}
.policy-info-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    gap: 16px;
}
.policy-info-item {
    background: #2a2a3a;
    border-radius: 8px;
    padding: 12px;
}
.policy-info-item .label {
    font-size: 11px;
    color: #888;
    text-transform: uppercase;
    margin-bottom: 4px;
}
.policy-info-item .value {
    font-size: 14px;
    color: #ffffff;
    font-weight: 500;
}

/* Tags/Badges */
.tag-container {
    display: flex;
    flex-wrap: wrap;
    gap: 6px;
    margin-top: 8px;
}
.tag {
    padding: 4px 10px;
    border-radius: 12px;
    font-size: 11px;
    font-weight: 500;
}
.tag-app { background: #3498db; color: #fff; }
.tag-category { background: #9b59b6; color: #fff; }
.tag-device { background: #1abc9c; color: #fff; }
.tag-vlan { background: #e67e22; color: #fff; }
.tag-network { background: #27ae60; color: #fff; }
.tag-security { background: #e74c3c; color: #fff; }
.tag-schedule { background: #2980b9; color: #fff; }

/* Action Badges */
.action-badge {
    padding: 6px 14px;
    border-radius: 20px;
    font-size: 12px;
    font-weight: 600;
    text-transform: uppercase;
}
.action-badge.block { background: #f44336; color: #fff; }
.action-badge.allow { background: #4caf50; color: #fff; }
.action-badge.log { background: #ff9800; color: #fff; }
.action-badge.throttle { background: #9c27b0; color: #fff; }

/* Toggle Switch */
.toggle-switch {
    position: relative;
    width: 50px;
    height: 26px;
}
.toggle-switch input {
    opacity: 0;
    width: 0;
    height: 0;
}
.toggle-slider {
    position: absolute;
    cursor: pointer;
    top: 0;
    left: 0;
    right: 0;
    bottom: 0;
    background-color: #555;
    transition: .3s;
    border-radius: 26px;
}
.toggle-slider:before {
    position: absolute;
    content: "";
    height: 20px;
    width: 20px;
    left: 3px;
    bottom: 3px;
    background-color: white;
    transition: .3s;
    border-radius: 50%;
}
input:checked + .toggle-slider {
    background-color: #00d4ff;
}
input:checked + .toggle-slider:before {
    transform: translateX(24px);
}

/* Buttons */
.btn-icon {
    width: 36px;
    height: 36px;
    border-radius: 8px;
    border: 1px solid #555;
    background: #2a2a3a;
    color: #ffffff;
    cursor: pointer;
    display: flex;
    align-items: center;
    justify-content: center;
    transition: all 0.2s;
}
.btn-icon:hover { background: #3a3a4a; }
.btn-icon.danger:hover { background: #c62828; border-color: #f44336; }

.btn-add-policy {
    background: linear-gradient(135deg, #00d4ff, #0099ff);
    color: #fff;
    border: none;
    padding: 12px 24px;
    border-radius: 8px;
    font-weight: 600;
    cursor: pointer;
    display: flex;
    align-items: center;
    gap: 8px;
}
.btn-add-policy:hover { opacity: 0.9; }

/* Empty State */
.empty-state {
    text-align: center;
    padding: 60px 20px;
    background: #1e1e2e;
    border-radius: 12px;
}
.empty-state i { font-size: 64px; color: #555; margin-bottom: 16px; }
.empty-state h3 { color: #ffffff; margin-bottom: 8px; }
.empty-state p { color: #888; margin-bottom: 24px; }

/* ===== TABBED MODAL STYLES ===== */
.policy-modal .modal-dialog {
    width: 900px;
    max-width: 95vw;
}
.policy-modal .modal-content {
    background: #1e1e2e;
    border: 1px solid #333;
    color: #ffffff;
}
.policy-modal .modal-header {
    background: #2a2a3a;
    border-bottom: 1px solid #333;
}
.policy-modal .modal-header .modal-title { color: #ffffff; }
.policy-modal .modal-body {
    background: #1e1e2e;
    padding: 0;
}
.policy-modal .modal-footer {
    background: #2a2a3a;
    border-top: 1px solid #333;
}

/* Tab Navigation */
.policy-tabs {
    display: flex;
    background: #16162a;
    border-bottom: 1px solid #333;
    overflow-x: auto;
}
.policy-tab {
    padding: 14px 18px;
    cursor: pointer;
    color: #888;
    font-size: 13px;
    font-weight: 500;
    display: flex;
    align-items: center;
    gap: 8px;
    border-bottom: 3px solid transparent;
    transition: all 0.2s;
    white-space: nowrap;
    flex-shrink: 0;
}
.policy-tab:hover {
    color: #ccc;
    background: rgba(255,255,255,0.03);
}
.policy-tab.active {
    color: #00d4ff;
    border-bottom-color: #00d4ff;
    background: rgba(0,212,255,0.05);
}
.policy-tab i { font-size: 14px; }

/* Tab Content */
.tab-content-area {
    padding: 24px;
    min-height: 400px;
    max-height: 65vh;
    overflow-y: auto;
}
.tab-pane {
    display: none;
}
.tab-pane.active {
    display: block;
}

/* Form Styles */
.policy-modal .form-group { margin-bottom: 20px; }
.policy-modal label {
    display: block;
    margin-bottom: 8px;
    font-weight: 500;
    color: #ffffff;
}
.policy-modal .form-control {
    background: #2a2a3a;
    border: 1px solid #555;
    color: #ffffff;
    border-radius: 8px;
    padding: 10px 12px;
}
.policy-modal .form-control:focus {
    border-color: #00d4ff;
    box-shadow: 0 0 0 2px rgba(0,212,255,0.2);
}
.policy-modal select.form-control option {
    background: #2a2a3a;
    color: #ffffff;
}
.policy-modal .help-block { color: #888; font-size: 12px; margin-top: 4px; }

/* Section Headers in Tabs */
.section-header {
    font-size: 14px;
    font-weight: 600;
    color: #00d4ff;
    margin: 24px 0 16px 0;
    padding-bottom: 8px;
    border-bottom: 1px solid #333;
    display: flex;
    align-items: center;
    gap: 8px;
}
.section-header:first-child { margin-top: 0; }

/* Multi-select Grid */
.multi-select-grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(180px, 1fr));
    gap: 8px;
    max-height: 400px;
    overflow-y: auto;
    padding: 4px;
    background: #2a2a3a;
    border-radius: 8px;
}
.multi-select-item {
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 8px 12px;
    background: #1e1e2e;
    border-radius: 6px;
    cursor: pointer;
    transition: all 0.2s;
    border: 1px solid transparent;
}
.multi-select-item:hover { background: #3a3a4a; }
.multi-select-item.selected {
    background: rgba(0,212,255,0.15);
    border-color: #00d4ff;
}
.multi-select-item input[type="checkbox"] {
    width: 16px;
    height: 16px;
    accent-color: #00d4ff;
}
.multi-select-item .item-icon {
    width: 24px;
    height: 24px;
    border-radius: 4px;
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 12px;
}
.multi-select-item .item-label {
    font-size: 13px;
    color: #ffffff;
}
.multi-select-item .item-count {
    font-size: 11px;
    color: #888;
    margin-left: auto;
}

/* Scope Selector */
.scope-options {
    display: flex;
    gap: 12px;
    margin-bottom: 16px;
}
.scope-option {
    flex: 1;
    padding: 16px;
    background: #2a2a3a;
    border: 2px solid #555;
    border-radius: 8px;
    cursor: pointer;
    text-align: center;
    transition: all 0.2s;
}
.scope-option:hover { border-color: #888; }
.scope-option.selected {
    border-color: #00d4ff;
    background: rgba(0,212,255,0.1);
}
.scope-option i { font-size: 24px; color: #888; margin-bottom: 8px; display: block; }
.scope-option.selected i { color: #00d4ff; }
.scope-option .scope-label { font-size: 14px; font-weight: 500; color: #ffffff; }
.scope-option .scope-desc { font-size: 11px; color: #888; margin-top: 4px; }

/* Device/VLAN Selector */
.target-selector {
    display: none;
    margin-top: 16px;
}
.target-selector.visible { display: block; }

/* Security Presets */
.preset-options {
    display: flex;
    gap: 12px;
    margin-bottom: 20px;
}
.preset-option {
    flex: 1;
    padding: 16px;
    background: #2a2a3a;
    border: 2px solid #555;
    border-radius: 8px;
    cursor: pointer;
    text-align: center;
    transition: all 0.2s;
}
.preset-option:hover { border-color: #888; }
.preset-option.selected {
    border-color: #00d4ff;
    background: rgba(0,212,255,0.1);
}
.preset-option .preset-name { font-size: 14px; font-weight: 600; color: #fff; }
.preset-option .preset-desc { font-size: 11px; color: #888; margin-top: 4px; }
.preset-option.permissive.selected { border-color: #4caf50; }
.preset-option.moderate.selected { border-color: #ff9800; }
.preset-option.high.selected { border-color: #f44336; }

/* Security Category Grid */
.security-grid {
    display: grid;
    grid-template-columns: 1fr 100px 100px;
    gap: 0;
    background: #2a2a3a;
    border-radius: 8px;
    overflow: hidden;
}
.security-grid .sg-header {
    padding: 10px 14px;
    font-size: 12px;
    font-weight: 600;
    color: #888;
    text-transform: uppercase;
    background: #222;
    border-bottom: 1px solid #333;
}
.security-grid .sg-cell {
    padding: 10px 14px;
    border-bottom: 1px solid #333;
    display: flex;
    align-items: center;
    font-size: 13px;
    color: #fff;
}
.security-grid .sg-cell:nth-child(3n+1) {
    gap: 8px;
}

/* Schedule Row */
.schedule-row {
    display: flex;
    gap: 12px;
    align-items: center;
    padding: 12px;
    background: #2a2a3a;
    border-radius: 8px;
    margin-bottom: 8px;
}
.schedule-row input[type="text"],
.schedule-row input[type="time"] {
    background: #1e1e2e;
    border: 1px solid #555;
    color: #fff;
    border-radius: 6px;
    padding: 8px 10px;
    font-size: 13px;
}
.schedule-row input[type="text"] { width: 150px; }
.schedule-row input[type="time"] { width: 110px; }
.schedule-row .day-pills {
    display: flex;
    gap: 4px;
}
.day-pill {
    width: 34px;
    height: 30px;
    border-radius: 6px;
    border: 1px solid #555;
    background: #1e1e2e;
    color: #888;
    cursor: pointer;
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 11px;
    font-weight: 600;
    transition: all 0.2s;
}
.day-pill.active {
    background: #00d4ff;
    color: #000;
    border-color: #00d4ff;
}
.schedule-row .btn-remove {
    background: none;
    border: none;
    color: #f44336;
    cursor: pointer;
    font-size: 16px;
    padding: 4px;
}

/* Exclusion Table */
.exclusion-table {
    width: 100%;
    border-collapse: collapse;
}
.exclusion-table th {
    background: #222;
    padding: 10px 14px;
    text-align: left;
    font-size: 12px;
    color: #888;
    text-transform: uppercase;
    border-bottom: 1px solid #333;
}
.exclusion-table td {
    padding: 10px 14px;
    border-bottom: 1px solid #333;
    font-size: 13px;
    color: #fff;
}

/* Prevention toggle row */
.prevention-row {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 14px 16px;
    background: #2a2a3a;
    border-radius: 8px;
    margin-bottom: 8px;
}
.prevention-row .prevention-info {
    display: flex;
    align-items: center;
    gap: 12px;
}
.prevention-row .prevention-info i {
    font-size: 20px;
    width: 36px;
    height: 36px;
    display: flex;
    align-items: center;
    justify-content: center;
    background: rgba(255,255,255,0.05);
    border-radius: 8px;
}
.prevention-row .prevention-name { font-weight: 600; color: #fff; }
.prevention-row .prevention-desc { font-size: 12px; color: #888; }

/* No Internet Banner */
.no-internet-banner {
    background: linear-gradient(135deg, #c62828 0%, #b71c1c 100%);
    border-radius: 8px;
    padding: 16px;
    margin-bottom: 20px;
    display: flex;
    justify-content: space-between;
    align-items: center;
}
.no-internet-banner .nib-info {
    display: flex;
    align-items: center;
    gap: 14px;
}
.no-internet-banner i { font-size: 28px; }
.no-internet-banner .nib-title { font-weight: 700; font-size: 16px; }
.no-internet-banner .nib-desc { font-size: 12px; opacity: 0.85; }
</style>

<!-- Policy Header -->
<div class="policy-header">
    <h2>
        <i class="fa fa-shield"></i>
        Security Policies
    </h2>
    <div class="stats">
        <div class="stat-item">
            <div class="stat-value" id="totalPolicies">0</div>
            <div class="stat-label">Policies</div>
        </div>
        <div class="stat-item">
            <div class="stat-value" id="activePolicies">0</div>
            <div class="stat-label">Active</div>
        </div>
        <div class="stat-item">
            <div class="stat-value" id="blockedToday">0</div>
            <div class="stat-label">Blocked Today</div>
        </div>
    </div>
</div>

<!-- Toolbar -->
<div class="row" style="margin-bottom: 20px;">
    <div class="col-xs-12">
        <button class="btn-add-policy" onclick="showAddPolicyModal()">
            <i class="fa fa-plus"></i>
            Add Policy
        </button>
        <button class="btn btn-default" onclick="loadPolicies()" style="margin-left: 8px;">
            <i class="fa fa-refresh"></i>
        </button>
    </div>
</div>

<!-- Policies List -->
<div class="policies-container" id="policiesContainer">
    <div class="empty-state">
        <i class="fa fa-shield"></i>
        <h3>No Policies Configured</h3>
        <p>Create security policies to control applications, websites, and network traffic.</p>
        <button class="btn-add-policy" onclick="showAddPolicyModal()">
            <i class="fa fa-plus"></i>
            Create First Policy
        </button>
    </div>
</div>

<!-- ===== TABBED POLICY MODAL ===== -->
<div class="modal fade policy-modal" id="policyModal" tabindex="-1" role="dialog">
    <div class="modal-dialog" role="document">
        <div class="modal-content">
            <div class="modal-header">
                <button type="button" class="close" data-dismiss="modal" style="color: #fff;">
                    <span>&times;</span>
                </button>
                <h4 class="modal-title" id="policyModalTitle">
                    <i class="fa fa-plus"></i> Add Policy
                </h4>
            </div>
            <div class="modal-body">
                <form id="policyForm">
                    <input type="hidden" id="policyId" name="id" value="">

                    <!-- Tab Navigation -->
                    <div class="policy-tabs">
                        <div class="policy-tab active" data-tab="config" onclick="switchTab('config')">
                            <i class="fa fa-cog"></i> Configuration
                        </div>
                        <div class="policy-tab" data-tab="security" onclick="switchTab('security')">
                            <i class="fa fa-shield"></i> Security
                        </div>
                        <div class="policy-tab" data-tab="apps" onclick="switchTab('apps')">
                            <i class="fa fa-cubes"></i> App Controls
                        </div>
                        <div class="policy-tab" data-tab="web" onclick="switchTab('web')">
                            <i class="fa fa-globe"></i> Web Controls
                        </div>
                        <div class="policy-tab" data-tab="exclusions" onclick="switchTab('exclusions')">
                            <i class="fa fa-filter"></i> Exclusions
                        </div>
                        <div class="policy-tab" data-tab="schedule" onclick="switchTab('schedule')">
                            <i class="fa fa-clock-o"></i> Schedule
                        </div>
                        <div class="policy-tab" data-tab="advanced" onclick="switchTab('advanced')">
                            <i class="fa fa-sliders"></i> Advanced
                        </div>
                    </div>

                    <!-- ===== TAB: Configuration ===== -->
                    <div class="tab-pane active" id="tab-config">
                        <div class="tab-content-area">
                            <!-- No Internet Kill Switch -->
                            <div class="no-internet-banner" id="noInternetBanner" style="display:none;">
                                <div class="nib-info">
                                    <i class="fa fa-ban"></i>
                                    <div>
                                        <div class="nib-title">No Internet Mode Active</div>
                                        <div class="nib-desc">All internet access will be blocked for matched devices</div>
                                    </div>
                                </div>
                                <label class="toggle-switch">
                                    <input type="checkbox" id="noInternetToggle" onchange="toggleNoInternet()">
                                    <span class="toggle-slider"></span>
                                </label>
                            </div>

                            <div class="row">
                                <div class="col-md-6">
                                    <div class="form-group">
                                        <label for="policyName">Policy Name</label>
                                        <input type="text" class="form-control" id="policyName" name="name"
                                               placeholder="e.g., Block Social Media for Kids" required>
                                    </div>
                                </div>
                                <div class="col-md-3">
                                    <div class="form-group">
                                        <label for="policyAction">Action</label>
                                        <select class="form-control" id="policyAction" name="action">
                                            <option value="block">Block</option>
                                            <option value="allow">Allow</option>
                                            <option value="log">Log Only</option>
                                            <option value="throttle">Throttle</option>
                                        </select>
                                    </div>
                                </div>
                                <div class="col-md-3">
                                    <div class="form-group">
                                        <label>Enable Policy</label>
                                        <div style="margin-top: 8px;">
                                            <label class="toggle-switch">
                                                <input type="checkbox" id="policyEnabled" name="enabled" checked>
                                                <span class="toggle-slider"></span>
                                            </label>
                                        </div>
                                    </div>
                                </div>
                            </div>

                            <div class="form-group">
                                <label for="policyDescription">Description (optional)</label>
                                <input type="text" class="form-control" id="policyDescription" name="description"
                                       placeholder="Brief description of what this policy does">
                            </div>

                            <!-- No Internet Toggle -->
                            <div class="prevention-row">
                                <div class="prevention-info">
                                    <i class="fa fa-ban" style="color: #f44336;"></i>
                                    <div>
                                        <div class="prevention-name">No Internet (Kill Switch)</div>
                                        <div class="prevention-desc">Block ALL internet access for matched devices. Overrides all other rules.</div>
                                    </div>
                                </div>
                                <label class="toggle-switch">
                                    <input type="checkbox" id="noInternetToggle2" onchange="toggleNoInternet()">
                                    <span class="toggle-slider"></span>
                                </label>
                            </div>

                            <!-- Scope -->
                            <div class="section-header" style="margin-top: 24px;">
                                <i class="fa fa-crosshairs"></i> Policy Scope
                            </div>

                            <div class="scope-options">
                                <div class="scope-option selected" data-scope="network" onclick="selectScope('network')">
                                    <i class="fa fa-globe"></i>
                                    <div class="scope-label">Whole Network</div>
                                    <div class="scope-desc">Apply to all devices</div>
                                </div>
                                <div class="scope-option" data-scope="vlan" onclick="selectScope('vlan')">
                                    <i class="fa fa-sitemap"></i>
                                    <div class="scope-label">VLAN</div>
                                    <div class="scope-desc">Specific network segment</div>
                                </div>
                                <div class="scope-option" data-scope="devices" onclick="selectScope('devices')">
                                    <i class="fa fa-laptop"></i>
                                    <div class="scope-label">Devices</div>
                                    <div class="scope-desc">Selected devices only</div>
                                </div>
                            </div>

                            <input type="hidden" id="policyScope" name="scope" value="network">

                            <div class="target-selector" id="vlanSelector">
                                <div class="form-group">
                                    <label>Select VLAN(s)</label>
                                    <select class="form-control" id="policyVlans" name="vlans" multiple>
                                    </select>
                                    <span class="help-block">Hold Ctrl/Cmd to select multiple VLANs</span>
                                </div>
                            </div>

                            <div class="target-selector" id="deviceSelector">
                                <div class="form-group">
                                    <label>Select Devices</label>
                                    <div class="multi-select-grid" id="deviceSelectGrid">
                                    </div>
                                </div>
                            </div>
                            <!-- Excluded Devices -->
                            <div class="section-header" style="margin-top: 24px;">
                                <i class="fa fa-user-times" style="color: #ef4444;"></i> Exclude Devices
                                <span style="font-size: 11px; color: #888; margin-left: 8px;">
                                    These devices will be exempt from this policy even if they match the scope
                                </span>
                            </div>
                            <div class="multi-select-grid" id="excludeDeviceGrid" style="max-height: 200px; overflow-y: auto;">
                            </div>
                        </div>
                    </div>

                    <!-- ===== TAB: Security ===== -->
                    <div class="tab-pane" id="tab-security">
                        <div class="tab-content-area">
                            <div class="section-header" style="margin-top:0;">
                                <i class="fa fa-shield"></i> Security Preset
                            </div>
                            <div class="preset-options">
                                <div class="preset-option permissive" data-preset="permissive" onclick="selectPreset('permissive')">
                                    <div class="preset-name">Permissive</div>
                                    <div class="preset-desc">Block only malware &amp; phishing</div>
                                </div>
                                <div class="preset-option moderate" data-preset="moderate" onclick="selectPreset('moderate')">
                                    <div class="preset-name">Moderate</div>
                                    <div class="preset-desc">Block threats, hacking, spam</div>
                                </div>
                                <div class="preset-option high" data-preset="high" onclick="selectPreset('high')">
                                    <div class="preset-name">High</div>
                                    <div class="preset-desc">Block all risky categories</div>
                                </div>
                                <div class="preset-option selected" data-preset="custom" onclick="selectPreset('custom')">
                                    <div class="preset-name">Custom</div>
                                    <div class="preset-desc">Configure manually</div>
                                </div>
                            </div>

                            <div class="section-header">
                                <i class="fa fa-exclamation-triangle"></i> Essential Security Categories
                            </div>
                            <div class="security-grid">
                                <div class="sg-header">Category</div>
                                <div class="sg-header">Status</div>
                                <div class="sg-header">Action</div>
                            </div>
                            <div id="essentialSecurityGrid"></div>

                            <div class="section-header">
                                <i class="fa fa-bug"></i> Advanced Security Categories
                            </div>
                            <div id="advancedSecurityGrid"></div>
                        </div>
                    </div>

                    <!-- ===== TAB: App Controls ===== -->
                    <div class="tab-pane" id="tab-apps">
                        <div class="tab-content-area">
                            <div class="form-group">
                                <input type="text" class="form-control" id="appSearch" placeholder="Search applications..."
                                       style="margin-bottom: 12px;">
                                <div class="multi-select-grid" id="appSelectGrid">
                                </div>
                            </div>
                        </div>
                    </div>

                    <!-- ===== TAB: Web Controls ===== -->
                    <div class="tab-pane" id="tab-web">
                        <div class="tab-content-area">
                            <div class="section-header" style="margin-top:0;">
                                <i class="fa fa-search"></i> Safe Search &amp; Privacy
                            </div>
                            <div class="prevention-row">
                                <div class="prevention-info">
                                    <i class="fa fa-search" style="color: #4caf50;"></i>
                                    <div>
                                        <div class="prevention-name">Force Safe Search</div>
                                        <div class="prevention-desc">Enforce safe search on Google, Bing, YouTube, and DuckDuckGo</div>
                                    </div>
                                </div>
                                <label class="toggle-switch">
                                    <input type="checkbox" id="safeSearchToggle">
                                    <span class="toggle-slider"></span>
                                </label>
                            </div>
                            <div class="prevention-row">
                                <div class="prevention-info">
                                    <i class="fa fa-lock" style="color: #ff9800;"></i>
                                    <div>
                                        <div class="prevention-name">Block TLS ECH (Encrypted Client Hello)</div>
                                        <div class="prevention-desc">Prevent TLS ECH which can hide the real destination from DNS filtering</div>
                                    </div>
                                </div>
                                <label class="toggle-switch">
                                    <input type="checkbox" id="blockEchToggle">
                                    <span class="toggle-slider"></span>
                                </label>
                            </div>

                            <div class="section-header">
                                <i class="fa fa-folder"></i> Category-Based Controls
                                <span style="font-weight: normal; color: #888; font-size: 12px; margin-left: auto;">
                                    Select categories to include in this policy
                                </span>
                            </div>

                            <div class="form-group">
                                <input type="text" class="form-control" id="categorySearch" placeholder="Search categories..."
                                       style="margin-bottom: 12px;">
                                <div class="multi-select-grid" id="categorySelectGrid">
                                </div>
                            </div>
                        </div>
                    </div>

                    <!-- ===== TAB: Exclusions ===== -->
                    <div class="tab-pane" id="tab-exclusions">
                        <div class="tab-content-area">
                            <div class="section-header" style="margin-top:0;">
                                <i class="fa fa-filter"></i> Whitelist / Blacklist
                            </div>
                            <div class="row" style="margin-bottom: 16px;">
                                <div class="col-md-5">
                                    <input type="text" class="form-control" id="exclusionEntry" placeholder="Domain, IP, or CIDR (e.g., example.com)">
                                </div>
                                <div class="col-md-2">
                                    <select class="form-control" id="exclusionType">
                                        <option value="whitelist">Whitelist</option>
                                        <option value="blacklist">Blacklist</option>
                                    </select>
                                </div>
                                <div class="col-md-3">
                                    <input type="text" class="form-control" id="exclusionDesc" placeholder="Description (optional)">
                                </div>
                                <div class="col-md-2">
                                    <button type="button" class="btn btn-primary btn-block" onclick="addExclusion()">
                                        <i class="fa fa-plus"></i> Add
                                    </button>
                                </div>
                            </div>
                            <div class="row" style="margin-bottom: 16px;">
                                <div class="col-md-6">
                                    <div class="btn-group" role="group">
                                        <button type="button" class="btn btn-default active" onclick="filterExclusions('all', this)">All</button>
                                        <button type="button" class="btn btn-default" onclick="filterExclusions('whitelist', this)">Whitelist</button>
                                        <button type="button" class="btn btn-default" onclick="filterExclusions('blacklist', this)">Blacklist</button>
                                    </div>
                                </div>
                                <div class="col-md-6 text-right">
                                    <label class="btn btn-default" style="margin-bottom:0;">
                                        <i class="fa fa-upload"></i> Import CSV
                                        <input type="file" id="csvImport" accept=".csv,.txt" style="display:none;" onchange="importCsvExclusions(this)">
                                    </label>
                                </div>
                            </div>
                            <table class="exclusion-table" id="exclusionTable">
                                <thead>
                                    <tr>
                                        <th>Entry</th>
                                        <th>Type</th>
                                        <th>Description</th>
                                        <th style="width:60px;"></th>
                                    </tr>
                                </thead>
                                <tbody id="exclusionBody">
                                    <tr><td colspan="4" style="text-align:center; color: #888; padding: 40px;">No exclusions added</td></tr>
                                </tbody>
                            </table>
                        </div>
                    </div>

                    <!-- ===== TAB: Schedule ===== -->
                    <div class="tab-pane" id="tab-schedule">
                        <div class="tab-content-area">
                            <div class="section-header" style="margin-top:0;">
                                <i class="fa fa-clock-o"></i> Named Time Schedules
                                <span style="font-weight: normal; color: #888; font-size: 12px; margin-left: auto;">
                                    Policy is active during ALL matching schedules. No schedules = always active.
                                </span>
                            </div>
                            <div id="schedulesContainer">
                                <!-- Schedule rows added dynamically -->
                            </div>
                            <button type="button" class="btn btn-default" onclick="addScheduleRow()" style="margin-top: 12px;">
                                <i class="fa fa-plus"></i> Add Schedule
                            </button>
                        </div>
                    </div>

                    <!-- ===== TAB: Advanced ===== -->
                    <div class="tab-pane" id="tab-advanced">
                        <div class="tab-content-area">
                            <div class="section-header" style="margin-top:0;">
                                <i class="fa fa-sort-numeric-asc"></i> Priority &amp; Bandwidth
                            </div>
                            <div class="row">
                                <div class="col-md-6">
                                    <div class="form-group">
                                        <label for="policyPriority">Priority</label>
                                        <input type="number" class="form-control" id="policyPriority" name="priority"
                                               value="100" min="1" max="9999">
                                        <span class="help-block">Lower number = higher priority</span>
                                    </div>
                                </div>
                                <div class="col-md-6">
                                    <div class="form-group">
                                        <label for="policyBandwidth">Bandwidth Limit (Kbps, 0 = unlimited)</label>
                                        <input type="number" class="form-control" id="policyBandwidth" name="bandwidth_kbps"
                                               value="0" min="0">
                                        <span class="help-block">Only applies when action is Throttle</span>
                                    </div>
                                </div>
                            </div>

                            <div class="section-header">
                                <i class="fa fa-user-secret"></i> Circumvention Prevention
                            </div>
                            <div class="prevention-row">
                                <div class="prevention-info">
                                    <i class="fa fa-eye-slash" style="color: #9c27b0;"></i>
                                    <div>
                                        <div class="prevention-name">Tor Prevention</div>
                                        <div class="prevention-desc">Block Tor network access, relay nodes, and .onion domains</div>
                                    </div>
                                </div>
                                <label class="toggle-switch">
                                    <input type="checkbox" id="blockTorToggle">
                                    <span class="toggle-slider"></span>
                                </label>
                            </div>
                            <div class="prevention-row">
                                <div class="prevention-info">
                                    <i class="fa fa-shield" style="color: #2196f3;"></i>
                                    <div>
                                        <div class="prevention-name">VPN Prevention</div>
                                        <div class="prevention-desc">Block commercial VPN providers (NordVPN, ExpressVPN, Surfshark, etc.)</div>
                                    </div>
                                </div>
                                <label class="toggle-switch">
                                    <input type="checkbox" id="blockVpnToggle">
                                    <span class="toggle-slider"></span>
                                </label>
                            </div>
                            <div class="prevention-row">
                                <div class="prevention-info">
                                    <i class="fa fa-server" style="color: #ff9800;"></i>
                                    <div>
                                        <div class="prevention-name">DoH Prevention</div>
                                        <div class="prevention-desc">Block DNS-over-HTTPS endpoints to prevent DNS filter bypass</div>
                                    </div>
                                </div>
                                <label class="toggle-switch">
                                    <input type="checkbox" id="blockDohToggle">
                                    <span class="toggle-slider"></span>
                                </label>
                            </div>
                        </div>
                    </div>
                </form>
            </div>
            <div class="modal-footer">
                <button type="button" class="btn btn-default" data-dismiss="modal">Cancel</button>
                <button type="button" class="btn btn-primary" onclick="savePolicy()">
                    <i class="fa fa-save"></i> Save Policy
                </button>
            </div>
        </div>
    </div>
</div>

<script>
var appCategories = {};
var webCategories = {};
var devices = [];
var vlans = [];
var selectedApps = [];
var selectedCategories = [];
var selectedDevices = [];
var excludedDevices = [];
var exclusions = [];
var schedules = [];
var securityPreset = 'custom';

// Essential security categories with preset mappings
var ESSENTIAL_SECURITY = [
    {id: 'malware',       name: 'Malware / Virus',         permissive: true, moderate: true, high: true},
    {id: 'phishing',      name: 'Phishing',                permissive: true, moderate: true, high: true},
    {id: 'hacking',       name: 'Hacking',                 permissive: false, moderate: true, high: true},
    {id: 'spam_sites',    name: 'Spam Sites',              permissive: false, moderate: true, high: true},
    {id: 'dangerous',     name: 'Potentially Dangerous',   permissive: false, moderate: false, high: true},
    {id: 'parked',        name: 'Parked Domains',          permissive: false, moderate: false, high: true},
    {id: 'firstly_seen',  name: 'Firstly Seen Sites',      permissive: false, moderate: false, high: true}
];

var ADVANCED_SECURITY = [
    {id: 'recent_malware',    name: 'Recent Malware/Phishing Outbreaks'},
    {id: 'botnet_cc',         name: 'Botnet C&C Servers'},
    {id: 'compromised',       name: 'Compromised Websites'},
    {id: 'spyware_adware',    name: 'Spyware / Adware'},
    {id: 'keyloggers',        name: 'Keyloggers'},
    {id: 'dead_sites',        name: 'Dead Sites (No content)'},
    {id: 'dynamic_dns',       name: 'Dynamic DNS Sites'},
    {id: 'newly_registered',  name: 'Newly Registered Domains'},
    {id: 'newly_recovered',   name: 'Newly Recovered Sites'}
];

var securityCategories = {};

$(document).ready(function() {
    loadPolicies();
    loadAppsAndCategories();
    loadDevicesAndVlans();
    renderSecurityGrids();

    $('#appSearch').on('input', function() { filterApps($(this).val()); });
    $('#categorySearch').on('input', function() { filterCategories($(this).val()); });
});

// ===== TAB NAVIGATION =====
function switchTab(tabId) {
    $('.policy-tab').removeClass('active');
    $('.policy-tab[data-tab="' + tabId + '"]').addClass('active');
    $('.tab-pane').removeClass('active');
    $('#tab-' + tabId).addClass('active');
}

// ===== SECURITY PRESETS =====
function selectPreset(preset) {
    securityPreset = preset;
    $('.preset-option').removeClass('selected');
    $('.preset-option[data-preset="' + preset + '"]').addClass('selected');

    if (preset !== 'custom') {
        ESSENTIAL_SECURITY.forEach(function(cat) {
            var blocked = cat[preset] || false;
            securityCategories[cat.id] = blocked;
            var toggle = $('#sec_' + cat.id);
            toggle.prop('checked', blocked);
        });
    }
}

function renderSecurityGrids() {
    var essGrid = $('#essentialSecurityGrid');
    essGrid.empty();
    ESSENTIAL_SECURITY.forEach(function(cat) {
        var checked = securityCategories[cat.id] ? 'checked' : '';
        essGrid.append(
            '<div class="security-grid">' +
                '<div class="sg-cell"><i class="fa fa-exclamation-circle" style="color: #f44336;"></i> ' + escapeHtml(cat.name) + '</div>' +
                '<div class="sg-cell" id="sec_status_' + cat.id + '">' + (securityCategories[cat.id] ? '<span style="color:#f44336;">Blocked</span>' : '<span style="color:#4caf50;">Allowed</span>') + '</div>' +
                '<div class="sg-cell"><label class="toggle-switch"><input type="checkbox" id="sec_' + cat.id + '" ' + checked + ' onchange="toggleSecurityCat(\'' + cat.id + '\', this.checked)"><span class="toggle-slider"></span></label></div>' +
            '</div>'
        );
    });

    var advGrid = $('#advancedSecurityGrid');
    advGrid.empty();
    ADVANCED_SECURITY.forEach(function(cat) {
        var checked = securityCategories[cat.id] ? 'checked' : '';
        advGrid.append(
            '<div class="prevention-row">' +
                '<div class="prevention-info">' +
                    '<i class="fa fa-bug" style="color: #ff9800;"></i>' +
                    '<div><div class="prevention-name">' + escapeHtml(cat.name) + '</div></div>' +
                '</div>' +
                '<label class="toggle-switch"><input type="checkbox" id="sec_' + cat.id + '" ' + checked + ' onchange="toggleSecurityCat(\'' + cat.id + '\', this.checked)"><span class="toggle-slider"></span></label>' +
            '</div>'
        );
    });
}

function toggleSecurityCat(catId, blocked) {
    securityCategories[catId] = blocked;
    securityPreset = 'custom';
    $('.preset-option').removeClass('selected');
    $('.preset-option[data-preset="custom"]').addClass('selected');
    var statusEl = $('#sec_status_' + catId);
    if (statusEl.length) {
        statusEl.html(blocked ? '<span style="color:#f44336;">Blocked</span>' : '<span style="color:#4caf50;">Allowed</span>');
    }
}

// ===== SCHEDULES =====
var scheduleCounter = 0;
function addScheduleRow(data) {
    scheduleCounter++;
    var id = scheduleCounter;
    var name = (data && data.name) || 'Schedule ' + id;
    var start = (data && data.start_time) || '08:00';
    var end = (data && data.end_time) || '17:00';
    var days = (data && data.days) || 'mon,tue,wed,thu,fri,sat,sun';
    var dayArr = days.split(',');

    var daysHtml = '';
    var allDays = ['mon','tue','wed','thu','fri','sat','sun'];
    var dayLabels = ['Mo','Tu','We','Th','Fr','Sa','Su'];
    for (var i = 0; i < allDays.length; i++) {
        var active = dayArr.indexOf(allDays[i]) > -1 ? 'active' : '';
        daysHtml += '<div class="day-pill ' + active + '" data-day="' + allDays[i] + '" onclick="toggleDay(this)">' + dayLabels[i] + '</div>';
    }

    var row = '<div class="schedule-row" data-schedule-id="' + id + '">' +
        '<input type="text" value="' + escapeHtml(name) + '" class="sched-name" placeholder="Name">' +
        '<input type="time" value="' + start + '" class="sched-start">' +
        '<span style="color:#888;">to</span>' +
        '<input type="time" value="' + end + '" class="sched-end">' +
        '<div class="day-pills">' + daysHtml + '</div>' +
        '<button type="button" class="btn-remove" onclick="removeScheduleRow(this)"><i class="fa fa-trash"></i></button>' +
    '</div>';

    $('#schedulesContainer').append(row);
}

function removeScheduleRow(btn) {
    $(btn).closest('.schedule-row').remove();
}

function toggleDay(el) {
    $(el).toggleClass('active');
}

function collectSchedules() {
    var result = [];
    $('#schedulesContainer .schedule-row').each(function() {
        var days = [];
        $(this).find('.day-pill.active').each(function() {
            days.push($(this).data('day'));
        });
        result.push({
            name: $(this).find('.sched-name').val(),
            start_time: $(this).find('.sched-start').val(),
            end_time: $(this).find('.sched-end').val(),
            days: days.join(',')
        });
    });
    return result;
}

// ===== EXCLUSIONS =====
function addExclusion() {
    var entry = $('#exclusionEntry').val().trim();
    if (!entry) return;
    var type = $('#exclusionType').val();
    var desc = $('#exclusionDesc').val().trim();
    exclusions.push({entry: entry, list_type: type, description: desc});
    renderExclusions();
    $('#exclusionEntry').val('');
    $('#exclusionDesc').val('');
}

function removeExclusion(idx) {
    exclusions.splice(idx, 1);
    renderExclusions();
}

function renderExclusions(filter) {
    var body = $('#exclusionBody');
    body.empty();
    var filtered = exclusions;
    if (filter && filter !== 'all') {
        filtered = exclusions.filter(function(e) { return e.list_type === filter; });
    }
    if (filtered.length === 0) {
        body.append('<tr><td colspan="4" style="text-align:center; color: #888; padding: 40px;">No exclusions added</td></tr>');
        return;
    }
    filtered.forEach(function(exc, i) {
        var realIdx = exclusions.indexOf(exc);
        var typeColor = exc.list_type === 'whitelist' ? '#4caf50' : '#f44336';
        body.append(
            '<tr>' +
                '<td>' + escapeHtml(exc.entry) + '</td>' +
                '<td><span style="color:' + typeColor + '; font-weight:600;">' + exc.list_type + '</span></td>' +
                '<td>' + escapeHtml(exc.description || '') + '</td>' +
                '<td><button class="btn-remove" onclick="removeExclusion(' + realIdx + ')"><i class="fa fa-trash"></i></button></td>' +
            '</tr>'
        );
    });
}

function filterExclusions(type, btn) {
    $(btn).closest('.btn-group').find('.btn').removeClass('active');
    $(btn).addClass('active');
    renderExclusions(type);
}

function importCsvExclusions(input) {
    var file = input.files[0];
    if (!file) return;
    var reader = new FileReader();
    reader.onload = function(e) {
        var lines = e.target.result.split('\n');
        lines.forEach(function(line) {
            line = line.trim();
            if (!line || line.startsWith('#')) return;
            var parts = line.split(',');
            var entry = parts[0].trim();
            var type = (parts[1] || 'blacklist').trim();
            var desc = (parts[2] || '').trim();
            if (entry) {
                if (type !== 'whitelist' && type !== 'blacklist') type = 'blacklist';
                exclusions.push({entry: entry, list_type: type, description: desc});
            }
        });
        renderExclusions();
    };
    reader.readAsText(file);
    input.value = '';
}

// ===== NO INTERNET =====
function toggleNoInternet() {
    var checked = $('#noInternetToggle2').is(':checked');
    $('#noInternetToggle').prop('checked', checked);
    if (checked) {
        $('#noInternetBanner').show();
    } else {
        $('#noInternetBanner').hide();
    }
}

// ===== POLICY LIST =====

    

    function loadPolicies() {
    $.getJSON('/api/netshield/policies/search', function(data) {
        var container = $('#policiesContainer');
        container.empty();
        var policies = data.rows || [];
        var activeCount = 0;

        if (policies.length === 0) {
            container.html(
                '<div class="empty-state">' +
                    '<i class="fa fa-shield"></i>' +
                    '<h3>No Policies Configured</h3>' +
                    '<p>Create security policies to control applications, websites, and network traffic.</p>' +
                    '<button class="btn-add-policy" onclick="showAddPolicyModal()">' +
                        '<i class="fa fa-plus"></i> Create First Policy' +
                    '</button>' +
                '</div>'
            );
            $('#totalPolicies').text('0');
            $('#activePolicies').text('0');
            return;
        }

        policies.forEach(function(policy) {
            if (policy.enabled == '1' || policy.enabled === true) activeCount++;
            var actionClass = 'action-' + (policy.action || 'block').toLowerCase();
            var disabledClass = (policy.enabled == '0' || policy.enabled === false) ? 'disabled' : '';
            var apps = policy.apps ? policy.apps.split(',').filter(Boolean) : [];
            var categories = policy.web_categories ? policy.web_categories.split(',').filter(Boolean) : [];
            var scopeDevices = policy.devices ? policy.devices.split(',').filter(Boolean) : [];
            var scopeVlans = policy.vlans ? policy.vlans.split(',').filter(Boolean) : [];

            var appTags = apps.slice(0, 5).map(function(a) { return '<span class="tag tag-app">' + escapeHtml(a) + '</span>'; }).join('');
            if (apps.length > 5) appTags += '<span class="tag tag-app">+' + (apps.length - 5) + ' more</span>';

            var catTags = categories.slice(0, 5).map(function(c) { return '<span class="tag tag-category">' + escapeHtml(c) + '</span>'; }).join('');
            if (categories.length > 5) catTags += '<span class="tag tag-category">+' + (categories.length - 5) + ' more</span>';

            var scopeText = 'Whole Network';
            var scopeTags = '';
            if (scopeDevices.length > 0) {
                scopeText = scopeDevices.length + ' Device(s)';
                scopeTags = scopeDevices.slice(0, 3).map(function(d) { return '<span class="tag tag-device">' + escapeHtml(d) + '</span>'; }).join('');
            } else if (scopeVlans.length > 0) {
                scopeText = 'VLAN ' + scopeVlans.join(', ');
                scopeTags = scopeVlans.map(function(v) { return '<span class="tag tag-vlan">VLAN ' + escapeHtml(v) + '</span>'; }).join('');
            }

            // Build feature badges
            var featureBadges = '';
            if (policy.no_internet == '1' || policy.no_internet === 1) {
                featureBadges += '<span class="tag tag-security"><i class="fa fa-ban"></i> No Internet</span>';
            }
            if (policy.security_preset && policy.security_preset !== 'custom') {
                featureBadges += '<span class="tag tag-security"><i class="fa fa-shield"></i> ' + escapeHtml(policy.security_preset) + '</span>';
            }
            if (policy.block_tor == '1') featureBadges += '<span class="tag tag-security"><i class="fa fa-eye-slash"></i> Tor</span>';
            if (policy.block_vpn == '1') featureBadges += '<span class="tag tag-security"><i class="fa fa-shield"></i> VPN</span>';
            if (policy.block_doh == '1') featureBadges += '<span class="tag tag-security"><i class="fa fa-server"></i> DoH</span>';

            // Schedule display
            var scheduleText = 'Always';
            if (policy.schedules_json) {
                try {
                    var scheds = JSON.parse(policy.schedules_json);
                    if (scheds.length > 0) {
                        scheduleText = scheds.length + ' schedule(s)';
                    }
                } catch(e) {}
            }

            var card =
                '<div class="policy-card ' + actionClass + ' ' + disabledClass + '" data-id="' + policy.id + '">' +
                    '<div class="policy-card-header">' +
                        '<div class="policy-name">' +
                            '<span class="action-badge ' + (policy.action || 'block').toLowerCase() + '">' + (policy.action || 'Block') + '</span>' +
                            escapeHtml(policy.name) +
                        '</div>' +
                        '<div class="policy-actions">' +
                            '<label class="toggle-switch" style="margin-right: 8px;">' +
                                '<input type="checkbox" ' + ((policy.enabled == '1' || policy.enabled === true) ? 'checked' : '') +
                                       ' onchange="togglePolicy(' + policy.id + ', this.checked)">' +
                                '<span class="toggle-slider"></span>' +
                            '</label>' +
                            '<button class="btn-icon" onclick="editPolicy(' + policy.id + ')" title="Edit">' +
                                '<i class="fa fa-pencil"></i>' +
                            '</button>' +
                            '<button class="btn-icon" onclick="clonePolicy(' + policy.id + ')" title="Clone">' +
                                '<i class="fa fa-copy"></i>' +
                            '</button>' +
                            '<button class="btn-icon danger" onclick="deletePolicy(' + policy.id + ', \'' + escapeHtml(policy.name).replace(/'/g, "\\'") + '\')" title="Delete">' +
                                '<i class="fa fa-trash"></i>' +
                            '</button>' +
                        '</div>' +
                    '</div>' +
                    '<div class="policy-card-body">' +
                        '<div class="policy-info-grid">' +
                            '<div class="policy-info-item">' +
                                '<div class="label">Scope</div>' +
                                '<div class="value">' + scopeText + '</div>' +
                                (scopeTags ? '<div class="tag-container">' + scopeTags + '</div>' : '') +
                            '</div>' +
                            '<div class="policy-info-item">' +
                                '<div class="label">Applications (' + apps.length + ')</div>' +
                                '<div class="tag-container">' + (appTags || '<span style="color: #888;">All applications</span>') + '</div>' +
                            '</div>' +
                            '<div class="policy-info-item">' +
                                '<div class="label">Web Categories (' + categories.length + ')</div>' +
                                '<div class="tag-container">' + (catTags || '<span style="color: #888;">No categories selected</span>') + '</div>' +
                            '</div>' +
                            '<div class="policy-info-item">' +
                                '<div class="label">Schedule</div>' +
                                '<div class="value"><i class="fa fa-clock-o"></i> ' + escapeHtml(scheduleText) + '</div>' +
                            '</div>' +
                        '</div>' +
                        (featureBadges ? '<div class="tag-container" style="margin-top: 12px;">' + featureBadges + '</div>' : '') +
                    '</div>' +
                '</div>';
            container.append(card);
        });

        $('#totalPolicies').text(policies.length);
        $('#activePolicies').text(activeCount);
    });

    $.getJSON('/api/netshield/policies/stats', function(data) {
        $('#blockedToday').text(data.blocked_today || 0);
    }).fail(function() {
        $('#blockedToday').text('0');
    });
}

function loadAppsAndCategories(callback) {
    $.getJSON('/api/netshield/appsignatures/list', function(data) {
        appCategories = {};
        var apps = Array.isArray(data) ? data : (data.apps || []);
        apps.forEach(function(app) {
            if (!appCategories[app.category]) {
                appCategories[app.category] = {
                    name: app.category_name || app.category,
                    color: app.category_color || '#888',
                    apps: []
                };
            }
            appCategories[app.category].apps.push(app);
        });
        renderAppGrid();
        if (typeof callback === 'function') callback();
    }).fail(function() {
        appCategories = {
            'streaming': {name: 'Streaming', color: '#9b59b6', apps: [
                {id: 'netflix', name: 'Netflix'}, {id: 'youtube', name: 'YouTube'},
                {id: 'twitch', name: 'Twitch'}, {id: 'spotify', name: 'Spotify'},
                {id: 'tiktok', name: 'TikTok'}, {id: 'disney_plus', name: 'Disney+'}
            ]},
            'social': {name: 'Social Media', color: '#3498db', apps: [
                {id: 'facebook', name: 'Facebook'}, {id: 'instagram', name: 'Instagram'},
                {id: 'twitter', name: 'Twitter/X'}, {id: 'snapchat', name: 'Snapchat'},
                {id: 'reddit', name: 'Reddit'}, {id: 'linkedin', name: 'LinkedIn'}
            ]},
            'gaming': {name: 'Gaming', color: '#e74c3c', apps: [
                {id: 'steam', name: 'Steam'}, {id: 'epic_games', name: 'Epic Games'},
                {id: 'roblox', name: 'Roblox'}, {id: 'minecraft', name: 'Minecraft'},
                {id: 'xbox', name: 'Xbox Live'}, {id: 'playstation', name: 'PlayStation'}
            ]},
            'communication': {name: 'Communication', color: '#1abc9c', apps: [
                {id: 'whatsapp', name: 'WhatsApp'}, {id: 'telegram', name: 'Telegram'},
                {id: 'discord', name: 'Discord'}, {id: 'zoom', name: 'Zoom'},
                {id: 'teams', name: 'MS Teams'}, {id: 'slack', name: 'Slack'}
            ]},
            'vpn': {name: 'VPN & Proxy', color: '#8e44ad', apps: [
                {id: 'nordvpn', name: 'NordVPN'}, {id: 'expressvpn', name: 'ExpressVPN'},
                {id: 'surfshark', name: 'Surfshark'}, {id: 'tor', name: 'Tor Network'}
            ]},
            'p2p': {name: 'P2P & Torrents', color: '#c0392b', apps: [
                {id: 'bittorrent', name: 'BitTorrent'}, {id: 'utorrent', name: 'uTorrent'},
                {id: 'qbittorrent', name: 'qBittorrent'}
            ]}
        };
        renderAppGrid();
    });

    $.getJSON('/api/netshield/webcategories/groups', function(data) {
        webCategories = {};
        var groups = Array.isArray(data) ? data : (data.groups || data.categories || []);
        groups.forEach(function(group) {
            webCategories[group.name] = {
                color: group.color || '#888',
                categories: group.categories || []
            };
        });
        renderCategoryGrid();
    }).fail(function() {
        webCategories = {
            'Adult': {color: '#e74c3c', categories: [
                {id: 'adult', name: 'Adult Content'}, {id: 'pornography', name: 'Pornography'},
                {id: 'nudity', name: 'Nudity'}
            ]},
            'Security': {color: '#c0392b', categories: [
                {id: 'malware', name: 'Malware'}, {id: 'phishing', name: 'Phishing'},
                {id: 'spyware', name: 'Spyware'}, {id: 'cryptomining', name: 'Cryptomining'}
            ]},
            'Social': {color: '#3498db', categories: [
                {id: 'social_networking', name: 'Social Networking'}, {id: 'dating', name: 'Dating'},
                {id: 'forums', name: 'Forums'}
            ]},
            'Entertainment': {color: '#9b59b6', categories: [
                {id: 'streaming', name: 'Streaming'}, {id: 'gaming', name: 'Gaming'},
                {id: 'gambling', name: 'Gambling'}
            ]},
            'Controversial': {color: '#e67e22', categories: [
                {id: 'weapons', name: 'Weapons'}, {id: 'violence', name: 'Violence'},
                {id: 'drugs', name: 'Drugs'}, {id: 'hate_speech', name: 'Hate Speech'}
            ]},
            'Downloads': {color: '#d35400', categories: [
                {id: 'file_sharing', name: 'File Sharing'}, {id: 'torrents', name: 'Torrents'},
                {id: 'warez', name: 'Warez/Piracy'}
            ]},
            'Technology': {color: '#34495e', categories: [
                {id: 'hacking', name: 'Hacking'}, {id: 'proxies', name: 'Proxy/Anonymizer'},
                {id: 'vpn', name: 'VPN Services'}
            ]}
        };
        renderCategoryGrid();
    });
}

function loadDevicesAndVlans() {
    $.getJSON('/api/netshield/devices/search', function(data) {
        devices = data.rows || [];
        renderDeviceGrid();
    });

    $.getJSON('/api/netshield/network/vlans', function(data) {
        vlans = data.vlans || [];
        var select = $('#policyVlans');
        select.empty();
        vlans.forEach(function(v) {
            select.append('<option value="' + v.id + '">' + escapeHtml(v.name || 'VLAN ' + v.id) + ' (' + (v.subnet || v.id) + ')</option>');
        });
    }).fail(function() {
        vlans = [
            {id: 'lan', name: 'LAN', subnet: 'auto'}
        ];
        var select = $('#policyVlans');
        select.empty();
        vlans.forEach(function(v) {
            select.append('<option value="' + v.id + '">' + escapeHtml(v.name) + ' (' + v.subnet + ')</option>');
        });
    });
}

function renderAppGrid() {
    var grid = $('#appSelectGrid');
    grid.empty();
    var allApps = [];
    Object.keys(appCategories).sort().forEach(function(catId) {
        var cat = appCategories[catId];
        cat.apps.forEach(function(app) {
            allApps.push({app: app, cat: cat});
        });
    });
    allApps.sort(function(a, b) {
        var aS = selectedApps.indexOf(a.app.id) > -1 ? 0 : 1;
        var bS = selectedApps.indexOf(b.app.id) > -1 ? 0 : 1;
        if (aS !== bS) return aS - bS;
        return a.app.name.localeCompare(b.app.name);
    });
    allApps.forEach(function(item) {
        var app = item.app, cat = item.cat;
        var selected = selectedApps.indexOf(app.id) > -1 ? 'selected' : '';
        var checked = selectedApps.indexOf(app.id) > -1 ? 'checked' : '';
        grid.append(
            '<div class="multi-select-item ' + selected + '" data-id="' + app.id + '" data-name="' + escapeHtml(app.name).toLowerCase() + '"' +
            ' onclick="toggleAppSelection(\'' + app.id + '\', this)">' +
                '<input type="checkbox" ' + checked + ' onclick="event.stopPropagation();">' +
                '<div class="item-icon" style="background: ' + cat.color + ';">' +
                    '<i class="fa fa-cube" style="color: #fff;"></i>' +
                '</div>' +
                '<span class="item-label">' + escapeHtml(app.name) + '</span>' +
            '</div>'
        );
    });
}

function renderCategoryGrid() {
    var grid = $('#categorySelectGrid');
    grid.empty();
    var allCats = [];
    Object.keys(webCategories).sort().forEach(function(groupName) {
        var group = webCategories[groupName];
        (group.categories || []).forEach(function(cat) {
            allCats.push({cat: cat, group: group});
        });
    });
    allCats.sort(function(a, b) {
        var aS = selectedCategories.indexOf(a.cat.id) > -1 ? 0 : 1;
        var bS = selectedCategories.indexOf(b.cat.id) > -1 ? 0 : 1;
        if (aS !== bS) return aS - bS;
        return a.cat.name.localeCompare(b.cat.name);
    });
    allCats.forEach(function(item) {
        var cat = item.cat, group = item.group;
        var selected = selectedCategories.indexOf(cat.id) > -1 ? 'selected' : '';
        var checked = selectedCategories.indexOf(cat.id) > -1 ? 'checked' : '';
        grid.append(
            '<div class="multi-select-item ' + selected + '" data-id="' + cat.id + '" data-name="' + escapeHtml(cat.name).toLowerCase() + '"' +
            ' onclick="toggleCategorySelection(\'' + cat.id + '\', this)">' +
                '<input type="checkbox" ' + checked + ' onclick="event.stopPropagation();">' +
                '<div class="item-icon" style="background: ' + (group.color || '#888') + ';">' +
                    '<i class="fa fa-folder" style="color: #fff;"></i>' +
                '</div>' +
                '<span class="item-label">' + escapeHtml(cat.name) + '</span>' +
            '</div>'
        );
    });
}


    // Friendly device label: hostname > vendor (IP) > IP > MAC
    function deviceLabel(d) {
        if (d.hostname && d.hostname !== d.mac) return d.hostname;
        if (d.device_name && d.device_name !== d.mac) return d.device_name;
        if (d.vendor && d.ip) return d.vendor + ' (' + d.ip + ')';
        if (d.vendor) return d.vendor + ' (' + d.mac + ')';
        if (d.ip) return d.ip;
        return d.mac;
    }

function renderDeviceGrid() {
    var grid = $('#deviceSelectGrid');
    grid.empty();
    var sortedDevices = devices.slice().sort(function(a, b) {
        var aS = selectedDevices.indexOf(a.mac) > -1 ? 0 : 1;
        var bS = selectedDevices.indexOf(b.mac) > -1 ? 0 : 1;
        if (aS !== bS) return aS - bS;
        return deviceLabel(a).localeCompare(deviceLabel(b));
    });
    sortedDevices.forEach(function(device) {
        var label = deviceLabel(device);
        var selected = selectedDevices.indexOf(device.mac) > -1 ? 'selected' : '';
        var checked = selectedDevices.indexOf(device.mac) > -1 ? 'checked' : '';
        grid.append(
            '<div class="multi-select-item ' + selected + '" data-id="' + device.mac + '" data-name="' + escapeHtml(label).toLowerCase() + '"' +
            ' onclick="toggleDeviceSelection(\'' + device.mac + '\', this)">' +
                '<input type="checkbox" ' + checked + ' onclick="event.stopPropagation();">' +
                '<div class="item-icon" style="background: #1abc9c;">' +
                    '<i class="fa fa-laptop" style="color: #fff;"></i>' +
                '</div>' +
                '<span class="item-label">' + escapeHtml(label) + '<br><small style="color:#888;font-size:10px;">' + device.ip + ' &middot; ' + device.mac + '</small></span>' +
            '</div>'
        );
    });
}

function toggleAppSelection(appId, el) {
    var idx = selectedApps.indexOf(appId);
    if (idx > -1) {
        selectedApps.splice(idx, 1);
        $(el).removeClass('selected').find('input').prop('checked', false);
    } else {
        selectedApps.push(appId);
        $(el).addClass('selected').find('input').prop('checked', true);
    }
}

function toggleCategorySelection(catId, el) {
    var idx = selectedCategories.indexOf(catId);
    if (idx > -1) {
        selectedCategories.splice(idx, 1);
        $(el).removeClass('selected').find('input').prop('checked', false);
    } else {
        selectedCategories.push(catId);
        $(el).addClass('selected').find('input').prop('checked', true);
    }
}

function toggleDeviceSelection(mac, el) {
    var idx = selectedDevices.indexOf(mac);
    if (idx > -1) {
        selectedDevices.splice(idx, 1);
        $(el).removeClass('selected').find('input').prop('checked', false);
    } else {
        selectedDevices.push(mac);
        $(el).addClass('selected').find('input').prop('checked', true);
    }
}

function renderExcludeGrid() {
    var grid = $('#excludeDeviceGrid');
    grid.empty();
    if (!devices.length) {
        grid.html('<div style="padding:12px; color:#888; text-align:center;">No devices loaded</div>');
        return;
    }
    var catIcons = {
        'smartphone': 'fa-mobile', 'laptop': 'fa-laptop', 'tablet': 'fa-tablet',
        'desktop': 'fa-desktop', 'printer': 'fa-print', 'tv': 'fa-television',
        'iot': 'fa-microchip', 'server': 'fa-server', 'gaming': 'fa-gamepad',
        'camera': 'fa-video-camera', 'other': 'fa-question-circle'
    };
    var sorted = devices.slice().sort(function(a, b) {
        var aS = excludedDevices.indexOf(a.mac) > -1 ? 0 : 1;
        var bS = excludedDevices.indexOf(b.mac) > -1 ? 0 : 1;
        if (aS !== bS) return aS - bS;
        return deviceLabel(a).localeCompare(deviceLabel(b));
    });
    sorted.forEach(function(d) {
        var label = deviceLabel(d);
        var selected = excludedDevices.indexOf(d.mac) > -1 ? 'selected' : '';
        var checked = excludedDevices.indexOf(d.mac) > -1 ? 'checked' : '';
        var cat = d.category || 'other';
        var icon = catIcons[cat] || 'fa-question-circle';
        grid.append(
            '<div class="multi-select-item ' + selected + '" data-id="' + d.mac + '"' +
            ' onclick="toggleExcludeDevice(\'' + d.mac + '\', this)"' +
            ' style="border-color: ' + (selected ? '#ef4444' : '') + ';">' +
                '<input type="checkbox" ' + checked + ' onclick="event.stopPropagation();">' +
                '<div class="item-icon" style="background: #ef4444;">' +
                    '<i class="fa ' + icon + '" style="color: #fff;"></i>' +
                '</div>' +
                '<span class="item-label">' + escapeHtml(label) + '</span>' +
            '</div>'
        );
    });
}

function toggleExcludeDevice(mac, el) {
    var idx = excludedDevices.indexOf(mac);
    if (idx > -1) {
        excludedDevices.splice(idx, 1);
        $(el).removeClass('selected').find('input').prop('checked', false);
        $(el).css('border-color', '');
    } else {
        excludedDevices.push(mac);
        $(el).addClass('selected').find('input').prop('checked', true);
        $(el).css('border-color', '#ef4444');
    }
}


function filterApps(query) {
    query = query.toLowerCase();
    $('#appSelectGrid .multi-select-item').each(function() {
        $(this).toggle($(this).data('name').indexOf(query) > -1);
    });
}

function filterCategories(query) {
    query = query.toLowerCase();
    $('#categorySelectGrid .multi-select-item').each(function() {
        $(this).toggle($(this).data('name').indexOf(query) > -1);
    });
}

function selectScope(scope) {
    $('.scope-option').removeClass('selected');
    $('.scope-option[data-scope="' + scope + '"]').addClass('selected');
    $('#policyScope').val(scope);
    $('.target-selector').removeClass('visible');
    if (scope === 'vlan') {
        $('#vlanSelector').addClass('visible');
    } else if (scope === 'devices') {
        $('#deviceSelector').addClass('visible');
    }
}

// ===== MODAL SHOW/EDIT =====
function showAddPolicyModal() {
    $('#policyForm')[0].reset();
    $('#policyId').val('');
    $('#policyModalTitle').html('<i class="fa fa-plus"></i> Add Policy');
    $('#policyEnabled').prop('checked', true);

    selectedApps = [];
    selectedCategories = [];
    selectedDevices = [];
    exclusions = [];
    securityCategories = {};
    securityPreset = 'custom';

    renderAppGrid();
    renderCategoryGrid();
    renderDeviceGrid();
    renderExclusions();
    renderSecurityGrids();
    selectScope('network');
    switchTab('config');

    $('.preset-option').removeClass('selected');
    $('.preset-option[data-preset="custom"]').addClass('selected');

    $('#schedulesContainer').empty();
    $('#noInternetToggle').prop('checked', false);
    $('#noInternetToggle2').prop('checked', false);
    $('#noInternetBanner').hide();
    $('#blockTorToggle').prop('checked', false);
    $('#blockVpnToggle').prop('checked', false);
    $('#blockDohToggle').prop('checked', false);
    $('#blockEchToggle').prop('checked', false);
    $('#safeSearchToggle').prop('checked', false);

    $('#policyModal').modal('show');
}

function editPolicy(id) {
    $.getJSON('/api/netshield/policies/get', {id: id}, function(policy) {
        $('#policyId').val(policy.id);
        $('#policyName').val(policy.name);
        $('#policyAction').val(policy.action || 'block');
        $('#policyDescription').val(policy.description || '');
        $('#policyPriority').val(policy.priority || 100);
        $('#policyBandwidth').val(policy.bandwidth_kbps || 0);
        $('#policyEnabled').prop('checked', policy.enabled == '1' || policy.enabled === true);

        // No internet
        var noInet = policy.no_internet == '1' || policy.no_internet === 1;
        $('#noInternetToggle').prop('checked', noInet);
        $('#noInternetToggle2').prop('checked', noInet);
        if (noInet) $('#noInternetBanner').show(); else $('#noInternetBanner').hide();

        // Security
        securityPreset = policy.security_preset || 'custom';
        $('.preset-option').removeClass('selected');
        $('.preset-option[data-preset="' + securityPreset + '"]').addClass('selected');

        securityCategories = {};
        if (policy.security_categories) {
            try {
                securityCategories = JSON.parse(policy.security_categories);
            } catch(e) {}
        }
        renderSecurityGrids();

        // Apps
        selectedApps = policy.apps ? policy.apps.split(',').filter(Boolean) : [];
        // Ensure app data is loaded before rendering grid
        if (Object.keys(appCategories).length === 0) {
            // App data not loaded yet - reload and render after
            loadAppsAndCategories(function() { renderAppGrid(); });
        } else {
            renderAppGrid();
        }

        // Categories
        selectedCategories = policy.web_categories ? policy.web_categories.split(',').filter(Boolean) : [];
        renderCategoryGrid();

        // Scope
        selectedDevices = policy.devices ? policy.devices.split(',').filter(Boolean) : [];
        excludedDevices = policy.excluded_devices ? policy.excluded_devices.split(',').filter(Boolean) : [];
        var policyVlans = policy.vlans ? policy.vlans.split(',').filter(Boolean) : [];

        if (selectedDevices.length > 0) {
            selectScope('devices');
            renderDeviceGrid();
            renderExcludeGrid();
        } else if (policyVlans.length > 0) {
            selectScope('vlan');
            $('#policyVlans').val(policyVlans);
        } else {
            selectScope('network');
            renderExcludeGrid();
        }

        // Exclusions
        exclusions = [];
        if (policy.exclusions_json) {
            try {
                exclusions = JSON.parse(policy.exclusions_json);
            } catch(e) {}
        }
        renderExclusions();

        // Schedules
        $('#schedulesContainer').empty();
        scheduleCounter = 0;
        if (policy.schedules_json) {
            try {
                var scheds = JSON.parse(policy.schedules_json);
                scheds.forEach(function(s) { addScheduleRow(s); });
            } catch(e) {}
        }

        // Advanced toggles
        $('#blockTorToggle').prop('checked', policy.block_tor == '1');
        $('#blockVpnToggle').prop('checked', policy.block_vpn == '1');
        $('#blockDohToggle').prop('checked', policy.block_doh == '1');
        $('#blockEchToggle').prop('checked', policy.block_ech == '1');
        $('#safeSearchToggle').prop('checked', policy.safe_search == '1');

        switchTab('config');
        $('#policyModalTitle').html('<i class="fa fa-pencil"></i> Edit Policy');
        $('#policyModal').modal('show');
    }).fail(function() {
        $.getJSON('/api/netshield/policies/search', {current: 1, rowCount: 9999}, function(data) {
            var policy = null;
            if (data && data.rows) {
                data.rows.forEach(function(r) { if (r.id == id) policy = r; });
            }
            if (policy) {
                $('#policyId').val(policy.id);
                $('#policyName').val(policy.name);
                $('#policyAction').val(policy.action || 'block');
                $('#policyPriority').val(policy.priority || 100);
                $('#policyEnabled').prop('checked', policy.enabled == '1' || policy.enabled === true);
                selectedApps = [];
                selectedCategories = [];
                selectedDevices = [];
                exclusions = [];
                securityCategories = {};
                renderAppGrid();
                renderCategoryGrid();
                renderExclusions();
                selectScope('network');
                switchTab('config');
                $('#policyModalTitle').html('<i class="fa fa-pencil"></i> Edit Policy');
                $('#policyModal').modal('show');
            }
        });
    });
}

function savePolicy() {
    var scope = $('#policyScope').val();
    var vlansVal = '';
    if (scope === 'vlan') {
        var vlansSelect = $('#policyVlans').val();
        vlansVal = (vlansSelect && vlansSelect.length) ? vlansSelect.join(',') : '';
    }

    var data = {
        id: $('#policyId').val(),
        name: $('#policyName').val(),
        action: $('#policyAction').val(),
        description: $('#policyDescription').val() || '',
        priority: $('#policyPriority').val(),
        enabled: $('#policyEnabled').is(':checked') ? '1' : '0',
        scope: scope,
        apps: selectedApps.join(','),
        web_categories: selectedCategories.join(','),
        devices: scope === 'devices' ? selectedDevices.join(',') : '',
        excluded_devices: excludedDevices.join(','),
        vlans: vlansVal,
        no_internet: $('#noInternetToggle2').is(':checked') ? '1' : '0',
        security_preset: securityPreset,
        security_categories: JSON.stringify(securityCategories),
        exclusions_json: JSON.stringify(exclusions),
        schedules_json: JSON.stringify(collectSchedules()),
        block_tor: $('#blockTorToggle').is(':checked') ? '1' : '0',
        block_vpn: $('#blockVpnToggle').is(':checked') ? '1' : '0',
        block_doh: $('#blockDohToggle').is(':checked') ? '1' : '0',
        block_ech: $('#blockEchToggle').is(':checked') ? '1' : '0',
        safe_search: $('#safeSearchToggle').is(':checked') ? '1' : '0',
        bandwidth_kbps: $('#policyBandwidth').val() || '0'
    };

    if (!data.name) {
        alert('Policy name is required');
        return;
    }

    console.log('[NetShield] Saving policy:', JSON.stringify({name: data.name, apps: data.apps, web_categories: data.web_categories, selectedApps: selectedApps}));
    var url = data.id ? '/api/netshield/policies/update' : '/api/netshield/policies/add';
    var saveBtn = $('.modal-footer .btn-primary');
    saveBtn.prop('disabled', true).html('<i class="fa fa-spinner fa-spin"></i> Saving...');

    ajaxCall(url, data, function(resp) {
        saveBtn.prop('disabled', false).html('<i class="fa fa-save"></i> Save Policy');
        if (resp && (resp.status === 'ok' || resp.id)) {
            $('#policyModal').modal('hide');
            loadPolicies();
        } else {
            alert('Failed to save policy: ' + (resp && resp.message ? resp.message : JSON.stringify(resp)));
        }
    });
}

function togglePolicy(id, enabled) {
    ajaxCall('/api/netshield/policies/toggle', {id: id, enabled: enabled ? '1' : '0'}, function() {
        loadPolicies();
    });
}

function deletePolicy(id, name) {
    if (!confirm('Delete policy "' + name + '"? This cannot be undone.')) return;
    ajaxCall('/api/netshield/policies/delete', {id: id}, function() {
        loadPolicies();
    });
}

function clonePolicy(id) {
    $.getJSON('/api/netshield/policies/get', {id: id}, function(policy) {
        policy.name = policy.name + ' (Copy)';
        policy.id = '';
        ajaxCall('/api/netshield/policies/add', policy, function() {
            loadPolicies();
        });
    }).fail(function() {
        editPolicy(id);
        setTimeout(function() {
            $('#policyId').val('');
            $('#policyName').val($('#policyName').val() + ' (Copy)');
            $('#policyModalTitle').html('<i class="fa fa-copy"></i> Clone Policy');
        }, 500);
    });
}

function escapeHtml(text) {
    if (!text) return '';
    var div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}
</script>
