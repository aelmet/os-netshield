{#
# Copyright (C) 2025-2026 NetShield
# All rights reserved.
#
# Target Lists Management - Firewalla Style
#}

<style>
.ns-tl-header {
    background: linear-gradient(135deg, #ea580c 0%, #f97316 100%);
    border-radius: 12px;
    padding: 24px;
    color: #fff;
    margin-bottom: 24px;
    display: flex;
    align-items: center;
    justify-content: space-between;
}
.ns-tl-header h2 { margin: 0; font-weight: 600; }
.ns-tl-stats {
    display: flex;
    gap: 24px;
}
.ns-tl-stats .stat {
    text-align: center;
}
.ns-tl-stats .stat-value {
    font-size: 28px;
    font-weight: 700;
}
.ns-tl-stats .stat-label {
    font-size: 12px;
    opacity: 0.8;
}

.ns-tl-grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(320px, 1fr));
    gap: 16px;
    margin-bottom: 24px;
}
.ns-tl-card {
    background: #fff;
    border-radius: 12px;
    border: 2px solid #e5e7eb;
    overflow: hidden;
    transition: all 0.2s;
}
.ns-tl-card:hover {
    border-color: #f97316;
    box-shadow: 0 4px 16px rgba(249, 115, 22, 0.15);
}
.ns-tl-card.builtin {
    border-left: 4px solid #f97316;
}
.ns-tl-card.custom {
    border-left: 4px solid #3b82f6;
}
.ns-tl-card-header {
    padding: 16px;
    display: flex;
    align-items: center;
    gap: 12px;
    border-bottom: 1px solid #f3f4f6;
}
.ns-tl-card-header .icon {
    width: 44px; height: 44px;
    border-radius: 10px;
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 20px;
}
.ns-tl-card-header .icon.social { background: #dbeafe; color: #2563eb; }
.ns-tl-card-header .icon.streaming { background: #dcfce7; color: #16a34a; }
.ns-tl-card-header .icon.gaming { background: #f3e8ff; color: #9333ea; }
.ns-tl-card-header .icon.adult { background: #fee2e2; color: #dc2626; }
.ns-tl-card-header .icon.ads { background: #fce7f3; color: #db2777; }
.ns-tl-card-header .icon.custom { background: #e0e7ff; color: #4f46e5; }
.ns-tl-card-header .icon.default { background: #f3f4f6; color: #6b7280; }
.ns-tl-card-header .info { flex: 1; }
.ns-tl-card-header .name {
    font-weight: 600;
    font-size: 16px;
    color: #111827;
}
.ns-tl-card-header .type {
    font-size: 11px;
    padding: 2px 8px;
    border-radius: 4px;
    background: #f3f4f6;
    color: #6b7280;
}
.ns-tl-card-header .type.builtin { background: #ffedd5; color: #ea580c; }
.ns-tl-card-header .type.custom { background: #dbeafe; color: #2563eb; }
.ns-tl-card-body {
    padding: 16px;
}
.ns-tl-card-body .desc {
    font-size: 13px;
    color: #6b7280;
    margin-bottom: 12px;
}
.ns-tl-card-body .stats {
    display: flex;
    gap: 20px;
    margin-bottom: 12px;
}
.ns-tl-card-body .stats .item {
    text-align: center;
}
.ns-tl-card-body .stats .value {
    font-weight: 600;
    font-size: 18px;
    color: #111827;
}
.ns-tl-card-body .stats .label {
    font-size: 11px;
    color: #9ca3af;
}
.ns-tl-card-actions {
    display: flex;
    gap: 8px;
    padding: 12px 16px;
    background: #f9fafb;
    border-top: 1px solid #f3f4f6;
}
.ns-tl-card-actions .btn {
    flex: 1;
    padding: 8px;
    border-radius: 8px;
    font-size: 13px;
}

.ns-tl-entries {
    background: #fff;
    border-radius: 12px;
    border: 1px solid #e5e7eb;
    margin-bottom: 24px;
}
.ns-tl-entries-header {
    padding: 16px 20px;
    border-bottom: 1px solid #e5e7eb;
    display: flex;
    align-items: center;
    justify-content: space-between;
    background: #f9fafb;
}
.ns-tl-entries-header h3 {
    margin: 0;
    font-size: 16px;
    font-weight: 600;
}
.ns-tl-entry {
    display: flex;
    align-items: center;
    padding: 12px 20px;
    border-bottom: 1px solid #f3f4f6;
}
.ns-tl-entry:hover {
    background: #f9fafb;
}
.ns-tl-entry .value {
    flex: 1;
    font-family: monospace;
    font-size: 14px;
}
.ns-tl-entry .type-badge {
    font-size: 11px;
    padding: 2px 8px;
    border-radius: 4px;
    margin-right: 12px;
}
.ns-tl-entry .type-badge.domain { background: #dbeafe; color: #2563eb; }
.ns-tl-entry .type-badge.ip { background: #dcfce7; color: #16a34a; }
.ns-tl-entry .type-badge.cidr { background: #fef3c7; color: #d97706; }
.ns-tl-entry .actions {
    display: flex;
    gap: 8px;
}

/* Create Modal Styling */
.ns-modal-form {
    padding: 20px;
}
.ns-modal-form .form-group {
    margin-bottom: 16px;
}
.ns-modal-form label {
    font-weight: 600;
    margin-bottom: 6px;
    display: block;
}
.ns-modal-form input,
.ns-modal-form textarea,
.ns-modal-form select {
    width: 100%;
    padding: 10px 12px;
    border: 2px solid #e5e7eb;
    border-radius: 8px;
    font-size: 14px;
}
.ns-modal-form input:focus,
.ns-modal-form textarea:focus,
.ns-modal-form select:focus {
    outline: none;
    border-color: #f97316;
}

.ns-tl-card.blocked {
    border-color: #16a34a !important;
    border-left: 4px solid #16a34a !important;
    background: #f0fdf4;
}
.ns-tl-card.blocked .ns-tl-card-header {
    background: #dcfce7;
}
</style>

<script>
$(document).ready(function() {
    // HTML escape helper (replaces _.escape for environments without Lodash)
    function escapeHtml(str) {
        if (!str) return '';
        return String(str).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;');
    }

    var selectedList = null;

    function loadStats() {
        $.getJSON('/api/netshield/targetlists/stats', function(data) {
            if (!data) return;
            $('#stat-total-lists').text(data.total_lists || 0);
            $('#stat-total-entries').text((data.total_entries || 0).toLocaleString());
            $('#stat-policies').text(data.active_policies || 0);
        });
    }

    function loadLists() {
        $.getJSON('/api/netshield/targetlists/list', function(data) {
            var $grid = $('#lists-grid').empty();
            var lists = data.lists || [];

            if (!lists.length) {
                $grid.html('<div class="text-muted text-center p-4">{{ lang._("No target lists available") }}</div>');
                return;
            }

            lists.forEach(function(list) {
                var iconClass = getListIcon(list.id || list.name);
                var typeClass = (list.builtin ? 'builtin' : 'custom') + (list.blocked ? ' blocked' : '');

                $grid.append(
                    '<div class="ns-tl-card ' + typeClass + '" data-list="' + escapeHtml(list.id) + '">' +
                        '<div class="ns-tl-card-header">' +
                            '<div class="icon ' + iconClass + '"><i class="fa ' + getListFa(list.id || list.name) + '"></i></div>' +
                            '<div class="info">' +
                                '<div class="name">' + escapeHtml(list.name) + '</div>' +
                            '</div>' +
                            '<span class="type ' + typeClass + '">' + ((list.blocked ? '<span class="label label-success" style="margin-right:4px">BLOCKED</span>' : '') + (list.builtin ? '{{ lang._("Built-in") }}' : '{{ lang._("Custom") }}')) + '</span>' +
                        '</div>' +
                        '<div class="ns-tl-card-body">' +
                            '<div class="desc">' + escapeHtml(list.description || '') + '</div>' +
                            '<div class="stats">' +
                                '<div class="item">' +
                                    '<div class="value">' + (list.domain_count || 0) + '</div>' +
                                    '<div class="label">{{ lang._("Domains") }}</div>' +
                                '</div>' +
                                '<div class="item">' +
                                    '<div class="value">' + (list.ip_count || 0) + '</div>' +
                                    '<div class="label">{{ lang._("IPs") }}</div>' +
                                '</div>' +
                                '<div class="item">' +
                                    '<div class="value">' + (list.hits || 0) + '</div>' +
                                    '<div class="label">{{ lang._("Hits") }}</div>' +
                                '</div>' +
                            '</div>' +
                        '</div>' +
                        '<div class="ns-tl-card-actions">' +
                            '<button class="btn btn-default btn-view" data-list="' + escapeHtml(list.id) + '">' +
                                '<i class="fa fa-eye"></i> {{ lang._("View") }}' +
                            '</button>' +
                            '<button class="btn ' + (list.blocked ? 'btn-success' : 'btn-danger') + ' btn-block-list" data-list="' + escapeHtml(list.id) + '" data-blocked="' + (list.blocked ? '1' : '0') + '">' +
                                '<i class="fa ' + (list.blocked ? 'fa-check-circle' : 'fa-ban') + '"></i> ' + (list.blocked ? '{{ lang._("Blocked - Click to Unblock") }}' : '{{ lang._("Block") }}') +
                            '</button>' +
                            (list.builtin ? '' :
                                '<button class="btn btn-warning btn-delete-list" data-list="' + escapeHtml(list.id) + '">' +
                                    '<i class="fa fa-trash"></i>' +
                                '</button>') +
                        '</div>' +
                    '</div>'
                );
            });

            // View entries
            $('.btn-view').click(function() {
                var listId = $(this).data('list');
                selectedList = listId;
                loadEntries(listId);
                $('#entries-panel').show();
            });

            // Block/unblock list
            $('.btn-block-list').click(function() {
                var listId = $(this).data('list');
                ajaxCall('/api/netshield/targetlists/toggleBlock', {list_id: listId}, function() {
                    loadStats();
                    loadLists();
                });
            });

            // Delete custom list
            $('.btn-delete-list').click(function() {
                var listId = $(this).data('list');
                BootstrapDialog.confirm({
                    title: '{{ lang._("Delete Target List") }}',
                    message: '{{ lang._("Are you sure you want to delete this target list?") }}',
                    type: BootstrapDialog.TYPE_DANGER,
                    callback: function(r) {
                        if (r) {
                            ajaxCall('/api/netshield/targetlists/delete', {list_id: listId}, function() {
                                loadStats();
                                loadLists();
                                if (selectedList === listId) {
                                    $('#entries-panel').hide();
                                    selectedList = null;
                                }
                            });
                        }
                    }
                });
            });
        });
    }

    function loadEntries(listId) {
        $.getJSON('/api/netshield/targetlists/entries?list_id=' + encodeURIComponent(listId), function(data) {
            var $list = $('#entries-list').empty();
            var entries = data.entries || [];

            $('#entries-list-name').text(data.list_name || listId);

            if (!entries.length) {
                $list.html('<div class="text-center text-muted p-4">{{ lang._("No entries in this list") }}</div>');
                return;
            }

            entries.forEach(function(entry) {
                var typeClass = entry.type || (entry.value.includes('/') ? 'cidr' : (entry.value.match(/^\d/) ? 'ip' : 'domain'));
                $list.append(
                    '<div class="ns-tl-entry">' +
                        '<span class="type-badge ' + typeClass + '">' + typeClass.toUpperCase() + '</span>' +
                        '<span class="value">' + escapeHtml(entry.value || entry.domain || entry.ip) + '</span>' +
                        '<div class="actions">' +
                            '<button class="btn btn-xs btn-danger btn-remove-entry" data-value="' + escapeHtml(entry.value || entry.domain || entry.ip) + '">' +
                                '<i class="fa fa-times"></i>' +
                            '</button>' +
                        '</div>' +
                    '</div>'
                );
            });

            // Remove entry
            $('.btn-remove-entry').click(function() {
                var value = $(this).data('value');
                ajaxCall('/api/netshield/targetlists/removeEntry', {list_id: selectedList, value: value}, function() {
                    loadEntries(selectedList);
                    loadStats();
                    loadLists();
                });
            });
        });
    }

    function getListIcon(id) {
        if (/social/i.test(id)) return 'social';
        if (/stream|video|netflix|youtube/i.test(id)) return 'streaming';
        if (/gam(e|ing)/i.test(id)) return 'gaming';
        if (/adult|porn/i.test(id)) return 'adult';
        if (/ad|track/i.test(id)) return 'ads';
        if (/custom/i.test(id)) return 'custom';
        return 'default';
    }

    function getListFa(id) {
        if (/social/i.test(id)) return 'fa-users';
        if (/stream|video/i.test(id)) return 'fa-play-circle';
        if (/gam(e|ing)/i.test(id)) return 'fa-gamepad';
        if (/adult|porn/i.test(id)) return 'fa-eye-slash';
        if (/ad|track/i.test(id)) return 'fa-ban';
        if (/vpn/i.test(id)) return 'fa-shield';
        if (/torrent|p2p/i.test(id)) return 'fa-cloud-download';
        return 'fa-list';
    }

    // Create new list
    $('#btn-create-list').click(function() {
        BootstrapDialog.show({
            title: '{{ lang._("Create Target List") }}',
            message: '<div class="ns-modal-form">' +
                '<div class="form-group">' +
                    '<label>{{ lang._("List Name") }}</label>' +
                    '<input type="text" id="new-list-name" placeholder="{{ lang._("e.g., Work Distractions") }}">' +
                '</div>' +
                '<div class="form-group">' +
                    '<label>{{ lang._("Description") }}</label>' +
                    '<textarea id="new-list-desc" rows="2" placeholder="{{ lang._("Optional description") }}"></textarea>' +
                '</div>' +
                '<div class="form-group">' +
                    '<label>{{ lang._("Initial Entries") }} ({{ lang._("one per line") }})</label>' +
                    '<textarea id="new-list-entries" rows="5" placeholder="{{ lang._("facebook.com\\ninstagram.com\\n192.168.1.100") }}"></textarea>' +
                '</div>' +
            '</div>',
            buttons: [{
                label: '{{ lang._("Cancel") }}',
                action: function(d) { d.close(); }
            }, {
                label: '{{ lang._("Create") }}',
                cssClass: 'btn-primary',
                action: function(d) {
                    var name = $('#new-list-name').val().trim();
                    var desc = $('#new-list-desc').val().trim();
                    var entries = $('#new-list-entries').val().trim();

                    if (!name) {
                        alert('{{ lang._("Name is required") }}');
                        return;
                    }

                    ajaxCall('/api/netshield/targetlists/create', {
                        name: name,
                        description: desc,
                        entries: entries
                    }, function(result) {
                        if (result && result.status === 'ok') {
                            d.close();
                            loadStats();
                            loadLists();
                        }
                    });
                }
            }]
        });
    });

    // Add entry to selected list
    $('#btn-add-entry').click(function() {
        if (!selectedList) return;

        BootstrapDialog.show({
            title: '{{ lang._("Add Entry") }}',
            message: '<div class="ns-modal-form">' +
                '<div class="form-group">' +
                    '<label>{{ lang._("Domain, IP, or CIDR") }}</label>' +
                    '<input type="text" id="new-entry-value" placeholder="{{ lang._("e.g., example.com or 192.168.1.0/24") }}">' +
                '</div>' +
            '</div>',
            buttons: [{
                label: '{{ lang._("Cancel") }}',
                action: function(d) { d.close(); }
            }, {
                label: '{{ lang._("Add") }}',
                cssClass: 'btn-primary',
                action: function(d) {
                    var value = $('#new-entry-value').val().trim();
                    if (!value) return;

                    ajaxCall('/api/netshield/targetlists/addEntry', {
                        list_id: selectedList,
                        value: value
                    }, function(result) {
                        if (result && result.status === 'ok') {
                            d.close();
                            loadEntries(selectedList);
                            loadStats();
                            loadLists();
                        }
                    });
                }
            }]
        });
    });

    // Close entries panel
    $('#btn-close-entries').click(function() {
        $('#entries-panel').hide();
        selectedList = null;
    });

    // Initialize
    loadStats();
    loadLists();
});
</script>

<!-- Header -->
<div class="ns-tl-header">
    <div>
        <h2><i class="fa fa-list-alt"></i> {{ lang._('Target Lists') }}</h2>
        <div style="margin-top: 8px; opacity: 0.9;">{{ lang._('Group domains and IPs for bulk blocking') }}</div>
    </div>
    <div class="ns-tl-stats">
        <div class="stat">
            <div class="stat-value" id="stat-total-lists">0</div>
            <div class="stat-label">{{ lang._('Lists') }}</div>
        </div>
        <div class="stat">
            <div class="stat-value" id="stat-total-entries">0</div>
            <div class="stat-label">{{ lang._('Entries') }}</div>
        </div>
        <div class="stat">
            <div class="stat-value" id="stat-policies">0</div>
            <div class="stat-label">{{ lang._('Policies') }}</div>
        </div>
    </div>
    <button class="btn btn-light" id="btn-create-list" style="background: rgba(255,255,255,0.2); border: none; color: #fff;">
        <i class="fa fa-plus"></i> {{ lang._('Create List') }}
    </button>
</div>

<!-- Lists Grid -->
<div class="ns-tl-grid" id="lists-grid">
    <div class="text-muted">{{ lang._('Loading target lists...') }}</div>
</div>

<!-- Entries Panel (initially hidden) -->
<div class="ns-tl-entries" id="entries-panel" style="display: none;">
    <div class="ns-tl-entries-header">
        <h3><i class="fa fa-list"></i> <span id="entries-list-name">-</span></h3>
        <div>
            <button class="btn btn-sm btn-primary" id="btn-add-entry">
                <i class="fa fa-plus"></i> {{ lang._('Add Entry') }}
            </button>
            <button class="btn btn-sm btn-default" id="btn-close-entries">
                <i class="fa fa-times"></i>
            </button>
        </div>
    </div>
    <div id="entries-list" style="max-height: 400px; overflow-y: auto;">
        <div class="text-center text-muted p-4">{{ lang._('Select a list to view entries') }}</div>
    </div>
</div>
