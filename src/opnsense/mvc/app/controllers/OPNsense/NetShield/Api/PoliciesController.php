<?php

namespace OPNsense\NetShield\Api;

use OPNsense\Base\ApiControllerBase;
use OPNsense\Core\Backend;

class PoliciesController extends ApiControllerBase
{
    private function encParam(string $val): string
    {
        return rawurlencode($val);
    }

    /**
     * Append a parameter to the command only if the value is non-empty.
     */
    private function addParam(string &$cmd, string $flag, string $val): void
    {
        if ($val !== '') {
            $cmd .= ',' . $flag . ',' . $this->encParam($val);
        }
    }

    /**
     * Trigger enforcement of all blocking rules via Unbound.
     */
    private function enforceNow(): array
    {
        $backend = new Backend();
        $raw = $backend->configdRun('netshield enforce');
        $result = json_decode($raw, true);
        if (!$result) {
            return ['enforce_status' => 'error', 'enforce_message' => trim($raw) ?: 'Enforce backend error'];
        }
        return ['enforce_status' => 'ok', 'enforce_result' => $result];
    }

    public function applyAction()
    {
        if (!$this->request->isPost()) {
            return ['status' => 'error', 'message' => 'POST required'];
        }
        $result = $this->enforceNow();
        $result['status'] = $result['enforce_status'];
        return $result;
    }

    public function searchAction()
    {
        $backend  = new Backend();
        $raw      = $backend->configdRun('netshield manage_policy list');
        $data     = json_decode($raw, true) ?: [];
        $policies = $data['data']['policies'] ?? ($data['data'] ?? []);

        foreach ($policies as &$p) {
            $targets = $p['targets'] ?? '';
            if (is_string($targets)) {
                $decoded = json_decode($targets, true);
                if (is_array($decoded)) {
                    $p['apps'] = !empty($decoded['apps']) ? implode(',', $decoded['apps']) : ($p['apps'] ?? '');
                    $p['web_categories'] = !empty($decoded['categories']) ? implode(',', $decoded['categories']) : ($p['web_categories'] ?? '');
                    $p['devices_list'] = !empty($decoded['devices']) ? implode(',', $decoded['devices']) : ($p['devices'] ?? '');
                }
            }
            if (!isset($p['scope'])) $p['scope'] = 'network';
            if (!isset($p['vlans'])) $p['vlans'] = '';
            if (!isset($p['description'])) $p['description'] = '';
            if (!isset($p['schedule_type'])) $p['schedule_type'] = 'always';
            if (!isset($p['start_time'])) $p['start_time'] = '';
            if (!isset($p['end_time'])) $p['end_time'] = '';
            // Phase 1 fields - defaults
            if (!isset($p['no_internet'])) $p['no_internet'] = '0';
            if (!isset($p['security_preset'])) $p['security_preset'] = 'custom';
            if (!isset($p['security_categories'])) $p['security_categories'] = '{}';
            if (!isset($p['exclusions_json'])) $p['exclusions_json'] = '[]';
            if (!isset($p['schedules_json'])) $p['schedules_json'] = '[]';
            if (!isset($p['block_tor'])) $p['block_tor'] = '0';
            if (!isset($p['block_vpn'])) $p['block_vpn'] = '0';
            if (!isset($p['block_doh'])) $p['block_doh'] = '0';
            if (!isset($p['block_ech'])) $p['block_ech'] = '0';
            if (!isset($p['safe_search'])) $p['safe_search'] = '0';
        }
        unset($p);

        $current  = (int)($this->request->get('current')  ?? 1);
        $rowCount = (int)($this->request->get('rowCount') ?? 25);
        $total    = count($policies);
        $offset   = ($current - 1) * $rowCount;
        $rows     = array_slice($policies, $offset, $rowCount);

        return [
            'rows'     => $rows,
            'rowCount' => $rowCount,
            'total'    => $total,
            'current'  => $current,
        ];
    }

    public function addAction()
    {
        if (!$this->request->isPost()) {
            return ['status' => 'error', 'message' => 'POST required'];
        }

        $name     = trim($this->request->getPost('name')     ?? '');
        $action   = trim($this->request->getPost('action')   ?? 'block');
        $description = trim($this->request->getPost('description') ?? '');
        $scope    = trim($this->request->getPost('scope')    ?? 'network');
        $schedule = trim($this->request->getPost('schedule') ?? 'always');
        $scheduleType = trim($this->request->getPost('schedule_type') ?? 'always');
        $startTime = trim($this->request->getPost('start_time') ?? '');
        $endTime   = trim($this->request->getPost('end_time') ?? '');
        $priority = (int)($this->request->getPost('priority') ?? 100);
        $enabled  = ($this->request->getPost('enabled') === '0') ? 'false' : 'true';
        $apps = trim($this->request->getPost('apps') ?? '');
        $webCategories = trim($this->request->getPost('web_categories') ?? '');
        $devices = trim($this->request->getPost('devices') ?? '');
        $vlans = trim($this->request->getPost('vlans') ?? '');

        // Phase 1 fields
        $noInternet = ($this->request->getPost('no_internet') === '1') ? '1' : '0';
        $securityPreset = trim($this->request->getPost('security_preset') ?? 'custom');
        $securityCategories = trim($this->request->getPost('security_categories') ?? '{}');
        $exclusionsJson = trim($this->request->getPost('exclusions_json') ?? '[]');
        $schedulesJson = trim($this->request->getPost('schedules_json') ?? '[]');
        $blockTor = ($this->request->getPost('block_tor') === '1') ? '1' : '0';
        $blockVpn = ($this->request->getPost('block_vpn') === '1') ? '1' : '0';
        $blockDoh = ($this->request->getPost('block_doh') === '1') ? '1' : '0';
        $blockEch = ($this->request->getPost('block_ech') === '1') ? '1' : '0';
        $safeSearch = ($this->request->getPost('safe_search') === '1') ? '1' : '0';
        $bandwidthKbps = trim($this->request->getPost('bandwidth_kbps') ?? '0');
        $excludedDevices = trim($this->request->getPost('excluded_devices') ?? '');

        if (empty($name)) {
            return ['status' => 'error', 'message' => 'name is required'];
        }

        $cmd = 'netshield manage_policy add,--name,' . $this->encParam($name)
            . ',--action,' . $this->encParam($action)
            . ',--priority,' . $priority
            . ',--enabled,' . $enabled;

        $this->addParam($cmd, '--description', $description);
        $this->addParam($cmd, '--scope', $scope);
        $this->addParam($cmd, '--apps', $apps);
        $this->addParam($cmd, '--web_categories', $webCategories);
        $this->addParam($cmd, '--devices', $devices);
        $this->addParam($cmd, '--vlans', $vlans);
        $this->addParam($cmd, '--schedule', $schedule);
        $this->addParam($cmd, '--schedule_type', $scheduleType);
        $this->addParam($cmd, '--start_time', $startTime);
        $this->addParam($cmd, '--end_time', $endTime);

        // Phase 1 fields
        $this->addParam($cmd, '--no_internet', $noInternet);
        $this->addParam($cmd, '--security_preset', $securityPreset);
        $this->addParam($cmd, '--security_categories', $securityCategories);
        $this->addParam($cmd, '--exclusions_json', $exclusionsJson);
        $this->addParam($cmd, '--schedules_json', $schedulesJson);
        $this->addParam($cmd, '--block_tor', $blockTor);
        $this->addParam($cmd, '--block_vpn', $blockVpn);
        $this->addParam($cmd, '--block_doh', $blockDoh);
        $this->addParam($cmd, '--block_ech', $blockEch);
        $this->addParam($cmd, '--safe_search', $safeSearch);
        $this->addParam($cmd, '--bandwidth_kbps', $bandwidthKbps);
        $this->addParam($cmd, '--excluded_devices', $excludedDevices);

        $backend = new Backend();
        $raw    = $backend->configdRun($cmd);
        $result = json_decode($raw, true);
        if (!$result) {
            return ['status' => 'error', 'message' => trim($raw) ?: 'Backend error'];
        }

        // Auto-enforce after adding a policy
        $enforce = $this->enforceNow();
        return array_merge($result, $enforce);
    }

    public function updateAction()
    {
        if (!$this->request->isPost()) {
            return ['status' => 'error', 'message' => 'POST required'];
        }

        $id = (int)($this->request->getPost('id') ?? 0);
        if (!$id) {
            return ['status' => 'error', 'message' => 'id required'];
        }

        $cmd = 'netshield manage_policy --update,--id,' . $id;

        // Fields that can be cleared (user may uncheck all apps/categories)
        $clearableFields = ['apps', 'web_categories', 'devices', 'vlans', 'excluded_devices', 'device_categories'];
        $otherFields = ['name', 'action', 'description', 'scope',
                        'schedule', 'schedule_type', 'start_time', 'end_time'];

        // Phase 1 new text fields
        $phase1TextFields = ['security_preset', 'security_categories',
                             'exclusions_json', 'schedules_json', 'bandwidth_kbps'];
        // Phase 1 boolean fields (always send if present)
        $phase1BoolFields = ['no_internet', 'block_tor', 'block_vpn',
                             'block_doh', 'block_ech', 'safe_search'];

        foreach ($otherFields as $field) {
            $val = $this->request->getPost($field);
            if ($val !== null && $val !== '') {
                $cmd .= ',--' . $field . ',' . $this->encParam(trim($val));
            }
        }
        foreach ($clearableFields as $field) {
            $val = $this->request->getPost($field);
            if ($val !== null) {
                $trimmed = trim($val);
                $cmd .= ',--' . $field . ',' . $this->encParam($trimmed === '' ? '__CLEAR__' : $trimmed);
            }
        }
        foreach ($phase1TextFields as $field) {
            $val = $this->request->getPost($field);
            if ($val !== null) {
                $cmd .= ',--' . $field . ',' . $this->encParam(trim($val));
            }
        }
        foreach ($phase1BoolFields as $field) {
            $val = $this->request->getPost($field);
            if ($val !== null) {
                $cmd .= ',--' . $field . ',' . (($val === '1' || $val === 'true') ? '1' : '0');
            }
        }

        $priority = $this->request->getPost('priority');
        if ($priority !== null) {
            $cmd .= ',--priority,' . (int)$priority;
        }

        $enabled = $this->request->getPost('enabled');
        if ($enabled !== null) {
            $cmd .= ',--enabled,' . (($enabled === '0' || $enabled === 'false') ? 'false' : 'true');
        }

        $backend = new Backend();
        $raw     = $backend->configdRun($cmd);
        $result  = json_decode($raw, true);
        if (!$result) {
            return ['status' => 'error', 'message' => trim($raw) ?: 'Backend error'];
        }

        // Auto-enforce after updating a policy
        $enforce = $this->enforceNow();
        return array_merge($result, $enforce);
    }

    public function blockIpAction()
    {
        if (!$this->request->isPost()) {
            return ['status' => 'error', 'message' => 'POST required'];
        }
        $ip = trim($this->request->getPost('ip') ?? '');
        if (empty($ip) || !filter_var($ip, FILTER_VALIDATE_IP)) {
            return ['status' => 'error', 'message' => 'valid ip required'];
        }

        $backend = new Backend();
        $cmd = 'netshield manage_policy add'
            . ',--name,' . $this->encParam("Block $ip")
            . ',--action,block'
            . ',--devices,' . $this->encParam($ip)
            . ',--schedule,always'
            . ',--priority,10'
            . ',--enabled,true';
        $raw = $backend->configdRun($cmd);
        $result = json_decode($raw, true);
        if (!$result) {
            return ['status' => 'error', 'message' => trim($raw) ?: 'Backend error'];
        }

        $enforce = $this->enforceNow();
        return array_merge($result, $enforce);
    }

    public function deleteAction()
    {
        if (!$this->request->isPost()) {
            return ['status' => 'error', 'message' => 'POST required'];
        }
        $id = (int)($this->request->getPost('id') ?? 0);
        if (!$id) {
            return ['status' => 'error', 'message' => 'id required'];
        }
        $backend = new Backend();
        $raw     = $backend->configdRun('netshield manage_policy --delete,--id,' . $id);
        $result  = json_decode($raw, true);
        if (!$result) {
            return ['status' => 'error', 'message' => trim($raw) ?: 'Backend error'];
        }

        // Auto-enforce after deleting a policy
        $enforce = $this->enforceNow();
        return array_merge($result, $enforce);
    }

    public function toggleAction()
    {
        if (!$this->request->isPost()) {
            return ['status' => 'error', 'message' => 'POST required'];
        }
        $id = (int)($this->request->getPost('id') ?? 0);
        if (!$id) {
            return ['status' => 'error', 'message' => 'id required'];
        }
        $backend = new Backend();
        $raw     = $backend->configdRun('netshield manage_policy --toggle,--id,' . $id);
        $result  = json_decode($raw, true);
        if (!$result) {
            return ['status' => 'error', 'message' => trim($raw) ?: 'Backend error'];
        }

        // Auto-enforce after toggling a policy
        $enforce = $this->enforceNow();
        return array_merge($result, $enforce);
    }

    public function reorderAction()
    {
        if (!$this->request->isPost()) {
            return ['status' => 'error', 'message' => 'POST required'];
        }
        $id       = (int)($this->request->getPost('id')       ?? 0);
        $priority = (int)($this->request->getPost('priority') ?? 100);
        if (!$id) {
            return ['status' => 'error', 'message' => 'id required'];
        }
        $backend = new Backend();
        $raw     = $backend->configdRun(
            'netshield manage_policy --reorder,--id,' . $id . ',--priority,' . $priority
        );
        $result  = json_decode($raw, true);
        if (!$result) {
            return ['status' => 'error', 'message' => trim($raw) ?: 'Backend error'];
        }
        return $result;
    }

    public function getAction()
    {
        $id = (int)($this->request->get('id') ?? 0);
        if (!$id) {
            return ['status' => 'error', 'message' => 'id required'];
        }

        $backend = new Backend();
        $raw = $backend->configdRun('netshield manage_policy list');
        $data = json_decode($raw, true) ?: [];
        $policies = $data['data']['policies'] ?? ($data['data'] ?? []);

        foreach ($policies as $p) {
            if ((int)($p['id'] ?? 0) === $id) {
                return $p;
            }
        }

        return ['status' => 'error', 'message' => 'Policy not found'];
    }

    public function statsAction()
    {
        $backend = new Backend();
        $raw = $backend->configdRun('netshield manage_policy stats');
        $data = json_decode($raw, true);
        if ($data) return $data;
        return ['total_policies' => 0, 'active_policies' => 0, 'blocked_today' => 0];
    }

    public function enforceStatusAction()
    {
        $backend = new Backend();
        $raw = $backend->configdRun('netshield enforce_status');
        $result = json_decode($raw, true);
        if ($result) return $result;
        return ['status' => 'error', 'message' => trim($raw) ?: 'Backend error'];
    }
}
