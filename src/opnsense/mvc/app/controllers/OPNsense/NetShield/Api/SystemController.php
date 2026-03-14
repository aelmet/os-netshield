<?php

/*
 * Copyright (C) 2025 NetShield
 * All rights reserved.
 */

namespace OPNsense\NetShield\Api;

use OPNsense\Base\ApiControllerBase;

class SystemController extends JwtAwareController
{
    /**
     * GET /api/netshield/system/stats
     * Returns CPU temp, CPU usage %, RAM usage %
     * All values read from FreeBSD sysctl — no user input, no injection risk.
     */
    public function statsAction()
    {
        $result = ['status' => 'ok'];

        // CPU temperature — sysctl with fixed argument, no user input
        $temp = trim(shell_exec('sysctl -n dev.cpu.0.temperature 2>/dev/null') ?? '');
        $result['cpu_temp'] = $temp ? floatval($temp) : null;

        // CPU usage from kern.cp_time: user nice system interrupt idle
        // Two samples 0.5s apart to calculate delta
        $cp1 = trim(shell_exec('sysctl -n kern.cp_time 2>/dev/null') ?? '');
        if ($cp1) {
            usleep(500000);
            $cp2 = trim(shell_exec('sysctl -n kern.cp_time 2>/dev/null') ?? '');
            $a = array_map('intval', preg_split('/\s+/', $cp1));
            $b = array_map('intval', preg_split('/\s+/', $cp2));
            if (count($a) >= 5 && count($b) >= 5) {
                $idle_d = $b[4] - $a[4];
                $total_d = array_sum($b) - array_sum($a);
                $result['cpu_usage'] = $total_d > 0 ? round((1 - $idle_d / $total_d) * 100, 1) : 0;
            }
        }

        // CPU count
        $ncpu = trim(shell_exec('sysctl -n hw.ncpu 2>/dev/null') ?? '');
        $result['cpu_cores'] = $ncpu ? intval($ncpu) : null;

        // RAM: active + wired + laundry pages
        $pageSize = intval(trim(shell_exec('sysctl -n hw.pagesize 2>/dev/null') ?? '4096'));
        $active = intval(trim(shell_exec('sysctl -n vm.stats.vm.v_active_count 2>/dev/null') ?? '0'));
        $wired = intval(trim(shell_exec('sysctl -n vm.stats.vm.v_wire_count 2>/dev/null') ?? '0'));
        $laundry = intval(trim(shell_exec('sysctl -n vm.stats.vm.v_laundry_count 2>/dev/null') ?? '0'));
        $totalBytes = intval(trim(shell_exec('sysctl -n hw.physmem 2>/dev/null') ?? '0'));
        $usedBytes = ($active + $wired + $laundry) * $pageSize;

        $result['ram_total_mb'] = $totalBytes > 0 ? round($totalBytes / 1048576) : null;
        $result['ram_used_mb'] = round($usedBytes / 1048576);
        $result['ram_usage'] = $totalBytes > 0 ? round($usedBytes / $totalBytes * 100, 1) : null;

        // Uptime
        $uptime = trim(shell_exec('sysctl -n kern.boottime 2>/dev/null') ?? '');
        if (preg_match('/sec\s*=\s*(\d+)/', $uptime, $m)) {
            $result['uptime_seconds'] = time() - intval($m[1]);
        }

        // Load average
        $loadavg = trim(shell_exec('sysctl -n vm.loadavg 2>/dev/null') ?? '');
        if (preg_match('/\{\s*([\d.]+)\s+([\d.]+)\s+([\d.]+)/', $loadavg, $m)) {
            $result['load_avg'] = [floatval($m[1]), floatval($m[2]), floatval($m[3])];
        }

        return $result;
    }
}
