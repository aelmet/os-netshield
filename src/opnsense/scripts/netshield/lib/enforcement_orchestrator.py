#!/usr/local/bin/python3
# Copyright (c) 2025-2026, NetShield Project
# All rights reserved.
#
# Enforcement Orchestrator — Central handler that chains all security checks
# and triggers appropriate enforcement actions.

"""
Enforcement Orchestrator for NetShield.

This module provides a unified enforcement layer that:
1. Checks flows against threat intelligence
2. Evaluates web categories
3. Applies parental controls
4. Enforces policies via pf/Unbound/Suricata
5. Logs all enforcement actions

Integration points:
- threat_intel.py → pf table blocking
- dns_filter.py → Unbound NXDOMAIN
- web_categories.py → Unbound blocking (NEW)
- policy_engine.py → pf anchor rules
- parental_engine.py → pf anchor rules
- quarantine.py → pf anchor rules
- ids_engine.py → Suricata integration
"""

import logging
import subprocess
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

log = logging.getLogger(__name__)

# Enforcement result codes
RESULT_ALLOWED = "allowed"
RESULT_BLOCKED_THREAT = "blocked_threat"
RESULT_BLOCKED_CATEGORY = "blocked_category"
RESULT_BLOCKED_POLICY = "blocked_policy"
RESULT_BLOCKED_PARENTAL = "blocked_parental"
RESULT_BLOCKED_QUARANTINE = "blocked_quarantine"
RESULT_THROTTLED = "throttled"


@dataclass
class EnforcementResult:
    """Result of an enforcement check."""
    action: str  # allowed, blocked, throttled
    reason: str
    source: str  # threat_intel, web_category, policy, parental, quarantine
    details: Dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "action": self.action,
            "reason": self.reason,
            "source": self.source,
            "details": self.details,
            "timestamp": self.timestamp,
        }


class EnforcementOrchestrator:
    """
    Central enforcement orchestrator that chains all security checks.

    Flow evaluation order (first match wins):
    1. Quarantine check (device isolation)
    2. Threat intelligence (IP/domain reputation)
    3. Parental controls (time limits, bedtime, categories)
    4. Web categories (content filtering)
    5. Policy rules (app/device/schedule blocking)

    Each check can trigger enforcement via:
    - pf rules (IP blocking)
    - Unbound (DNS blocking)
    - Suricata (IPS alerts/blocks)
    """

    def __init__(
        self,
        db_module: Any,
        threat_intel: Any = None,
        dns_filter: Any = None,
        web_categories: Any = None,
        policy_engine: Any = None,
        parental_engine: Any = None,
        quarantine_mgr: Any = None,
        ids_engine: Any = None,
    ):
        self._db = db_module
        self._threat_intel = threat_intel
        self._dns_filter = dns_filter
        self._web_categories = web_categories
        self._policy_engine = policy_engine
        self._parental_engine = parental_engine
        self._quarantine_mgr = quarantine_mgr
        self._ids_engine = ids_engine

        self._init_tables()
        self._enforcement_stats = {
            "total_checks": 0,
            "blocks": 0,
            "allows": 0,
            "by_source": {},
        }

    def _init_tables(self) -> None:
        """Create enforcement log table."""
        self._db.execute("""
            CREATE TABLE IF NOT EXISTS enforcement_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                device_mac TEXT,
                device_ip TEXT,
                dst_ip TEXT,
                dst_port INTEGER,
                domain TEXT,
                app_name TEXT,
                category TEXT,
                action TEXT NOT NULL,
                reason TEXT,
                source TEXT,
                details TEXT
            )
        """)
        self._db.execute("""
            CREATE INDEX IF NOT EXISTS idx_enforcement_timestamp
            ON enforcement_log(timestamp)
        """)
        self._db.execute("""
            CREATE INDEX IF NOT EXISTS idx_enforcement_device
            ON enforcement_log(device_mac)
        """)
        self._db.commit()

    # ------------------------------------------------------------------
    # Main enforcement check
    # ------------------------------------------------------------------

    def check_and_enforce(
        self,
        device_mac: Optional[str] = None,
        device_ip: Optional[str] = None,
        dst_ip: Optional[str] = None,
        dst_port: Optional[int] = None,
        domain: Optional[str] = None,
        app_name: Optional[str] = None,
        category: Optional[str] = None,
        protocol: str = "tcp",
    ) -> EnforcementResult:
        """
        Main entry point: evaluate a flow/request against all security layers.

        Returns EnforcementResult with action taken.
        """
        self._enforcement_stats["total_checks"] += 1

        # Build flow context
        flow = {
            "device_mac": device_mac or "",
            "device_ip": device_ip or "",
            "src_ip": device_ip or "",
            "dst_ip": dst_ip or "",
            "dst_port": dst_port or 0,
            "domain": domain or "",
            "app_name": app_name or "Unknown",
            "category": category or "uncategorized",
            "protocol": protocol,
        }

        # 1. Quarantine check (highest priority)
        result = self._check_quarantine(flow)
        if result:
            self._log_and_enforce(flow, result)
            return result

        # 2. Threat intelligence check
        result = self._check_threat_intel(flow)
        if result:
            self._log_and_enforce(flow, result)
            return result

        # 3. Parental controls check
        result = self._check_parental(flow)
        if result:
            self._log_and_enforce(flow, result)
            return result

        # 4. Web category check
        result = self._check_web_category(flow)
        if result:
            self._log_and_enforce(flow, result)
            return result

        # 5. Policy check
        result = self._check_policy(flow)
        if result:
            self._log_and_enforce(flow, result)
            return result

        # All checks passed - allow
        self._enforcement_stats["allows"] += 1
        return EnforcementResult(
            action=RESULT_ALLOWED,
            reason="all checks passed",
            source="orchestrator",
        )

    # ------------------------------------------------------------------
    # Individual checks
    # ------------------------------------------------------------------

    def _check_quarantine(self, flow: Dict[str, Any]) -> Optional[EnforcementResult]:
        """Check if device is quarantined."""
        if not self._quarantine_mgr:
            return None

        mac = flow.get("device_mac", "")
        if mac and self._quarantine_mgr.is_quarantined(mac):
            return EnforcementResult(
                action=RESULT_BLOCKED_QUARANTINE,
                reason="device quarantined",
                source="quarantine",
                details={"device_mac": mac},
            )
        return None

    def _check_threat_intel(self, flow: Dict[str, Any]) -> Optional[EnforcementResult]:
        """Check against threat intelligence feeds."""
        if not self._threat_intel:
            return None

        # Check destination IP
        dst_ip = flow.get("dst_ip", "")
        if dst_ip:
            result = self._threat_intel.check_ip(dst_ip)
            if result.get("matched"):
                return EnforcementResult(
                    action=RESULT_BLOCKED_THREAT,
                    reason=f"threat IP: {result.get('feeds', [])}",
                    source="threat_intel",
                    details={
                        "ip": dst_ip,
                        "feeds": result.get("feeds", []),
                        "severity": result.get("severity", "high"),
                    },
                )

        # Check domain
        domain = flow.get("domain", "")
        if domain:
            result = self._threat_intel.check_domain(domain)
            if result.get("matched"):
                return EnforcementResult(
                    action=RESULT_BLOCKED_THREAT,
                    reason=f"threat domain: {result.get('feeds', [])}",
                    source="threat_intel",
                    details={
                        "domain": domain,
                        "feeds": result.get("feeds", []),
                        "severity": result.get("severity", "high"),
                    },
                )

        return None

    def _check_parental(self, flow: Dict[str, Any]) -> Optional[EnforcementResult]:
        """Check parental control restrictions."""
        if not self._parental_engine:
            return None

        mac = flow.get("device_mac", "")
        if not mac:
            return None

        result = self._parental_engine.check_access(
            device_mac=mac,
            domain=flow.get("domain"),
            category=flow.get("category"),
        )

        if not result.get("allowed", True):
            return EnforcementResult(
                action=RESULT_BLOCKED_PARENTAL,
                reason=result.get("reason", "parental restriction"),
                source="parental",
                details={"device_mac": mac},
            )

        return None

    def _check_web_category(self, flow: Dict[str, Any]) -> Optional[EnforcementResult]:
        """Check web content category restrictions."""
        if not self._web_categories:
            return None

        domain = flow.get("domain", "")
        if not domain:
            return None

        mac = flow.get("device_mac")
        should_block, category_name = self._web_categories.should_block(domain, mac)

        if should_block:
            # Get classification details
            classification = self._web_categories.classify(domain)
            return EnforcementResult(
                action=RESULT_BLOCKED_CATEGORY,
                reason=f"blocked category: {category_name}",
                source="web_category",
                details={
                    "domain": domain,
                    "category": classification.category,
                    "category_name": category_name,
                    "group": classification.group,
                    "severity": classification.severity,
                },
            )

        return None

    def _check_policy(self, flow: Dict[str, Any]) -> Optional[EnforcementResult]:
        """Check policy rules."""
        if not self._policy_engine:
            return None

        policy = self._policy_engine.evaluate(flow)
        if policy and policy.action == "block":
            return EnforcementResult(
                action=RESULT_BLOCKED_POLICY,
                reason=f"policy: {policy.name}",
                source="policy",
                details={
                    "policy_id": policy.id,
                    "policy_name": policy.name,
                },
            )
        elif policy and policy.action == "throttle":
            return EnforcementResult(
                action=RESULT_THROTTLED,
                reason=f"throttled by policy: {policy.name}",
                source="policy",
                details={
                    "policy_id": policy.id,
                    "policy_name": policy.name,
                    "bandwidth_kbps": policy.bandwidth_kbps,
                },
            )

        return None

    # ------------------------------------------------------------------
    # Enforcement execution
    # ------------------------------------------------------------------

    def _log_and_enforce(self, flow: Dict[str, Any], result: EnforcementResult) -> None:
        """Log the enforcement action and apply it."""
        import json

        self._enforcement_stats["blocks"] += 1
        source = result.source
        self._enforcement_stats["by_source"][source] = (
            self._enforcement_stats["by_source"].get(source, 0) + 1
        )

        # Log to database
        now = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
        self._db.execute(
            """
            INSERT INTO enforcement_log
            (timestamp, device_mac, device_ip, dst_ip, dst_port, domain,
             app_name, category, action, reason, source, details)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                now,
                flow.get("device_mac"),
                flow.get("device_ip"),
                flow.get("dst_ip"),
                flow.get("dst_port"),
                flow.get("domain"),
                flow.get("app_name"),
                flow.get("category"),
                result.action,
                result.reason,
                result.source,
                json.dumps(result.details),
            ),
        )
        self._db.commit()

        # Execute enforcement based on source
        if result.action in (RESULT_BLOCKED_THREAT, RESULT_BLOCKED_POLICY):
            self._enforce_ip_block(flow, result)
        elif result.action == RESULT_BLOCKED_CATEGORY:
            self._enforce_dns_block(flow, result)
        elif result.action == RESULT_BLOCKED_PARENTAL:
            # Parental engine handles its own pf rules
            if self._parental_engine:
                self._parental_engine.enforce(flow.get("device_mac", ""))
        elif result.action == RESULT_THROTTLED:
            self._enforce_throttle(flow, result)

        log.info(
            "ENFORCEMENT %s: %s - %s (device=%s dst=%s domain=%s)",
            result.action,
            result.source,
            result.reason,
            flow.get("device_mac", "?"),
            flow.get("dst_ip", "?"),
            flow.get("domain", "?"),
        )

    def _enforce_ip_block(self, flow: Dict[str, Any], result: EnforcementResult) -> None:
        """Enforce IP-based blocking via policy engine."""
        if self._policy_engine:
            self._policy_engine.enforce_block(flow)

    def _enforce_dns_block(self, flow: Dict[str, Any], result: EnforcementResult) -> None:
        """Enforce DNS-based blocking via dns_filter."""
        if self._dns_filter:
            domain = flow.get("domain", "")
            if domain:
                # Add to DNS blocklist and reload Unbound
                self._dns_filter.add_custom_rule(domain, "block")
                log.info("DNS block applied for domain: %s", domain)

    def _enforce_throttle(self, flow: Dict[str, Any], result: EnforcementResult) -> None:
        """Enforce bandwidth throttling via policy engine."""
        if self._policy_engine:
            bandwidth = result.details.get("bandwidth_kbps", 100)
            self._policy_engine.enforce_throttle(flow, bandwidth)

    # ------------------------------------------------------------------
    # Batch enforcement for web categories
    # ------------------------------------------------------------------

    def sync_category_blocks_to_dns(self) -> Dict[str, Any]:
        """
        Sync blocked web categories to DNS filter.

        This creates NXDOMAIN entries for all domains in blocked categories,
        enabling proactive blocking without waiting for individual requests.
        """
        if not self._web_categories or not self._dns_filter:
            return {"status": "error", "message": "modules not initialized"}

        blocked_count = 0
        categories = self._web_categories.get_categories()

        for cat in categories:
            if not cat.enabled:
                continue

            # Get domains for this category from web_categories database
            domains = self._web_categories.search_domains("", category=cat.id, limit=10000)

            for domain_info in domains:
                domain = domain_info.get("domain", "")
                if domain:
                    # Check if domain should be blocked globally
                    should_block, _ = self._web_categories.should_block(domain)
                    if should_block:
                        self._dns_filter.add_custom_rule(domain, "block")
                        blocked_count += 1

        # Regenerate Unbound config and reload
        self._dns_filter.generate_unbound_overrides()
        self._dns_filter.reload_unbound()

        return {
            "status": "ok",
            "domains_blocked": blocked_count,
        }

    # ------------------------------------------------------------------
    # Stats and monitoring
    # ------------------------------------------------------------------

    def get_stats(self) -> Dict[str, Any]:
        """Get enforcement statistics."""
        # Recent blocks from database
        recent_blocks = self._db.query(
            """
            SELECT source, COUNT(*) as count
            FROM enforcement_log
            WHERE timestamp > datetime('now', '-1 hour')
            AND action != 'allowed'
            GROUP BY source
            """
        )

        today_total = self._db.query(
            """
            SELECT COUNT(*) as count
            FROM enforcement_log
            WHERE timestamp > datetime('now', 'start of day')
            AND action != 'allowed'
            """
        )

        return {
            **self._enforcement_stats,
            "recent_blocks_by_source": {r["source"]: r["count"] for r in recent_blocks},
            "today_total_blocks": today_total[0]["count"] if today_total else 0,
        }

    def get_recent_blocks(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Get recent enforcement blocks."""
        rows = self._db.query(
            """
            SELECT * FROM enforcement_log
            WHERE action != 'allowed'
            ORDER BY timestamp DESC
            LIMIT ?
            """,
            (limit,),
        )
        return [dict(r) for r in rows]

    def get_blocks_by_device(self, device_mac: str, limit: int = 100) -> List[Dict[str, Any]]:
        """Get enforcement blocks for a specific device."""
        rows = self._db.query(
            """
            SELECT * FROM enforcement_log
            WHERE device_mac = ? AND action != 'allowed'
            ORDER BY timestamp DESC
            LIMIT ?
            """,
            (device_mac.upper(), limit),
        )
        return [dict(r) for r in rows]
