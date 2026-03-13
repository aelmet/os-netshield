#!/usr/local/bin/python3
# SPDX-License-Identifier: BSD-2-Clause
#
# NetShield - manage_policy.py
# Called by configd with %s param substitution.
# First argument is the action; subsequent arguments are action-specific.
# Actions: apply | status | enforce_apps | enforce_categories | enforce_targetlists

import sys
import os
import json
import logging
import logging.handlers
import traceback

_SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))
sys.path.insert(0, _SCRIPT_DIR)

from lib import config, policy_engine, enforcement, dns_filter, app_signatures
from lib import web_categories, target_lists

LOG_DIR  = "/var/log/netshield"
LOG_FILE = os.path.join(LOG_DIR, "netshield.log")


def _setup_logging() -> logging.Logger:
    os.makedirs(LOG_DIR, exist_ok=True)
    logger = logging.getLogger("netshield.manage_policy")
    logger.setLevel(logging.INFO)
    if logger.handlers:
        return logger
    handler = logging.handlers.RotatingFileHandler(
        LOG_FILE, maxBytes=5 * 1024 * 1024, backupCount=3
    )
    handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s"))
    logger.addHandler(handler)
    return logger


log = _setup_logging()


def _output(data) -> None:
    print(json.dumps(data, default=str))


# ---------------------------------------------------------------------------
# Action: apply
# ---------------------------------------------------------------------------

def action_apply() -> None:
    """Read all policies from config, generate and apply enforcement rules."""
    log.info("manage_policy: apply started")
    try:
        policies = policy_engine.get_active_policies()
        result = enforcement.apply_policies(policies)
        log.info("manage_policy: apply completed — %d policies applied", len(policies))
        _output({
            "result": "applied",
            "policies_applied": len(policies),
            "enforcement": result,
        })
    except Exception as exc:
        log.error("manage_policy apply error: %s\n%s", exc, traceback.format_exc())
        _output({"error": str(exc)})


# ---------------------------------------------------------------------------
# Action: status
# ---------------------------------------------------------------------------

def action_status() -> None:
    """Return current enforcement state as JSON."""
    try:
        policies = policy_engine.get_active_policies()
        enf_status = enforcement.get_status()
        _output({
            "policies_active": len(policies),
            "policies": [
                {
                    "name":    p.get("name"),
                    "type":    p.get("type"),
                    "enabled": p.get("enabled"),
                    "targets": p.get("targets", []),
                }
                for p in policies
            ],
            "enforcement": enf_status,
        })
    except Exception as exc:
        log.error("manage_policy status error: %s\n%s", exc, traceback.format_exc())
        _output({"error": str(exc)})


# ---------------------------------------------------------------------------
# Action: enforce_apps
# ---------------------------------------------------------------------------

def action_enforce_apps() -> None:
    """Generate DNS blocks for app-based policies specifically."""
    try:
        policies = policy_engine.get_policies_by_type("app")
        if not policies:
            _output({"result": "no_app_policies", "domains_blocked": 0})
            return

        domains: list[str] = []
        for policy in policies:
            for app_id in policy.get("targets", []):
                app_domains = app_signatures.get_domains_for_app(app_id)
                domains.extend(app_domains)

        # Deduplicate
        domains = sorted(set(domains))
        dns_filter.write_block_list(name="app_policies", domains=domains)
        dns_filter.reload()

        log.info("enforce_apps: blocked %d domains for %d policies", len(domains), len(policies))
        _output({
            "result": "applied",
            "policies_processed": len(policies),
            "domains_blocked": len(domains),
        })
    except Exception as exc:
        log.error("manage_policy enforce_apps error: %s\n%s", exc, traceback.format_exc())
        _output({"error": str(exc)})


# ---------------------------------------------------------------------------
# Action: enforce_categories
# ---------------------------------------------------------------------------

def action_enforce_categories() -> None:
    """Generate DNS blocks for web category policies."""
    try:
        policies = policy_engine.get_policies_by_type("category")
        if not policies:
            _output({"result": "no_category_policies", "domains_blocked": 0})
            return

        domains: list[str] = []
        for policy in policies:
            for cat_id in policy.get("targets", []):
                cat_domains = web_categories.get_domains_for_category(cat_id)
                domains.extend(cat_domains)

        domains = sorted(set(domains))
        dns_filter.write_block_list(name="category_policies", domains=domains)
        dns_filter.reload()

        log.info("enforce_categories: blocked %d domains for %d policies", len(domains), len(policies))
        _output({
            "result": "applied",
            "policies_processed": len(policies),
            "domains_blocked": len(domains),
        })
    except Exception as exc:
        log.error("manage_policy enforce_categories error: %s\n%s", exc, traceback.format_exc())
        _output({"error": str(exc)})


# ---------------------------------------------------------------------------
# Action: enforce_targetlists
# ---------------------------------------------------------------------------

def action_enforce_targetlists() -> None:
    """Generate DNS blocks for target list policies."""
    try:
        policies = policy_engine.get_policies_by_type("targetlist")
        if not policies:
            _output({"result": "no_targetlist_policies", "domains_blocked": 0})
            return

        domains: list[str] = []
        for policy in policies:
            for list_id in policy.get("targets", []):
                list_domains = target_lists.get_domains_for_list(list_id)
                domains.extend(list_domains)

        domains = sorted(set(domains))
        dns_filter.write_block_list(name="targetlist_policies", domains=domains)
        dns_filter.reload()

        log.info("enforce_targetlists: blocked %d domains for %d policies", len(domains), len(policies))
        _output({
            "result": "applied",
            "policies_processed": len(policies),
            "domains_blocked": len(domains),
        })
    except Exception as exc:
        log.error("manage_policy enforce_targetlists error: %s\n%s", exc, traceback.format_exc())
        _output({"error": str(exc)})


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

ACTIONS = {
    "apply":               action_apply,
    "status":              action_status,
    "enforce_apps":        action_enforce_apps,
    "enforce_categories":  action_enforce_categories,
    "enforce_targetlists": action_enforce_targetlists,
}


def main() -> None:
    if len(sys.argv) < 2:
        _output({"error": "No action specified. Use: apply | status | enforce_apps | enforce_categories | enforce_targetlists"})
        return

    action = sys.argv[1].lower()
    fn = ACTIONS.get(action)
    if fn is None:
        _output({"error": f"Unknown action: {action}"})
        return

    fn()


if __name__ == "__main__":
    main()
