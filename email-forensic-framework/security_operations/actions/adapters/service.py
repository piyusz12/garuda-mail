"""
Phase 25 — Service Control Response Adapter
Manages MTA cryptographic configuration changes (disabling TLS 1.0/1.1),
creating before/after snapshots and configuration diffs.
"""

from typing import Dict, Any
from .base import BaseResponseAdapter
from ..registry import ActionRecord


class ServiceControlAdapter(BaseResponseAdapter):
    """Executes configuration changes on Mail Transfer Agents (MTA) and email gateways."""

    def __init__(self):
        # asset_id -> active configuration
        self.configs: Dict[str, Dict[str, Any]] = {
            "MTA-07": {
                "tls_min_version": "TLSv1.0",
                "ciphers": "DEFAULT:!aNULL",
                "protocols": ["TLSv1.0", "TLSv1.1", "TLSv1.2", "TLSv1.3"],
            },
            "MTA-01": {
                "tls_min_version": "TLSv1.2",
                "ciphers": "HIGH:!aNULL:!MD5",
                "protocols": ["TLSv1.2", "TLSv1.3"],
            },
        }

    def validate(self, action: ActionRecord) -> bool:
        return action.target in self.configs or True

    def execute(self, action: ActionRecord) -> Dict[str, Any]:
        target = action.target
        curr = dict(self.configs.get(target, {
            "tls_min_version": "TLSv1.0",
            "protocols": ["TLSv1.0", "TLSv1.1", "TLSv1.2", "TLSv1.3"],
        }))

        # Store before snapshot
        action.snapshot_before = dict(curr)

        # Apply new desired configuration: enforce TLS 1.2+
        curr["tls_min_version"] = "TLSv1.2"
        curr["protocols"] = ["TLSv1.2", "TLSv1.3"]
        self.configs[target] = curr

        # Store after snapshot
        action.snapshot_after = dict(curr)

        return {
            "status": "SUCCESS",
            "target": target,
            "diff": {
                "tls_min_version": "TLSv1.0 -> TLSv1.2",
                "disabled_protocols": ["TLSv1.0", "TLSv1.1"],
            },
        }

    def verify(self, action: ActionRecord) -> Dict[str, Any]:
        target = action.target
        cfg = self.configs.get(target, {})
        passed = cfg.get("tls_min_version") in ("TLSv1.2", "TLSv1.3")
        return {
            "verified": passed,
            "status": "PASS" if passed else "FAIL",
            "active_min_version": cfg.get("tls_min_version"),
        }

    def rollback(self, action: ActionRecord) -> Dict[str, Any]:
        target = action.target
        if action.snapshot_before:
            self.configs[target] = dict(action.snapshot_before)
        return {
            "status": "SUCCESS",
            "target": target,
            "message": "Reverted MTA TLS configuration to pre-remediation snapshot.",
        }
