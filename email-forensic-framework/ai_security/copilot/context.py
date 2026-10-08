from __future__ import annotations

import re
from typing import Any, Dict, List

from ai_security.copilot.intent import resolve_entity


class ContextEngine:
    """Retrieve structured artifact context for a user investigation request."""

    def build_context(
        self,
        query: str,
        tenant_id: str,
        analyst_id: str,
        permissions: List[str] | None = None,
        entity_id: str | None = None,
    ) -> Dict[str, Any]:
        permissions = permissions or []
        entity_id = entity_id or resolve_entity(query)
        is_authorized = bool(permissions)

        artifacts = {
            "alerts": ["ALERT-3311", "ALERT-4519"],
            "cases": ["CASE-1042"],
            "incidents": ["INC-1042"],
            "sessions": ["SESS-0124", "SESS-0441"],
            "tls_events": ["TLS-4420"],
            "ja4": ["JA4-4A4A"],
            "certificates": ["CERT-0199"],
            "domains": ["mail.example.com"],
            "ips": ["203.0.113.77"],
            "threat_hunts": ["HUNT-JA4-LEGACY"],
        }

        context = {
            "tenant_id": tenant_id,
            "analyst_id": analyst_id,
            "entity_id": entity_id,
            "authorized": is_authorized,
            "artifacts": artifacts,
            "permissions": permissions,
            "query": query,
            "risk_context": {
                "risk_level": "HIGH",
                "entity_type": "ASSET",
            },
        }

        if not is_authorized:
            context["reason"] = "No investigation permissions granted for this tenant scope."
        return context

    def retrieve_context(self, *args, **kwargs) -> Dict[str, Any]:
        return self.build_context(*args, **kwargs)


__all__ = ["ContextEngine"]
