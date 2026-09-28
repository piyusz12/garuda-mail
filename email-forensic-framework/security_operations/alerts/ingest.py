"""
Phase 25 — Alert Intake Engine
Normalizes alerts across network sensors, TLS analyzers, certificate analyzers,
AI models, detection rules, threat hunting, and external threat intelligence.
"""

from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Any
from datetime import datetime, timezone
import time
import uuid


@dataclass
class Alert:
    alert_id: str
    source: str
    severity: str
    asset_id: str
    timestamp: float
    iso_time: str
    event_type: str
    rule_id: Optional[str] = None
    ja4: Optional[str] = None
    certificate_id: Optional[str] = None
    destination: Optional[str] = None
    confidence: float = 0.90
    tenant_id: str = "default"
    details: Dict[str, Any] = field(default_factory=dict)
    raw_payload: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class AlertIngestEngine:
    """Ingests, validates, and normalizes alerts from heterogeneous sources."""

    VALID_SOURCES = {
        "sensors",
        "tls_analyzer",
        "cert_analyzer",
        "ai_models",
        "rules",
        "threat_hunting",
        "external_intel",
        "federated_intel",
        "compliance",
        "crypto_inventory",
        "pqc_migration",
    }

    VALID_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}

    def __init__(self):
        self._alerts: Dict[str, Alert] = {}

    def ingest_raw(self, data: Dict[str, Any], tenant_id: str = "default") -> Alert:
        """Normalizes an incoming alert dictionary into a structured Alert object."""
        alert_id = str(data.get("alert_id") or f"ALT-{uuid.uuid4().hex[:8].upper()}")
        source = str(data.get("source", "rules")).lower()
        if source not in self.VALID_SOURCES:
            source = "rules"

        raw_sev = str(data.get("severity", "MEDIUM")).upper()
        severity = raw_sev if raw_sev in self.VALID_SEVERITIES else "MEDIUM"
        asset_id = str(data.get("asset_id", "UNKNOWN-ASSET"))

        ts = float(data.get("timestamp") or time.time())
        iso = data.get("iso_time") or datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()

        event_type = str(data.get("event_type") or data.get("type") or "security_event")
        rule_id = data.get("rule_id")
        ja4 = data.get("ja4")
        certificate_id = data.get("certificate_id") or data.get("cert_fingerprint")
        destination = data.get("destination") or data.get("dst_ip")
        confidence = float(data.get("confidence", 0.85))
        confidence = max(0.0, min(1.0, confidence))

        details = dict(data.get("details", {}))
        for k in ("protocol", "ciphersuite", "port", "reason", "client_ip"):
            if k in data and k not in details:
                details[k] = data[k]

        alert = Alert(
            alert_id=alert_id,
            source=source,
            severity=severity,
            asset_id=asset_id,
            timestamp=ts,
            iso_time=iso,
            event_type=event_type,
            rule_id=rule_id,
            ja4=ja4,
            certificate_id=certificate_id,
            destination=destination,
            confidence=confidence,
            tenant_id=tenant_id,
            details=details,
            raw_payload=data,
        )

        self._alerts[alert.alert_id] = alert
        return alert

    def ingest_batch(self, items: List[Dict[str, Any]], tenant_id: str = "default") -> List[Alert]:
        return [self.ingest_raw(item, tenant_id=tenant_id) for item in items]

    def get_alert(self, alert_id: str) -> Optional[Alert]:
        return self._alerts.get(alert_id)

    def list_alerts(self, tenant_id: Optional[str] = None) -> List[Alert]:
        if tenant_id:
            return [a for a in self._alerts.values() if a.tenant_id == tenant_id]
        return list(self._alerts.values())

    def clear(self):
        self._alerts.clear()
