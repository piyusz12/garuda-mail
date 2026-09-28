"""
Phase 25 — Alert Clustering
Manages clusters of correlated alerts targeting the same asset or composite incident pattern.
"""

from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Set, Any
import time
import uuid
from .ingest import Alert


SEVERITY_WEIGHTS = {
    "CRITICAL": 5,
    "HIGH": 4,
    "MEDIUM": 3,
    "LOW": 2,
    "INFO": 1,
}

WEIGHT_TO_SEVERITY = {v: k for k, v in SEVERITY_WEIGHTS.items()}


@dataclass
class AlertCluster:
    cluster_id: str
    asset_id: str
    tenant_id: str
    alerts: List[Alert] = field(default_factory=list)
    event_types: Set[str] = field(default_factory=set)
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    aggregate_severity: str = "MEDIUM"
    correlation_score: float = 0.5
    is_incident_candidate: bool = False

    def add_alert(self, alert: Alert):
        self.alerts.append(alert)
        self.event_types.add(alert.event_type)
        if alert.timestamp < self.first_seen:
            self.first_seen = alert.timestamp
        if alert.timestamp > self.last_seen:
            self.last_seen = alert.timestamp

        # Recalculate aggregate severity (max severity of constituent alerts)
        max_weight = max(SEVERITY_WEIGHTS.get(a.severity, 1) for a in self.alerts)
        self.aggregate_severity = WEIGHT_TO_SEVERITY.get(max_weight, "MEDIUM")

        # Composite incident trigger: multi-indicator pattern
        # e.g., certificate_change + new_ja4 or tls_downgrade
        has_cert = any("cert" in et.lower() for et in self.event_types)
        has_tls = any("tls" in et.lower() or "downgrade" in et.lower() for et in self.event_types)
        has_ja4 = any("ja4" in et.lower() for et in self.event_types)

        if len(self.event_types) >= 2 or len(self.alerts) >= 3 or (has_cert and (has_tls or has_ja4)):
            self.is_incident_candidate = True
            self.correlation_score = min(1.0, 0.4 + 0.2 * len(self.event_types) + 0.1 * len(self.alerts))
        else:
            self.correlation_score = min(1.0, 0.3 + 0.15 * len(self.alerts))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "cluster_id": self.cluster_id,
            "asset_id": self.asset_id,
            "tenant_id": self.tenant_id,
            "alert_count": len(self.alerts),
            "alert_ids": [a.alert_id for a in self.alerts],
            "event_types": list(self.event_types),
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "aggregate_severity": self.aggregate_severity,
            "correlation_score": round(self.correlation_score, 2),
            "is_incident_candidate": self.is_incident_candidate,
        }


class ClusterManager:
    """Manages active alert clusters in memory with temporal clustering windows."""

    def __init__(self, cluster_window_seconds: int = 600):
        self.cluster_window = cluster_window_seconds
        self._clusters: Dict[str, AlertCluster] = {}
        # (tenant_id, asset_id) -> cluster_id
        self._active_asset_clusters: Dict[str, str] = {}

    def get_or_create_cluster(self, alert: Alert) -> AlertCluster:
        key = f"{alert.tenant_id}:{alert.asset_id}"
        cid = self._active_asset_clusters.get(key)
        now = alert.timestamp or time.time()

        if cid and cid in self._clusters:
            cluster = self._clusters[cid]
            if (now - cluster.last_seen) <= self.cluster_window:
                cluster.add_alert(alert)
                return cluster

        # Create new cluster
        new_cid = f"CLUSTER-{uuid.uuid4().hex[:8].upper()}"
        cluster = AlertCluster(
            cluster_id=new_cid,
            asset_id=alert.asset_id,
            tenant_id=alert.tenant_id,
            first_seen=now,
            last_seen=now,
        )
        cluster.add_alert(alert)
        self._clusters[new_cid] = cluster
        self._active_asset_clusters[key] = new_cid
        return cluster

    def get_cluster(self, cluster_id: str) -> Optional[AlertCluster]:
        return self._clusters.get(cluster_id)

    def list_clusters(self, tenant_id: Optional[str] = None) -> List[AlertCluster]:
        if tenant_id:
            return [c for c in self._clusters.values() if c.tenant_id == tenant_id]
        return list(self._clusters.values())

    def clear(self):
        self._clusters.clear()
        self._active_asset_clusters.clear()
