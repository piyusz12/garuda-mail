"""
Phase 25 — Alert Correlation Engine
Correlates incoming alerts across dimensions:
same asset, complementary event chains (cert change + new JA4 + TLS downgrade + unusual destination),
and evaluates whether an alert cluster warrants automated escalation to a Case.
"""

from typing import Dict, List, Optional, Any
from .ingest import Alert
from .dedup import AlertDeduplicator
from .clustering import AlertCluster, ClusterManager


class AlertCorrelator:
    """Orchestrates ingestion, deduplication, and multi-dimensional correlation."""

    def __init__(self, dedup_window_seconds: int = 300, cluster_window_seconds: int = 600):
        self.deduplicator = AlertDeduplicator(time_window_seconds=dedup_window_seconds)
        self.cluster_manager = ClusterManager(cluster_window_seconds=cluster_window_seconds)

    def process_alert(self, alert: Alert) -> Dict[str, Any]:
        """
        Deduplicates alert, assigns to cluster, and evaluates composite patterns.
        Returns:
            {
                "alert": Alert,
                "is_duplicate": bool,
                "hit_count": int,
                "cluster": AlertCluster,
                "is_incident_candidate": bool,
                "correlation_summary": str
            }
        """
        is_dup, rep_alert, count = self.deduplicator.process(alert)
        cluster = self.cluster_manager.get_or_create_cluster(rep_alert)

        # Build correlation summary description
        events_str = ", ".join(sorted(cluster.event_types))
        summary = (
            f"Asset {cluster.asset_id} involved in {len(cluster.alerts)} alerts "
            f"spanning events [{events_str}] with aggregate severity {cluster.aggregate_severity}"
        )

        return {
            "alert": rep_alert,
            "is_duplicate": is_dup,
            "hit_count": count,
            "cluster": cluster,
            "is_incident_candidate": cluster.is_incident_candidate,
            "correlation_summary": summary,
        }

    def get_cluster(self, cluster_id: str) -> Optional[AlertCluster]:
        return self.cluster_manager.get_cluster(cluster_id)

    def list_clusters(self, tenant_id: Optional[str] = None) -> List[AlertCluster]:
        return self.cluster_manager.list_clusters(tenant_id=tenant_id)
