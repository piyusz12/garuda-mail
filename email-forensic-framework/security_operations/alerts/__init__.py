"""
Phase 25 — Alerts Package
Alert intake, deduplication, correlation, and clustering.
"""

from .ingest import Alert, AlertIngestEngine
from .dedup import AlertDeduplicator
from .clustering import AlertCluster, ClusterManager
from .correlation import AlertCorrelator

__all__ = [
    "Alert",
    "AlertIngestEngine",
    "AlertDeduplicator",
    "AlertCluster",
    "ClusterManager",
    "AlertCorrelator",
]
