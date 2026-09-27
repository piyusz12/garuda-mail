"""
Phase 25 — Investigation Package
Automated investigation tasks, context management, and DAG orchestration.
"""

from .context import AssetContext, MaintenanceWindow, MaintenanceWindowChecker
from .tasks import (
    InvestigationTask,
    ResolveAssetTask,
    GetCertificateHistoryTask,
    GetTLSHistoryTask,
    GetJA4HistoryTask,
    GetRecentChangesTask,
    GetHistoricalCasesTask,
    GetThreatIntelTask,
    GetDependenciesTask,
)
from .dag import InvestigationDAG

__all__ = [
    "AssetContext",
    "MaintenanceWindow",
    "MaintenanceWindowChecker",
    "InvestigationTask",
    "ResolveAssetTask",
    "GetCertificateHistoryTask",
    "GetTLSHistoryTask",
    "GetJA4HistoryTask",
    "GetRecentChangesTask",
    "GetHistoricalCasesTask",
    "GetThreatIntelTask",
    "GetDependenciesTask",
    "InvestigationDAG",
]
