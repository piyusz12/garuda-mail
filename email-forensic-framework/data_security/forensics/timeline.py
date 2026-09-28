"""
Data Incident Chronological Timeline Generator.
Components 29.36 & 29.59: Correlates data access, volume surges, DLP blocks, and verification events.
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
import time


@dataclass
class DataTimelineEntry:
    time_str: str
    epoch_timestamp: float
    event_category: str  # ACCESS, ANOMALY, DLP_TRIGGER, RESPONSE, VERIFICATION
    summary: str
    actor: str
    evidence_ref: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "time_str": self.time_str,
            "epoch_timestamp": self.epoch_timestamp,
            "event_category": self.event_category,
            "summary": self.summary,
            "actor": self.actor,
            "evidence_ref": self.evidence_ref,
        }


class DataTimelineBuilder:
    """Constructs chronological forensic timelines for data incidents and exfiltration attempts."""

    @classmethod
    def build_incident_timeline(
        cls,
        asset_id: str = "DATA-8821",
        workload_id: str = "WORKLOAD-991",
        identity_id: str = "SERVICE-91",
    ) -> List[DataTimelineEntry]:
        now = time.time()
        return [
            DataTimelineEntry("09:00:00", now - 1800, "ACCESS", f"Normal baseline queries executed on {asset_id}", "DBA-ADMIN-01", "LOG-900"),
            DataTimelineEntry("09:15:10", now - 890, "ACCESS", f"New workload {workload_id} initiated connection under identity {identity_id}", identity_id, "IAM-BIND-91"),
            DataTimelineEntry("09:16:30", now - 810, "ACCESS", f"Workload accessed RESTRICTED table {asset_id} for the first time", workload_id, "DB-QUERY-101"),
            DataTimelineEntry("09:18:00", now - 720, "ANOMALY", "Query volume spiked: 900,000 records extracted (historical: 10,000/day)", workload_id, "DANOM-VOL-01"),
            DataTimelineEntry("09:19:15", now - 645, "NETWORK_FLOW", "Outbound socket connection opened to external.example (198.51.100.42:4444)", workload_id, "NET-FLOW-991"),
            DataTimelineEntry("09:20:05", now - 595, "DLP_TRIGGER", "Policy DLP-01 triggered: Restricted data external egress prohibited", "DLP-Enforcement-Engine", "DLP-ALERT-01"),
            DataTimelineEntry("09:22:00", now - 480, "RESPONSE", "Autonomous Security Ops opened CASE-5001 and flagged quarantine requirement", "SOC-Engine", "CASE-5001"),
            DataTimelineEntry("09:25:00", now - 300, "RESPONSE", "External transfer severed; egress route blocked", "DLP-Enforcer", "BLOCK-ACTION-11"),
            DataTimelineEntry("09:30:00", now, "VERIFICATION", "Verification engine confirmed external destination unreachable; data leak halted", "Verification-Engine", "VERIFY-PASS"),
        ]
