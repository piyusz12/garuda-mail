"""
Data Movement Anomaly and Exfiltration Detector.
Components 29.32 & 29.33: Identifies volume surges, new destination flows, and unauthorized reader identities.
"""
from dataclasses import dataclass, field
from typing import Dict, List, Set, Optional, Any
from enum import Enum
import uuid
import time

from data_security.flows.monitor import DataMovementEvent
from data_security.inventory.normalization import ClassificationLevel


class DataAnomalyType(str, Enum):
    VOLUME_ANOMALY = "VOLUME_ANOMALY"
    READER_ANOMALY = "READER_ANOMALY"
    DESTINATION_ANOMALY = "DESTINATION_ANOMALY"
    CROSS_BORDER_EXFILTRATION = "CROSS_BORDER_EXFILTRATION"


@dataclass
class DataMovementAnomalyFinding:
    anomaly_id: str
    anomaly_type: DataAnomalyType
    asset_id: str
    severity: str
    title: str
    description: str
    evidence: Dict[str, Any]
    detected_at: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "anomaly_id": self.anomaly_id,
            "anomaly_type": self.anomaly_type.value,
            "asset_id": self.asset_id,
            "severity": self.severity,
            "title": self.title,
            "description": self.description,
            "evidence": self.evidence,
            "detected_at": self.detected_at,
        }


class DataMovementAnomalyDetector:
    """Detects exfiltration, sudden bulk exports, and anomalous reader workloads."""

    def __init__(self):
        # asset_id -> baseline expected daily records
        self._volume_baselines: Dict[str, int] = {"DATA-8821": 15000}
        # asset_id -> set of approved reader identities
        self._approved_readers: Dict[str, Set[str]] = {"DATA-8821": {"SERVICE-91", "DBA-ADMIN-01"}}
        # approved internal destinations
        self._approved_destinations: Set[str] = {"internal.vault.garuda", "10.0.1.10", "DATA-WH-CUSTOMERS"}

    def inspect_flow_event(self, event: DataMovementEvent) -> List[DataMovementAnomalyFinding]:
        findings: List[DataMovementAnomalyFinding] = []

        # 1. Volume Surge Anomaly Check (e.g. > 10x normal baseline)
        baseline_vol = self._volume_baselines.get(event.source_asset_id, 10000)
        if event.record_count > (baseline_vol * 10):
            findings.append(
                DataMovementAnomalyFinding(
                    anomaly_id=f"DANOM-{uuid.uuid4().hex[:8].upper()}",
                    anomaly_type=DataAnomalyType.VOLUME_ANOMALY,
                    asset_id=event.source_asset_id,
                    severity="CRITICAL" if event.classification == ClassificationLevel.RESTRICTED else "HIGH",
                    title=f"Bulk Data Extraction Surge on {event.source_asset_id}",
                    description=f"Observed {event.record_count:,} records transferred, exceeding baseline ({baseline_vol:,} records) by {event.record_count/baseline_vol:.1f}x.",
                    evidence=event.to_dict(),
                )
            )

        # 2. Reader Workload / Identity Anomaly
        approved_readers = self._approved_readers.get(event.source_asset_id)
        if approved_readers and event.identity_id not in approved_readers:
            findings.append(
                DataMovementAnomalyFinding(
                    anomaly_id=f"DANOM-{uuid.uuid4().hex[:8].upper()}",
                    anomaly_type=DataAnomalyType.READER_ANOMALY,
                    asset_id=event.source_asset_id,
                    severity="HIGH",
                    title=f"Unbaselined Reader Identity accessing {event.source_asset_id}",
                    description=f"Identity {event.identity_id} (Workload {event.workload_id}) has no historical baseline accessing this sensitive dataset.",
                    evidence=event.to_dict(),
                )
            )

        # 3. Destination Anomaly / External Exfiltration
        if event.is_external_destination or (event.destination_id not in self._approved_destinations and "external" in event.destination_id.lower()):
            findings.append(
                DataMovementAnomalyFinding(
                    anomaly_id=f"DANOM-{uuid.uuid4().hex[:8].upper()}",
                    anomaly_type=DataAnomalyType.DESTINATION_ANOMALY,
                    asset_id=event.source_asset_id,
                    severity="CRITICAL",
                    title=f"Potential Data Exfiltration to External Destination {event.destination_id}",
                    description=f"Sensitive dataset {event.source_asset_id} routed to unapproved external destination {event.destination_id}.",
                    evidence=event.to_dict(),
                )
            )

        return findings
