"""
Data Behavioral Risk and Insider Signal Engine.
Component 29.34: Evidence-based behavioral anomaly scoring without personal intent inference.
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
import time


@dataclass
class BehaviorRiskSignal:
    signal_id: str
    identity_id: str
    workload_id: str
    anomaly_category: str
    description: str
    severity: str
    evidence_metrics: Dict[str, Any]
    detected_at: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "signal_id": self.signal_id,
            "identity_id": self.identity_id,
            "workload_id": self.workload_id,
            "anomaly_category": self.anomaly_category,
            "description": self.description,
            "severity": self.severity,
            "evidence_metrics": self.evidence_metrics,
            "detected_at": self.detected_at,
        }


class DataBehaviorRiskAnalyzer:
    """Analyzes observable data access patterns and export behaviors for risk signals."""

    def evaluate_access_behavior(
        self,
        identity_id: str,
        workload_id: str,
        records_read: int,
        baseline_records: int,
        is_new_dataset: bool = False,
    ) -> List[BehaviorRiskSignal]:
        signals: List[BehaviorRiskSignal] = []

        if is_new_dataset:
            signals.append(
                BehaviorRiskSignal(
                    signal_id=f"BSIG-NEW-{int(time.time())}",
                    identity_id=identity_id,
                    workload_id=workload_id,
                    anomaly_category="FIRST_SEEN_DATASET_ACCESS",
                    description=f"Identity {identity_id} accessed dataset for the first time without prior baseline.",
                    severity="MEDIUM",
                    evidence_metrics={"is_new_dataset": True},
                )
            )

        if records_read > (baseline_records * 5):
            signals.append(
                BehaviorRiskSignal(
                    signal_id=f"BSIG-VOL-{int(time.time())}",
                    identity_id=identity_id,
                    workload_id=workload_id,
                    anomaly_category="UNUSUAL_ACCESS_VOLUME",
                    description=f"Observed query volume of {records_read:,} records exceeds historical baseline ({baseline_records:,}) by {records_read/max(1, baseline_records):.1f}x.",
                    severity="HIGH",
                    evidence_metrics={"records_read": records_read, "baseline": baseline_records},
                )
            )

        return signals
