"""
Phase 25 — Analyst Outcome Labeling
Captures true positive, false positive, benign, and duplicate labels from analysts.
"""

from enum import Enum
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
import time
import uuid


class AnalystLabel(str, Enum):
    TP = "TP"              # True Positive (confirmed malicious/unauthorized)
    FP = "FP"              # False Positive (erroneous detection)
    BENIGN = "BENIGN"      # Legitimate anomalous activity (e.g. approved migration)
    DUPLICATE = "DUPLICATE"
    UNKNOWN = "UNKNOWN"


@dataclass
class AnalystFeedbackRecord:
    record_id: str
    detection_id: str
    case_id: str
    label: AnalystLabel
    analyst_id: str
    reason: str
    timestamp: float = field(default_factory=time.time)
    metadata: Dict[str, Any] = field(default_factory=dict)


class FeedbackLabelStore:
    """Stores analyst verdict labels for closed-loop detection engineering."""

    def __init__(self):
        self._labels: List[AnalystFeedbackRecord] = []

    def record_label(
        self,
        detection_id: str,
        case_id: str,
        label: AnalystLabel,
        analyst_id: str,
        reason: str = "",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> AnalystFeedbackRecord:
        rec = AnalystFeedbackRecord(
            record_id=f"FDB-{uuid.uuid4().hex[:8].upper()}",
            detection_id=detection_id,
            case_id=case_id,
            label=label,
            analyst_id=analyst_id,
            reason=reason,
            metadata=metadata or {},
        )
        self._labels.append(rec)
        return rec

    def get_labels_for_detection(self, detection_id: str) -> List[AnalystFeedbackRecord]:
        return [l for l in self._labels if l.detection_id == detection_id]

    def list_all(self) -> List[AnalystFeedbackRecord]:
        return list(self._labels)
