"""
Validation Metrics & Multi-Dimensional Security Scorecard.
Maintains separate dimensions for visibility, detection, triage, investigation, response, verification, and recovery.
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any


@dataclass
class ValidationScorecard:
    """Multi-dimensional security scorecard preventing lossy single-number flattening."""
    visibility_pct: float
    detection_pct: float
    triage_pct: float
    investigation_pct: float
    response_pct: float
    verification_pct: float
    recovery_pct: float
    open_validation_gaps_count: int = 0
    critical_gaps_count: int = 0
    total_scenarios_evaluated: int = 0
    passed_scenarios: int = 0
    partial_scenarios: int = 0
    failed_scenarios: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "visibility_pct": round(self.visibility_pct, 1),
            "detection_pct": round(self.detection_pct, 1),
            "triage_pct": round(self.triage_pct, 1),
            "investigation_pct": round(self.investigation_pct, 1),
            "response_pct": round(self.response_pct, 1),
            "verification_pct": round(self.verification_pct, 1),
            "recovery_pct": round(self.recovery_pct, 1),
            "open_validation_gaps_count": self.open_validation_gaps_count,
            "critical_gaps_count": self.critical_gaps_count,
            "total_scenarios_evaluated": self.total_scenarios_evaluated,
            "passed_scenarios": self.passed_scenarios,
            "partial_scenarios": self.partial_scenarios,
            "failed_scenarios": self.failed_scenarios,
        }


@dataclass
class LatencyMetrics:
    """Timeline metrics for detection and response speed."""
    ttv_avg_sec: float  # Time to Visibility
    ttd_avg_sec: float  # Time to Detection
    tta_avg_sec: float  # Time to Acknowledge
    tti_avg_sec: float  # Time to Investigate
    ttr_avg_sec: float  # Time to Respond
    ttvr_avg_sec: float # Time to Verify

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ttv_avg_sec": round(self.ttv_avg_sec, 2),
            "ttd_avg_sec": round(self.ttd_avg_sec, 2),
            "tta_avg_sec": round(self.tta_avg_sec, 2),
            "tti_avg_sec": round(self.tti_avg_sec, 2),
            "ttr_avg_sec": round(self.ttr_avg_sec, 2),
            "ttvr_avg_sec": round(self.ttvr_avg_sec, 2),
        }
