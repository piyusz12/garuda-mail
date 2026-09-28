"""
Validation Gap Lifecycle & SLA Management.
Ensures every failed defensive validation is tracked, assigned, remediated, and re-tested.
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
from enum import Enum
import time
import uuid


class GapType(str, Enum):
    VISIBILITY_GAP = "VISIBILITY_GAP"
    DETECTION_GAP = "DETECTION_GAP"
    RESPONSE_GAP = "RESPONSE_GAP"
    VERIFICATION_GAP = "VERIFICATION_GAP"
    RECOVERY_GAP = "RECOVERY_GAP"


class GapSeverity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class GapStatus(str, Enum):
    NEW = "NEW"
    TRIAGED = "TRIAGED"
    ASSIGNED = "ASSIGNED"
    REMEDIATION = "REMEDIATION"
    READY_FOR_RETEST = "READY_FOR_RETEST"
    RETEST_PASSED = "RETEST_PASSED"
    RETEST_FAILED = "RETEST_FAILED"
    CLOSED = "CLOSED"
    REOPENED = "REOPENED"


@dataclass
class ValidationGap:
    gap_id: str
    gap_type: GapType
    technique_id: str
    target_asset: str
    scenario_id: str
    run_id: str
    severity: GapSeverity
    title: str
    description: str
    root_cause_details: Optional[str] = None
    owner_team: str = "detection_engineering"  # sensor_engineering, detection_engineering, soc_automation
    owner_individual: Optional[str] = None
    status: GapStatus = GapStatus.NEW
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)
    retest_run_id: Optional[str] = None
    remediation_notes: Optional[str] = None
    sla_hours: int = 72

    def to_dict(self) -> Dict[str, Any]:
        return {
            "gap_id": self.gap_id,
            "gap_type": self.gap_type.value if isinstance(self.gap_type, GapType) else self.gap_type,
            "technique_id": self.technique_id,
            "target_asset": self.target_asset,
            "scenario_id": self.scenario_id,
            "run_id": self.run_id,
            "severity": self.severity.value if isinstance(self.severity, GapSeverity) else self.severity,
            "title": self.title,
            "description": self.description,
            "root_cause_details": self.root_cause_details,
            "owner_team": self.owner_team,
            "owner_individual": self.owner_individual,
            "status": self.status.value if isinstance(self.status, GapStatus) else self.status,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "retest_run_id": self.retest_run_id,
            "remediation_notes": self.remediation_notes,
            "sla_hours": self.sla_hours,
        }


class GapManager:
    """Manages the lifecycle of defensive validation gaps."""

    def __init__(self):
        self._gaps: Dict[str, ValidationGap] = {}

    def create_gap(
        self,
        gap_type: GapType,
        technique_id: str,
        target_asset: str,
        scenario_id: str,
        run_id: str,
        severity: GapSeverity,
        title: str,
        description: str,
        root_cause_details: Optional[str] = None,
    ) -> ValidationGap:
        gap_id = f"GAP-{uuid.uuid4().hex[:6].upper()}"

        # Assign default team by gap type
        if gap_type == GapType.VISIBILITY_GAP:
            owner_team = "sensor_engineering"
        elif gap_type == GapType.DETECTION_GAP:
            owner_team = "detection_engineering"
        elif gap_type == GapType.RESPONSE_GAP:
            owner_team = "soc_automation"
        else:
            owner_team = "security_operations"

        gap = ValidationGap(
            gap_id=gap_id,
            gap_type=gap_type,
            technique_id=technique_id,
            target_asset=target_asset,
            scenario_id=scenario_id,
            run_id=run_id,
            severity=severity,
            title=title,
            description=description,
            root_cause_details=root_cause_details,
            owner_team=owner_team,
        )
        self._gaps[gap_id] = gap
        return gap

    def get_gap(self, gap_id: str) -> Optional[ValidationGap]:
        return self._gaps.get(gap_id)

    def list_gaps(self, status: Optional[GapStatus] = None, severity: Optional[GapSeverity] = None) -> List[ValidationGap]:
        gaps = list(self._gaps.values())
        if status:
            gaps = [g for g in gaps if g.status == status]
        if severity:
            gaps = [g for g in gaps if g.severity == severity]
        return gaps

    def assign_gap(self, gap_id: str, owner_team: str, owner_individual: Optional[str] = None) -> ValidationGap:
        gap = self._gaps.get(gap_id)
        if not gap:
            raise ValueError(f"Gap {gap_id} not found.")
        gap.owner_team = owner_team
        gap.owner_individual = owner_individual
        gap.status = GapStatus.ASSIGNED
        gap.updated_at = time.time()
        return gap

    def mark_ready_for_retest(self, gap_id: str, remediation_notes: str) -> ValidationGap:
        gap = self._gaps.get(gap_id)
        if not gap:
            raise ValueError(f"Gap {gap_id} not found.")
        gap.remediation_notes = remediation_notes
        gap.status = GapStatus.READY_FOR_RETEST
        gap.updated_at = time.time()
        return gap

    def close_gap_on_verified_retest(self, gap_id: str, retest_run_id: str) -> ValidationGap:
        """Closes the gap ONLY when a re-test has verified remediation."""
        gap = self._gaps.get(gap_id)
        if not gap:
            raise ValueError(f"Gap {gap_id} not found.")
        gap.retest_run_id = retest_run_id
        gap.status = GapStatus.CLOSED
        gap.updated_at = time.time()
        return gap

    def reopen_gap_on_failed_retest(self, gap_id: str, retest_run_id: str, reason: str) -> ValidationGap:
        gap = self._gaps.get(gap_id)
        if not gap:
            raise ValueError(f"Gap {gap_id} not found.")
        gap.retest_run_id = retest_run_id
        gap.status = GapStatus.REOPENED
        gap.description += f" [Re-test {retest_run_id} failed: {reason}]"
        gap.updated_at = time.time()
        return gap
