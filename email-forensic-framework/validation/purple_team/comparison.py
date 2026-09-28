"""
Purple Team Attack-Defense Comparator.
Directly contrasts Red (Emulation) behavior against Blue (Detection & SOAR) evidence.
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any


@dataclass
class ComparisonDelta:
    technique_id: str
    target_asset: str
    emitted_behavior: Dict[str, Any]
    telemetry_observed: bool
    detection_observed: bool
    response_observed: bool
    verification_observed: bool
    is_fully_covered: bool
    gap_summary: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "technique_id": self.technique_id,
            "target_asset": self.target_asset,
            "telemetry_observed": self.telemetry_observed,
            "detection_observed": self.detection_observed,
            "response_observed": self.response_observed,
            "verification_observed": self.verification_observed,
            "is_fully_covered": self.is_fully_covered,
            "gap_summary": self.gap_summary,
        }


class PurpleTeamComparator:
    """Compares attack emissions against defensive detection and response artifacts."""

    @staticmethod
    def compare_step(
        technique_id: str,
        target_asset: str,
        emitted_behavior: Dict[str, Any],
        observed_telemetry: List[str],
        fired_detections: List[str],
        case_created: bool,
        action_executed: bool,
        verification_passed: bool,
    ) -> ComparisonDelta:
        telemetry_ok = len(observed_telemetry) > 0
        detection_ok = len(fired_detections) > 0
        response_ok = case_created and action_executed
        verification_ok = verification_passed

        gaps = []
        if not telemetry_ok:
            gaps.append("Visibility Gap")
        if not detection_ok:
            gaps.append("Detection Gap")
        if not response_ok:
            gaps.append("Response Gap")
        if not verification_ok:
            gaps.append("Verification Gap")

        is_covered = len(gaps) == 0

        return ComparisonDelta(
            technique_id=technique_id,
            target_asset=target_asset,
            emitted_behavior=emitted_behavior,
            telemetry_observed=telemetry_ok,
            detection_observed=detection_ok,
            response_observed=response_ok,
            verification_observed=verification_ok,
            is_fully_covered=is_covered,
            gap_summary=", ".join(gaps) if gaps else "Fully Covered",
        )
