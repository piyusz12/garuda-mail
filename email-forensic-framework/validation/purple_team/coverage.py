"""
Three-Level Coverage Model & Technique-Asset Coverage Matrix.
Measures Visibility, Detection, and Response across assets and techniques.
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any


@dataclass
class TechniqueCoverageStatus:
    technique_id: str
    asset_id: str
    visibility: bool
    detection: bool
    response: bool

    @property
    def level(self) -> str:
        if self.visibility and self.detection and self.response:
            return "FULL"
        elif self.visibility and self.detection:
            return "DETECTED_NO_RESPONSE"
        elif self.visibility:
            return "VISIBLE_NO_DETECTION"
        else:
            return "BLIND"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "technique_id": self.technique_id,
            "asset_id": self.asset_id,
            "visibility": self.visibility,
            "detection": self.detection,
            "response": self.response,
            "level": self.level,
        }


class CoverageMatrix:
    """Technique-by-Asset coverage matrix & heatmap."""

    def __init__(self):
        # Key: (technique_id, asset_id) -> TechniqueCoverageStatus
        self._matrix: Dict[tuple, TechniqueCoverageStatus] = {}

    def record(self, technique_id: str, asset_id: str, visibility: bool, detection: bool, response: bool) -> None:
        self._matrix[(technique_id, asset_id)] = TechniqueCoverageStatus(
            technique_id=technique_id,
            asset_id=asset_id,
            visibility=visibility,
            detection=detection,
            response=response,
        )

    def get_status(self, technique_id: str, asset_id: str) -> Optional[TechniqueCoverageStatus]:
        return self._matrix.get((technique_id, asset_id))

    def get_summary(self) -> Dict[str, Any]:
        total_cells = len(self._matrix)
        if total_cells == 0:
            return {
                "total_evaluations": 0,
                "visibility_coverage_pct": 0.0,
                "detection_coverage_pct": 0.0,
                "response_coverage_pct": 0.0,
                "full_coverage_pct": 0.0,
                "matrix": {},
            }

        vis_count = sum(1 for s in self._matrix.values() if s.visibility)
        det_count = sum(1 for s in self._matrix.values() if s.detection)
        resp_count = sum(1 for s in self._matrix.values() if s.response)
        full_count = sum(1 for s in self._matrix.values() if s.level == "FULL")

        matrix_repr = {}
        for (tech, asset), status in self._matrix.items():
            if tech not in matrix_repr:
                matrix_repr[tech] = {}
            matrix_repr[tech][asset] = status.to_dict()

        return {
            "total_evaluations": total_cells,
            "visibility_coverage_pct": round((vis_count / total_cells) * 100, 1),
            "detection_coverage_pct": round((det_count / total_cells) * 100, 1),
            "response_coverage_pct": round((resp_count / total_cells) * 100, 1),
            "full_coverage_pct": round((full_count / total_cells) * 100, 1),
            "matrix": matrix_repr,
        }
