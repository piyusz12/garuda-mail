"""
Data Exposure Management Engine.
Component 29.12: Evaluates public internet exposure, cross-tenant reachability, and unmanaged dataset copies.
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
from data_security.inventory.normalization import DataAsset, ClassificationLevel


@dataclass
class ExposureAssessment:
    asset_id: str
    is_public: bool
    exposure_score: float  # 0 to 100
    exposure_level: str    # "LOW", "MEDIUM", "HIGH", "CRITICAL"
    risk_factors: List[str]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "asset_id": self.asset_id,
            "is_public": self.is_public,
            "exposure_score": self.exposure_score,
            "exposure_level": self.exposure_level,
            "risk_factors": self.risk_factors,
        }


class DataExposureAnalyzer:
    """Calculates data exposure risks across networks and cloud stores."""

    def evaluate_exposure(self, asset: DataAsset, effective_identities_count: int = 1) -> ExposureAssessment:
        factors = []
        score = 10.0

        if asset.is_publicly_exposed:
            score += 50.0
            factors.append("Direct public internet accessibility enabled")

        if asset.classification == ClassificationLevel.RESTRICTED:
            score += 25.0
            factors.append("Contains RESTRICTED sensitivity records")
        elif asset.classification == ClassificationLevel.SENSITIVE:
            score += 15.0
            factors.append("Contains SENSITIVE contact or personal data")

        if effective_identities_count > 10:
            score += 15.0
            factors.append(f"Broad access footprint ({effective_identities_count} reachable entities)")

        score = min(100.0, score)

        if score >= 75.0:
            level = "CRITICAL"
        elif score >= 50.0:
            level = "HIGH"
        elif score >= 25.0:
            level = "MEDIUM"
        else:
            level = "LOW"

        return ExposureAssessment(
            asset_id=asset.data_asset_id,
            is_public=asset.is_publicly_exposed,
            exposure_score=score,
            exposure_level=level,
            risk_factors=factors,
        )
