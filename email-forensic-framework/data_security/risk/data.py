"""
Multi-Dimensional Data Risk Scoring Engine.
Components 29.30, 29.31, 29.51 & 29.76: Calculates Cyber Risk, Privacy Risk, and Operational Risk separately.
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
from data_security.inventory.normalization import DataAsset, ClassificationLevel


@dataclass
class DataRiskProfile:
    asset_id: str
    composite_risk_rating: str  # "LOW", "MEDIUM", "HIGH", "CRITICAL"
    cyber_risk_score: float     # 0 to 100
    privacy_risk_score: float   # 0 to 100
    operational_risk_score: float  # 0 to 100
    risk_factors: List[str]
    breakdown: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "asset_id": self.asset_id,
            "composite_risk_rating": self.composite_risk_rating,
            "cyber_risk_score": round(self.cyber_risk_score, 1),
            "privacy_risk_score": round(self.privacy_risk_score, 1),
            "operational_risk_score": round(self.operational_risk_score, 1),
            "risk_factors": self.risk_factors,
            "breakdown": self.breakdown,
        }


class DataRiskEngine:
    """Calculates granular risk profiles separating privacy dimensions from pure cyber vulnerabilities."""

    def calculate_asset_risk(
        self,
        asset: DataAsset,
        effective_identities_count: int = 2,
        has_anomalies: bool = False,
    ) -> DataRiskProfile:
        factors: List[str] = []

        # 1. Base Sensitivity
        is_restricted = asset.classification == ClassificationLevel.RESTRICTED
        is_sensitive = asset.classification == ClassificationLevel.SENSITIVE

        base_cyber = 20.0
        base_privacy = 25.0
        base_ops = 15.0

        if is_restricted:
            base_cyber += 30.0
            base_privacy += 45.0
            factors.append("RESTRICTED classification requires strict confidentiality")
        elif is_sensitive:
            base_cyber += 15.0
            base_privacy += 30.0
            factors.append("SENSITIVE data involves PII or contact attributes")

        # 2. Exposure & Reachability
        if asset.is_publicly_exposed:
            base_cyber += 35.0
            base_privacy += 20.0
            factors.append("Public internet exposure enabled on data store")

        if effective_identities_count > 5:
            base_cyber += 15.0
            base_privacy += 15.0
            factors.append(f"Excessive access breadth ({effective_identities_count} entities)")

        # 3. Encryption Coverage
        if not asset.encryption_at_rest:
            base_cyber += 25.0
            factors.append("Missing encryption at rest")

        # 4. Retention & Anomalies
        if has_anomalies:
            base_cyber += 20.0
            base_ops += 25.0
            factors.append("Active behavioral data movement anomaly detected")

        cyber_score = min(100.0, base_cyber)
        privacy_score = min(100.0, base_privacy)
        ops_score = min(100.0, base_ops)

        # Composite rating driven by max dimension
        peak_score = max(cyber_score, privacy_score, ops_score)
        if peak_score >= 80.0:
            rating = "CRITICAL"
        elif peak_score >= 60.0:
            rating = "HIGH"
        elif peak_score >= 35.0:
            rating = "MEDIUM"
        else:
            rating = "LOW"

        return DataRiskProfile(
            asset_id=asset.data_asset_id,
            composite_risk_rating=rating,
            cyber_risk_score=cyber_score,
            privacy_risk_score=privacy_score,
            operational_risk_score=ops_score,
            risk_factors=factors,
            breakdown={
                "sensitivity": asset.classification.value,
                "exposure": "PUBLIC" if asset.is_publicly_exposed else "PRIVATE",
                "access_breadth": effective_identities_count,
                "encryption": "COMPLIANT" if asset.encryption_at_rest else "MISSING",
            },
        )
