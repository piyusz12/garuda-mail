"""
Phase 25 — Dynamic Risk Scoring & Uncertainty Modeling
Computes transparent multi-factor risk scores and tracks orthogonal confidence dimensions.
"""

from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field, asdict


@dataclass
class UncertaintyModel:
    detection_confidence: float = 0.95
    context_confidence: float = 0.90
    attribution_confidence: float = 0.70
    response_confidence: float = 0.80
    verification_confidence: float = 0.95

    def is_uncertain(self, threshold: float = 0.65) -> Tuple[bool, List[str]]:
        low_dims = []
        for dim, val in asdict(self).items():
            if val < threshold:
                low_dims.append(f"{dim} ({round(val, 2)})")
        return len(low_dims) > 0, low_dims

    def to_dict(self) -> Dict[str, float]:
        return asdict(self)


class DynamicRiskScorer:
    """Computes transparent, weighted dynamic risk scores across operational dimensions."""

    CRITICALITY_VALUES = {
        "CRITICAL": 1.0,
        "HIGH": 0.85,
        "MEDIUM": 0.50,
        "LOW": 0.20,
    }

    SEVERITY_VALUES = {
        "CRITICAL": 1.0,
        "HIGH": 0.80,
        "MEDIUM": 0.50,
        "LOW": 0.25,
        "INFO": 0.10,
    }

    def __init__(self):
        # Weights must sum to 1.0
        self.weights = {
            "asset_criticality": 0.25,
            "severity": 0.20,
            "historical_recurrence": 0.15,
            "confidence": 0.15,
            "threat_intelligence": 0.10,
            "blast_radius": 0.10,
            "policy_sensitivity": 0.05,
        }

    def score(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """Calculates dynamic risk score (0-100) and returns detailed factor breakdown."""
        # 1. Asset criticality
        crit = str(context.get("criticality", "MEDIUM")).upper()
        v_crit = self.CRITICALITY_VALUES.get(crit, 0.50)

        # 2. Severity
        sev = str(context.get("severity", context.get("aggregate_severity", "MEDIUM"))).upper()
        v_sev = self.SEVERITY_VALUES.get(sev, 0.50)

        # 3. Recurrence
        has_recurrence = bool(context.get("has_historical_recurrence", False))
        recurrence_count = int(context.get("recurrence_count_90d", 0))
        v_recurrence = min(1.0, 0.5 + 0.2 * recurrence_count) if has_recurrence else 0.10

        # 4. Confidence
        v_conf = float(context.get("confidence", 0.85))

        # 5. Threat Intel
        threat_score = float(context.get("threat_score", 10))
        v_threat = min(1.0, threat_score / 100.0)

        # 6. Blast Radius
        blast_ratio = float(context.get("blast_radius_ratio", 0.10))
        v_blast = min(1.0, blast_ratio * 2.0)

        # 7. Policy Sensitivity (e.g. unapproved change ticket or unexpected change)
        in_maint = bool(context.get("in_maintenance_window", False))
        v_policy = 0.20 if in_maint else 0.80  # Much higher sensitivity if outside maintenance

        factor_values = {
            "asset_criticality": v_crit,
            "severity": v_sev,
            "historical_recurrence": v_recurrence,
            "confidence": v_conf,
            "threat_intelligence": v_threat,
            "blast_radius": v_blast,
            "policy_sensitivity": v_policy,
        }

        total_score_norm = sum(self.weights[k] * factor_values[k] for k in self.weights)
        final_risk_score = round(total_score_norm * 100.0, 1)

        factors = [
            {
                "factor": k,
                "weight": self.weights[k],
                "value": round(factor_values[k], 2),
                "contribution": round(self.weights[k] * factor_values[k] * 100.0, 1),
            }
            for k in self.weights
        ]

        # Uncertainty modeling
        uncertainty = UncertaintyModel(
            detection_confidence=v_conf,
            context_confidence=0.90 if context.get("hostname") else 0.60,
            attribution_confidence=0.85 if v_threat > 0.5 else 0.65,
            response_confidence=0.85 if blast_ratio < 0.3 else 0.60,
            verification_confidence=0.95,
        )

        return {
            "risk_score": final_risk_score,
            "factors": factors,
            "uncertainty_model": uncertainty.to_dict(),
        }
