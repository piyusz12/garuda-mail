"""
Phase 23 - Detection Scoring, Fusion, and Confidence Decomposition.
Combines deterministic rules, ML anomalies, graph context, and counter-evidence.
"""
from typing import Dict, Any, Tuple
from .models import SeverityDimensions

class DetectionScorer:
    """Calculates multi-dimensional severity and confidence metrics."""

    @staticmethod
    def calculate_severity(dimensions: SeverityDimensions) -> Tuple[float, str]:
        score = dimensions.calculate_score()
        return score, dimensions.to_qualitative()

    @staticmethod
    def decompose_confidence(
        historical_support: float = 0.5,
        behavioral_support: float = 0.5,
        graph_support: float = 0.5,
        intelligence_support: float = 0.5,
        counter_evidence: float = 0.0
    ) -> Dict[str, float]:
        """
        Decomposes confidence into distinct transparent components.
        Counter-evidence actively dampens the gross confidence to prevent confirmation bias.
        """
        historical_support = max(0.0, min(1.0, historical_support))
        behavioral_support = max(0.0, min(1.0, behavioral_support))
        graph_support = max(0.0, min(1.0, graph_support))
        intelligence_support = max(0.0, min(1.0, intelligence_support))
        counter_evidence = max(0.0, min(1.0, counter_evidence))

        # Gross confidence from positive evidence
        gross = (
            0.30 * historical_support +
            0.30 * behavioral_support +
            0.20 * graph_support +
            0.20 * intelligence_support
        )
        # Net confidence dampened by counter-evidence
        net = max(0.05, gross * (1.0 - 0.75 * counter_evidence))

        return {
            "historical_support": round(historical_support, 3),
            "behavioral_support": round(behavioral_support, 3),
            "graph_support": round(graph_support, 3),
            "intelligence_support": round(intelligence_support, 3),
            "counter_evidence": round(counter_evidence, 3),
            "net_confidence": round(net, 3)
        }

    @staticmethod
    def fuse_models(
        rule_confidence: float,
        anomaly_score: float,
        historical_similarity: float,
        graph_context_score: float
    ) -> Dict[str, Any]:
        """
        Preserves individual model/rule components rather than blindly flattening.
        Returns explicit decomposed fusion.
        """
        fused_score = (
            0.35 * rule_confidence +
            0.25 * anomaly_score +
            0.25 * historical_similarity +
            0.15 * graph_context_score
        )
        return {
            "components": {
                "rule_confidence": round(rule_confidence, 3),
                "anomaly_score": round(anomaly_score, 3),
                "historical_similarity": round(historical_similarity, 3),
                "graph_context_score": round(graph_context_score, 3),
            },
            "fused_risk": round(fused_score, 3)
        }
