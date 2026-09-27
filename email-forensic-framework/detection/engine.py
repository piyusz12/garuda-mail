"""
Phase 23 - Detection Engine.
Coordinates evaluation, health metrics, drift monitoring, explainability, and finding generation.
"""
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional, Tuple
import time
import uuid
import logging

from .models import DetectionRule, Finding, SeverityDimensions
from .evaluator import DetectionEvaluator
from .scoring import DetectionScorer
from .correlation import CorrelationEngine
from .versioning import DetectionVersioningEngine

logger = logging.getLogger("Phase23-DetectionEngine")

@dataclass
class DetectionHealthStats:
    detection_id: str
    executions: int = 0
    errors: int = 0
    matches: int = 0
    total_latency_ms: float = 0.0
    last_execution: Optional[datetime] = None
    baseline_precision: float = 0.90
    current_precision: float = 0.90
    drift_suspected: bool = False

    @property
    def avg_latency_ms(self) -> float:
        return round(self.total_latency_ms / max(1, self.executions), 2)

    @property
    def match_rate(self) -> float:
        return round(self.matches / max(1, self.executions), 4)


class DetectionEngine:
    """Core runtime engine for detection engineering and evaluation."""

    def __init__(self, versioning: Optional[DetectionVersioningEngine] = None, correlation: Optional[CorrelationEngine] = None):
        self.versioning = versioning or DetectionVersioningEngine()
        self.correlation = correlation or CorrelationEngine()
        self.health_tracker: Dict[str, DetectionHealthStats] = {}
        self.findings: Dict[str, Finding] = {}

    def register_rule(self, rule: DetectionRule) -> DetectionRule:
        stored = self.versioning.register_rule(rule)
        if stored.detection_id not in self.health_tracker:
            self.health_tracker[stored.detection_id] = DetectionHealthStats(detection_id=stored.detection_id)
        return stored

    def evaluate_event(self, event_data: Dict[str, Any], context: Optional[Dict[str, Any]] = None) -> List[Finding]:
        """Evaluates active production/canary rules against an incoming telemetry event."""
        context = context or {}
        asset_id = event_data.get("asset", event_data.get("asset_id", "UNKNOWN-ASSET"))
        generated_findings = []

        active_rules = self.versioning.list_all_active()
        for rule in active_rules:
            # Canary checks
            if rule.status == "CANARY":
                if asset_id not in rule.canary_target_assets:
                    continue
            elif rule.status != "PRODUCTION":
                # Only PRODUCTION and target CANARY execute on live telemetry
                continue

            health = self.health_tracker.setdefault(rule.detection_id, DetectionHealthStats(detection_id=rule.detection_id))
            health.executions += 1
            start_t = time.perf_counter()

            try:
                is_match, explanations = DetectionEvaluator.evaluate(
                    rule_type=rule.rule_type,
                    logic=rule.logic,
                    event_data=event_data,
                    context=context
                )
                elapsed_ms = (time.perf_counter() - start_t) * 1000.0
                health.total_latency_ms += elapsed_ms
                health.last_execution = datetime.now(timezone.utc)

                if is_match:
                    health.matches += 1
                    event_id = event_data.get("event_id", f"EVT-{uuid.uuid4().hex[:6].upper()}")
                    
                    # Deduplicate into cluster
                    is_new_cluster, cluster_id, event_count = self.correlation.cluster_and_deduplicate(
                        rule.detection_id, asset_id, event_id
                    )

                    # Scoring and decomposed confidence
                    gross_conf = rule.confidence
                    counter_evidence_factor = context.get("counter_evidence_factor", 0.0)
                    confidence_decomp = DetectionScorer.decompose_confidence(
                        historical_support=context.get("historical_support", 0.8),
                        behavioral_support=context.get("behavioral_support", 0.85),
                        graph_support=context.get("graph_support", 0.75),
                        intelligence_support=context.get("intelligence_support", 0.7),
                        counter_evidence=counter_evidence_factor
                    )
                    
                    sev_score, qual_sev = DetectionScorer.calculate_severity(rule.severity_dimensions)
                    
                    # Build explainable finding
                    full_explanation = [
                        f"Detection '{rule.name}' ({rule.detection_id} v{rule.version}) triggered.",
                        *explanations,
                        f"Severity evaluated as {qual_sev} (Score: {sev_score}).",
                        f"Confidence decomposed to Net {confidence_decomp['net_confidence']} (Counter-evidence: {confidence_decomp['counter_evidence']})."
                    ]

                    finding_id = cluster_id if not is_new_cluster else f"FINDING-{uuid.uuid4().hex[:6].upper()}"
                    finding = Finding(
                        finding_id=finding_id,
                        detection_id=rule.detection_id,
                        asset_id=asset_id,
                        timestamp=datetime.now(timezone.utc),
                        severity=qual_sev,
                        confidence=confidence_decomp["net_confidence"],
                        confidence_breakdown=confidence_decomp,
                        evidence_refs=[event_id],
                        status="NEW",
                        details={
                            "event_count": event_count,
                            "rule_name": rule.name,
                            "event_sample": event_data,
                            "context": context
                        },
                        explanation=full_explanation
                    )
                    self.findings[finding_id] = finding
                    generated_findings.append(finding)

            except Exception as e:
                health.errors += 1
                logger.error(f"Error evaluating rule {rule.detection_id}: {e}")

        return generated_findings

    def record_drift_metric(self, detection_id: str, new_precision: float):
        """Records validation precision and flags detection drift if significant drop occurs."""
        health = self.health_tracker.get(detection_id)
        if health:
            health.current_precision = new_precision
            if health.baseline_precision - new_precision > 0.10:
                health.drift_suspected = True
                logger.warning(f"[DETECTION_DRIFT] Rule {detection_id} precision dropped from {health.baseline_precision} to {new_precision}!")

    def get_health_summary(self) -> Dict[str, Any]:
        return {
            "total_rules": len(self.health_tracker),
            "healthy_rules": sum(1 for h in self.health_tracker.values() if not h.drift_suspected and h.errors == 0),
            "drift_suspected_rules": sum(1 for h in self.health_tracker.values() if h.drift_suspected),
            "failed_rules": sum(1 for h in self.health_tracker.values() if h.errors > 0),
            "rules": {rid: vars(h) for rid, h in self.health_tracker.items()}
        }
