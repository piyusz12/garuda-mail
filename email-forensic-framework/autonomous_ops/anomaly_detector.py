"""Garuda Phase 35: Module K - System Anomaly Detection.
Statistical threshold & baseline-comparing anomaly detector identifying latency spikes,
GPU memory saturation, worker desync, and authorization bursts.
"""
from typing import Dict, List, Optional, Any
import time
import uuid
import statistics

from autonomous_ops.models import AnomalyType, IncidentSeverity
from autonomous_ops.baselines import ServiceBaselineManager


class AnomalyEvent:
    def __init__(
        self,
        anomaly_id: str,
        anomaly_type: AnomalyType,
        metric_name: str,
        baseline_val: float,
        observed_val: float,
        deviation_ratio: float,
        severity: IncidentSeverity,
        recommended_action: str,
        suggested_action_type: str,
        target_resource: str,
        timestamp: Optional[float] = None,
    ):
        self.anomaly_id = anomaly_id
        self.anomaly_type = anomaly_type
        self.metric_name = metric_name
        self.baseline_val = baseline_val
        self.observed_val = observed_val
        self.deviation_ratio = deviation_ratio
        self.severity = severity
        self.recommended_action = recommended_action
        self.suggested_action_type = suggested_action_type
        self.target_resource = target_resource
        self.timestamp = timestamp if timestamp is not None else time.time()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "anomaly_id": self.anomaly_id,
            "anomaly_type": self.anomaly_type.value,
            "metric_name": self.metric_name,
            "baseline_val": round(self.baseline_val, 2),
            "observed_val": round(self.observed_val, 2),
            "deviation_ratio": round(self.deviation_ratio, 2),
            "severity": self.severity.value,
            "recommended_action": self.recommended_action,
            "suggested_action_type": self.suggested_action_type,
            "target_resource": self.target_resource,
            "timestamp": self.timestamp,
        }


class SystemAnomalyDetector:
    """Detects operational anomalies by comparing telemetry measurements against baselines and statistical thresholds."""

    def __init__(self, baseline_manager: Optional[ServiceBaselineManager] = None):
        self.baseline_manager = baseline_manager or ServiceBaselineManager()
        self._detected_anomalies: List[AnomalyEvent] = []

    def check_inference_latency(self, observed_latency_ms: float, target_resource: str = "qwen-2.5-coder-7b") -> Optional[AnomalyEvent]:
        """Detects sudden rise in inference latency compared to SLO baseline."""
        baseline = (
            self.baseline_manager.get_slo("ai_ttft_p95_ms")
            or self.baseline_manager.get_slo("ai_latency_ttft_ms")
            or 350.0
        )
        if observed_latency_ms > (baseline * 2.5):
            dev = observed_latency_ms / max(1.0, baseline)
            sev = IncidentSeverity.HIGH if dev > 3.0 else IncidentSeverity.MEDIUM
            event = AnomalyEvent(
                anomaly_id=f"ANOM-{uuid.uuid4().hex[:6].upper()}",
                anomaly_type=AnomalyType.LATENCY_SPIKE,
                metric_name="ai_ttft_p95_ms",
                baseline_val=baseline,
                observed_val=observed_latency_ms,
                deviation_ratio=dev,
                severity=sev,
                recommended_action="Evaluate alternate eligible node or shed low-priority queue jobs",
                suggested_action_type="reroute_eligible_job",
                target_resource=target_resource,
            )
            self._detected_anomalies.append(event)
            return event
        return None

    def check_vram_pressure(self, used_vram_gb: float, total_vram_gb: float, node_id: str = "NODE-001") -> Optional[AnomalyEvent]:
        """Detects approaching GPU OOM and excessive memory retention."""
        utilization = used_vram_gb / max(1.0, total_vram_gb)
        if utilization >= 0.88:
            event = AnomalyEvent(
                anomaly_id=f"ANOM-{uuid.uuid4().hex[:6].upper()}",
                anomaly_type=AnomalyType.VRAM_PRESSURE,
                metric_name="gpu_vram_utilization_ratio",
                baseline_val=0.65,
                observed_val=utilization,
                deviation_ratio=utilization / 0.65,
                severity=IncidentSeverity.HIGH if utilization >= 0.95 else IncidentSeverity.MEDIUM,
                recommended_action=f"Unload idle models on {node_id} to reclaim VRAM before OOM",
                suggested_action_type="unload_idle_model",
                target_resource=node_id,
            )
            self._detected_anomalies.append(event)
            return event
        return None

    def check_queue_backlog(self, current_queue: int, worker_count: int) -> Optional[AnomalyEvent]:
        """Detects queue growth despite active workers."""
        capacity = max(1, worker_count * 10)
        if current_queue > capacity:
            event = AnomalyEvent(
                anomaly_id=f"ANOM-{uuid.uuid4().hex[:6].upper()}",
                anomaly_type=AnomalyType.QUEUE_OVERLOAD,
                metric_name="queue_depth",
                baseline_val=float(capacity // 2),
                observed_val=float(current_queue),
                deviation_ratio=float(current_queue) / float(max(1, capacity // 2)),
                severity=IncidentSeverity.HIGH,
                recommended_action="Trigger queue backpressure and shed background jobs",
                suggested_action_type="apply_queue_backpressure",
                target_resource="FABRIC_QUEUE",
            )
            self._detected_anomalies.append(event)
            return event
        return None

    def check_auth_spike(self, policy_denials_per_min: int) -> Optional[AnomalyEvent]:
        """Detects spikes in policy denials or unauthenticated token probes."""
        if policy_denials_per_min > 5:
            event = AnomalyEvent(
                anomaly_id=f"ANOM-{uuid.uuid4().hex[:6].upper()}",
                anomaly_type=AnomalyType.AUTH_SPIKE,
                metric_name="policy_denials_per_min",
                baseline_val=0.2,
                observed_val=float(policy_denials_per_min),
                deviation_ratio=float(policy_denials_per_min) / 0.2,
                severity=IncidentSeverity.CRITICAL if policy_denials_per_min > 20 else IncidentSeverity.HIGH,
                recommended_action="Quarantine suspicious worker client and initiate security containment",
                suggested_action_type="quarantine_worker",
                target_resource="CLIENT_AUTH_GATEWAY",
            )
            self._detected_anomalies.append(event)
            return event
        return None

    def list_anomalies(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Returns the list of recently detected anomalies."""
        return [a.to_dict() for a in reversed(self._detected_anomalies[-limit:])]

    def clear(self):
        self._detected_anomalies.clear()
