"""Garuda Phase 35: Module L - Learning from Previous Actions & Outcome Feedback.
Captures pre- and post-action operational states, evaluates net utility deltas (latency vs VRAM),
and ranks candidate actions using historical effectiveness without unauthorized self-modification.
"""
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
import time
import uuid


@dataclass
class ActionOutcomeRecord:
    record_id: str
    action_id: str
    action_type: str
    target_resource: str
    prior_state: Dict[str, Any]
    post_state: Dict[str, Any]
    expected_effect: str
    observed_effect: str
    latency_delta_ms: float
    vram_delta_gb: float
    success: bool
    rolled_back: bool
    conclusion: str
    recorded_at: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "record_id": self.record_id,
            "action_id": self.action_id,
            "action_type": self.action_type,
            "target_resource": self.target_resource,
            "prior_state": self.prior_state,
            "post_state": self.post_state,
            "expected_effect": self.expected_effect,
            "observed_effect": self.observed_effect,
            "latency_delta_ms": round(self.latency_delta_ms, 2),
            "vram_delta_gb": round(self.vram_delta_gb, 2),
            "success": self.success,
            "rolled_back": self.rolled_back,
            "conclusion": self.conclusion,
            "recorded_at": self.recorded_at,
        }


class ActionOutcomeEvaluator:
    """Stores historical action outcomes and computes action effectiveness scores."""

    def __init__(self):
        self._records: List[ActionOutcomeRecord] = []
        self._seed_sample_outcomes()

    def record_outcome(
        self,
        action_id: str,
        action_type: str,
        target_resource: str,
        prior_state: Dict[str, Any],
        post_state: Dict[str, Any],
        expected_effect: str,
        latency_delta_ms: float,
        vram_delta_gb: float,
        success: bool = True,
        rolled_back: bool = False,
    ) -> ActionOutcomeRecord:
        """Evaluates and records the net operational impact of an executed action."""
        if latency_delta_ms < 0 and vram_delta_gb <= 0:
            conclusion = f"Highly effective: {action_type} reduced latency by {abs(latency_delta_ms):.1f}ms without increasing VRAM."
        elif latency_delta_ms < 0 and vram_delta_gb > 0:
            conclusion = f"Trade-off: {action_type} reduced latency by {abs(latency_delta_ms):.1f}ms at the expense of +{vram_delta_gb:.1f}GB VRAM."
        elif latency_delta_ms > 0:
            conclusion = f"Degraded: {action_type} increased latency by {latency_delta_ms:.1f}ms. Rollback recommended."
        else:
            conclusion = f"Neutral: {action_type} completed with nominal state changes."

        record = ActionOutcomeRecord(
            record_id=f"OUTCOME-{uuid.uuid4().hex[:6].upper()}",
            action_id=action_id,
            action_type=action_type,
            target_resource=target_resource,
            prior_state=prior_state,
            post_state=post_state,
            expected_effect=expected_effect,
            observed_effect=f"Latency change: {latency_delta_ms:+.1f}ms, VRAM change: {vram_delta_gb:+.2f}GB",
            latency_delta_ms=latency_delta_ms,
            vram_delta_gb=vram_delta_gb,
            success=success,
            rolled_back=rolled_back,
            conclusion=conclusion,
        )
        self._records.append(record)
        return record

    def rank_candidate_actions(self, candidate_types: List[str]) -> List[Dict[str, Any]]:
        """Ranks candidate action types by their historical success rate and mean latency reduction."""
        stats: Dict[str, Dict[str, Any]] = {}
        for c in candidate_types:
            stats[c] = {"count": 0, "success_count": 0, "total_lat_saved": 0.0}

        for r in self._records:
            if r.action_type in stats:
                stats[r.action_type]["count"] += 1
                if r.success and not r.rolled_back:
                    stats[r.action_type]["success_count"] += 1
                stats[r.action_type]["total_lat_saved"] += max(0.0, -r.latency_delta_ms)

        ranked = []
        for a_type, data in stats.items():
            count = data["count"]
            rate = (data["success_count"] / count) if count > 0 else 0.5
            avg_saved = (data["total_lat_saved"] / count) if count > 0 else 0.0
            score = (rate * 0.6) + (min(100.0, avg_saved) / 100.0 * 0.4)
            ranked.append({
                "action_type": a_type,
                "confidence_score": round(score, 2),
                "historical_success_rate": round(rate, 2),
                "avg_latency_reduced_ms": round(avg_saved, 1),
                "samples": count,
            })

        ranked.sort(key=lambda x: x["confidence_score"], reverse=True)
        return ranked

    def list_outcomes(self, limit: int = 25) -> List[Dict[str, Any]]:
        return [r.to_dict() for r in reversed(self._records[-limit:])]

    def _seed_sample_outcomes(self):
        self.record_outcome(
            action_id="ACT-SEED-01",
            action_type="prewarm_model",
            target_resource="qwen-2.5-coder-7b",
            prior_state={"state": "UNLOADED", "cold_start_ms": 3200.0, "vram_free_gb": 6.8},
            post_state={"state": "WARMED", "cold_start_ms": 120.0, "vram_free_gb": 2.6},
            expected_effect="Eliminate cold start delay for coding agent",
            latency_delta_ms=-3080.0,
            vram_delta_gb=4.2,
            success=True,
        )
        self.record_outcome(
            action_id="ACT-SEED-02",
            action_type="reroute_eligible_job",
            target_resource="JOB-829",
            prior_state={"node": "NODE-002", "queue_wait_ms": 1850.0},
            post_state={"node": "NODE-001", "queue_wait_ms": 120.0},
            expected_effect="Alleviate queue wait on saturated worker",
            latency_delta_ms=-1730.0,
            vram_delta_gb=0.0,
            success=True,
        )
