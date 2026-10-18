"""Garuda Phase 35: Module D - Self-Optimizing Workload Scheduler Adapter.
Extends the Phase 34 WorkloadScheduler with predictive demand, latency baselines,
dynamic weights, and policy-gated explainable optimization.
"""
from typing import Dict, List, Optional, Any
import time

from fabric.models import (
    WorkloadRequest,
    SchedulingDecision,
    CandidateScore,
    FabricNodeRecord,
    NodeStatus,
    NodeTrust,
    NetworkZone,
    DataClassification,
    WorkloadPriority,
)
from fabric.scheduler import WorkloadScheduler
from autonomous_ops.forecasting import WorkloadPredictor


from fabric.node_registry import NodeRegistry
from fabric.model_placement import ModelPlacementManager


class SelfOptimizingScheduler:
    """Combines hard governance boundaries with predictive latency and capacity optimization."""

    def __init__(
        self,
        base_scheduler: Optional[WorkloadScheduler] = None,
        predictor: Optional[WorkloadPredictor] = None,
        node_registry: Optional[NodeRegistry] = None,
        forecaster: Optional[WorkloadPredictor] = None,
        weights: Optional[Dict[str, float]] = None,
    ):
        reg = node_registry or NodeRegistry()
        pm = ModelPlacementManager(reg)
        self.base_scheduler = base_scheduler or WorkloadScheduler(reg, pm)
        self.predictor = predictor or forecaster or WorkloadPredictor()
        # Configured weights (Section 35.6)
        self.weights = weights or {
            "w_policy": 100.0,
            "w_resource": 1.2,
            "w_locality": 1.0,
            "w_health": 0.8,
            "w_queue": 1.5,
            "w_cost": 0.5,
        }

    def schedule_with_optimization(self, request: WorkloadRequest) -> SchedulingDecision:
        """Executes the self-optimizing scheduling pipeline."""
        # 1. Base schedule provides strict eligibility filters (policy, capability, trust, locality, VRAM)
        base_decision = self.base_scheduler.schedule(request)
        if not base_decision.scheduled:
            return base_decision

        # 2. Extract eligible nodes
        eligible_candidates = [c for c in base_decision.candidate_scores if c.is_eligible]
        if not eligible_candidates:
            return base_decision

        # 3. Forecast workload impact
        curr_queue = sum(
            n.active_jobs for n in self.base_scheduler.registry.list_nodes() if n.status == NodeStatus.HEALTHY
        )
        forecast = self.predictor.forecast_workload(
            current_queue_depth=curr_queue,
            available_vram_gb=4.8,
            target_model=request.required_model or "qwen-local",
        )

        optimized_scores: List[CandidateScore] = []
        for cand in base_decision.candidate_scores:
            if not cand.is_eligible:
                optimized_scores.append(cand)
                continue

            node = self.base_scheduler.registry.get_node(cand.node_id)
            if not node:
                optimized_scores.append(cand)
                continue

            # Compute enhanced score
            p_score = self.weights["w_policy"] * (1.0 if cand.is_eligible else 0.0)
            r_score = self.weights["w_resource"] * (node.free_vram_gb * 8.0 + (node.free_ram_gb * 0.5))
            l_score = self.weights["w_locality"] * (50.0 if node.network_zone == NetworkZone.RESTRICTED_AI else 25.0)
            h_score = self.weights["w_health"] * (100.0 if node.trust_level == NodeTrust.TRUSTED else 50.0)

            # Predictive queue pressure incorporating forecasted arrival rate
            predicted_pressure_penalty = (
                self.weights["w_queue"] * (node.active_jobs * 35.0 + (forecast["arrival_velocity_jobs_per_step"] * 10.0))
            )

            # Execution cost / transfer latency estimate
            c_cost = self.weights["w_cost"] * (15.0 if node.network_zone != NetworkZone.RESTRICTED_AI else 0.0)

            total_opt_score = p_score + r_score + l_score + h_score - predicted_pressure_penalty - c_cost

            reasons = list(cand.reasons)
            reasons.append(f"Predicted queue adjustment: -{round(predicted_pressure_penalty, 1)} pts")
            reasons.append(f"Health score: +{round(h_score, 1)} pts")

            optimized_scores.append(
                CandidateScore(
                    node_id=cand.node_id,
                    score=round(total_opt_score, 2),
                    policy_compat_score=cand.policy_compat_score,
                    trust_score=cand.trust_score,
                    resource_score=cand.resource_score,
                    locality_score=cand.locality_score,
                    queue_penalty=round(predicted_pressure_penalty, 2),
                    network_cost=round(c_cost, 2),
                    reasons=reasons,
                    is_eligible=True,
                )
            )

        # Sort eligible candidates by optimized score descending
        eligible_sorted = [c for c in optimized_scores if c.is_eligible]
        eligible_sorted.sort(key=lambda c: c.score, reverse=True)

        winner = eligible_sorted[0]
        selected_record = self.base_scheduler.registry.get_node(winner.node_id)

        explanation = (
            f"Selected: {winner.node_id} (Score: {winner.score}) "
            f"✓ Policy compatible ✓ Resource optimized ({selected_record.free_vram_gb if selected_record else 0} GB free) "
            f"✓ Predicted queue wait minimized."
        )

        return SchedulingDecision(
            request_id=request.request_id,
            selected_node_id=winner.node_id,
            selected_node=selected_record.to_dict() if selected_record else None,
            explanation=explanation,
            candidate_scores=optimized_scores,
            rejected_reasons=base_decision.rejected_reasons,
            scheduled=True,
        )

    def schedule_workload(
        self,
        job_id: str,
        required_model: str,
        data_classification: str = "INTERNAL",
        origin_zone: str = "ZONE_INTERNAL",
        estimated_tokens: int = 256,
    ) -> Dict[str, Any]:
        """Convenience method wrapping WorkloadRequest and returning clean dictionary."""
        cls_enum = DataClassification[data_classification] if data_classification in DataClassification.__members__ else DataClassification.INTERNAL
        req = WorkloadRequest(
            request_id=job_id,
            capability="llm_inference",
            required_model=required_model,
            data_classification=cls_enum,
            min_vram_gb=1.0,
        )
        decision = self.schedule_with_optimization(req)
        return {
            "job_id": job_id,
            "selected_node": decision.selected_node_id,
            "explanation": decision.explanation,
            "scheduled": decision.scheduled,
            "candidate_scores": [c.to_dict() for c in decision.candidate_scores],
            "rejected_reasons": decision.rejected_reasons,
        }
