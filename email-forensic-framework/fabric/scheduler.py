"""Garuda Distributed Sovereign AI Fabric - Workload Scheduler & Policy Dispatcher.
Phase 34 Sections 34.7, 34.8, 34.11, 34.21, 34.48, 34.49, 34.50, 34.51:
Multi-stage scheduling pipeline:
Policy gate -> Capability filter -> Model placement filter -> Data locality filter ->
Trust status filter -> Resource filter (VRAM / RAM) -> Fair concurrency check ->
Explainable deterministic scoring -> Selected Node + Rejection reasons for all candidates.
"""
from typing import Dict, List, Optional, Any
import time

from fabric.models import (
    WorkloadRequest,
    CandidateScore,
    SchedulingDecision,
    FabricNodeRecord,
    NodeStatus,
    NodeTrust,
    NetworkZone,
    DataClassification,
    WorkloadPriority,
    ModelLifecycleStatus,
)
from fabric.node_registry import NodeRegistry
from fabric.model_placement import ModelPlacementManager


# Priority weighting boosts
PRIORITY_BOOSTS = {
    WorkloadPriority.CRITICAL: 35.0,
    WorkloadPriority.HIGH: 18.0,
    WorkloadPriority.NORMAL: 0.0,
    WorkloadPriority.LOW: -10.0,
    WorkloadPriority.BACKGROUND: -25.0,
}

# Trust base scores
TRUST_SCORES = {
    NodeTrust.TRUSTED: 100.0,
    NodeTrust.LIMITED: 50.0,
    NodeTrust.UNTRUSTED: -200.0,
    NodeTrust.QUARANTINED: -1000.0,
}


class WorkloadScheduler:
    """Core scheduler orchestrating explainable, resource-aware, sovereign AI placement."""

    def __init__(
        self,
        registry: NodeRegistry,
        model_mgr: ModelPlacementManager,
        max_active_jobs_per_node: int = 10,
        max_user_concurrency: int = 5,
    ):
        self.registry = registry
        self.model_mgr = model_mgr
        self.max_active_jobs_per_node = max_active_jobs_per_node
        self.max_user_concurrency = max_user_concurrency
        self._user_active_jobs: Dict[str, int] = {}
        self.air_gapped_mode: bool = False

    def set_air_gapped_mode(self, enabled: bool) -> None:
        self.air_gapped_mode = enabled

    def schedule(self, request: WorkloadRequest) -> SchedulingDecision:
        """Evaluates all registered nodes through the multi-stage filter and scoring pipeline."""
        nodes = self.registry.list_nodes()
        candidates: List[CandidateScore] = []
        rejected_reasons: Dict[str, str] = {}

        # -------------------------------------------------------------
        # Fair Concurrency Gate (Section 34.51)
        # -------------------------------------------------------------
        current_user_jobs = self._user_active_jobs.get(request.caller_id, 0)
        if current_user_jobs >= self.max_user_concurrency and request.priority not in (
            WorkloadPriority.CRITICAL,
            WorkloadPriority.HIGH,
        ):
            return SchedulingDecision(
                request_id=request.request_id,
                selected_node_id=None,
                selected_node=None,
                explanation=(
                    f"Fair scheduling throttle: user '{request.caller_id}' has reached active "
                    f"job limit ({current_user_jobs}/{self.max_user_concurrency})."
                ),
                candidate_scores=[],
                rejected_reasons={"all": "Fair-use concurrency limit reached"},
                scheduled=False,
            )

        for node in nodes:
            reasons: List[str] = []
            is_eligible = True
            rejection: Optional[str] = None

            # ---------------------------------------------------------
            # Stage 1: Health & Trust Filter (Section 34.21 & 34.38)
            # ---------------------------------------------------------
            if node.status in (NodeStatus.UNAVAILABLE, NodeStatus.QUARANTINED):
                is_eligible = False
                rejection = f"Node status is {node.status.value}"
            elif node.trust_level in (NodeTrust.UNTRUSTED, NodeTrust.QUARANTINED):
                is_eligible = False
                rejection = f"Node trust level is {node.trust_level.value} (refused for compute)"

            # ---------------------------------------------------------
            # Stage 2: Capability Filter (Section 34.6)
            # ---------------------------------------------------------
            if is_eligible and request.capability not in node.capabilities:
                is_eligible = False
                rejection = f"Lacks required capability '{request.capability}'"
            elif is_eligible:
                reasons.append(f"Provides capability '{request.capability}'")

            # ---------------------------------------------------------
            # Stage 3: Model Availability Filter (Section 34.9)
            # ---------------------------------------------------------
            if is_eligible and request.required_model:
                has_model = (
                    node.models_loaded.get(request.required_model) == ModelLifecycleStatus.READY
                )
                if not has_model:
                    # Check if model can be loaded dynamically
                    can_load, load_reason = self.model_mgr.can_place_model(request.required_model, node)
                    if not can_load:
                        is_eligible = False
                        rejection = f"Requested model '{request.required_model}' unavailable: {load_reason}"
                    else:
                        reasons.append(f"Model '{request.required_model}' can be dynamically placed")
                else:
                    reasons.append(f"Model '{request.required_model}' is READY and hot-loaded")

            # ---------------------------------------------------------
            # Stage 4: Data Locality & Sovereignty Filter (Section 34.11 & 34.30)
            # ---------------------------------------------------------
            if is_eligible:
                # Top secret or restricted data requires strict zone isolation
                if request.data_classification in (DataClassification.RESTRICTED, DataClassification.TOP_SECRET):
                    if node.network_zone != NetworkZone.RESTRICTED_AI:
                        is_eligible = False
                        rejection = (
                            f"Data locality violation: {request.data_classification.value} data "
                            f"forbidden in zone '{node.network_zone.value}' (requires RESTRICTED_AI)"
                        )
                    else:
                        reasons.append("Sovereign data locality verified (RESTRICTED_AI zone match)")
                elif request.data_classification == DataClassification.CONFIDENTIAL:
                    if node.network_zone not in (NetworkZone.RESTRICTED_AI, NetworkZone.INTERNAL_AI):
                        is_eligible = False
                        rejection = (
                            f"Confidential data forbidden in zone '{node.network_zone.value}'"
                        )
                    else:
                        reasons.append("Data locality verified for CONFIDENTIAL tier")

                # If caller provided specific allowed zones
                if is_eligible and request.allowed_zones:
                    if node.network_zone not in request.allowed_zones:
                        is_eligible = False
                        rejection = f"Node zone '{node.network_zone.value}' not in request allowed_zones"

            # ---------------------------------------------------------
            # Stage 5: Resource-Aware VRAM / RAM Filter (Section 34.8)
            # ---------------------------------------------------------
            if is_eligible:
                # If a specific min_vram_gb is requested
                req_vram = request.min_vram_gb
                if not req_vram and request.required_model:
                    m_spec = self.model_mgr.get_model(request.required_model)
                    if m_spec:
                        req_vram = m_spec.required_vram_gb

                if req_vram > 0 and node.free_vram_gb < req_vram:
                    is_eligible = False
                    rejection = (
                        f"Insufficient VRAM: required {req_vram} GB, "
                        f"available {node.free_vram_gb} GB"
                    )
                elif req_vram > 0:
                    reasons.append(f"Sufficient VRAM: {node.free_vram_gb} GB free >= {req_vram} GB required")

                # Check active queue limits
                if is_eligible and node.active_jobs >= self.max_active_jobs_per_node:
                    is_eligible = False
                    rejection = f"Node queue full ({node.active_jobs}/{self.max_active_jobs_per_node} active jobs)"

            # ---------------------------------------------------------
            # Stage 6: Explainable Deterministic Scoring (Section 34.48)
            # ---------------------------------------------------------
            policy_score = 100.0 if is_eligible else 0.0
            trust_score = TRUST_SCORES.get(node.trust_level, 0.0)
            resource_score = node.free_vram_gb * 8.0 + (node.free_ram_gb * 0.5)
            locality_score = 50.0 if node.network_zone == NetworkZone.RESTRICTED_AI else 25.0
            queue_penalty = float(node.active_jobs * 45.0 + (node.cpu_usage_pct * 0.2))
            network_cost = 5.0 if node.network_zone != NetworkZone.RESTRICTED_AI else 0.0
            priority_boost = PRIORITY_BOOSTS.get(request.priority, 0.0)

            total_score = (
                policy_score
                + trust_score
                + resource_score
                + locality_score
                + priority_boost
                - queue_penalty
                - network_cost
            )

            if not is_eligible:
                rejected_reasons[node.node_id] = rejection or "Failed filter"
                candidates.append(
                    CandidateScore(
                        node_id=node.node_id,
                        score=0.0,
                        policy_compat_score=0.0,
                        trust_score=trust_score,
                        resource_score=resource_score,
                        locality_score=locality_score,
                        queue_penalty=queue_penalty,
                        network_cost=network_cost,
                        reasons=[],
                        is_eligible=False,
                        rejection_reason=rejection,
                    )
                )
            else:
                reasons.append(f"Trust level '{node.trust_level.value}' (+{trust_score})")
                reasons.append(f"Resource headroom: {node.free_vram_gb} GB VRAM free")
                candidates.append(
                    CandidateScore(
                        node_id=node.node_id,
                        score=total_score,
                        policy_compat_score=policy_score,
                        trust_score=trust_score,
                        resource_score=resource_score,
                        locality_score=locality_score,
                        queue_penalty=queue_penalty,
                        network_cost=network_cost,
                        reasons=reasons,
                        is_eligible=True,
                    )
                )

        # Sort eligible candidates by score descending
        eligible = [c for c in candidates if c.is_eligible]
        eligible.sort(key=lambda c: c.score, reverse=True)

        if not eligible:
            return SchedulingDecision(
                request_id=request.request_id,
                selected_node_id=None,
                selected_node=None,
                explanation="No eligible node satisfied the capability, data locality, trust, or resource constraints.",
                candidate_scores=candidates,
                rejected_reasons=rejected_reasons,
                scheduled=False,
            )

        winner = eligible[0]
        selected_record = self.registry.get_node(winner.node_id)

        # Build Explainable summary (Section 34.49)
        explanation = (
            f"Selected {winner.node_id} (Score: {round(winner.score, 1)}). "
            f"Reasons: {'; '.join(winner.reasons[:4])}."
        )

        return SchedulingDecision(
            request_id=request.request_id,
            selected_node_id=winner.node_id,
            selected_node=selected_record.to_dict() if selected_record else None,
            explanation=explanation,
            candidate_scores=candidates,
            rejected_reasons=rejected_reasons,
            scheduled=True,
        )

    def allocate_job(self, node_id: str, caller_id: str) -> None:
        """Tracks active job allocation."""
        node = self.registry.get_node(node_id)
        if node:
            node.active_jobs += 1
        self._user_active_jobs[caller_id] = self._user_active_jobs.get(caller_id, 0) + 1

    def release_job(self, node_id: str, caller_id: str) -> None:
        """Releases job slot after completion or failover."""
        node = self.registry.get_node(node_id)
        if node and node.active_jobs > 0:
            node.active_jobs -= 1
        if caller_id in self._user_active_jobs and self._user_active_jobs[caller_id] > 0:
            self._user_active_jobs[caller_id] -= 1
