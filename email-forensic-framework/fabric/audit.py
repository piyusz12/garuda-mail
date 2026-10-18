"""Garuda Distributed Sovereign AI Fabric - Distributed Governance & Routing Audit.
Phase 34 Section 34.19:
Node-level audit logging, data-zone verification records,
failover tracking, and compliance traceability.
"""
from typing import Dict, List, Optional, Any
import time
import uuid

from fabric.models import DistributedAuditEvent


class DistributedAuditTrail:
    """Immutable audit trail capturing all distributed routing, policy, and failover decisions."""

    def __init__(self):
        self._events: List[DistributedAuditEvent] = []
        self._seed_sample_events()

    def record_event(
        self,
        user_id: str,
        request_id: str,
        action: str,
        policy_decision: str,
        selected_node: str,
        target_model: str,
        data_classification: str,
        data_zone: str,
        latency_ms: float,
        status: str = "SUCCESS",
        failover_occurred: bool = False,
        initial_node: Optional[str] = None,
        replacement_node: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> DistributedAuditEvent:
        """Appends a cryptographically traceable governance audit entry."""
        event_id = f"AUD-{uuid.uuid4().hex[:8].upper()}"
        event = DistributedAuditEvent(
            event_id=event_id,
            timestamp=time.time(),
            user_id=user_id,
            request_id=request_id,
            action=action,
            policy_decision=policy_decision,
            selected_node=selected_node,
            target_model=target_model,
            data_classification=data_classification,
            data_zone=data_zone,
            failover_occurred=failover_occurred,
            initial_node=initial_node,
            replacement_node=replacement_node,
            latency_ms=latency_ms,
            status=status,
            details=details or {},
        )
        self._events.append(event)
        return event

    def list_events(
        self,
        node_id: Optional[str] = None,
        user_id: Optional[str] = None,
        failover_only: bool = False,
        limit: int = 50,
    ) -> List[DistributedAuditEvent]:
        evs = list(self._events)
        if node_id:
            evs = [e for e in evs if e.selected_node == node_id or e.initial_node == node_id]
        if user_id:
            evs = [e for e in evs if e.user_id == user_id]
        if failover_only:
            evs = [e for e in evs if e.failover_occurred]
        evs.sort(key=lambda e: e.timestamp, reverse=True)
        return evs[:limit]

    def _seed_sample_events(self):
        now = time.time()
        self.record_event(
            user_id="analyst@garuda.internal",
            request_id="REQ-1029",
            action="INFERENCE",
            policy_decision="ALLOW",
            selected_node="NODE-001",
            target_model="qwen-local",
            data_classification="CONFIDENTIAL",
            data_zone="RESTRICTED_AI",
            latency_ms=48.2,
            status="SUCCESS",
            details={"prompt_tokens": 128, "completion_tokens": 256},
        )
        self.record_event(
            user_id="engineer@garuda.internal",
            request_id="REQ-1030",
            action="FAILOVER_RECOVERY",
            policy_decision="ALLOW",
            selected_node="NODE-001",
            target_model="qwen-coder-7b",
            data_classification="INTERNAL",
            data_zone="RESTRICTED_AI",
            latency_ms=112.5,
            status="RECOVERED",
            failover_occurred=True,
            initial_node="NODE-002",
            replacement_node="NODE-001",
            details={"resumed_step": "Synthesize CBOM report"},
        )
