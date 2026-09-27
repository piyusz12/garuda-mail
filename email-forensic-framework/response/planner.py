"""
Phase 24 — Response Planner (Components 4, 19, 20, 21, 61)
Generates structured response plans with dependency ordering, canary rollout stages, and evidence preservation.
"""

from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Dict, List, Optional, Any
import time
import uuid

from incident.models import Incident
from response.actions import ResponseAction, ActionType, ActionStatus
from response.risk import ActionRiskClass


class PlanStatus(str, Enum):
    DRAFT = "DRAFT"
    SIMULATING = "SIMULATING"
    AWAITING_APPROVAL = "AWAITING_APPROVAL"
    APPROVED = "APPROVED"
    EXECUTING = "EXECUTING"
    VERIFYING = "VERIFYING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    ROLLED_BACK = "ROLLED_BACK"


@dataclass
class ResponsePlan:
    plan_id: str
    incident_id: str
    title: str
    playbook_id: str
    actions: List[ResponseAction]
    status: PlanStatus = PlanStatus.DRAFT
    created_at: float = field(default_factory=time.time)
    completed_at: Optional[float] = None
    approval_request_id: Optional[str] = None
    blast_radius_summary: Dict[str, Any] = field(default_factory=dict)
    canary_stages: List[List[str]] = field(default_factory=list)  # e.g. [["MTA-07"], ["MTA-01", "MTA-02"]]
    evidence_bundle_id: Optional[str] = None
    change_ticket_id: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class ResponsePlanner:
    """Formulates phased Response Plans for an incident based on matched playbook steps."""

    @classmethod
    def create_plan_for_incident(
        cls,
        incident: Incident,
        playbook: Any,
        target_assets: Optional[List[str]] = None
    ) -> ResponsePlan:
        plan_id = f"PLAN-{uuid.uuid4().hex[:6].upper()}"
        assets = target_assets or incident.affected_assets or ["MTA-07"]
        playbook_id = getattr(playbook, "playbook_id", "PLAYBOOK-CUSTOM")

        actions: List[ResponseAction] = []
        seq = 1

        # Step 1: Mandatory Evidence Preservation (R0)
        actions.append(ResponseAction(
            action_id=f"ACT-{uuid.uuid4().hex[:6].upper()}",
            sequence=seq,
            name="Preserve Pre-Remediation Telemetry Evidence",
            action_type=ActionType.ENDPOINT,
            target_asset=assets[0],
            parameters={"evidence_types": ["PCAP", "SESSION", "TLS_RECORD", "CONFIG_SNAPSHOT"]},
            risk_class=ActionRiskClass.R0,
            idempotency_key=f"{incident.incident_id}:PRESERVE:{assets[0]}",
            forward_command="preserve_evidence",
            rollback_command="",
            verification_spec={"check": "evidence_bundle_created"}
        ))
        seq += 1

        # Step 2: Digital Twin Pre-simulation (R0)
        actions.append(ResponseAction(
            action_id=f"ACT-{uuid.uuid4().hex[:6].upper()}",
            sequence=seq,
            name="Simulate Blast Radius & Client Compatibility in Digital Twin",
            action_type=ActionType.ENDPOINT,
            target_asset=assets[0],
            parameters={"simulation_type": "CRYPTO_COMPATIBILITY", "proposed_change": "DISABLE_LEGACY_TLS"},
            risk_class=ActionRiskClass.R0,
            idempotency_key=f"{incident.incident_id}:SIMULATE:{assets[0]}",
            forward_command="simulate_change",
            rollback_command="",
            verification_spec={"check": "simulation_completed"}
        ))
        seq += 1

        # Step 3: Canary Remediation on first host (R3)
        canary_asset = assets[0]
        actions.append(ResponseAction(
            action_id=f"ACT-{uuid.uuid4().hex[:6].upper()}",
            sequence=seq,
            name=f"Canary Remediation: Enforce TLS 1.3/1.2 on {canary_asset}",
            action_type=ActionType.CRYPTOGRAPHIC,
            target_asset=canary_asset,
            parameters={"disable_protocols": ["TLSv1.0", "TLSv1.1"], "enforce_cipher_suite": "AEAD_ONLY"},
            risk_class=ActionRiskClass.R3,
            idempotency_key=f"{incident.incident_id}:REMEDIATE_CANARY:{canary_asset}",
            forward_command=f"mta_config_set --asset {canary_asset} --protocols 'TLSv1.2 TLSv1.3'",
            rollback_command=f"mta_config_set --asset {canary_asset} --protocols 'TLSv1.0 TLSv1.1 TLSv1.2 TLSv1.3'",
            verification_spec={"telemetry_zero_sessions": ["TLS 1.0", "TLS 1.1"], "min_verification_seconds": 60}
        ))
        seq += 1

        # Step 4: Expand to remaining assets if multi-host (R3)
        remaining_assets = [a for a in assets if a != canary_asset]
        for a in remaining_assets:
            actions.append(ResponseAction(
                action_id=f"ACT-{uuid.uuid4().hex[:6].upper()}",
                sequence=seq,
                name=f"Expanded Remediation: Enforce TLS 1.3/1.2 on {a}",
                action_type=ActionType.CRYPTOGRAPHIC,
                target_asset=a,
                parameters={"disable_protocols": ["TLSv1.0", "TLSv1.1"], "enforce_cipher_suite": "AEAD_ONLY"},
                risk_class=ActionRiskClass.R3,
                idempotency_key=f"{incident.incident_id}:REMEDIATE_EXPAND:{a}",
                forward_command=f"mta_config_set --asset {a} --protocols 'TLSv1.2 TLSv1.3'",
                rollback_command=f"mta_config_set --asset {a} --protocols 'TLSv1.0 TLSv1.1 TLSv1.2 TLSv1.3'",
                verification_spec={"telemetry_zero_sessions": ["TLS 1.0", "TLS 1.1"], "min_verification_seconds": 60}
            ))
            seq += 1

        # Step 5: Multi-layer Telemetry Verification
        actions.append(ResponseAction(
            action_id=f"ACT-{uuid.uuid4().hex[:6].upper()}",
            sequence=seq,
            name="Passive Telemetry & Service Health Multi-Layer Verification",
            action_type=ActionType.ENDPOINT,
            target_asset=assets[0],
            parameters={"target_assets": assets, "monitor_window_minutes": 30},
            risk_class=ActionRiskClass.R0,
            idempotency_key=f"{incident.incident_id}:VERIFY_ALL",
            forward_command="verify_passive_telemetry",
            rollback_command="",
            verification_spec={"check": "zero_legacy_traffic"}
        ))
        seq += 1

        # Step 6: Post-Response Recurrence Watcher
        actions.append(ResponseAction(
            action_id=f"ACT-{uuid.uuid4().hex[:6].upper()}",
            sequence=seq,
            name="Schedule 24h & 7d Post-Remediation Recurrence Watcher",
            action_type=ActionType.NOTIFICATION,
            target_asset=assets[0],
            parameters={"watch_windows": ["1h", "24h", "7d", "30d"]},
            risk_class=ActionRiskClass.R1,
            idempotency_key=f"{incident.incident_id}:START_WATCHER",
            forward_command="start_recurrence_watcher",
            rollback_command="",
            verification_spec={"check": "watcher_active"}
        ))

        canary_stages = [[canary_asset]]
        if remaining_assets:
            canary_stages.append(remaining_assets)

        plan = ResponsePlan(
            plan_id=plan_id,
            incident_id=incident.incident_id,
            title=f"Phased Remediation Plan: {getattr(playbook, 'name', 'Crypto Remediation')} ({playbook_id})",
            playbook_id=playbook_id,
            actions=actions,
            canary_stages=canary_stages,
            change_ticket_id=f"CHG-{uuid.uuid4().hex[:6].upper()}"
        )

        incident.response_plan_id = plan_id
        incident.add_timeline_event(
            event_type="RESPONSE_PLAN_CREATED",
            description=f"Generated response plan {plan_id} with {len(actions)} actions and {len(canary_stages)} canary stages.",
            actor="response_planner",
            details={"plan_id": plan_id, "actions_count": len(actions), "canary_stages": canary_stages}
        )
        return plan
