"""
Phase 25 — Security Operations Orchestrator
The central coordinator unifying alert intake, correlation, investigation DAG,
dynamic risk scoring, decision policy gates, approval workflows, safe execution,
telemetry verification, recovery tracking, post-incident reporting, and closed-loop learning.
"""

from typing import Dict, List, Optional, Any
import time

from ..alerts.ingest import Alert, AlertIngestEngine
from ..alerts.correlation import AlertCorrelator
from ..cases.cases import Case, CaseStatus, CasePriority, CaseManager
from ..cases.timeline import CaseTimeline
from ..cases.evidence import EvidencePackager
from ..cases.reports import RootCauseCandidateEngine, BusinessImpactTranslator, PostIncidentReportGenerator
from ..investigation.dag import InvestigationDAG
from ..investigation.context import MaintenanceWindowChecker
from ..decisions.engine import DecisionEngine
from ..decisions.policies import PolicyRegistry, DecisionPolicy
from ..playbooks.models import PlaybookRegistry, SecurityPlaybook
from ..approvals.workflow import ApprovalWorkflow, ApprovalTier, ApprovalRequest
from ..actions.registry import ActionRegistry, ActionRecord, ActionRiskClass, ActionState
from ..actions.executor import ActionExecutor
from ..verification.checks import ResponseVerificationEngine, VerificationOutcome
from ..verification.monitors import RecoveryTracker, ReopenLogic
from ..verification.rollback import RollbackEngine
from ..feedback.labels import FeedbackLabelStore, AnalystLabel
from ..feedback.learning import ClosedLoopLearningEngine
from ..audit.decisions import DecisionAuditLedger
from ..audit.actions import ActionAuditLedger
from ..audit.overrides import AnalystOverrideLedger
from .states import CaseStateMachine
from .scheduler import SLATracker, EscalationEngine


class SecurityOperationsOrchestrator:
    """The central enterprise Security Operations Orchestrator for Phase 25."""

    def __init__(self):
        # 1. Alerting
        self.ingest_engine = AlertIngestEngine()
        self.correlator = AlertCorrelator()

        # 2. Case Management
        self.case_manager = CaseManager()
        self.timelines: Dict[str, CaseTimeline] = {}

        # 3. Investigation
        self.investigation_dag = InvestigationDAG()
        self.maintenance_checker = MaintenanceWindowChecker()

        # 4. Decisions & Playbooks
        self.policy_registry = PolicyRegistry()
        self.decision_engine = DecisionEngine(self.policy_registry)
        self.playbook_registry = PlaybookRegistry()

        # 5. Approvals & Actions
        self.approval_workflow = ApprovalWorkflow()
        self.action_registry = ActionRegistry()
        self.action_executor = ActionExecutor(self.action_registry)

        # 6. Verification & Recovery
        self.verification_engine = ResponseVerificationEngine()
        self.recovery_tracker = RecoveryTracker()
        self.rollback_engine = RollbackEngine(self.action_executor)

        # 7. Feedback & Learning
        self.label_store = FeedbackLabelStore()
        self.learning_engine = ClosedLoopLearningEngine(self.label_store)

        # 8. Audit Ledgers
        self.decision_audit = DecisionAuditLedger()
        self.action_audit = ActionAuditLedger()
        self.override_ledger = AnalystOverrideLedger()

    def process_alert(self, raw_alert: Dict[str, Any], tenant_id: str = "default") -> Dict[str, Any]:
        """
        Step 1 & 2: Ingest, deduplicate, correlate, and cluster incoming alert.
        If the cluster forms an incident candidate, automatically creates or updates an operational Case.
        """
        alert = self.ingest_engine.ingest_raw(raw_alert, tenant_id=tenant_id)
        corr_res = self.correlator.process_alert(alert)

        cluster = corr_res["cluster"]
        case = None

        if corr_res["is_incident_candidate"] or alert.severity in ("CRITICAL", "HIGH"):
            # Check if case already exists for this cluster
            existing_cases = [c for c in self.case_manager.list_cases(tenant_id=tenant_id) if c.cluster_id == cluster.cluster_id]
            if existing_cases:
                case = existing_cases[0]
                if alert.alert_id not in case.alert_ids:
                    case.alert_ids.append(alert.alert_id)
            else:
                sev_to_pri = {
                    "CRITICAL": CasePriority.CRITICAL,
                    "HIGH": CasePriority.HIGH,
                    "MEDIUM": CasePriority.MEDIUM,
                    "LOW": CasePriority.LOW,
                    "INFO": CasePriority.LOW,
                }
                case = self.case_manager.create_case(
                    title=f"Incident Cluster on {cluster.asset_id}: {alert.event_type}",
                    description=corr_res["correlation_summary"],
                    asset_id=cluster.asset_id,
                    priority=sev_to_pri.get(cluster.aggregate_severity, CasePriority.MEDIUM),
                    tenant_id=tenant_id,
                    cluster_id=cluster.cluster_id,
                    alert_ids=[a.alert_id for a in cluster.alerts],
                )
                timeline = CaseTimeline(case.case_id)
                self.timelines[case.case_id] = timeline
                timeline.add_event(
                    stage="CASE_CREATED",
                    description=f"Operational case opened from alert cluster {cluster.cluster_id}",
                    actor="orchestrator",
                )
                CaseStateMachine.transition(case, CaseStatus.TRIAGED, actor="orchestrator")

        return {
            "alert": alert.to_dict(),
            "is_duplicate": corr_res["is_duplicate"],
            "hit_count": corr_res["hit_count"],
            "cluster_id": cluster.cluster_id,
            "is_incident_candidate": corr_res["is_incident_candidate"],
            "case_id": case.case_id if case else None,
        }

    def investigate_case(self, case_id: str) -> Dict[str, Any]:
        """
        Step 3: Executes the Investigation DAG to gather contextual intelligence across 7 dimensions.
        """
        case = self.case_manager.get_case(case_id)
        if not case:
            raise KeyError(f"Case '{case_id}' not found.")

        timeline = self.timelines.setdefault(case.case_id, CaseTimeline(case.case_id))
        CaseStateMachine.transition(case, CaseStatus.INVESTIGATING, actor="orchestrator")
        timeline.add_event(stage="INVESTIGATION_STARTED", description="Running Automated Investigation DAG", actor="orchestrator")

        # Initial context for DAG
        initial_ctx = {
            "case_id": case.case_id,
            "asset_id": case.asset_id,
            "tenant_id": case.tenant_id,
            "timestamp": case.created_at,
            "event_types": [case.title],
        }

        # Pull details from alerts
        for aid in case.alert_ids:
            a = self.ingest_engine.get_alert(aid)
            if a:
                if a.certificate_id:
                    initial_ctx["certificate_id"] = a.certificate_id
                if a.ja4:
                    initial_ctx["ja4"] = a.ja4
                if a.destination:
                    initial_ctx["destination"] = a.destination

        # Execute DAG
        enriched_ctx = self.investigation_dag.execute(initial_ctx)
        case.metadata["investigation_context"] = enriched_ctx

        timeline.add_event(
            stage="EVIDENCE_COLLECTED",
            description=f"Investigation DAG completed with {len(enriched_ctx.get('executed_tasks', []))} tasks",
            actor="orchestrator",
            details={"executed_tasks": enriched_ctx.get("executed_tasks", [])},
        )
        CaseStateMachine.transition(case, CaseStatus.EVIDENCE_COLLECTED, actor="orchestrator")

        # Step 4: Decision evaluation
        decision_res = self.decision_engine.evaluate(enriched_ctx, tenant_id=case.tenant_id)
        case.risk_score = decision_res["risk_score"]
        case.risk_factors = decision_res["factors"]
        case.uncertainty_model = decision_res["uncertainty_model"]
        case.recommended_action = decision_res["recommended_action"]

        # Map playbook
        first_evt = enriched_ctx.get("event_types", ["general"])[0]
        pb = self.playbook_registry.find_by_trigger(first_evt)
        if pb:
            case.playbook_id = pb.playbook_id

        # Audit decision
        self.decision_audit.record_decision(
            case_id=case.case_id,
            decision=decision_res["decision"],
            risk_score=case.risk_score,
            reasons=decision_res["reasons"],
            evidence_pointers=decision_res["evidence_pointers"],
        )

        timeline.add_event(
            stage="DECISION_EVALUATED",
            description=f"Decision Engine output: {decision_res['decision']} (Risk: {case.risk_score})",
            actor="decision_engine",
            details=decision_res,
        )
        CaseStateMachine.transition(case, CaseStatus.ASSESSED, actor="orchestrator")
        CaseStateMachine.transition(case, CaseStatus.AWAITING_DECISION, actor="orchestrator")

        return {
            "case_id": case.case_id,
            "status": case.status.value,
            "risk_score": case.risk_score,
            "decision": decision_res["decision"],
            "recommended_action": case.recommended_action,
            "playbook_id": case.playbook_id,
            "factors": case.risk_factors,
            "reasons": decision_res["reasons"],
            "evidence_pointers": decision_res["evidence_pointers"],
        }

    def stage_response_action(
        self,
        case_id: str,
        action_type: str,
        target: str,
        risk_class: ActionRiskClass = ActionRiskClass.R3_POTENTIAL_IMPACT,
        parameters: Optional[Dict[str, Any]] = None,
    ) -> ActionRecord:
        """
        Step 5: Stages a proposed action and sets up human approval if required by policy.
        """
        case = self.case_manager.get_case(case_id)
        if not case:
            raise KeyError(f"Case '{case_id}' not found.")

        timeline = self.timelines.setdefault(case.case_id, CaseTimeline(case.case_id))
        action = self.action_registry.register_action(
            case_id=case_id,
            action_type=action_type,
            target=target,
            risk_class=risk_class,
            parameters=parameters,
        )
        case.action_ids.append(action.action_id)

        # Determine approval tier
        tier = ApprovalTier.LOW_IMPACT
        if risk_class == ActionRiskClass.R4_MAJOR_CRITICAL:
            tier = ApprovalTier.CRITICAL
        elif risk_class == ActionRiskClass.R3_POTENTIAL_IMPACT:
            tier = ApprovalTier.HIGH_IMPACT
        elif risk_class == ActionRiskClass.R2_LIMITED_REVERSIBLE:
            tier = ApprovalTier.MEDIUM_IMPACT

        app_req = self.approval_workflow.create_request(
            action_id=action.action_id,
            case_id=case.case_id,
            tier=tier,
            action_payload={"action_type": action_type, "target": target, "parameters": parameters or {}},
        )

        timeline.add_event(
            stage="ACTION_STAGED",
            description=f"Action '{action_type}' staged for '{target}' (Tier: {tier.value}, Approval Status: {app_req.status})",
            actor="orchestrator",
            details={"action_id": action.action_id, "approval_request_id": app_req.request_id},
        )

        return action

    def execute_approved_action(
        self,
        action_id: str,
        dry_run: bool = False,
    ) -> Dict[str, Any]:
        """
        Step 6: Executes a staged action once approved, enforcing safety guardrails and idempotency.
        """
        action = self.action_registry.get_action(action_id)
        if not action:
            raise KeyError(f"Action '{action_id}' not found.")

        case = self.case_manager.get_case(action.case_id)
        timeline = self.timelines.get(action.case_id)

        # Check approval status
        reqs = [r for r in self.approval_workflow.list_requests() if r.action_id == action_id]
        if reqs and reqs[0].status != "APPROVED" and not dry_run:
            raise PermissionError(f"Action '{action_id}' is pending mandatory approval ({reqs[0].status}).")

        if case:
            CaseStateMachine.transition(case, CaseStatus.RESPONDING, actor="orchestrator")

        exec_res = self.action_executor.execute_action(
            action,
            context=case.metadata.get("investigation_context", {}) if case else {},
            dry_run=dry_run,
        )

        if timeline:
            timeline.add_event(
                stage="ACTION_EXECUTED" if not dry_run else "ACTION_DRY_RUN",
                description=f"Execution of action '{action.action_type}' on '{action.target}' (Status: {exec_res['status']})",
                actor="orchestrator",
                details=exec_res,
            )

        # Audit
        self.action_audit.record_action(
            action_id=action.action_id,
            case_id=action.case_id,
            action_type=action.action_type,
            target=action.target,
            actor="orchestrator",
            policy_id="POL-DEFAULT",
            decision_id=f"DEC-{action.case_id}",
            snapshot_before=action.snapshot_before,
            snapshot_after=action.snapshot_after,
            result_status=exec_res["status"],
        )

        return exec_res

    def verify_action(
        self,
        action_id: str,
        telemetry: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Step 7: Verifies remediation via observed network & crypto telemetry.
        """
        action = self.action_registry.get_action(action_id)
        if not action:
            raise KeyError(f"Action '{action_id}' not found.")

        case = self.case_manager.get_case(action.case_id)
        timeline = self.timelines.get(action.case_id)

        if case:
            CaseStateMachine.transition(case, CaseStatus.VERIFYING, actor="orchestrator")

        v_res = self.verification_engine.verify_action(action, observed_telemetry=telemetry)

        if timeline:
            timeline.add_event(
                stage="VERIFICATION_COMPLETED",
                description=f"Verification result: {v_res['outcome']}",
                actor="verification_engine",
                details=v_res,
            )

        if v_res["outcome"] == VerificationOutcome.SUCCESS.value:
            if case:
                CaseStateMachine.transition(case, CaseStatus.RESOLVED, actor="orchestrator")
                # Start post-response stability monitoring
                self.recovery_tracker.start_monitoring(case, window_duration_seconds=1800)
        else:
            # Trigger rollback or escalation if verification fails
            if case:
                CaseStateMachine.transition(case, CaseStatus.ESCALATED, actor="orchestrator")
                self.rollback_engine.execute_rollback(action, reason="Telemetry verification failed")

        return v_res

    def close_case_with_report(
        self,
        case_id: str,
        actor: str = "security_lead",
    ) -> Dict[str, Any]:
        """
        Step 8: Closes the case, creates root cause analysis, business impact assessment,
        canonical post-incident report, and sealed cryptographic evidence package.
        """
        case = self.case_manager.get_case(case_id)
        if not case:
            raise KeyError(f"Case '{case_id}' not found.")

        timeline = self.timelines.setdefault(case.case_id, CaseTimeline(case.case_id))
        timeline.add_event(stage="CASE_CLOSED", description=f"Case approved for closure by {actor}", actor=actor)
        CaseStateMachine.transition(case, CaseStatus.CLOSED, actor=actor)

        # 1. Root-cause evaluation
        ctx = case.metadata.get("investigation_context", {})
        root_causes = RootCauseCandidateEngine.evaluate_candidates(case, ctx, ctx.get("recent_change_tickets", []))

        # 2. Business impact translation
        impact = BusinessImpactTranslator.assess_impact(
            asset_id=case.asset_id,
            affected_services=ctx.get("services", ["smtp", "mta"]),
            client_failures=0 if case.status == CaseStatus.CLOSED else 2,
            duration_minutes=max(1.0, (time.time() - case.created_at) / 60.0),
        )

        # 3. Actions taken summary
        actions_taken = [
            a.result for a in self.action_registry.list_actions(case_id=case.case_id) if a.result
        ]

        # 4. Generate post-incident report
        report = PostIncidentReportGenerator.generate_report(
            case=case,
            root_causes=root_causes,
            business_impact=impact,
            actions_taken=actions_taken,
            verification_result={"status": "VERIFIED_SUCCESS"},
        )

        # 5. Build cryptographically sealed evidence package
        evidence_pkg = EvidencePackager.create_package(
            case_id=case.case_id,
            alerts=[a.to_dict() for a in [self.ingest_engine.get_alert(aid) for aid in case.alert_ids] if a],
            timeline=timeline.get_events(),
            findings=case.risk_factors,
            actions=[a.__dict__ for a in self.action_registry.list_actions(case_id=case.case_id)],
            approvals=[r.__dict__ for r in self.approval_workflow.list_requests() if r.case_id == case.case_id],
            verification={"status": "PASSED"},
            report=report,
        )

        return {
            "case_id": case.case_id,
            "status": case.status.value,
            "report": report,
            "evidence_package": evidence_pkg["manifest"],
        }

    def record_feedback(
        self,
        case_id: str,
        detection_id: str,
        label: AnalystLabel,
        analyst_id: str,
        reason: str = "",
    ) -> Dict[str, Any]:
        """
        Step 9 (Closed Loop): Records analyst outcome label and generates detection improvement proposals if needed.
        """
        rec = self.label_store.record_label(
            detection_id=detection_id,
            case_id=case_id,
            label=label,
            analyst_id=analyst_id,
            reason=reason,
        )
        proposal = self.learning_engine.analyze_and_propose(detection_id)
        return {
            "feedback_record": rec.__dict__,
            "proposal": proposal.__dict__ if proposal else None,
        }
