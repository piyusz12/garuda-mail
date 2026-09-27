import json
import uuid
import logging
import argparse
from datetime import datetime, timezone
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Any, Optional

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] Phase11 - %(message)s")
logger = logging.getLogger("Response-Orchestration")

try:
    from fastapi import FastAPI, HTTPException, BackgroundTasks
    import uvicorn
    HAS_FASTAPI = True
except ImportError:
    HAS_FASTAPI = False
    logger.warning("FastAPI not installed. API mode disabled.")

# --- DATA MODELS ---

@dataclass
class Finding:
    finding_id: str
    rule_id: str
    severity: str
    asset_id: str
    session_count: int
    description: str

@dataclass
class ResponseAction:
    action_id: str
    incident_id: str
    action_type: str # e.g., CREATE_TICKET, UPDATE_TLS_POLICY
    target_asset: str
    requires_approval: bool
    status: str = "PENDING_APPROVAL" # PROPOSED, PENDING_APPROVAL, APPROVED, REJECTED, EXECUTED, FAILED
    parameters: Dict[str, Any] = field(default_factory=dict)
    external_reference: Optional[str] = None
    executed_at: Optional[datetime] = None

@dataclass
class Incident:
    incident_id: str
    title: str
    status: str = "NEW" # NEW, TRIAGED, INVESTIGATING, REMEDIATION, VERIFYING, RESOLVED, CLOSED
    risk_score: float = 0.0
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    findings: List[Finding] = field(default_factory=list)
    actions: List[ResponseAction] = field(default_factory=list)
    timeline: List[Dict[str, str]] = field(default_factory=list)
    evidence_manifest: Dict[str, Any] = field(default_factory=dict)
    owner: Optional[str] = None

class IncidentManager:
    """Consolidates related findings into actionable Incident cases."""
    
    def __init__(self):
        self.incidents: Dict[str, Incident] = {}

    def correlate_findings(self, findings: List[Finding], context: Dict[str, Any]) -> Incident:
        """Groups related findings (e.g., STARTTLS failure + AI anomaly) into one incident."""
        inc_id = f"INC-{datetime.now(timezone.utc).strftime('%Y%m%d')}-{uuid.uuid4().hex[:4].upper()}"
        
        # Determine highest severity for title and risk approximation
        primary_asset = findings[0].asset_id if findings else "UNKNOWN_ASSET"
        
        incident = Incident(
            incident_id=inc_id,
            title=f"Security Degradation on {primary_asset}",
            risk_score=context.get("aggregated_risk", 85.0),
            findings=findings,
            evidence_manifest={
                "pcap_hash": context.get("pcap_hash", "UNKNOWN"),
                "affected_sessions": sum(f.session_count for f in findings),
                "ai_anomalies": context.get("ai_anomalies", 0)
            }
        )
        
        self.add_timeline_event(incident, "Incident correlated and created automatically.")
        self.incidents[inc_id] = incident
        logger.info(f"Created {inc_id} containing {len(findings)} findings.")
        return incident

    def add_timeline_event(self, incident: Incident, description: str):
        event = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "description": description
        }
        incident.timeline.append(event)
        
    def get_incident(self, incident_id: str) -> Optional[Incident]:
        return self.incidents.get(incident_id)


class PlaybookEngine:
    """Maps findings to standardized Response Actions based on playbooks."""
    
    PLAYBOOKS = {
        "STARTTLS_FAILURE": [
            {"action_type": "CREATE_TICKET", "requires_approval": False, "params": {"priority": "High"}},
            {"action_type": "UPDATE_TLS_POLICY", "requires_approval": True, "params": {"enforce_tls": True}}
        ],
        "TLS_DEPRECATED": [
            {"action_type": "CREATE_TICKET", "requires_approval": False, "params": {"priority": "Medium"}},
            {"action_type": "DISABLE_LEGACY_CIPHERS", "requires_approval": True, "params": {"min_version": "TLS 1.2"}}
        ]
    }

    def generate_response_plan(self, incident: Incident) -> List[ResponseAction]:
        """Proposes a list of actions based on the incident's findings."""
        actions = []
        applied_playbooks = set()
        
        for finding in incident.findings:
            if finding.rule_id in self.PLAYBOOKS and finding.rule_id not in applied_playbooks:
                applied_playbooks.add(finding.rule_id)
                for step in self.PLAYBOOKS[finding.rule_id]:
                    act = ResponseAction(
                        action_id=f"ACT-{uuid.uuid4().hex[:6].upper()}",
                        incident_id=incident.incident_id,
                        action_type=step["action_type"],
                        target_asset=finding.asset_id,
                        requires_approval=step["requires_approval"],
                        status="PENDING_APPROVAL" if step["requires_approval"] else "APPROVED",
                        parameters=step.get("params", {})
                    )
                    actions.append(act)
                    incident.actions.append(act)
                    
        return actions


class BaseConnector:
    def execute(self, action: ResponseAction) -> Dict[str, Any]:
        raise NotImplementedError

class TicketingConnector(BaseConnector):
    def execute(self, action: ResponseAction) -> Dict[str, Any]:
        # Mocking an external JIRA/ServiceNow API call
        ticket_id = f"TICKET-{uuid.uuid4().hex[:5].upper()}"
        logger.info(f"External API: Created ticket {ticket_id} for asset {action.target_asset}")
        return {"status": "SUCCESS", "external_id": ticket_id}

class ConfigurationConnector(BaseConnector):
    def execute(self, action: ResponseAction) -> Dict[str, Any]:
        # Mocking an infrastructure deployment (e.g., Ansible, Chef, API)
        logger.warning(f"External API: Applied {action.action_type} to {action.target_asset}! (Requires Verification)")
        return {"status": "SUCCESS", "external_id": "JOB-9921"}


class ActionExecutor:
    """Manages the execution of actions, respecting approval gates."""
    def __init__(self):
        self.connectors = {
            "CREATE_TICKET": TicketingConnector(),
            "UPDATE_TLS_POLICY": ConfigurationConnector(),
            "DISABLE_LEGACY_CIPHERS": ConfigurationConnector()
        }

    def execute_action(self, action: ResponseAction, incident_manager: IncidentManager) -> bool:
        if action.status not in ["APPROVED", "AUTO_APPROVED"]:
            logger.error(f"Action {action.action_id} cannot be executed. Status: {action.status}")
            return False
            
        connector = self.connectors.get(action.action_type)
        if not connector:
            logger.error(f"No connector found for {action.action_type}")
            action.status = "FAILED"
            return False

        try:
            result = connector.execute(action)
            action.status = "EXECUTED"
            action.executed_at = datetime.now(timezone.utc)
            action.external_reference = result.get("external_id")
            
            incident = incident_manager.get_incident(action.incident_id)
            if incident:
                incident_manager.add_timeline_event(incident, f"Executed action {action.action_type} ({action.action_id})")
                
            return True
        except Exception as e:
            action.status = "FAILED"
            logger.error(f"Action execution failed: {e}")
            return False


class VerificationEngine:
    """Compares pre-remediation metrics to post-remediation metrics to verify success."""
    
    def verify_remediation(self, incident: Incident, before_metrics: Dict[str, int], after_metrics: Dict[str, int]) -> str:
        """
        Example: 
        Before: {"STARTTLS_FAILURE": 82}
        After:  {"STARTTLS_FAILURE": 0}
        """
        logger.info(f"Verifying remediation for {incident.incident_id}...")
        
        is_resolved = True
        verification_details = []
        
        for metric, before_val in before_metrics.items():
            after_val = after_metrics.get(metric, 0)
            if after_val > 0 and after_val >= (before_val * 0.1): # e.g., didn't fix at least 90%
                is_resolved = False
                verification_details.append(f"{metric} still present ({after_val} occurrences).")
            else:
                verification_details.append(f"{metric} resolved ({before_val} -> {after_val}).")

        if is_resolved:
            incident.status = "RESOLVED"
            logger.info("VERIFICATION PASSED: Incident resolved.")
        else:
            incident.status = "REMEDIATION_FAILED"
            logger.warning(f"VERIFICATION FAILED: {verification_details}")
            
        return incident.status

if HAS_FASTAPI:
    app = FastAPI(title="Phase 11 - Orchestration API")
    inc_manager = IncidentManager()
    playbook_engine = PlaybookEngine()
    executor = ActionExecutor()
    verifier = VerificationEngine()

    @app.post("/api/incidents")
    def create_incident(findings_payload: List[dict]):
        findings = [Finding(**f) for f in findings_payload]
        incident = inc_manager.correlate_findings(findings, {"aggregated_risk": 90.0})
        
        # Auto-generate response plan
        playbook_engine.generate_response_plan(incident)
        return {"incident_id": incident.incident_id, "actions_proposed": len(incident.actions)}

    @app.get("/api/incidents/{incident_id}")
    def get_incident(incident_id: str):
        inc = inc_manager.get_incident(incident_id)
        if not inc:
            raise HTTPException(status_code=404, detail="Incident not found")
        return asdict(inc)

    @app.post("/api/actions/{action_id}/approve")
    def approve_action(action_id: str, incident_id: str, approver: str = "Admin"):
        inc = inc_manager.get_incident(incident_id)
        if not inc:
            raise HTTPException(status_code=404, detail="Incident not found")
            
        for action in inc.actions:
            if action.action_id == action_id and action.status == "PENDING_APPROVAL":
                action.status = "APPROVED"
                inc_manager.add_timeline_event(inc, f"Action {action_id} approved by {approver}.")
                
                # Execute immediately upon approval for this demo
                executor.execute_action(action, inc_manager)
                return {"status": "Action Approved and Executed", "action": asdict(action)}
                
        raise HTTPException(status_code=400, detail="Action not found or already processed")

def run_demo():
    print("\n" + "="*50)
    print(" PHASE 11: RESPONSE & ORCHESTRATION DEMO")
    print("="*50 + "\n")
    
    inc_manager = IncidentManager()
    playbook_engine = PlaybookEngine()
    executor = ActionExecutor()
    verifier = VerificationEngine()

    # 1. Detection Phase (From Phase 10)
    print("[1] DETECT: Ingesting correlated findings...")
    findings = [
        Finding("F-01", "STARTTLS_FAILURE", "CRITICAL", "smtp.enterprise.com", 82, "STARTTLS explicitly rejected by server"),
        Finding("F-02", "PLAINTEXT_AUTH", "CRITICAL", "smtp.enterprise.com", 82, "Auth occurring over plaintext")
    ]
    incident = inc_manager.correlate_findings(findings, {"aggregated_risk": 95.0, "ai_anomalies": 12})
    
    # 2. Response Planning
    print(f"\n[2] PLAN: Generating Response Playbook for {incident.incident_id}...")
    incident.status = "TRIAGED"
    actions = playbook_engine.generate_response_plan(incident)
    
    print("\nProposed Actions:")
    for a in actions:
        auth_req = "[Approval Required]" if a.requires_approval else "[Auto-Approve]"
        print(f"  -> {a.action_id} | {a.action_type} | {auth_req}")

    # 3. Execution (Automated vs Human)
    print("\n[3] EXECUTE: Processing Actions...")
    incident.status = "REMEDIATION"
    for action in actions:
        if not action.requires_approval:
            print(f"  -> Auto-executing {action.action_type}...")
            action.status = "AUTO_APPROVED"
            executor.execute_action(action, inc_manager)
        else:
            print(f"  -> {action.action_type} requires HUMAN APPROVAL. Simulating Admin approval...")
            action.status = "APPROVED"
            inc_manager.add_timeline_event(incident, f"Human Admin approved {action.action_type}")
            executor.execute_action(action, inc_manager)
            
    # 4. Verification (Post-Remediation)
    print("\n[4] VERIFY: Simulating post-remediation traffic capture...")
    incident.status = "VERIFYING"
    before_state = {"STARTTLS_FAILURE": 82, "PLAINTEXT_AUTH": 82}
    after_state = {"STARTTLS_FAILURE": 0, "PLAINTEXT_AUTH": 0} # Remediation was successful
    
    verifier.verify_remediation(incident, before_state, after_state)
    
    # 5. Incident Summary
    print("\n[5] CLOSURE: Incident Final State")
    print(json.dumps(asdict(incident), indent=2, default=str))

def main():
    parser = argparse.ArgumentParser(description="Phase 11 - Orchestration Engine")
    parser.add_argument("command", choices=["serve", "demo"], help="Command to run")
    args = parser.parse_args()

    if args.command == "serve":
        if HAS_FASTAPI:
            print("Starting Phase 11 Orchestration API on port 8000...")
            uvicorn.run(app, host="127.0.0.1", port=8000)
        else:
            print("FastAPI not installed. Run 'demo' instead.")
    elif args.command == "demo":
        run_demo()

if __name__ == "__main__":
    import sys
    if len(sys.argv) == 1:
        sys.argv.append("demo")
    main()