import json
import uuid
import time
import logging
import argparse
from datetime import datetime, timezone
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Any, Optional

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] Phase17 - %(message)s")
logger = logging.getLogger("Self-Healing-Orchestrator")

try:
    from fastapi import FastAPI, HTTPException, BackgroundTasks
    import uvicorn
    HAS_FASTAPI = True
except ImportError:
    HAS_FASTAPI = False
    logger.warning("FastAPI not installed. Phase 17 API mode disabled.")

@dataclass
class InfrastructureChange:
    """A specific configuration change mapped to a physical asset."""
    target_asset: str
    config_key: str # e.g., 'tls.min_version'
    new_value: Any
    previous_value: Any
    target_environment: str # e.g., 'aws-prod', 'k8s-cluster-1'

@dataclass
class IaCArtifact:
    """The generated Infrastructure-as-Code payload."""
    artifact_id: str
    engine: str # TERRAFORM, ANSIBLE, KUBERNETES
    payload: str
    rollback_payload: str
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

@dataclass
class DeploymentStrategy:
    """How the change should be rolled out."""
    mode: str = "CANARY" # CANARY, BLUE_GREEN, ALL_AT_ONCE
    canary_steps: List[int] = field(default_factory=lambda: [10, 50, 100]) # Percentages
    bake_time_seconds: int = 60 # Time to wait and monitor between steps
    error_budget: int = 5 # Max allowable failed sessions before rollback

@dataclass
class DeploymentPlan:
    """The complete execution plan generated from a Phase 16 Simulation."""
    deployment_id: str
    simulation_id: str
    changes: List[InfrastructureChange]
    artifacts: List[IaCArtifact] = field(default_factory=list)
    strategy: DeploymentStrategy = field(default_factory=DeploymentStrategy)
    status: str = "PENDING" # PENDING, DEPLOYING, BAKING, SUCCESS, ROLLING_BACK, ROLLED_BACK, FAILED
    current_step_index: int = 0
    audit_trail: List[str] = field(default_factory=list)

class IaCTranslator:
    """Translates abstract configuration changes into deployable IaC code."""
    
    def generate_artifacts(self, changes: List[InfrastructureChange]) -> List[IaCArtifact]:
        logger.info("Translating infrastructure changes into IaC artifacts...")
        artifacts = []
        
        for change in changes:
            artifact_id = f"IAC-{uuid.uuid4().hex[:6].upper()}"
            
            # Mocking generation based on environment
            if "k8s" in change.target_environment.lower():
                payload, rollback = self._generate_k8s_manifest(change)
                engine = "KUBERNETES"
            elif "aws" in change.target_environment.lower():
                payload, rollback = self._generate_terraform(change)
                engine = "TERRAFORM"
            else:
                payload, rollback = self._generate_ansible(change)
                engine = "ANSIBLE"
                
            artifacts.append(IaCArtifact(artifact_id, engine, payload, rollback))
            logger.info(f"Generated {engine} artifact {artifact_id} for {change.target_asset}")
            
        return artifacts

    def _generate_k8s_manifest(self, change: InfrastructureChange) -> tuple[str, str]:
        # Mocking a Kubernetes Ingress/Gateway API change
        payload = f"""
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: {change.target_asset}-ingress
  annotations:
    nginx.ingress.kubernetes.io/ssl-protocols: "{change.new_value}"
"""
        rollback = f"""
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: {change.target_asset}-ingress
  annotations:
    nginx.ingress.kubernetes.io/ssl-protocols: "{change.previous_value}"
"""
        return payload.strip(), rollback.strip()

    def _generate_terraform(self, change: InfrastructureChange) -> tuple[str, str]:
        payload = f'resource "aws_lb_listener" "front_end" {{\n  ssl_policy = "{change.new_value}"\n}}'
        rollback = f'resource "aws_lb_listener" "front_end" {{\n  ssl_policy = "{change.previous_value}"\n}}'
        return payload, rollback

    def _generate_ansible(self, change: InfrastructureChange) -> tuple[str, str]:
        payload = f"- name: Update Postfix TLS\n  lineinfile:\n    path: /etc/postfix/main.cf\n    line: smtpd_tls_mandatory_protocols = {change.new_value}"
        rollback = f"- name: Rollback Postfix TLS\n  lineinfile:\n    path: /etc/postfix/main.cf\n    line: smtpd_tls_mandatory_protocols = {change.previous_value}"
        return payload, rollback

class SafetyCircuitBreaker:
    """
    Monitors real-time PCAP telemetry during a deployment.
    Trips if connection errors (e.g., STARTTLS failures, TLS handshake drops) exceed the error budget.
    """
    def __init__(self):
        self.active_deployments: Dict[str, DeploymentPlan] = {}
        self.error_counters: Dict[str, int] = {}

    def register_deployment(self, plan: DeploymentPlan):
        self.active_deployments[plan.deployment_id] = plan
        self.error_counters[plan.deployment_id] = 0
        logger.info(f"[CircuitBreaker] Monitoring activated for Deployment {plan.deployment_id}")

    def ingest_telemetry_event(self, asset_id: str, event_type: str, severity: str):
        """Simulates receiving a real-time event from Phase 1-5 analyzers."""
        # Find deployments affecting this asset
        for dep_id, plan in self.active_deployments.items():
            if plan.status not in ["DEPLOYING", "BAKING"]:
                continue
                
            is_affected = any(c.target_asset == asset_id for c in plan.changes)
            if is_affected and event_type in ["STARTTLS_FAILURE", "TLS_HANDSHAKE_FAILED"]:
                self.error_counters[dep_id] += 1
                current_errors = self.error_counters[dep_id]
                logger.warning(f"[CircuitBreaker] Intercepted {event_type} on {asset_id}. Error count: {current_errors}/{plan.strategy.error_budget}")
                
                if current_errors >= plan.strategy.error_budget:
                    logger.error(f"[CircuitBreaker] 🚨 ERROR BUDGET EXCEEDED FOR {dep_id}! TRIPPING BREAKER! 🚨")
                    return dep_id # Signals the orchestrator to rollback
        return None

class DeploymentOrchestrator:
    """Executes the IaC deployments and handles canary progressions and rollbacks."""
    
    def __init__(self, translator: IaCTranslator, breaker: SafetyCircuitBreaker):
        self.translator = translator
        self.breaker = breaker
        self.deployments: Dict[str, DeploymentPlan] = {}

    def create_plan(self, simulation_id: str, changes: List[InfrastructureChange]) -> DeploymentPlan:
        dep_id = f"DEPLOY-{datetime.now(timezone.utc).strftime('%Y%m%d')}-{uuid.uuid4().hex[:4].upper()}"
        artifacts = self.translator.generate_artifacts(changes)
        
        plan = DeploymentPlan(
            deployment_id=dep_id,
            simulation_id=simulation_id,
            changes=changes,
            artifacts=artifacts
        )
        self.deployments[dep_id] = plan
        plan.audit_trail.append(f"Deployment plan created. {len(artifacts)} IaC artifacts generated.")
        return plan

    def _execute_iac(self, artifact: IaCArtifact, target: int, rollback: bool = False):
        """Mocks the execution of Terraform/Ansible/Kubectl."""
        action = "Rolling back" if rollback else "Deploying"
        payload = artifact.rollback_payload if rollback else artifact.payload
        logger.info(f"[{artifact.engine}] {action} artifact {artifact.artifact_id} (Target: {target}% fleet)...")
        # print(f"    Payload:\n      {payload.replace(chr(10), chr(10)+'      ')}")
        time.sleep(1.0) # Simulate network IO to IaC controller

    def execute_deployment(self, deployment_id: str):
        """Runs the deployment pipeline synchronously for demonstration."""
        plan = self.deployments.get(deployment_id)
        if not plan:
            raise ValueError("Deployment not found.")
            
        self.breaker.register_deployment(plan)
        plan.status = "DEPLOYING"
        
        try:
            for step_idx, rollout_pct in enumerate(plan.strategy.canary_steps):
                plan.current_step_index = step_idx
                logger.info(f"\n🚀 [Deployer] Commencing Canary Step {step_idx+1}/{len(plan.strategy.canary_steps)}: {rollout_pct}%")
                
                # 1. Apply IaC
                for artifact in plan.artifacts:
                    self._execute_iac(artifact, rollout_pct)
                
                # 2. Bake and Monitor
                plan.status = "BAKING"
                logger.info(f"⏱️ [Deployer] Baking for {plan.strategy.bake_time_seconds}s. Circuit breaker is active.")
                
                # Simulate the baking period where live traffic is monitored
                for _ in range(plan.strategy.bake_time_seconds):
                    time.sleep(0.1) # Accelerated for demo
                    
                    # Simulated mock telemetry stream based on the environment
                    if deployment_id == "FAIL_DEMO" and step_idx == 0:
                        # Artificially trigger errors to demonstrate self-healing
                        asset = plan.changes[0].target_asset
                        tripped_dep = self.breaker.ingest_telemetry_event(asset, "STARTTLS_FAILURE", "HIGH")
                        if tripped_dep == deployment_id:
                            raise Exception("Circuit breaker tripped due to excessive real-time failures.")
                            
                plan.audit_trail.append(f"Successfully completed {rollout_pct}% rollout step.")
                plan.status = "DEPLOYING"
                
            plan.status = "SUCCESS"
            logger.info(f"✅ [Deployer] Deployment {deployment_id} completed successfully.")
            
        except Exception as e:
            logger.error(f"❌ [Deployer] Deployment aborted: {e}")
            self.trigger_rollback(deployment_id)

    def trigger_rollback(self, deployment_id: str):
        """Automatically reverts IaC changes to the previous known-good state."""
        plan = self.deployments.get(deployment_id)
        plan.status = "ROLLING_BACK"
        plan.audit_trail.append("INITIATING EMERGENCY ROLLBACK.")
        
        logger.warning(f"🔄 [Rollback Engine] Reverting changes for {deployment_id}...")
        for artifact in plan.artifacts:
            # Revert to 100% of the previous known good state
            self._execute_iac(artifact, 100, rollback=True)
            
        plan.status = "ROLLED_BACK"
        plan.audit_trail.append("Rollback completed successfully. Infrastructure restored.")
        logger.info(f"🛡️ [Rollback Engine] {deployment_id} has been fully rolled back and neutralized.")

if HAS_FASTAPI:
    app = FastAPI(title="Phase 17 - Self-Healing Infrastructure API", version="17.0.0")
    
    translator = IaCTranslator()
    breaker = SafetyCircuitBreaker()
    orchestrator = DeploymentOrchestrator(translator, breaker)
    
    @app.post("/api/v1/deployments", tags=["Deployment"])
    def create_deployment(simulation_id: str, changes: List[dict]):
        infra_changes = [InfrastructureChange(**c) for c in changes]
        plan = orchestrator.create_plan(simulation_id, infra_changes)
        return asdict(plan)

    @app.post("/api/v1/deployments/{deployment_id}/execute", tags=["Deployment"])
    def execute_deployment(deployment_id: str, background_tasks: BackgroundTasks):
        if deployment_id not in orchestrator.deployments:
            raise HTTPException(404, "Deployment not found")
        background_tasks.add_task(orchestrator.execute_deployment, deployment_id)
        return {"status": "Execution started in background."}

    @app.get("/api/v1/deployments/{deployment_id}", tags=["Deployment"])
    def get_deployment_status(deployment_id: str):
        plan = orchestrator.deployments.get(deployment_id)
        if not plan:
            raise HTTPException(404, "Deployment not found")
        return asdict(plan)

def run_phase17_demo():
    print("\n" + "="*70)
    print(" PHASE 17: AUTONOMOUS SELF-HEALING & IaC ORCHESTRATION")
    print("="*70 + "\n")

    translator = IaCTranslator()
    breaker = SafetyCircuitBreaker()
    orchestrator = DeploymentOrchestrator(translator, breaker)

    # ---------------------------------------------------------
    # SCENARIO 1: Successful Deployment (Closing the loop from Phase 16)
    # ---------------------------------------------------------
    print("--- SCENARIO 1: SUCCESSFUL CANARY ROLLOUT ---")
    changes_success = [
        InfrastructureChange(
            target_asset="MTA-01",
            config_key="tls.minimum_version",
            new_value="TLSv1.2",
            previous_value="TLSv1.1",
            target_environment="k8s-prod-cluster"
        )
    ]
    
    plan_success = orchestrator.create_plan("SIM-TLS-MIGRATION-99", changes_success)
    # Fast forward baking time for the demo
    plan_success.strategy.bake_time_seconds = 5 
    
    orchestrator.execute_deployment(plan_success.deployment_id)
    print("\n")
    
    # ---------------------------------------------------------
    # SCENARIO 2: Self-Healing Rollback
    # ---------------------------------------------------------
    print("--- SCENARIO 2: CIRCUIT BREAKER & AUTO-ROLLBACK ---")
    changes_fail = [
        InfrastructureChange(
            target_asset="MTA-02",
            config_key="smtp.require_starttls",
            new_value="true",
            previous_value="false",
            target_environment="aws-ec2-legacy"
        )
    ]
    
    plan_fail = orchestrator.create_plan("SIM-STARTTLS-ENFORCE-01", changes_fail)
    plan_fail.strategy.bake_time_seconds = 10
    
    # We hijack the ID so our demo logic triggers failures in the loop
    orchestrator.deployments["FAIL_DEMO"] = plan_fail
    plan_fail.deployment_id = "FAIL_DEMO"
    
    orchestrator.execute_deployment("FAIL_DEMO")
    
    print("\n[Audit Trail for FAIL_DEMO]")
    for log in plan_fail.audit_trail:
        print(f"  -> {log}")
        
    print("\n[✓] Phase 17 Complete. The platform is now capable of autonomous infrastructure healing.")

def main():
    parser = argparse.ArgumentParser(description="Phase 17 - Autonomous Self-Healing")
    parser.add_argument("command", choices=["serve", "demo"], help="Command to run", default="demo", nargs="?")
    args = parser.parse_args()

    if args.command == "serve":
        if HAS_FASTAPI:
            print("Starting Phase 17 Self-Healing API on port 8000...")
            uvicorn.run(app, host="127.0.0.1", port=8000)
        else:
            print("FastAPI not installed. Run 'demo' instead.")
    elif args.command == "demo":
        run_phase17_demo()

if __name__ == "__main__":
    main()