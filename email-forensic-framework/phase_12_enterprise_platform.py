import json
import time
import uuid
import hashlib
import asyncio
import logging
import argparse
from datetime import datetime, timezone
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Any, Optional, Callable

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] Phase12 - %(message)s")
logger = logging.getLogger("Enterprise-Platform")

try:
    from fastapi import FastAPI, HTTPException, Security, Depends, Request
    from fastapi.security import APIKeyHeader
    import uvicorn
    HAS_FASTAPI = True
except ImportError:
    HAS_FASTAPI = False
    logger.warning("FastAPI not installed. Enterprise API mode disabled.")

# --- ENTERPRISE DATA MODELS ---

@dataclass
class Tenant:
    tenant_id: str
    name: str
    subscription_tier: str
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

@dataclass
class User:
    user_id: str
    tenant_id: str
    username: str
    roles: List[str]

@dataclass
class PCAPJob:
    job_id: str
    tenant_id: str
    pcap_uri: str
    sha256: str
    status: str = "QUEUED"  # QUEUED, RUNNING, COMPLETED, FAILED
    priority: str = "NORMAL"
    worker_id: Optional[str] = None
    policy_version: str = "latest"
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    completed_at: Optional[str] = None

@dataclass
class AuditEvent:
    event_id: str
    tenant_id: str
    timestamp: str
    actor: str
    action: str
    resource: str
    previous_hash: str
    event_hash: str = ""

@dataclass
class ComplianceControl:
    control_id: str
    name: str
    description: str
    status: str = "UNKNOWN" # COMPLIANT, NON_COMPLIANT, PARTIAL
    violations: int = 0
    evidence_links: List[str] = field(default_factory=list)


# --- CORE ENTERPRISE ENGINES ---

class TamperEvidentLog:
    """Maintains a cryptographic chain of custody for all forensic and system events."""
    
    def __init__(self):
        self.chain: List[AuditEvent] = []
        self._last_hash = hashlib.sha256(b"genesis_block").hexdigest()

    def record_event(self, tenant_id: str, actor: str, action: str, resource: str) -> AuditEvent:
        event_id = f"AUD-{uuid.uuid4().hex[:8].upper()}"
        timestamp = datetime.now(timezone.utc).isoformat()
        
        # Prepare content for hashing
        content = f"{event_id}|{tenant_id}|{timestamp}|{actor}|{action}|{resource}|{self._last_hash}"
        event_hash = hashlib.sha256(content.encode('utf-8')).hexdigest()
        
        event = AuditEvent(
            event_id=event_id,
            tenant_id=tenant_id,
            timestamp=timestamp,
            actor=actor,
            action=action,
            resource=resource,
            previous_hash=self._last_hash,
            event_hash=event_hash
        )
        
        self.chain.append(event)
        self._last_hash = event_hash
        logger.info(f"Audit Logged: {actor} performed {action} on {resource} (Hash: {event_hash[:8]}...)")
        return event

    def verify_chain(self) -> bool:
        """Validates the cryptographic integrity of the entire audit history."""
        logger.info("Verifying Tamper-Evident Audit Chain...")
        recalculated_prev = hashlib.sha256(b"genesis_block").hexdigest()
        
        for event in self.chain:
            if event.previous_hash != recalculated_prev:
                logger.error(f"CHAIN BROKEN at {event.event_id}: Invalid previous hash.")
                return False
            
            content = f"{event.event_id}|{event.tenant_id}|{event.timestamp}|{event.actor}|{event.action}|{event.resource}|{event.previous_hash}"
            recalculated_hash = hashlib.sha256(content.encode('utf-8')).hexdigest()
            
            if event.event_hash != recalculated_hash:
                logger.error(f"CHAIN BROKEN at {event.event_id}: Hash mismatch (tampering detected).")
                return False
                
            recalculated_prev = event.event_hash
            
        logger.info(f"Audit Chain Validated. {len(self.chain)} events intact.")
        return True


class ObjectStore:
    """Mock implementation of S3/MinIO for secure forensic data lake storage."""
    def __init__(self):
        self.storage: Dict[str, Dict[str, Any]] = {}

    def upload_evidence(self, tenant_id: str, uploader: str, filename: str, content: bytes, audit_log: TamperEvidentLog) -> Dict[str, Any]:
        """Calculates hash during upload to ensure immediate evidence integrity."""
        file_hash = hashlib.sha256(content).hexdigest()
        object_uri = f"s3://forensics/{tenant_id}/{datetime.now(timezone.utc).strftime('%Y/%m')}/{uuid.uuid4().hex[:6]}_{filename}"
        
        metadata = {
            "uri": object_uri,
            "filename": filename,
            "sha256": file_hash,
            "size_bytes": len(content),
            "uploaded_by": uploader,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "immutable": True
        }
        
        self.storage[object_uri] = metadata
        audit_log.record_event(tenant_id, uploader, "UPLOAD_EVIDENCE", object_uri)
        return metadata


class PolicyEngine:
    """Manages versioned, declarative security policies per tenant."""
    def __init__(self):
        self.policies: Dict[str, Dict[str, Any]] = {}
        self._load_defaults()

    def _load_defaults(self):
        # In production, these are loaded from YAML files or GitOps pipelines.
        self.policies["strict-prod-2026.09"] = {
            "tls": {"minimum_version": "TLS 1.2", "preferred": "TLS 1.3"},
            "certificates": {"rsa_min_bits": 2048, "reject_sha1": True},
            "protocols": {"tls1.0": "CRITICAL", "tls1.1": "HIGH"}
        }

    def evaluate_compliance(self, findings: List[Dict[str, Any]], policy_id: str) -> List[ComplianceControl]:
        """Maps specific technical findings to overarching compliance controls."""
        logger.info(f"Evaluating compliance against policy: {policy_id}")
        
        controls = [
            ComplianceControl("TLS-MIN-001", "Approved TLS Versions", "Enforce TLS 1.2+"),
            ComplianceControl("CERT-STR-001", "Certificate Strength", "Enforce 2048-bit+ RSA and SHA-256+")
        ]
        
        # Mock evaluation logic
        for finding in findings:
            if finding.get("rule_id") == "TLS_DEPRECATED":
                controls[0].status = "NON_COMPLIANT"
                controls[0].violations += 1
                controls[0].evidence_links.append(finding.get("session_id"))
            if finding.get("rule_id") in ["WEAK_RSA", "SHA1_SIG"]:
                controls[1].status = "NON_COMPLIANT"
                controls[1].violations += 1
                controls[1].evidence_links.append(finding.get("session_id"))
                
        # Mark compliant if no violations
        for c in controls:
            if c.status == "UNKNOWN" and c.violations == 0:
                c.status = "COMPLIANT"
                
        return controls


class EventBus:
    """Asynchronous event router for decoupled architecture."""
    def __init__(self):
        self.subscribers: Dict[str, List[Callable]] = {}

    def subscribe(self, event_type: str, handler: Callable):
        if event_type not in self.subscribers:
            self.subscribers[event_type] = []
        self.subscribers[event_type].append(handler)

    async def publish(self, event_type: str, payload: Dict[str, Any]):
        logger.debug(f"Event Published: {event_type}")
        if event_type in self.subscribers:
            for handler in self.subscribers[event_type]:
                await handler(payload)


class DistributedQueue:
    """Manages asynchronous analysis jobs across simulated workers."""
    def __init__(self, event_bus: EventBus, audit_log: TamperEvidentLog):
        self.jobs: Dict[str, PCAPJob] = {}
        self.queue = asyncio.Queue()
        self.event_bus = event_bus
        self.audit = audit_log

    async def submit_job(self, tenant_id: str, pcap_uri: str, sha256: str, submitter: str) -> str:
        job_id = f"JOB-{uuid.uuid4().hex[:6].upper()}"
        job = PCAPJob(job_id=job_id, tenant_id=tenant_id, pcap_uri=pcap_uri, sha256=sha256)
        
        self.jobs[job_id] = job
        await self.queue.put(job)
        
        self.audit.record_event(tenant_id, submitter, "SUBMIT_JOB", job_id)
        await self.event_bus.publish("JOB_QUEUED", asdict(job))
        return job_id

    async def worker_loop(self, worker_name: str, is_gpu: bool = False):
        """Simulates a distributed worker node processing PCAPs."""
        logger.info(f"Worker {worker_name} [GPU={is_gpu}] started and listening for jobs...")
        while True:
            job: PCAPJob = await self.queue.get()
            job.status = "RUNNING"
            job.worker_id = worker_name
            await self.event_bus.publish("JOB_STARTED", asdict(job))
            
            logger.info(f"[{worker_name}] Processing {job.job_id} for tenant {job.tenant_id}...")
            
            # Simulate CPU/GPU bound pipeline processing (Phases 1-8)
            try:
                processing_time = 1.0 if is_gpu else 2.5
                await asyncio.sleep(processing_time) 
                
                job.status = "COMPLETED"
                job.completed_at = datetime.now(timezone.utc).isoformat()
                
                # Emit finding events to simulate pipeline output
                await self.event_bus.publish("FINDING_CREATED", {
                    "tenant_id": job.tenant_id,
                    "job_id": job.job_id,
                    "rule_id": "TLS_DEPRECATED",
                    "session_id": f"FLOW-{uuid.uuid4().hex[:4]}",
                    "severity": "HIGH"
                })
                
                logger.info(f"[{worker_name}] Completed {job.job_id} successfully.")
                await self.event_bus.publish("JOB_COMPLETED", asdict(job))
                
            except Exception as e:
                job.status = "FAILED"
                logger.error(f"[{worker_name}] Job {job.job_id} failed: {e}")
                await self.event_bus.publish("JOB_FAILED", asdict(job))
            finally:
                self.queue.task_done()


if HAS_FASTAPI:
    app = FastAPI(
        title="Phase 12 - Enterprise Control Plane",
        description="Centralized multi-tenant governance, API gateway, and distributed processing controller.",
        version="12.0.0"
    )

    # In-memory singletons for the API
    audit_log = TamperEvidentLog()
    object_store = ObjectStore()
    policy_engine = PolicyEngine()
    event_bus = EventBus()
    job_queue = DistributedQueue(event_bus, audit_log)
    
    # Mock Database
    MOCK_USERS = {
        "admin-key": User("U-01", "enterprise-a", "alice_admin", ["SUPER_ADMIN", "SOC_ANALYST"]),
        "auditor-key": User("U-02", "enterprise-a", "bob_auditor", ["AUDITOR"]),
    }

    api_key_header = APIKeyHeader(name="X-API-KEY", auto_error=True)

    async def get_current_user(key: str = Depends(api_key_header)) -> User:
        user = MOCK_USERS.get(key)
        if not user:
            raise HTTPException(status_code=401, detail="Invalid API Key")
        return user

    def require_role(required_role: str):
        """RBAC Dependency Injection."""
        def role_checker(user: User = Depends(get_current_user)):
            if required_role not in user.roles and "SUPER_ADMIN" not in user.roles:
                audit_log.record_event(user.tenant_id, user.username, "ACCESS_DENIED", f"Role Required: {required_role}")
                raise HTTPException(status_code=403, detail="Insufficient permissions")
            return user
        return role_checker

    @app.post("/api/v1/pcaps", tags=["Storage"])
    async def upload_pcap(filename: str, user: User = Depends(require_role("SOC_ANALYST"))):
        """Simulates secure evidence ingestion to the object store."""
        # Mock file content
        mock_content = b"dummy_pcap_binary_data_" + filename.encode()
        metadata = object_store.upload_evidence(user.tenant_id, user.username, filename, mock_content, audit_log)
        return {"status": "UPLOADED", "evidence": metadata}

    @app.post("/api/v1/jobs", tags=["Processing"])
    async def create_analysis_job(pcap_uri: str, sha256: str, user: User = Depends(require_role("SOC_ANALYST"))):
        """Submits a PCAP to the distributed worker queue."""
        job_id = await job_queue.submit_job(user.tenant_id, pcap_uri, sha256, user.username)
        return {"job_id": job_id, "status": "QUEUED"}

    @app.get("/api/v1/jobs/{job_id}", tags=["Processing"])
    async def get_job_status(job_id: str, user: User = Depends(get_current_user)):
        job = job_queue.jobs.get(job_id)
        if not job or job.tenant_id != user.tenant_id: # Tenant Isolation Check
            raise HTTPException(status_code=404, detail="Job not found")
        return asdict(job)

    @app.get("/api/v1/compliance", tags=["Governance"])
    async def get_compliance_posture(policy_id: str = "strict-prod-2026.09", user: User = Depends(get_current_user)):
        """Calculates enterprise compliance based on policies."""
        # Mocking findings for the demo
        mock_findings = [{"rule_id": "TLS_DEPRECATED", "session_id": "FLOW-999"}]
        controls = policy_engine.evaluate_compliance(mock_findings, policy_id)
        
        audit_log.record_event(user.tenant_id, user.username, "VIEW_COMPLIANCE", policy_id)
        return {"tenant_id": user.tenant_id, "policy": policy_id, "controls": [asdict(c) for c in controls]}

    @app.get("/api/v1/audit/verify", tags=["Governance"])
    async def verify_audit_chain(user: User = Depends(require_role("AUDITOR"))):
        """Cryptographically verifies the platform's audit chain."""
        is_valid = audit_log.verify_chain()
        audit_log.record_event(user.tenant_id, user.username, "VERIFY_AUDIT_CHAIN", "SYSTEM")
        return {"chain_valid": is_valid, "event_count": len(audit_log.chain)}


async def run_enterprise_demo():
    print("\n" + "="*60)
    print(" PHASE 12: ENTERPRISE PLATFORM & DISTRIBUTED WORKERS DEMO")
    print("="*60 + "\n")

    audit = TamperEvidentLog()
    store = ObjectStore()
    bus = EventBus()
    queue = DistributedQueue(bus, audit)
    policy = PolicyEngine()

    # 1. Setup simulated event listeners (e.g., SIEM integration or Reporting)
    findings_db = []
    
    async def on_finding(payload):
        findings_db.append(payload)
        print(f"  [EventBus] -> SIEM Notified: Finding {payload['rule_id']} for {payload['session_id']}")

    bus.subscribe("FINDING_CREATED", on_finding)

    # 2. Start Distributed Workers in the background
    print("[*] Starting distributed workers (1 CPU, 1 GPU)...")
    worker1 = asyncio.create_task(queue.worker_loop("CPU-Node-01", is_gpu=False))
    worker2 = asyncio.create_task(queue.worker_loop("GPU-Node-01", is_gpu=True))
    
    await asyncio.sleep(0.5)

    # 3. Secure Ingestion (Simulating Web UI Upload)
    tenant = "enterprise-a"
    actor = "alice_analyst"
    
    print(f"\n[*] {actor} uploading large enterprise PCAP to object store...")
    meta = store.upload_evidence(tenant, actor, "hq_traffic_01.pcap", b"mock_binary_data", audit)
    print(json.dumps(meta, indent=2))

    # 4. Job Submission
    print(f"\n[*] Submitting distributed analysis jobs...")
    job1_id = await queue.submit_job(tenant, meta["uri"], meta["sha256"], actor)
    job2_id = await queue.submit_job(tenant, "s3://forensics/enterprise-a/historical.pcap", "mockhash", actor)

    # Wait for queue to empty
    await queue.queue.join()

    # 5. Continuous Compliance Evaluation
    print("\n[*] Evaluating Continuous Compliance Posture...")
    controls = policy.evaluate_compliance(findings_db, "strict-prod-2026.09")
    for c in controls:
        print(f"  -> {c.control_id} [{c.status}]: {c.violations} violations. Links: {c.evidence_links}")

    # 6. Audit & Integrity Check (Auditor Workflow)
    print("\n[*] Internal Auditor verifying tamper-evident chain of custody...")
    audit.record_event(tenant, "bob_auditor", "DOWNLOAD_REPORT", "CASE-001")
    audit.verify_chain()
    
    print("\n[*] Simulating malicious database tampering...")
    # Deliberately modify an old record to test the cryptographic chain
    audit.chain[0].action = "DELETED_EVIDENCE" 
    audit.verify_chain() # Should fail!

    # Cleanup workers
    worker1.cancel()
    worker2.cancel()


def main():
    parser = argparse.ArgumentParser(description="Phase 12 - Enterprise Platform")
    parser.add_argument("command", choices=["serve", "demo"], help="Command to run")
    args = parser.parse_args()

    if args.command == "serve":
        if HAS_FASTAPI:
            print("Starting Enterprise API Gateway on port 8000...")
            print("To authenticate, use Header: X-API-KEY: admin-key")
            uvicorn.run(app, host="127.0.0.1", port=8000)
        else:
            print("FastAPI not installed. Run 'demo' instead.")
    elif args.command == "demo":
        asyncio.run(run_enterprise_demo())


if __name__ == "__main__":
    import sys
    if len(sys.argv) == 1:
        sys.argv.append("demo")
    main()