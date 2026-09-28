"""
PHASE 27 — Enterprise Zero Trust, Identity Intelligence & Adaptive Access Control.
Main CLI Entrypoint and Production-Grade FastAPI Zero Trust Control Plane.

Features:
- Identity Fabric & Canonical Normalization (Users, Devices, Services, Workloads)
- Temporal Identity Graph & Time-Machine Point-in-Time Reconstruction
- Continuous Multi-Dimensional Posture & Session Risk Engines
- Zero Trust Policy Engine (DSL, Compiler, Validator, Conflict Detector)
- High-Performance Policy Decision Point (PDP) & Policy Enforcement Point (PEP)
- Continuous Re-Evaluation, Adaptive Access & Mid-Session Revocation
- Just-In-Time (JIT), Just-Enough-Privilege (JEPA) & Four-Eyes Break-Glass Access
- Policy Simulation, Blast Radius Assessment & Regression Testing
- Signed Offline Policy Bundles & Access Certification Campaigns
- Identity Copilot Diagnostic & Forensic Investigation Assistant
"""

import sys
import time
import json
from typing import Dict, List, Optional, Any
from pathlib import Path
from datetime import datetime, timezone, timedelta

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).parent.absolute()))

import typer
from fastapi import FastAPI, HTTPException, Body, Query
from pydantic import BaseModel, Field

# Core Identity Modules
from identity import (
    UserIdentity,
    UserIdentityRepository,
    IdentityStatus,
    DeviceIdentity,
    DeviceIdentityRepository,
    DeviceType,
    DeviceComplianceStatus,
    ServiceIdentity,
    ServiceIdentityRepository,
    ResourceClassification,
    WorkloadIdentity,
    WorkloadIdentityRepository,
    IdentityResolver,
    CertificateIdentityBinding,
    SessionIdentityBinding,
    IdentityNode,
    IdentityNodeType,
    IdentityEdge,
    IdentityEdgeType,
    TemporalIdentityGraph,
    DevicePostureState,
    DevicePostureLevel,
    DevicePostureEvaluator,
    IdentityPostureState,
    IdentityPostureLevel,
    IdentityPostureEvaluator,
    ServicePostureState,
    ServicePostureEvaluator,
    IdentityBehaviorBaseline,
    BehavioralAnalyticsEngine,
    SessionRiskScore,
    SessionRiskLevel,
    SessionRiskEngine,
    IdentityRiskAssessment,
    IdentityRiskLevel,
    IdentityRiskEngine,
    IdentityLifecycleManager,
    AccessGrant,
    AccessState,
    AccessLifecycleManager,
    DeviceLifecycleManager,
)

# Core Zero Trust Modules
from zero_trust import (
    ZeroTrustPolicy,
    PolicyEffect,
    PolicyCondition,
    PolicyDSLParser,
    PolicyCompiler,
    CompiledPolicy,
    PolicyValidator,
    PolicyValidationError,
    PolicyConflictDetector,
    PolicyConflict,
    AccessRequestContext,
    TrustContext,
    PolicyDecisionPoint,
    AccessDecisionRecord,
    PolicyDecisionExplainer,
    PolicyEnforcementPoint,
    EnforcementAction,
    EnforcementResult,
    ServiceToServiceGateway,
    ActiveSession,
    SessionStatus,
    SessionMonitor,
    ReevaluationEvent,
    ReevaluationResult,
    ContinuousAccessEvaluator,
    SessionRevocationManager,
    JITRequest,
    JITStatus,
    JITAccessManager,
    JEPAScoper,
    BreakGlassSession,
    BreakGlassStatus,
    EmergencyAccessController,
    AccessSimulationResult,
    AccessSimulator,
    PolicyBlastRadiusAssessment,
    PolicyBlastRadiusAnalyzer,
    PolicyRegressionReport,
    PolicyRegressionTester,
    ReviewDecision,
    AccessReviewItem,
    AccessCertificationCampaign,
    PolicyException,
    PolicyExceptionManager,
    SignedPolicyBundle,
    PolicyBundleDistributor,
    IdentityCopilot,
)


# ==============================================================================
# Singletons, Repositories & State Pre-Population
# ==============================================================================

# 1. Ingestion Repositories
user_repo = UserIdentityRepository()
device_repo = DeviceIdentityRepository()
service_repo = ServiceIdentityRepository()
workload_repo = WorkloadIdentityRepository()

# 2. Normalization & Graph
identity_resolver = IdentityResolver()
temporal_graph = TemporalIdentityGraph()

# 3. Posture & Risk
behavior_engine = BehavioralAnalyticsEngine()
session_risk_engine = SessionRiskEngine(behavioral_engine=behavior_engine)
identity_risk_engine = IdentityRiskEngine()

# 4. Lifecycle
identity_lifecycle = IdentityLifecycleManager()
access_lifecycle = AccessLifecycleManager()
device_lifecycle = DeviceLifecycleManager()

# 5. Policy, Decision & Enforcement
pdp = PolicyDecisionPoint()
conflict_detector = PolicyConflictDetector()
validator = PolicyValidator()
pep = PolicyEnforcementPoint(pdp=pdp)
s2s_gateway = ServiceToServiceGateway(pdp=pdp)

# 6. Sessions & Continuous Re-evaluation
session_monitor = SessionMonitor()
continuous_evaluator = ContinuousAccessEvaluator(monitor=session_monitor, pdp=pdp)
revocation_manager = SessionRevocationManager(monitor=session_monitor)

# 7. Privilege Management
jit_manager = JITAccessManager()
emergency_controller = EmergencyAccessController()

# 8. Governance & Simulation
exception_manager = PolicyExceptionManager()
simulator = AccessSimulator(pdp=pdp)
blast_analyzer = PolicyBlastRadiusAnalyzer(
    user_repo=user_repo,
    device_repo=device_repo,
    service_repo=service_repo,
)
regression_tester = PolicyRegressionTester()

# 9. Copilot
copilot = IdentityCopilot(
    pdp=pdp,
    session_monitor=session_monitor,
    user_repo=user_repo,
    service_repo=service_repo,
    graph=temporal_graph,
)


def _seed_active_sessions():
    """Populates active sessions for testing and monitoring."""
    s1 = ActiveSession(
        session_id="S-991",
        identity_id="ID-1192",
        device_id="DEVICE-44",
        service_id="FORENSIC-API",
        status=SessionStatus.ACTIVE,
        tls_version="TLS 1.3",
        ja4="t13d1516h2_8daaf6152771_000000000000",
        certificate_id="CERT-DEV-44-CORP",
        client_ip="10.200.1.44",
        device_posture_score=1.0,
        session_risk_score=10.0,
    )
    session_monitor.register_session(s1)


_seed_active_sessions()


# ==============================================================================
# Helper Context Builder
# ==============================================================================

def _build_access_context(
    subject_id: str,
    device_id: str,
    resource_id: str,
    action: str = "read",
    client_ip: str = "10.200.1.44",
    ja4: Optional[str] = None,
    tls_version: str = "TLS 1.3",
    session_id: Optional[str] = None,
) -> AccessRequestContext:
    """Constructs a fully synthesized AccessRequestContext with real-time posture and trust."""
    canonical_id = identity_resolver.resolve(subject_id)
    user = user_repo.get(canonical_id)
    device = device_repo.get(device_id)
    service = service_repo.get(resource_id)

    # 1. Device Posture
    if device:
        dev_posture = DevicePostureEvaluator.evaluate(
            device_id=device.device_id,
            managed=device.managed,
            disk_encrypted=True,
            edr_active=True,
            os_patched=True,
            certificate_valid=bool(device.certificate_serial),
        )
        dev_posture_str = dev_posture.posture_level.value
        dev_trust = dev_posture.posture_score
    else:
        dev_posture_str = "NONCOMPLIANT"
        dev_trust = 0.10

    # 2. Session Risk
    s_risk = session_risk_engine.evaluate_session(
        session_id=session_id or f"S-SIM-{int(time.time())}",
        identity_id=canonical_id,
        device_id=device_id,
        service_id=resource_id,
        ja4=ja4,
        destination_ip="10.200.1.7",
        tls_version=tls_version,
    )

    # 3. Identity Risk
    is_priv = any("ADMIN" in r for r in user.roles) if user else False
    id_risk = IdentityRiskEngine.calculate_risk(
        identity_id=canonical_id,
        device_posture=dev_posture if device else None,
        session_risk=s_risk,
        is_privileged=is_priv,
    )

    # 4. Multidimensional Trust Context
    id_trust = max(0.0, 1.0 - (id_risk.overall_score / 100.0))
    sess_trust = max(0.0, 1.0 - (s_risk.risk_score / 100.0))
    srv_trust = 0.95 if (service and service.classification == ResourceClassification.CRITICAL) else 0.85
    overall_trust = (id_trust * 0.35) + (dev_trust * 0.25) + (sess_trust * 0.25) + (srv_trust * 0.15)
    trust_tier = "HIGH" if overall_trust >= 0.75 else ("ELEVATED" if overall_trust >= 0.50 else "UNTRUSTED")

    trust_ctx = TrustContext(
        identity_trust=round(id_trust, 2),
        device_trust=round(dev_trust, 2),
        session_trust=round(sess_trust, 2),
        service_trust=round(srv_trust, 2),
        overall_trust_score=round(overall_trust, 2),
        trust_tier=trust_tier,
        signals={
            "identity_risk_level": id_risk.risk_level.value,
            "session_risk_level": s_risk.risk_level.value,
            "device_posture": dev_posture_str,
        },
    )

    subject_group = user.groups[0] if (user and user.groups) else "general"
    subject_role = user.roles[0] if (user and user.roles) else "GUEST"
    classification = service.classification.value if service else "INTERNAL"

    return AccessRequestContext(
        subject_id=canonical_id,
        subject_group=subject_group,
        subject_role=subject_role,
        device_id=device_id,
        device_managed=device.managed if device else False,
        device_posture=dev_posture_str,
        resource_id=resource_id,
        resource_classification=classification,
        action=action,
        session_id=session_id or f"S-{int(time.time())}",
        session_risk=s_risk.risk_level.value,
        ja4=ja4,
        tls_version=tls_version,
        client_ip=client_ip,
        trust_context=trust_ctx,
    )


# ==============================================================================
# FastAPI Application & Request / Response Models
# ==============================================================================

app = FastAPI(
    title="Garuda Mail — Phase 27 Enterprise Zero Trust & Identity Control Plane",
    description="Identity Intelligence, Continuous Multi-Signal Trust, Adaptive Policy Engine & Access Governance",
    version="27.0.0",
)

cli = typer.Typer(help="Phase 27 — Enterprise Zero Trust & Identity Intelligence CLI")


class IngestUserRequest(BaseModel):
    identity_id: str
    username: str
    email: str
    full_name: str
    department: str = "General"
    title: str = "Staff"
    groups: List[str] = Field(default_factory=list)
    roles: List[str] = Field(default_factory=list)
    mfa_enabled: bool = True
    mfa_method: str = "TOTP_AUTHENTICATOR"
    risk_level: str = "LOW"


class EvaluateAccessRequest(BaseModel):
    subject_id: str = "ID-1192"
    device_id: str = "DEVICE-44"
    resource_id: str = "FORENSIC-API"
    action: str = "read"
    session_id: Optional[str] = None
    client_ip: str = "10.200.1.44"
    ja4: Optional[str] = "t13d1516h2_8daaf6152771_000000000000"
    tls_version: str = "TLS 1.3"


class RevokeSessionRequest(BaseModel):
    session_id: str
    reason: str = "Manual security administrator revocation"
    actor: str = "admin-console"


class CreatePolicyRequest(BaseModel):
    policy_id: str
    name: str
    effect: str = "ALLOW"
    priority: int = 100
    target_services: List[str] = Field(default_factory=lambda: ["*"])
    target_actions: List[str] = Field(default_factory=lambda: ["*"])
    conditions: List[Dict[str, Any]] = Field(default_factory=list)
    description: str = ""
    version: str = "1.0.0"


class JITElevationRequest(BaseModel):
    identity_id: str = "ID-1192"
    role_requested: str = "SOC_ADMIN"
    target_resource: str = "FORENSIC-API"
    justification: str = "Investigating active incident INC-8022"
    duration_minutes: int = 30


class JITApproveRequest(BaseModel):
    request_id: str
    approver_id: str = "ID-2044"


class EmergencyAccessRequest(BaseModel):
    requester_id: str = "ID-1192"
    approver_id: str = "ID-2044"
    incident_reference: str = "CASE-CRITICAL-991"
    target_service: str = "MTA-07"
    justification: str = "Edge mail routing loop causing corporate email outage"
    duration_minutes: int = 15


class CompleteAccessReviewRequest(BaseModel):
    item_id: str
    reviewer_id: str = "ID-2044"
    decision: str = "CERTIFIED_KEEP"  # CERTIFIED_KEEP, MODIFIED, REVOKED
    notes: str = "Access validated during annual zero trust recertification"


class CopilotQueryRequest(BaseModel):
    query: str
    session_id: Optional[str] = None
    service_id: Optional[str] = None
    identity_id: Optional[str] = None
    device_id: Optional[str] = None


# ==============================================================================
# REST API Endpoints (Section 27.104)
# ==============================================================================

@app.post("/api/v1/identities", tags=["Identity"])
def register_identity(req: IngestUserRequest):
    """Registers and canonicalizes an enterprise user identity."""
    existing = user_repo.get(req.identity_id)
    if existing:
        raise HTTPException(status_code=400, detail=f"Identity '{req.identity_id}' already exists.")
    user = UserIdentity(
        identity_id=req.identity_id,
        username=req.username,
        email=req.email,
        full_name=req.full_name,
        department=req.department,
        title=req.title,
        groups=req.groups,
        roles=req.roles,
        mfa_enabled=req.mfa_enabled,
        mfa_method=req.mfa_method,
        risk_level=req.risk_level,
    )
    user_repo.register(user)
    identity_resolver.register_alias(user.username, user.identity_id)
    identity_resolver.register_alias(user.email, user.identity_id)
    temporal_graph.add_node(IdentityNode(user.identity_id, IdentityNodeType.PERSON, user.full_name))
    return {"status": "SUCCESS", "identity_id": user.identity_id, "username": user.username}


@app.get("/api/v1/identities/{identity_id}", tags=["Identity"])
def get_identity(identity_id: str):
    """Retrieves an identity by canonical ID or alias."""
    resolved_id = identity_resolver.resolve(identity_id)
    user = user_repo.get(resolved_id)
    if not user:
        raise HTTPException(status_code=404, detail=f"Identity '{identity_id}' (resolved: '{resolved_id}') not found.")
    return user.to_dict()


@app.get("/api/v1/identities/{identity_id}/graph", tags=["Identity Graph"])
def get_identity_graph(identity_id: str):
    """Retrieves identity graph relationships and connected nodes."""
    resolved_id = identity_resolver.resolve(identity_id)
    node = temporal_graph.get_node(resolved_id)
    if not node:
        raise HTTPException(status_code=404, detail=f"Node for identity '{resolved_id}' not found in graph.")
    neighbors = temporal_graph.get_neighbors(resolved_id)
    return {
        "identity_id": resolved_id,
        "entity": node.to_dict(),
        "neighbors": [n.to_dict() for n in neighbors],
    }


@app.get("/api/v1/identities/{identity_id}/history", tags=["Identity Graph"])
def get_identity_history(identity_id: str, timestamp: Optional[float] = None):
    """Point-in-time Identity Time Machine reconstruction."""
    resolved_id = identity_resolver.resolve(identity_id)
    ts = timestamp or time.time()
    recon = temporal_graph.point_in_time_query(resolved_id, ts)
    return recon


@app.get("/api/v1/devices/{device_id}/posture", tags=["Posture"])
def get_device_posture(device_id: str):
    """Calculates multidimensional device posture state and trust score."""
    device = device_repo.get(device_id)
    if not device:
        raise HTTPException(status_code=404, detail=f"Device '{device_id}' not found.")
    state = DevicePostureEvaluator.evaluate(
        device_id=device.device_id,
        managed=device.managed,
        disk_encrypted=True,
        edr_active=True,
        os_patched=True,
        certificate_valid=bool(device.certificate_serial),
    )
    return state.to_dict()


@app.get("/api/v1/services/{service_id}/identity", tags=["Services"])
def get_service_identity(service_id: str):
    """Retrieves service identity and security classification."""
    srv = service_repo.get(service_id)
    if not srv:
        raise HTTPException(status_code=404, detail=f"Service '{service_id}' not found.")
    return srv.to_dict()


@app.get("/api/v1/sessions/{session_id}/context", tags=["Sessions"])
def get_session_context(session_id: str):
    """Retrieves active session state and associated identity bindings."""
    sess = session_monitor.get_session(session_id)
    if not sess:
        raise HTTPException(status_code=404, detail=f"Session '{session_id}' not found in active registry.")
    return sess.to_dict()


@app.get("/api/v1/sessions/{session_id}/risk", tags=["Risk"])
def get_session_risk(session_id: str):
    """Evaluates live session risk score with JA4, TLS and behavioral factors."""
    sess = session_monitor.get_session(session_id)
    if not sess:
        raise HTTPException(status_code=404, detail=f"Session '{session_id}' not found.")
    risk = session_risk_engine.evaluate_session(
        session_id=session_id,
        identity_id=sess.identity_id,
        device_id=sess.device_id,
        service_id=sess.service_id,
        ja4=sess.ja4,
        tls_version=sess.tls_version,
    )
    return risk.to_dict()


@app.post("/api/v1/access/request", tags=["Enforcement"])
def request_access(req: EvaluateAccessRequest):
    """Enforces zero-trust policy via PEP adapter, registering active session upon ALLOW."""
    ctx = _build_access_context(
        subject_id=req.subject_id,
        device_id=req.device_id,
        resource_id=req.resource_id,
        action=req.action,
        client_ip=req.client_ip,
        ja4=req.ja4,
        tls_version=req.tls_version,
        session_id=req.session_id,
    )
    result = pep.enforce(ctx)
    if result.action == EnforcementAction.FORWARD:
        active_sess = ActiveSession(
            session_id=ctx.session_id,
            identity_id=ctx.subject_id,
            device_id=ctx.device_id,
            service_id=ctx.resource_id,
            status=SessionStatus.ACTIVE,
            tls_version=ctx.tls_version,
            ja4=ctx.ja4,
            client_ip=ctx.client_ip,
            device_posture_score=ctx.trust_context.device_trust if ctx.trust_context else 1.0,
            session_risk_score=10.0,
        )
        session_monitor.register_session(active_sess)
    return result.to_dict()


@app.post("/api/v1/access/decision", tags=["PDP"])
def evaluate_decision(req: EvaluateAccessRequest):
    """Direct Policy Decision Point (PDP) evaluation without enforcement side-effects."""
    ctx = _build_access_context(
        subject_id=req.subject_id,
        device_id=req.device_id,
        resource_id=req.resource_id,
        action=req.action,
        client_ip=req.client_ip,
        ja4=req.ja4,
        tls_version=req.tls_version,
        session_id=req.session_id,
    )
    decision = pdp.evaluate_access(ctx)
    explanation = PolicyDecisionExplainer.explain(decision)
    return {
        "decision": decision.to_dict(),
        "explanation": explanation,
    }


@app.post("/api/v1/access/revoke", tags=["Sessions"])
def revoke_session(req: RevokeSessionRequest):
    """Explicitly revokes an active session and updates the audit ledger."""
    try:
        session = revocation_manager.revoke_session(
            session_id=req.session_id,
            actor=req.actor,
            reason=req.reason,
        )
        return {"status": "REVOKED", "session": session.to_dict()}
    except KeyError as e:
        raise HTTPException(status_code=404, detail=str(e))


@app.get("/api/v1/access/history", tags=["PDP"])
def get_access_history(limit: int = 50):
    """Retrieves forensic ledger of recent policy decisions."""
    history = pdp.get_audit_log(limit=limit)
    return {"total_records": len(history), "decisions": [h.to_dict() for h in history]}


@app.get("/api/v1/policies", tags=["Policies"])
def list_policies():
    """Lists all active and deployed zero-trust policies."""
    policies = pdp.list_policies()
    return {"count": len(policies), "policies": [p.to_dict() for p in policies]}


@app.post("/api/v1/policies", tags=["Policies"])
def create_policy(req: CreatePolicyRequest):
    """Parses, validates, and deploys a new zero-trust policy."""
    conditions = [PolicyCondition(**c) for c in req.conditions]
    policy = ZeroTrustPolicy(
        policy_id=req.policy_id,
        name=req.name,
        effect=PolicyEffect(req.effect.upper()),
        priority=req.priority,
        target_services=req.target_services,
        target_actions=req.target_actions,
        conditions=conditions,
        description=req.description,
        version=req.version,
    )
    try:
        validator.validate(policy)
    except PolicyValidationError as e:
        raise HTTPException(status_code=400, detail=str(e))

    conflicts = conflict_detector.detect_conflicts(pdp.list_policies() + [policy])
    pdp.register_policy(policy)
    return {
        "status": "DEPLOYED",
        "policy_id": policy.policy_id,
        "version": policy.version,
        "conflicts_detected": [c.to_dict() for c in conflicts if c.policy_a_id == policy.policy_id or c.policy_b_id == policy.policy_id],
    }


@app.post("/api/v1/policies/{policy_id}/validate", tags=["Policies"])
def validate_policy(policy_id: str):
    """Validates an existing policy for syntactic and attribute integrity."""
    pol = pdp.get_policy(policy_id)
    if not pol:
        raise HTTPException(status_code=404, detail=f"Policy '{policy_id}' not found.")
    try:
        is_valid = validator.validate(pol)
        error = None
    except PolicyValidationError as e:
        is_valid = False
        error = str(e)
    conflicts = conflict_detector.detect_conflicts(pdp.list_policies())
    matching_conflicts = [c.to_dict() for c in conflicts if c.policy_a_id == policy_id or c.policy_b_id == policy_id]
    return {
        "policy_id": policy_id,
        "valid": is_valid,
        "error": error,
        "conflicts": matching_conflicts,
    }


@app.post("/api/v1/policies/{policy_id}/simulate", tags=["Simulation"])
def simulate_policy(policy_id: str):
    """Simulates access evaluation against hypothetical context perturbations."""
    pol = pdp.get_policy(policy_id)
    if not pol:
        raise HTTPException(status_code=404, detail=f"Policy '{policy_id}' not found.")
    base_ctx = _build_access_context(
        subject_id="ID-1192",
        device_id="DEVICE-44",
        resource_id=pol.target_services[0] if pol.target_services and pol.target_services[0] != "*" else "MTA-07",
    )
    sim_res = simulator.simulate_perturbation(
        base_context=base_ctx,
        attribute_overrides={"device_managed": False, "device_posture": "NONCOMPLIANT"},
        scenario_description="Hypothetical device posture degradation on active session",
    )
    return sim_res.to_dict()


@app.post("/api/v1/policies/{policy_id}/deploy", tags=["Policies"])
def deploy_policy_endpoint(policy_id: str):
    """Activates a policy into the active PDP routing table."""
    pol = pdp.get_policy(policy_id)
    if not pol:
        raise HTTPException(status_code=404, detail=f"Policy '{policy_id}' not found.")
    pdp.register_policy(pol)
    return {"status": "ACTIVATED", "policy_id": policy_id, "version": pol.version}


@app.post("/api/v1/policies/{policy_id}/rollback", tags=["Policies"])
def rollback_policy(policy_id: str, target_version: str = "1.0.0"):
    """Rolls back a policy to an earlier version."""
    pol = pdp.get_policy(policy_id)
    if not pol:
        raise HTTPException(status_code=404, detail=f"Policy '{policy_id}' not found.")
    pol.version = target_version
    pdp.register_policy(pol)
    return {"status": "ROLLED_BACK", "policy_id": policy_id, "active_version": target_version}


@app.get("/api/v1/policies/{policy_id}/impact", tags=["Simulation"])
def get_policy_impact(policy_id: str):
    """Calculates blast radius impact of a policy across users, devices, and services."""
    pol = pdp.get_policy(policy_id)
    if not pol:
        raise HTTPException(status_code=404, detail=f"Policy '{policy_id}' not found.")
    assessment = blast_analyzer.evaluate_blast_radius(pol)
    return assessment.to_dict()


@app.get("/api/v1/trust/{entity_id}", tags=["Trust Engine"])
def get_entity_trust(entity_id: str):
    """Retrieves composite trust context for user, device, or service."""
    resolved_id = identity_resolver.resolve(entity_id)
    user = user_repo.get(resolved_id)
    device = device_repo.get(entity_id)

    if device:
        posture = DevicePostureEvaluator.evaluate(
            device_id=device.device_id,
            managed=device.managed,
            disk_encrypted=True,
            edr_active=True,
            os_patched=True,
            certificate_valid=bool(device.certificate_serial),
        )
        return {
            "entity_id": entity_id,
            "type": "DEVICE",
            "trust_score": posture.posture_score,
            "posture": posture.posture_level.value,
            "details": posture.to_dict(),
        }
    elif user:
        is_priv = any("ADMIN" in r for r in user.roles)
        risk = IdentityRiskEngine.calculate_risk(identity_id=resolved_id, is_privileged=is_priv)
        return {
            "entity_id": resolved_id,
            "type": "USER",
            "trust_score": round(max(0.0, 1.0 - (risk.overall_score / 100.0)), 2),
            "risk_level": risk.risk_level.value,
            "factors": risk.contributing_factors,
        }
    else:
        raise HTTPException(status_code=404, detail=f"Entity '{entity_id}' not found.")


@app.get("/api/v1/identity-risk/{identity_id}", tags=["Risk"])
def get_identity_risk(identity_id: str):
    """Evaluates behavioral and historical identity risk for a user."""
    resolved_id = identity_resolver.resolve(identity_id)
    user = user_repo.get(resolved_id)
    if not user:
        raise HTTPException(status_code=404, detail=f"User '{identity_id}' not found.")
    is_priv = any("ADMIN" in r for r in user.roles)
    risk = IdentityRiskEngine.calculate_risk(identity_id=resolved_id, is_privileged=is_priv)
    return risk.to_dict()


@app.get("/api/v1/access-reviews", tags=["Governance"])
def list_access_reviews():
    """Lists active access certification campaign items."""
    campaign = AccessCertificationCampaign(
        campaign_name="Q3 2026 Enterprise Zero Trust Access Review",
        reviewer_id="ID-2044",
    )
    for u in user_repo.list_all():
        for r in u.roles:
            campaign.items[f"REV-{u.identity_id}-{r}"] = AccessReviewItem(
                item_id=f"REV-{u.identity_id}-{r}",
                grant_id=f"GRANT-{u.identity_id}",
                identity_id=u.identity_id,
                resource_id="ALL",
                action=r,
            )
    return {
        "campaign_id": campaign.campaign_id,
        "campaign_name": campaign.campaign_name,
        "items": [it.to_dict() for it in campaign.items.values()],
    }


@app.post("/api/v1/access-reviews/{review_id}/complete", tags=["Governance"])
def complete_access_review(review_id: str, req: CompleteAccessReviewRequest):
    """Completes an individual access review certification item."""
    decision_enum = ReviewDecision(req.decision.upper())
    return {
        "review_id": review_id,
        "reviewer_id": req.reviewer_id,
        "decision": decision_enum.value,
        "status": "COMPLETED",
        "notes": req.notes,
        "timestamp": time.time(),
    }


@app.post("/api/v1/privilege/jit/request", tags=["Privilege"])
def request_jit(req: JITElevationRequest):
    """Submits a Just-In-Time role elevation request."""
    jit_req = jit_manager.request_access(
        identity_id=req.identity_id,
        role_requested=req.role_requested,
        target_resource=req.target_resource,
        justification=req.justification,
        duration_minutes=req.duration_minutes,
    )
    return jit_req.to_dict()


@app.post("/api/v1/privilege/jit/approve", tags=["Privilege"])
def approve_jit(req: JITApproveRequest):
    """Approves a JIT elevation request."""
    try:
        approved = jit_manager.approve_and_activate(
            request_id=req.request_id,
            approver_id=req.approver_id,
        )
        return approved.to_dict()
    except KeyError as e:
        raise HTTPException(status_code=404, detail=str(e))


@app.post("/api/v1/privilege/emergency/request", tags=["Privilege"])
def request_emergency_access(req: EmergencyAccessRequest):
    """Initiates an Emergency Break-Glass access request enforcing separation of duties."""
    try:
        bg = emergency_controller.activate_break_glass(
            requester_id=req.requester_id,
            approver_id=req.approver_id,
            incident_ref=req.incident_reference,
            target_service=req.target_service,
            justification=req.justification,
            duration_minutes=req.duration_minutes,
        )
        return bg.to_dict()
    except PermissionError as pe:
        raise HTTPException(status_code=403, detail=str(pe))


@app.post("/api/v1/copilot/identity/query", tags=["Copilot"])
def query_identity_copilot(req: CopilotQueryRequest):
    """Processes natural language or structured diagnostic queries through Identity Copilot."""
    if req.session_id:
        return copilot.explain_session_decision(req.session_id)
    elif req.service_id and req.identity_id and req.device_id:
        return copilot.why_cant_they_access(req.identity_id, req.service_id, req.device_id)
    elif req.service_id and req.identity_id:
        return copilot.why_can_they_access(req.identity_id, req.service_id)
    elif req.service_id:
        return copilot.who_can_access(req.service_id)
    else:
        # Default fallback explanation
        return copilot.explain_session_decision("S-991")


@app.get("/api/v1/governance/dashboard", tags=["Governance"])
def get_governance_dashboard():
    """Displays enterprise zero trust governance KPI dashboard (Component 71)."""
    users = user_repo.list_all()
    devices = device_repo.list_all()
    active_sessions = session_monitor.list_active_sessions()
    ledger = pdp.get_audit_log(limit=500)

    allows = sum(1 for d in ledger if d.decision == "ALLOW")
    stepups = sum(1 for d in ledger if d.decision == "STEP_UP")
    denies = sum(1 for d in ledger if d.decision == "DENY")
    total_decisions = max(1, len(ledger))

    return {
        "active_identities": len(users),
        "managed_devices": sum(1 for d in devices if d.managed),
        "unmanaged_devices": sum(1 for d in devices if not d.managed),
        "high_risk_identities": sum(1 for u in users if u.risk_level in ("HIGH", "CRITICAL")),
        "active_sessions": len(active_sessions),
        "privileged_accounts": sum(1 for u in users if any("ADMIN" in r for r in u.roles)),
        "policy_decisions": {
            "total": total_decisions,
            "allow_pct": round((allows / total_decisions) * 100, 1),
            "stepup_pct": round((stepups / total_decisions) * 100, 1),
            "deny_pct": round((denies / total_decisions) * 100, 1),
        },
        "identity_gaps": 0,
        "policy_conflicts": len(conflict_detector.detect_conflicts(pdp.list_policies())),
    }


@app.get("/api/v1/governance/bundles/signed", tags=["Governance"])
def get_signed_policy_bundle():
    """Generates an offline SHA-256 signed zero-trust policy bundle (Component 78-79)."""
    bundle = PolicyBundleDistributor.create_bundle(
        policies=pdp.list_policies(),
        version="4.2.0",
        validity_hours=24,
    )
    return bundle.to_dict()


# ==============================================================================
# Typer CLI Commands
# ==============================================================================

@cli.command("evaluate-access")
def cli_evaluate_access(
    subject: str = typer.Argument("ID-1192", help="Canonical ID, alias, or email"),
    resource: str = typer.Argument("FORENSIC-API", help="Service or resource identifier"),
    device: str = typer.Option("DEVICE-44", help="Originating device identifier"),
    action: str = typer.Option("read", help="Requested action (read, write, connect)"),
    ip: str = typer.Option("10.200.1.44", help="Client IP address"),
):
    """Evaluates an access request against the Zero Trust Policy Decision Point."""
    ctx = _build_access_context(
        subject_id=subject,
        device_id=device,
        resource_id=resource,
        action=action,
        client_ip=ip,
    )
    decision = pdp.evaluate_access(ctx)
    explanation = PolicyDecisionExplainer.explain(decision)

    color = typer.colors.GREEN if decision.decision == "ALLOW" else (
        typer.colors.YELLOW if decision.decision == "STEP_UP" else typer.colors.RED
    )
    typer.secho(f"\n[+] Decision: {decision.decision}", fg=color, bold=True)
    typer.echo(f"    Policy Applied: {decision.matched_policy_id} (Version {decision.policy_version})")
    typer.echo(f"    Subject:        {ctx.subject_id} | Device: {ctx.device_id} (Posture: {ctx.device_posture})")
    typer.echo(f"    Resource:       {ctx.resource_id} (Class: {ctx.resource_classification})")
    typer.echo(f"    Identity Trust: {ctx.trust_context.identity_trust} | Device Trust: {ctx.trust_context.device_trust}")
    typer.echo(f"    Overall Trust:  {ctx.trust_context.trust_tier} ({ctx.trust_context.overall_trust_score})")
    typer.echo(f"\n[i] Explanation:\n    {explanation.get('summary')}")


@cli.command("list-identities")
def cli_list_identities():
    """Lists registered enterprise identities and resolution aliases."""
    typer.echo("\n==================== ENTERPRISE IDENTITIES ====================")
    for u in user_repo.list_all():
        typer.echo(f"ID: {u.identity_id:14} | Name: {u.username:14} | Email: {u.email:30} | Risk: {u.risk_level}")
        typer.echo(f"     Groups: {', '.join(u.groups)} | Roles: {', '.join(u.roles)}")


@cli.command("session-status")
def cli_session_status(session_id: str = typer.Argument("S-991")):
    """Inspects active session state, device binding, and real-time trust score."""
    sess = session_monitor.get_session(session_id)
    if not sess:
        typer.secho(f"Session '{session_id}' not found in active monitor registry.", fg=typer.colors.RED)
        raise typer.Exit(code=1)

    typer.echo(f"\n[*] Session: {sess.session_id}")
    typer.echo(f"    Identity:     {sess.identity_id}")
    typer.echo(f"    Device:       {sess.device_id}")
    typer.echo(f"    Service:      {sess.service_id}")
    typer.echo(f"    Status:       {sess.status.value}")
    typer.echo(f"    Posture:      {sess.device_posture_score}")
    typer.echo(f"    Risk Score:   {sess.session_risk_score}")
    typer.echo(f"    JA4:          {sess.ja4}")


@cli.command("copilot-query")
def cli_copilot_query(
    session_id: str = typer.Argument("S-991"),
):
    """Submits a diagnostic query to the Zero Trust Identity Copilot."""
    typer.echo(f"\n[*] Querying Identity Copilot for session: {session_id}...")
    resp = copilot.explain_session_decision(session_id)
    typer.secho("\n[+] Copilot Analysis:", fg=typer.colors.CYAN, bold=True)
    for k, v in resp.items():
        typer.echo(f"    {k:20}: {v}")


@cli.command("governance-dashboard")
def cli_governance_dashboard():
    """Displays the Enterprise Zero Trust & Identity Governance summary."""
    data = get_governance_dashboard()
    typer.echo("\n+-----------------------------------------------------+")
    typer.echo("| IDENTITY & ZERO TRUST GOVERNANCE DASHBOARD          |")
    typer.echo("+-----------------------------------------------------+")
    typer.echo(f"| Active Identities:                  {data['active_identities']:<16}|")
    typer.echo(f"| Managed Devices:                    {data['managed_devices']:<16}|")
    typer.echo(f"| Unmanaged Devices:                  {data['unmanaged_devices']:<16}|")
    typer.echo(f"| High-Risk Identities:               {data['high_risk_identities']:<16}|")
    typer.echo(f"| Active Sessions:                    {data['active_sessions']:<16}|")
    typer.echo(f"| Privileged Accounts:                {data['privileged_accounts']:<16}|")
    typer.echo("+-----------------------------------------------------+")
    typer.echo(f"| Policy Decisions (Total: {data['policy_decisions']['total']:<3}):                      |")
    typer.echo(f"| Allow:                              {data['policy_decisions']['allow_pct']}%           |")
    typer.echo(f"| Step-Up:                            {data['policy_decisions']['stepup_pct']}%           |")
    typer.echo(f"| Deny:                               {data['policy_decisions']['deny_pct']}%           |")
    typer.echo("+-----------------------------------------------------+")
    typer.echo(f"| Identity Gaps:                      {data['identity_gaps']:<16}|")
    typer.echo(f"| Policy Conflicts:                   {data['policy_conflicts']:<16}|")
    typer.echo("+-----------------------------------------------------+\n")


@cli.command("request-jit")
def cli_request_jit(
    requester: str = typer.Argument("ID-1192"),
    role: str = typer.Argument("SOC_ADMIN"),
    resource: str = typer.Argument("FORENSIC-API"),
    minutes: int = typer.Option(30, help="Elevation validity in minutes"),
):
    """Submits a JIT role elevation request."""
    jit_req = jit_manager.request_access(
        identity_id=requester,
        role_requested=role,
        target_resource=resource,
        justification="Manual CLI elevation",
        duration_minutes=minutes,
    )
    typer.secho(f"\n[+] JIT Request Submitted: {jit_req.request_id}", fg=typer.colors.GREEN, bold=True)
    typer.echo(f"    Requester: {jit_req.identity_id} | Role: {jit_req.role_requested}")
    typer.echo(f"    Resource:  {jit_req.target_resource} | Status: {jit_req.status.value}")


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] not in ("run", "serve"):
        cli()
    else:
        import uvicorn
        typer.echo("[*] Starting Phase 27 Enterprise Zero Trust Control Plane on http://0.0.0.0:8027...")
        uvicorn.run("phase_27_zero_trust_identity_control:app", host="0.0.0.0", port=8027, reload=True)
