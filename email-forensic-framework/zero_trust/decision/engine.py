"""
Policy Decision Point (PDP) Engine.
Evaluates access requests against compiled policies with caching, auditing, and fail-safe handling.
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
import time
import uuid

from zero_trust.policy.parser import ZeroTrustPolicy, PolicyEffect, PolicyCondition
from zero_trust.policy.compiler import PolicyCompiler, CompiledPolicy
from .context import AccessRequestContext, TrustContext


@dataclass
class AccessDecisionRecord:
    decision_id: str
    decision: str  # ALLOW, DENY, STEP_UP, RESTRICT
    subject_id: str
    device_id: str
    resource_id: str
    action: str
    matched_policy_id: Optional[str]
    policy_version: str
    reasons: List[str]
    risk_factors: List[str]
    context_snapshot: Dict[str, Any]
    timestamp: float = field(default_factory=time.time)
    cached: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "decision_id": self.decision_id,
            "decision": self.decision,
            "subject_id": self.subject_id,
            "device_id": self.device_id,
            "resource_id": self.resource_id,
            "action": self.action,
            "matched_policy_id": self.matched_policy_id,
            "policy_version": self.policy_version,
            "reasons": self.reasons,
            "risk_factors": self.risk_factors,
            "timestamp": self.timestamp,
            "cached": self.cached,
        }


class PolicyDecisionPoint:
    """Core Zero Trust Policy Decision Point (PDP)."""

    def __init__(self, policies: Optional[List[ZeroTrustPolicy]] = None):
        self._policies: Dict[str, ZeroTrustPolicy] = {}
        self._compiled_policies: List[CompiledPolicy] = []
        self._decision_cache: Dict[str, AccessDecisionRecord] = {}
        self._audit_log: List[AccessDecisionRecord] = []
        self.policy_version: str = "1.0.0"
        self._load_default_policies()

    def _load_default_policies(self):
        defaults = [
            # Policy 1: Global Security Ops SOC Admin Access
            ZeroTrustPolicy(
                policy_id="POL-SOC-ADMIN",
                name="SOC Admin Access Policy",
                effect=PolicyEffect.ALLOW,
                description="Allows managed healthy devices in security-ops to access forensic services",
                target_services=["FORENSIC-API", "EVIDENCE-VAULT"],
                target_actions=["*"],
                conditions=[
                    PolicyCondition("subject.group", "==", "security-ops"),
                    PolicyCondition("device.managed", "==", True),
                    PolicyCondition("device.posture", "==", "HEALTHY"),
                    PolicyCondition("session.risk", "not_in", ["HIGH", "CRITICAL"]),
                ],
                priority=10,
            ),
            # Policy 2: Strict Unmanaged Device Block on Critical Resources
            ZeroTrustPolicy(
                policy_id="POL-BLOCK-UNMANAGED-CRITICAL",
                name="Block Unmanaged Access to Critical Systems",
                effect=PolicyEffect.DENY,
                description="Strictly denies access to Critical resources from unmanaged devices",
                target_services=["*"],
                target_actions=["*"],
                conditions=[
                    PolicyCondition("device.managed", "==", False),
                    PolicyCondition("resource.classification", "==", "CRITICAL"),
                ],
                priority=1,  # Highest priority
            ),
            # Policy 3: Step-Up Authentication on Elevated Session Risk
            ZeroTrustPolicy(
                policy_id="POL-STEPUP-RISKY-SESSION",
                name="Step-Up Authentication for Elevated Session Risk",
                effect=PolicyEffect.STEP_UP,
                description="Demands step-up authentication when session risk is HIGH or destination is critical",
                target_services=["*"],
                target_actions=["*"],
                conditions=[
                    PolicyCondition("session.risk", "in", ["HIGH", "CRITICAL"]),
                ],
                priority=5,
            ),
            # Policy 4: Standard MTA Relay & Infrastructure Admin
            ZeroTrustPolicy(
                policy_id="POL-MTA-ADMIN",
                name="MTA Management Access",
                effect=PolicyEffect.ALLOW,
                description="Allows network engineering MTA admins to administer mail edge gateways",
                target_services=["MTA-07", "MTA-02"],
                target_actions=["*"],
                conditions=[
                    PolicyCondition("subject.group", "==", "mta-admins"),
                    PolicyCondition("device.managed", "==", True),
                    PolicyCondition("session.risk", "!=", "CRITICAL"),
                ],
                priority=20,
            ),
            # Policy 5: General Employee Internal Access
            ZeroTrustPolicy(
                policy_id="POL-GENERAL-INTERNAL",
                name="General Internal Employee Access",
                effect=PolicyEffect.ALLOW,
                description="Allows internal access to standard webmail",
                target_services=["PUBLIC-WEBMAIL"],
                target_actions=["read", "write"],
                conditions=[
                    PolicyCondition("device.managed", "==", True),
                ],
                priority=50,
            ),
            # Policy 6: Authorized East-West Microservice Interconnect
            ZeroTrustPolicy(
                policy_id="POL-S2S-MICROSERVICE",
                name="Authorized East-West Microservice Interconnect",
                effect=PolicyEffect.ALLOW,
                description="Allows mutual TLS authenticated service accounts to call designated backend services",
                target_services=["*"],
                target_actions=["*"],
                conditions=[
                    PolicyCondition("subject.group", "==", "service-accounts"),
                    PolicyCondition("device.managed", "==", True),
                    PolicyCondition("device.posture", "==", "HEALTHY"),
                    PolicyCondition("session.risk", "==", "LOW"),
                ],
                priority=15,
            ),
        ]
        for p in defaults:
            self._policies[p.policy_id] = p
        self._recompile()

    def _recompile(self):
        self._compiled_policies = PolicyCompiler.compile_all(list(self._policies.values()))
        self._decision_cache.clear()

    def register_policy(self, policy: ZeroTrustPolicy) -> None:
        self._policies[policy.policy_id] = policy
        self._recompile()

    def remove_policy(self, policy_id: str) -> None:
        if policy_id in self._policies:
            del self._policies[policy_id]
            self._recompile()

    def get_policy(self, policy_id: str) -> Optional[ZeroTrustPolicy]:
        return self._policies.get(policy_id)

    def list_policies(self) -> List[ZeroTrustPolicy]:
        return list(self._policies.values())

    def evaluate_access(self, ctx: AccessRequestContext, use_cache: bool = True) -> AccessDecisionRecord:
        cache_key = ctx.compute_cache_key(self.policy_version)
        if use_cache and cache_key in self._decision_cache:
            cached_rec = self._decision_cache[cache_key]
            rec = AccessDecisionRecord(
                decision_id=f"DEC-{uuid.uuid4().hex[:6].upper()}",
                decision=cached_rec.decision,
                subject_id=ctx.subject_id,
                device_id=ctx.device_id,
                resource_id=ctx.resource_id,
                action=ctx.action,
                matched_policy_id=cached_rec.matched_policy_id,
                policy_version=self.policy_version,
                reasons=[f"[CACHED] {r}" for r in cached_rec.reasons],
                risk_factors=cached_rec.risk_factors,
                context_snapshot=cached_rec.context_snapshot,
                cached=True,
            )
            self._audit_log.append(rec)
            return rec

        eval_dict = ctx.to_evaluation_dict()
        reasons = []
        risk_factors = []

        # Collect risk factors
        if not ctx.device_managed:
            risk_factors.append("Device is unmanaged")
        if ctx.device_posture != "HEALTHY":
            risk_factors.append(f"Device posture is {ctx.device_posture}")
        if ctx.session_risk in ("HIGH", "CRITICAL"):
            risk_factors.append(f"Session risk is {ctx.session_risk}")

        # Evaluate against compiled policies in priority order
        decision = "DENY"
        matched_policy: Optional[ZeroTrustPolicy] = None

        for cp in self._compiled_policies:
            if cp.matches(eval_dict, ctx.resource_id, ctx.action):
                matched_policy = cp.policy
                decision = cp.policy.effect.value
                reasons.append(f"Matched policy '{cp.policy.name}' ({cp.policy.policy_id}) with effect {decision}")
                break

        if not matched_policy:
            # Default Deny (Component 29 / Zero Trust principle)
            reasons.append("Default Deny: No explicit policy permitted this subject/device/action on resource.")

        rec = AccessDecisionRecord(
            decision_id=f"DEC-{uuid.uuid4().hex[:6].upper()}",
            decision=decision,
            subject_id=ctx.subject_id,
            device_id=ctx.device_id,
            resource_id=ctx.resource_id,
            action=ctx.action,
            matched_policy_id=matched_policy.policy_id if matched_policy else None,
            policy_version=self.policy_version,
            reasons=reasons,
            risk_factors=risk_factors,
            context_snapshot=eval_dict,
            cached=False,
        )

        if use_cache:
            self._decision_cache[cache_key] = rec

        self._audit_log.append(rec)
        return rec

    def get_audit_log(self, limit: int = 100) -> List[AccessDecisionRecord]:
        return self._audit_log[-limit:]
